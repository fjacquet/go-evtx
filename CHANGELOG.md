# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2026-08-23

### Added

- `RotationConfig.SyncPolicy`, with `SyncEveryChunk` and `SyncOnTick`.
  `SyncEveryChunk` is the zero value and is the durability model go-evtx has
  always had — every sealed chunk is fsynced before the writer commits it — so
  **the default configuration is byte-identical to v0.10.0** and no existing
  caller changes behaviour. `SyncOnTick` is opt-in group commit: sealed chunks
  are written and the file header is patched, but the fsync is deferred to the
  background flush tick, to `Rotate()` and to `Close()`, so one fsync covers
  every chunk written since the previous tick. Measured at 2770 ns/op against
  `SyncEveryChunk`'s 77 373 ns/op on `darwin/arm64 M1 Pro, APFS, go1.27.0` —
  about 27.9x, with 1 total fsync across the run instead of one per ~81
  records.

  **`SyncOnTick` widens the crash-loss window** from at most one chunk to up
  to `FlushIntervalSec` seconds of arrivals, which is why `New` returns an
  error for `SyncOnTick` with `FlushIntervalSec <= 0` rather than applying a
  default — with no tick the window would be unbounded. It also changes the
  *shape* of a power-loss failure, not only its size: the chunk bytes and the
  file header that advertises them are written with no sync between them, so a
  torn image can show a header claiming a chunk whose bytes never landed — a
  file a parser rejects, not merely a short one. A process crash is unaffected.
  See [ADR-008](docs/adr/ADR-008-sync-policy-group-commit.md).

- `WriteRecords(recs []RecordInput) error` and `RecordInput`, a batch write
  API. Every record is validated before any record is encoded, so a batch
  containing an invalid record writes nothing and returns an error naming that
  record's index (`go_evtx: record 3: …`). The whole slice is written under a
  single lock acquisition. The all-or-nothing guarantee covers *validation*,
  not I/O: a batch spanning chunks seals them as it goes, and a write failure
  partway through leaves earlier records written.

  **`WriteRecords` is not faster per record — it is slower.** At a batch size
  of 100 it runs roughly 1.4x slower per record than 100 sequential
  `WriteRecord` calls (3934 vs 2770 ns/op, matched sync policy), because the
  validation pre-pass collects each record's substitution values to size them
  and the encode then collects them again. Adopt it for the contract, not for
  throughput. See [ADR-009](docs/adr/ADR-009-batch-write-api.md).

  The size check `WriteRecords` uses is an analytic upper bound
  (`estimateMaxPayload`) derived from the encoder's own template and
  substitution structures rather than from constants. It bounds the
  inline-template worst case, so it is stricter than `WriteRecord`'s
  post-encode check by roughly 2 KB: a record whose payload lands in
  approximately the top 2 KB of the 64 996-byte limit is accepted by
  `WriteRecord` and rejected by `WriteRecords`.

### Changed

- Per-record allocation cut by roughly an order of magnitude. `WriteRecord`
  fell from **49.0 to 5.0** allocations per call by `testing.AllocsPerRun`
  (60 → 5 allocs/op and 6822 → 5033 B/op in the benchmark rows), via a reused
  64 KiB chunk assembly buffer shared by both flush paths, a reused BinXML
  encode buffer, and a single arena backing every substitution value.
  `TestWriteRecord_AllocationCeiling` fails the build if this regresses.

  **This raises the per-`Writer` memory floor.** Each `Writer` now retains the
  64 KiB chunk buffer for its lifetime after the first flush, plus an encode
  buffer grown to the largest record it has encoded and never shrunk — so
  budget roughly 64 KiB per `Writer` in steady state, rising toward 128 KiB for
  one that has encoded a near-chunk-sized record. It was previously near zero
  between calls. A process holding many concurrent `Writer`s should size for
  it.

- `RotationConfig` gained a field (`SyncPolicy`). Keyed struct literals — the
  form used in every example, godoc snippet and test in this repository — are
  unaffected. An unkeyed `RotationConfig{...}` literal would no longer
  compile.

- `rotate()` now reports its own `f.Sync()` through `OnFsync`. This closes a
  gap that only `SyncOnTick` exposed: under `SyncEveryChunk` the pending-chunk
  flush at the start of a rotation had already fired the callback, but
  `SyncOnTick` defers that flush's sync, so a rotation fired **no** callback at
  all and a caller counting durability points never learned the archive had
  landed.

  **Callers that count callbacks will see one more per rotation under
  `SyncEveryChunk`** — the flush's and the rotation's, where previously only
  the flush's was reported. The sync of the *replacement* file's placeholder
  header is deliberately not reported: it makes an empty header durable, not
  caller data.

## [0.10.0] - 2026-08-22

### Changed

- The background flush tick no longer rewrites the whole 64 KiB chunk and
  fsyncs on every interval regardless of arrivals. A tick with no new records
  since the previous one now does nothing at all — no write, no fsync — which
  at `FlushIntervalSec: 1` turns up to 86 400 fsyncs/day at idle into zero,
  measured at 13.84 ns/op with 0 allocations
  (`BenchmarkTickFlushIdle`). A tick with new records still builds a full
  chunk buffer internally (`fillHashTables` back-patches offsets inside the
  records region, so a smaller buffer cannot be used safely) but writes only
  the used prefix to disk — the records region plus the 512-byte header — a
  real reduction versus the flat 65536 bytes every tick used to write, though
  roughly half on average rather than an order of magnitude; see
  `docs/perf-baseline.md`'s "Derived figures" section for the honest,
  labeled-as-arithmetic estimate. No API change, and the bytes on disk after
  `Close()` are byte-identical to v0.9.0's — asserted by
  `TestTickFlush_ByteIdenticalToNoTick`. See ADR-007.
- The event-records CRC continues to be computed by a full rescan of the
  records region on every flush (`patchEventRecordsCRC`). An earlier commit on
  this release replaced it with a CRC maintained incrementally over `w.records`
  and claimed bit-identical output; that was **false and was reverted before
  release**. The checksum at `chunk[52:56]` covers the *patched* chunk buffer,
  and `fillHashTables` writes hash-chain offsets inside the records region, so
  the bytes on disk are not the bytes in `w.records`. Every chunk written under
  the incremental scheme carried a wrong records checksum while the record
  bytes themselves were unchanged — checksum-invisible corruption, and a
  violation of this release's byte-identity invariant.
  `TestWrittenFile_EventRecordsCRCMatchesRecords` now guards the property
  directly against a written file. See ADR-007's Decision 3.

### Added

- `docs/perf-baseline.md` and `bench_test.go`: reproducible writer throughput
  benchmarks under the same append-only discipline as `docs/format-baseline.md`.

## [0.9.0] - 2026-08-22

### Added

- **`IpAddress` as a thirteenth `EventData` field.** The schema was closed at
  twelve, and `WriteRecord` ignored every key outside it without returning an
  error — so a caller with a peer address could pass `IpAddress`, see the write
  succeed, and get a file that did not contain it. Windows Security auditing
  carries a peer address on 4625 and 5145, and every network audit-event source
  has one; a downstream adapter shipped a field-map entry and a passing unit
  test for it, and produced 19 records in which the address occurred zero times.

  The substitution pair is appended at indices 42/43 rather than extending the
  contiguous 5..28 data block, because widening that block would renumber every
  named `<System>` index from 29 up. Document order and substitution index are
  independent, so the element still reads back in position thirteen.

  This changes the encoding: `testdata/binxml-golden.bin` is regenerated in the
  same commit, per the rule stated on `TestBuildBinXML_PayloadUnchangedByCollection`.

## [0.8.2] - 2026-08-10

### Fixed

- **`evtx dump --shape=flat` rounded any integer above 2^53.** `Keywords`
  `0x8000000000000000` was written as `9223372036854776000` instead of
  `9223372036854775808`. The top `Keywords` bit is set on nearly every real
  Windows event, so this affected almost every record — in the shape intended
  for ingestion, where the value is a bitmask and a rounded one is simply
  wrong.

  The flat projection lifted `System` by marshalling it and decoding into a
  `map[string]any`, and Go decodes every JSON number in an `any` as a
  `float64`, whose 53-bit mantissa cannot hold a `uint64` that large. It now
  decodes with `UseNumber`, so the original digits survive and re-marshal
  verbatim.

  The faithful shape was never affected: it marshals `Event` directly and
  never round-trips through `float64`.

  Found by running the released binary against a real Windows Server 2025
  file. No test could have caught it: every fixture this repository writes
  carries `Keywords` 0. The regression test now asserts on the marshalled
  bytes, since re-parsing the output would hide the defect it guards.

## [0.8.1] - 2026-08-10

Review findings from the v0.8.0 pull request, fixed after merge. The first of
them is the kind of defect this project treats as its worst: a read that
stopped early and reported success.

v0.8.0 itself shipped as a module version but without binaries — its release
workflow failed on a goreleaser config key that the version CI pins does not
accept, so no archives were built. That is fixed on this release's branch, and
the config is now validated against both the pinned version and the current
one before a tag is cut.

### Added

- `ErrChunkUnreadable`, a sentinel wrapping every failure to load a chunk that
  is not simply the end of the file. `errors.Is(err, evtx.ErrChunkUnreadable)`
  is how a caller now tells "the file ended" from "the file stopped".

### Fixed

- **A chunk that could not be read was reported as a clean end of stream.**
  `Reader` collapsed a failing read, and a chunk with no signature, into
  `ErrNoMoreRecords` — the same value a fully-read file returns. A file
  truncated part-way, or whose fifth chunk of eleven was corrupt, therefore
  looked finished: `evtx dump` exited 0 over a partial dump and `evtx info`
  printed "0 failures" for a file it never reached the end of. The genuine end
  of stream is still `ErrNoMoreRecords`; anything else now reaches the caller
  as itself, wrapping `ErrChunkUnreadable`. The failed chunk cannot be stepped
  over — its own bytes are what would say where the next one begins — so the
  stream ends there and every later call returns `ErrNoMoreRecords`, keeping
  the guarantee that a loop reading until `ErrNoMoreRecords` terminates.
- **A record could be declared longer than the records region.** `Reader`
  checked a record's declared size against the chunk buffer but not against
  `FreeSpaceOffset`, where the records end and the chunk's padding begins. A
  corrupt size that stayed under 65536 but ran past that offset was accepted,
  so padding was decoded as payload and a fabricated event could be returned
  in place of a framing error. Both bounds are now checked — `FreeSpaceOffset`
  is itself read from the chunk header and may be the corrupt value, so the
  buffer-length guard stays.
- **`evtx dump --out` naming the input file destroyed it.** `os.Create`
  truncates, so `evtx dump --in f.evtx --out f.evtx` emptied the file it was
  still reading. Rejected now with exit 1, comparing the two paths by file
  identity rather than by string, so a relative and an absolute spelling of the
  same file are both caught.
- **`dump --shape=flat` dropped the whole `System` block when marshalling it
  failed.** The error was discarded and the projection carried on, so the
  record went out with no provider, channel, event ID or timestamp fields and
  nothing on either stream to say so. It is now reported like any other failure
  on one record: a line on stderr, that record left out, exit 2.
- **`evtx info` merged genuinely different causes in its tally.** Every run of
  digits in an error message was replaced before grouping, so two causes
  differing only by a numeric value — two unsupported type codes, say — became
  one line and one of them vanished behind the other's count. Only the position
  fields the library attaches (chunk, record, offset) are erased now; a number
  that is part of what went wrong is part of the cause.

### Changed

- Both commands exit 1 when the input cannot be read to the end, rather than
  reporting a clean pass over the records they did read. `dump` still writes
  those records and `info` still prints its report, followed by a
  `read incomplete after N records` line. `--allow-errors` does not suppress
  this: it means "some records were skipped is acceptable", never "the file was
  not finished is acceptable".
- `docs/user-guide.md` now distinguishes the three ways a read can fail — a
  decode failure continues to the next record, a framing failure abandons the
  rest of the chunk, a chunk-load failure ends the stream — where it previously
  described the first as though it applied to all of them. It also no longer
  says `dump` normalises error messages the way `info` does; `dump` writes each
  error as the library phrased it, and only `info` groups.

## [0.8.0] - 2026-08-10

### Added

- `evtx` command line binary with `dump` and `info`, shipped as a release
  artefact for linux/darwin/windows on amd64 and arm64. Install with
  `go install github.com/fjacquet/go-evtx/cmd/evtx@latest`. `dump` writes
  NDJSON in a faithful shape (the library's own `Event`) or a flat shape;
  exit code 2 when records were skipped, `--allow-errors` to suppress it.
  `info` reports the file header and a full decode pass with failures grouped
  by cause.
- `Reader.FileInfo` returning the format version, chunk count and the
  dirty/full flags.

### Fixed

- FILETIME conversion covers the format's whole range. FILETIME 0 is
  1601-01-01T00:00:00Z and Windows writes it for an unset timestamp; both
  conversions routed the epoch offset through `int64` nanoseconds, which spans
  only 1678–2262, so `ReadEvent` rejected records outside that range.
  `ReadEvent` failures across the local corpus fell from 206 records across
  178 of 285 files to 26 records across 4 files — the remaining 26 all being
  the unsupported `AnsiString` type, a separate and unrelated limitation.

## [0.7.4] - 2026-08-10

### Fixed

- **`Level`, `Version`, `Task`, `Opcode` and `Keywords` are read from the
  fields map instead of being written as literal zeros.** The keys were
  accepted and dropped without a word, while `Channel` in the same call was
  honoured — so they looked supported precisely because nothing rejected them.
  A caller could not express any non-default value for the five. Reported as
  issue #13, measured on Windows Server 2025.

  The symptom is a wrong value, not a missing one. Event Viewer resolves a
  zero `Level` to `Information`, a zero `Task` to `None`, a zero `Opcode` to
  `Info` and zero `Keywords` to `None` from its own defaults, so an event a
  caller marked `Level=2` (Error) displayed as `Information`, plausibly and
  silently.

  Each value is parsed as an unsigned integer of its field's width, in decimal
  or with an `0x` prefix. Windows displays `Keywords` in hex, so that is the
  form a caller copies.

  **One limit worth stating:** `Task`'s display name is resolved from a
  provider manifest registered on the reading host. Writing a non-zero `Task`
  puts the number in the file, but no value written here can make Event Viewer
  render a name for it.

  Absent or empty keys still produce 0, which is what every record written
  before this release carried, so nothing changes for a caller that does not
  supply them.

### Added

- `ErrInvalidFieldValue`, returned by `WriteRecord` when one of those five keys
  holds a value that will not fit its field — `Level=256`, `Keywords=0xZZ`. The
  record is rejected and nothing is written.

  An error rather than a substituted zero, because the quiet zero is what
  issue #13 was about. Same stance as `ErrMissingProviderName`: report at the
  point of the mistake, not through a blank column on a Windows host three
  steps later.

## [0.7.3] - 2026-08-10

### Changed

- **A template definition is declared once per chunk instead of once per
  record.** Files shrink by 46%: the 403-record CI fixture goes from
  1 839 104 bytes in 28 chunks to 987 136 bytes in 15. Each record carried its
  own inline copy of the same 1978-byte definition; the writer now remembers
  the pending chunk's definition offset and later records point their template
  instance backward at it.

  Real Windows has always done this, and the corpus is unambiguous: 545
  definitions against 36 819 backward references, and not one forward
  reference.

  Nothing for a caller to change. Files written by earlier versions still
  read — a self-contained definition per record remains valid, just larger.
  Verified on Windows Server 2025: 403 records, `ToXml` renders, both
  `Get-WinEvent` orderings enumerate, and python-evtx agrees.

### Fixed

- **An oversized record is rejected again on the flush-and-retry path.**
  `WriteRecord` size-checks the payload it first builds, which may *reference*
  the pending chunk's definition. When that build does not fit the chunk, the
  record is rebuilt for a fresh chunk and must *inline* the definition —
  roughly 2 KB larger. That rebuilt payload was never re-checked, so a record
  sized between the two limits could be appended to a chunk it does not fit,
  with the chunk CRCs computed over the result. The rebuild is now checked
  against `maxRecordPayload` too, and returns `ErrRecordTooLarge` naming the
  inlining as the cause.

  Only reachable since the change above; no released version can produce it.

### Changed

- **BREAKING:** `WriteRecord` returns `ErrMissingProviderName` when `fields`
  has no non-empty `"ProviderName"`, instead of writing the record.

  Since 0.7.1 an unsupplied value is a `NULL` substitution, which omits its
  element — so an empty provider name produced `<Provider></Provider>`, and
  `Get-WinEvent` threw a `NullReferenceException` on the whole file. The file
  was otherwise valid: `EventLogReader` read every record and `wevtutil`
  exited 0, which is what made the cause so hard to find. It cost a downstream
  consumer a full investigation (issue #10) before an empty `ProviderName` was
  isolated as the trigger.

  Callers passing an empty provider name were already producing a file
  `Get-WinEvent` could not read. This turns that into an error at the point of
  the mistake.

  Only this field is validated. Measured on Windows Server 2025, one variable
  at a time: an empty `Computer` and an empty `Channel` both read fine, so
  rejecting them would be a rule nothing measured.

- `cmd/gen-fixture` removed — it supplied no `ProviderName` and no longer
  runs. `cmd/gen-fixture-system` is the CI gate. What the frozen fixture stood
  for is now `conformance_test.go`, which asserts the rules the corpus taught
  (8-alignment, the EOF token and padding, `NULL` for zero-length values)
  against output written by today's encoder rather than against old bytes.
  See the note at the end of `docs/format-baseline.md`.

- `binxml.go` split into three files — 1174 lines to 431, with the `<Event>`
  template body in `binxml_template.go` and the token writers in
  `binxml_tokens.go`. No behaviour change: `testdata/binxml-golden.bin` matches
  byte for byte, so the encoder emits exactly what it did before. The
  F14/F15/F16 narrative moved to `docs/evtx-format-notes.md`.

  Nothing for a consumer to act on. It is here because the split is what makes
  the remaining format work reviewable: every format fix lands in the template
  file, and the token writers have no reason to change when an event's shape
  does.

## [0.7.1] - 2026-08-09

The writer now emits what Windows emits. 0.7.0 made `ToXml()` render; this
closes the two conformance gaps it left, and the one that was silently
blocking them.

### Fixed

- **A value the caller did not supply is now encoded the way Windows encodes
  one.** `ProviderName`, `Provider/@Guid`, `Channel`, `Computer` and the twelve
  `<Data>` values are referenced by an `OptionalSubstitution` declaring the
  field's real type, and their substitution-array entry is `NULL` when nothing
  was supplied. go-evtx used to write `{size 0, type String}` — a shape that
  occurs **zero** times in 333 100 real records, against 1 686 434 zero-length
  descriptors that all declare `0x00`.

- **Records carry a fragment EOF token and are 8-byte aligned** (W1 and W2).
  Both are absolutes in real output: 37 364 of 37 364 measured records are
  8-aligned in size and offset, and every one carries 1 to 8 trailing bytes
  after its substitution array.

  These were implemented and reverted twice in earlier releases because
  Windows rejected the result. The empty-value encoding above is why: while a
  zero-length value was written as a `String`, Windows refused any record that
  also carried trailing bytes. All three had to land together — measured
  separately, each alone still fails.

  Verified in CI run `31335727200`: 403 records read, `ToXml` renders, both
  `Get-WinEvent` orderings enumerate, content round-trips, and python-evtx
  agrees. `docs/format-baseline.md` row 23.

### Changed

- **An unsupplied field now omits its element** rather than emitting an empty
  one — which is what the format means by a `NULL` substitution, and what
  Windows does. If you leave `ProviderName` or `Computer` unset, the resulting
  event has no `<Provider Name>` and no `<Computer>`. The file is valid and
  `EventLogReader` reads it, but `Get-WinEvent`'s formatting layer throws on an
  event with no provider name. **Supply them.**

### Added

- `cmd/gen-fixture-system`, the generator `Format Verify` now gates on. It
  supplies the three `<System>` fields above; `cmd/gen-fixture` is frozen and
  does not, and still reproduces every historical row of
  `docs/format-baseline.md`.

### Known limitations

- Each record still re-declares its template inline, where Windows declares
  one per chunk and points later records at it. A file-size matter, not a
  correctness one.
- The template hash-table bucket rule is correct for format 3.1 and scores at
  or below chance on 3.2. The 3.2 rule is unknown. Reading is unaffected.
- `AnsiString` is rejected rather than guessed at: the format carries no
  codepage. 16 records in a 320 398-record corpus.

## [0.7.0] - 2026-08-09

Windows reads the files this library writes, and this library reads the files
Windows writes. Neither was true in 0.6.0.

### Fixed

- **`EventLogRecord.ToXml()` and `Get-WinEvent` rejected every file go-evtx
  had ever produced** — `"The data is invalid."`, on records that
  `EventLogReader` itself read without complaint. The cause was five bytes per
  record: an `OptionalSubstitution`'s *token* declares the field's own type,
  while its entry in the *substitution array* declares `NULL` when the value
  is absent. go-evtx wrote `NULL` in both places. That combination occurs zero
  times in 27 million structural observations across 320 398 real records; the
  correct one occurs 1.15 million times. `Correlation/@ActivityID` and
  `@RelatedActivityID` now declare `Guid`, `Execution/@ProcessID` and
  `@ThreadID` declare `UInt32`, `Security/@UserID` declares `Sid`.

  Verified on a Windows VM and then in CI, run `31331708365`, `head_sha`
  `78c1894`: `ToXml ok`, both `Get-WinEvent` orderings at 403 records, and the
  content assertion passing. `docs/format-baseline.md` row 22.

- **The decoder refused a quarter of all real records.** Three causes, all
  measured against the corpus rather than guessed:
  - value type `0x81`, an array of UTF-16 strings, was rejected by a guard
    whose comment claimed "measured zero occurrences" — 22 036 records carry
    one;
  - a template's declared type disagreeing with the substitution array's was
    treated as fatal, when libyal documents exactly that for `SizeT`, whose
    pointer width only the array knows — 62 089 records;
  - `SysTime` was unimplemented — 8 records.

  Local corpus decode: 73.8 % → **99.995 %**.

- `SysTime` now rejects out-of-range components instead of letting
  `time.Date` normalise month 13 into January of the next year.

### Added

- Generic strict BinXML decoding: any Windows-generated `.evtx` file can be
  read, with values carrying their declared type and JSON encoding that
  preserves it.
- A corpus fact dumper and a structural shape census
  (`corpus_scan_test.go`, `corpus_shape_test.go`), both skipped unless pointed
  at a corpus. This is how the `ToXml` defect was found: census what Windows
  writes, profile what go-evtx writes, and list every shape only go-evtx
  emits. The list had one entry. `testdata/shape-census.json` is the committed
  result — 68 shapes, no names and no values.

### Changed

- **BREAKING:** `Reader.ReadRecord()` and the `Record` struct are removed. Use
  `Reader.ReadEvent()`, which returns a typed `Event`. The previous decoder
  assumed go-evtx's own template and returned empty fields with fabricated
  names on any real Windows file, without reporting an error.

### Removed

- **`testdata/system.evtx`.** Every format rule this project encoded was
  derived from that one 1601-record sample, and the same file was then used to
  assert the rules were right — an assertion that cannot fail when the
  derivation is wrong. It did not fail; the rules were wrong. No `.evtx` is
  tracked now, and `isExcludedFixture` refuses any file by that name. The
  consequence is stated rather than hidden: CI no longer checks the chunk
  hash-table rules against a real file. See `testdata/README.md`.
- **The format bisection harness** — eleven `cmd/` packages,
  `binxml_variants.go` and its test, 3067 lines. Its results stay in
  `docs/format-baseline.md`. `Format Verify` drops from 28 jobs to 5,
  including all eleven that had been permanently red and therefore mute.

### Known limitations

- Records are not 8-byte aligned and carry no fragment EOF token, where real
  Windows does both on 37 364 of 37 364 measured records. Windows reads
  go-evtx files regardless.
- Each record re-declares its template inline; real Windows declares one per
  chunk and points back at it.
- The template hash-table bucket rule is correct for format 3.1 and is at
  chance on 3.2. The 3.2 rule is unknown. Reading is unaffected.
- `AnsiString` is rejected, not guessed: the format carries no codepage.

## [0.6.0] - 2026-08-08

### Fixed

- **Oversized records silently corrupted the file.** A record whose BinXML
  payload exceeded the chunk capacity was written truncated, with both CRCs
  computed over the corrupt bytes so the damage was checksum-invisible.
  python-evtx dropped the chunk without warning; this library's own reader
  aborted the file and returned zero records, including from undamaged later
  chunks. `WriteRecord` returned `nil`. Such records are now rejected with
  `ErrRecordTooLarge`. **If you wrote a record whose encoded BinXML payload
  exceeded 64,996 bytes, affected files are unrecoverable.** That is a
  property of the encoded payload, not any single field: BinXML overhead
  plus several moderately sized fields can exceed the limit even when every
  individual field is well under it.
- **A failed rotation silently discarded every subsequent event.** `rotate()`
  left a closed file handle in place when the rename or reopen failed, and
  `WriteRecord` returned `nil` forever after. Failures now set a permanent
  error returned by every method.
- **Sub-second rotations destroyed archives.** Archive filenames used
  one-second resolution, so `os.Rename` silently overwrote a previous archive
  when two rotations landed in the same second. Filenames now carry nanosecond
  resolution, and an existing archive is an error rather than a target.
- **`Close()` panicked when called twice** with `close of closed channel`,
  reachable through the ordinary `defer w.Close()` plus explicit-shutdown
  pattern. `Close` is now idempotent.
- **Writes after `Close` returned `nil` and were discarded.** They now return
  `ErrClosed`.
- **`OnFsync` was invoked while holding the writer lock**, deadlocking any
  callback that re-entered the `Writer`. It is now called after the lock is
  released. Its documented contract was also wrong: it fires on every sync,
  not only when `FlushIntervalSec > 0`.
- **`Reader` was documented as safe for concurrent use but was not.** It now
  is.

### Changed

- `go.mod` Go directive raised from 1.26.4 to 1.26.5 to match the toolchain
  in use.

## [0.5.0] - 2026-03-05

### Added

- `RotationConfig.OnFsync func(time.Time)` — optional callback invoked after each
  successful `f.Sync()` in both `flushChunkLocked()` and `tickFlushLocked()`. When nil
  (the default), behaviour is identical to v0.4.0. Enables callers to track fsync
  timestamps without importing caller-side packages into go-evtx.

[0.5.0]: https://github.com/fjacquet/go-evtx/compare/v0.4.0...v0.5.0

## [0.4.0] - 2026-03-05

### Added

- `RotationConfig.MaxFileSizeMB` — size-based rotation: when the active file reaches N MiB, rotate() is triggered automatically after each `WriteRecord`/`WriteRaw` call
- `RotationConfig.MaxFileCount` — archive retention: after rotation, archives exceeding N are deleted oldest-first
- `RotationConfig.RotationIntervalH` — time-based rotation: `backgroundLoop` fires `rotate()` on a per-hour ticker when this field is > 0
- `Rotate()` public method — manually trigger rotation from any goroutine; safe for concurrent use
- `rotate()` private method — core rotation logic: flush pending chunk, fsync, close, rename to timestamped archive, open fresh file, reset state, call `cleanOldFiles()`
- `archivePathFor()` helper — derives archive name: `base-YYYY-MM-DDTHH-MM-SS.evtx` (UTC, hyphens instead of colons)
- `cleanOldFiles()` helper — glob `base-*.evtx`, sort by mtime, delete oldest beyond `MaxFileCount`
- `Writer.currentSize int64` — approximate file size tracked via `flushChunkLocked()` for size-based rotation
- `evtx_unix.go` (!windows) — `syncDir()` using `syscall.Open` + `syscall.Fsync` for directory durability after rename
- `evtx_windows.go` (windows) — `syncDir()` no-op (NTFS rename is durable without fsync)
- `rotation_test.go` — 6 TDD tests: `TestWriter_SizeRotation`, `TestWriter_CountRetention`, `TestWriter_TimeRotation`, `TestWriter_ManualRotate`, `TestWriter_RotatedFileValid`, `TestWriter_RotateRace`

### Changed

- `New()` goroutine start condition: `FlushIntervalSec > 0 || RotationIntervalH > 0` (was `FlushIntervalSec > 0` only)
- `backgroundLoop()` uses nil-channel idiom for optional rotation ticker: receive on nil channel never fires, so disabled tickers add zero overhead
- `flushChunkLocked()` now updates `w.currentSize += evtxChunkSize` after each committed chunk

## [0.3.0] - 2026-03-05

### Added

- Multi-chunk EVTX support — sessions exceeding ~2,400 events now write correctly (EVTX-01)
- `flushChunkLocked()` — writes complete 65,536-byte chunks incrementally via `f.WriteAt`; patches file header after each chunk; calls `f.Sync()`
- `tickFlushLocked()` — goroutine tick writes partial chunk to disk without advancing chunk count (Option A flush-without-reset)
- Open-handle model: `f *os.File` held open from `New()` through `Close()`, enabling incremental writes
- Pre-append capacity check in `WriteRecord()` and `WriteRaw()` — triggers `flushChunkLocked()` when buffer reaches 65,024 bytes
- `goroutine_test.go` — lifecycle and concurrency tests: flush ticker, graceful shutdown, goroutine leak detection, race-condition coverage
- `docs/adr/ADR-004` — Open-handle incremental flush model decision record

### Changed

- `WriteRecord()` and `WriteRaw()` now call `flushChunkLocked()` when buffer reaches 65,024 bytes (was warn-only in v0.2.x)
- `Close()` deletes placeholder file on empty session (zero-record backward compatibility)

### Removed

- `flushToFile()` — replaced by `flushChunkLocked()` and `tickFlushLocked()`

## [0.2.0] - 2026-03-05

### Added

- `RotationConfig` struct — configures periodic background flush via `FlushIntervalSec` (0 = disabled)
- `New()` now accepts `RotationConfig` as second argument (breaking change from v0.1.0)
- Background goroutine (`backgroundLoop`) — fires `tickFlushLocked()` on a configurable ticker interval
- `Reader` struct with `Open(path)`, `ReadRecord()`, `ReadRaw()`, `Close()`, and `ErrNoMoreRecords` — symmetric read API for `.evtx` files
- `fromFILETIME` — converts Windows FILETIME to `time.Time`
- `docs/PRD.md` — Product Requirements Document
- GitHub Actions `release.yml` — GoReleaser-based release workflow triggered on `v*` tags
- GitHub Actions `pages.yml` — Builds and deploys landing page + API docs to GitHub Pages on every push to `main`
- `.goreleaser.yaml` — GoReleaser v2 configuration (library mode: source archives + auto-changelog)
- Simplified README with CI / Go Reference / Go Report Card / License badges

### Changed

- `Close()` now signals the background goroutine via a `done` channel and waits for it with `sync.WaitGroup` before final flush

## [0.1.0] - 2026-03-04

### Added

- `Writer` struct with `New(path string) (*Writer, error)` constructor
- `WriteRecord(eventID int, fields map[string]string) error` — high-level API; handles BinXML encoding, record wrapping, and timestamp parsing internally
- `WriteRaw(chunk []byte) error` — low-level API; accepts a pre-encoded BinXML payload; go-evtx wraps it with record header and monotonic record ID
- `Close() error` — flushes all buffered records to disk as a valid `.evtx` file (write-on-close model)
- Reserved field keys for `WriteRecord`: `ProviderName`, `Computer`, `TimeCreated` (RFC3339Nano), plus 12 Windows audit data fields (`SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `ObjectServer`, `ObjectType`, `ObjectName`, `HandleId`, `AccessList`, `AccessMask`, `ProcessId`, `ProcessName`)
- BinXML template-based encoding with static NameNode string table (template reuse per chunk)
- EVTX file header and chunk header generation with correct CRC32 patching
- FILETIME conversion from `time.Time`
- UTF-16LE encoding for string values
- 12 unit and integration tests; zero external dependencies (stdlib only)
- MIT license
- GitHub Actions CI: `go test ./...` + `go vet` + `golangci-lint` on push/PR

[Unreleased]: https://github.com/fjacquet/go-evtx/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/fjacquet/go-evtx/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/fjacquet/go-evtx/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/fjacquet/go-evtx/compare/v0.8.3...v0.9.0
[0.8.2]: https://github.com/fjacquet/go-evtx/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/fjacquet/go-evtx/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/fjacquet/go-evtx/compare/v0.7.4...v0.8.0
[0.7.4]: https://github.com/fjacquet/go-evtx/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/fjacquet/go-evtx/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/fjacquet/go-evtx/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/fjacquet/go-evtx/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/fjacquet/go-evtx/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/fjacquet/go-evtx/compare/v0.5.0...v0.6.0
[0.4.0]: https://github.com/fjacquet/go-evtx/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/fjacquet/go-evtx/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/fjacquet/go-evtx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fjacquet/go-evtx/releases/tag/v0.1.0
