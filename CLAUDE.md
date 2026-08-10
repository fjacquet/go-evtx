# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests (race detector is required — the writer is concurrent)
go test -race ./... -count=1

# Run a single test
go test -race -run TestWriter_WriteRecord_ProducesValidFile ./...

# Build, including the Windows path (evtx_windows.go is not built on darwin/linux)
go build ./...
GOOS=windows go build ./...

# Vet and coverage
go vet ./...
go test -race -cover ./...

# Lint (requires golangci-lint)
golangci-lint run
```

## Architecture

This is a single-package Go library (`package evtx`) with zero external dependencies. It reads and writes Windows Event Log `.evtx` binary files without any Windows dependencies.

**Format reference:** [`docs/evtx-format-notes.md`](docs/evtx-format-notes.md) is the durable record of what this project has verified about the EVTX/BinXML binary format — source assessments, measured vs. read-from-source claims for every field this codebase encodes, a table of every defect found and fixed in v0.7.0, and what remains unknown (notably the `ToXml`/`Get-WinEvent` vs. `EventLogReader.ReadEvent()` gap). Read it before changing anything in `binformat.go`, `binxml.go`, `binxml_reader.go`, or `chunkhash.go`.

**File layout:**

| File | Purpose |
|------|---------|
| `evtx.go` | Writer API: `Writer`, `New()`, `WriteRecord()`, `WriteRaw()`, `Rotate()`, `Close()`, `RotationConfig`, rotation and background-goroutine logic |
| `errors.go` | Sentinel errors (`ErrClosed`, `ErrRecordTooLarge`) and capacity limits (`maxChunkPayload`, `maxRecordPayload`) |
| `reader.go` | Reader API: `Reader`, `Record`, `Open()`, `ReadRecord()`, `ReadRaw()`, `Close()`, `ErrNoMoreRecords` |
| `binformat.go` | Binary format helpers: file/chunk headers, event record wrapper, CRC32, `toFILETIME`/`fromFILETIME`, UTF-16LE encoding |
| `binxml.go` | BinXML encoder, record assembly: `buildBinXML`, the substitution array, the substitution index map |
| `binxml_template.go` | The `<Event>` template body — which element gets which token, in which order, with which substitution index. **This is the file a format fix touches.** `fieldPatch` back-patching for `data_size`/`attr_list_size` lives here |
| `binxml_tokens.go` | The token writers and little-endian helpers. Knows nothing about `<System>`; writes one token as the format defines it |
| `binxml_reader.go` | BinXML decoder: `decodeBinXML()`, substitution array parser, UTF-16LE decoder |
| `chunkhash.go` | Per-chunk hash tables: `sdbmHash` (UTF-16 code units), `guidHash`, bucket rules, `fillHashTables` |
| `corpus_scan_test.go` | Corpus fact dumper: one JSON Lines fact per file, chunk and record. Never string values |
| `corpus_shape_test.go` | The shape census and the diff that found F15 |
| `evtx_unix.go` | `syncDir()` — fsyncs the containing directory so a rename is durable (`//go:build !windows`) |
| `evtx_windows.go` | `syncDir()` no-op — NTFS makes the directory entry durable on `MoveFileEx` (`//go:build windows`) |

**Test files:**

| File | Covers |
|------|--------|
| `evtx_test.go` | Writer integration |
| `reader_test.go` | Reader integration (round-trip, `ErrNoMoreRecords`, multi-record) |
| `binformat_test.go` | Binary format helpers |
| `rotation_test.go` | Rotation happy path, `MaxFileSizeMB`, `MaxFileCount` |
| `rotate_failure_test.go` | Rotation failure poisons the writer; archive-name collisions |
| `goroutine_test.go` | Background flush/rotation ticks, `OnFsync` |
| `openhandle_test.go` | File-handle lifecycle across rotation |
| `state_test.go` | Writer lifecycle guards: double `Close`, write-after-`Close`, sticky-error precedence |
| `oversize_test.go` | Oversized records rejected, not truncated |
| `example_test.go` | Godoc examples |
| `reader_concurrency_test.go` | `Reader` is safe for concurrent use: parallel callers, `r.mu` held for each exported method |
| `flush_atomicity_test.go` | `flushChunkLocked` commits `chunkCount`/`currentSize`/`records`/`firstID`/`lastRecordOffset` together or not at all |
| `onfsync_test.go` | `OnFsync` fires on every sync, and outside `w.mu` |
| `evtx_unix_test.go` / `evtx_windows_test.go` | `isLinkUnsupported` classification per platform |
| `chunkhash_test.go` | Bucket rules validated against `$EVTX_FIXTURE` (skips without one); the template GUID rule is 3.1-only and skips on 3.2; `fillHashTables` unit tests |
| `nodecollect_test.go` | `buildBinXML` reports NameNode/TemplateNode offsets; `goldenFields()` lives here |
| `hashtable_integration_test.go` | A written file's chunk tables are populated and self-consistent; the CRC-ordering guard |
| `fileheader_test.go` | `LastEventRecordDataOffset`, dirty/full flags, `LastChunkNumber` underflow, chunk ceiling |
| `dependency_test.go` | Every `OpenStartElement` carries the `0xffff` "not set" sentinel |
| `datasize_test.go` | `data_size` spans the element rather than being zero |
| `attrlist_test.go` | `attr_list_size` sits after the inline NameNode and carries a real value |
| `namespace_test.go` | The `<Event>` root declares the event schema namespace |
| `system_test.go` | `<System>` children, their value types and optional substitutions |

**Write data flow:**

1. `buildBinXML()` → constructs a BinXML fragment using a fixed template with 42 substitution slots (ProviderName, EventID, Level, SystemTime, Computer, 12×data name+value, plus 13 more added in v0.7.0/Task 8b/8c to round `<System>` out to match a real Windows record — see the index map below)
2. `wrapEventRecord()` → wraps BinXML payload in a 24-byte event record header (signature, size, recordID, FILETIME timestamp)
3. Records appended to the `Writer.records` byte buffer (the pending chunk)
4. The buffer is committed as a chunk by `flushChunkLocked()` when it fills, by `tickFlushLocked()` on the background flush tick, by `rotate()`, and by `Close()`

**Read data flow:**

1. `Open()` → validates file magic, reads chunk count, loads first chunk into memory buffer
2. `nextRecord()` → reads 24-byte event record header from buffer, slices BinXML payload, advances offset; on chunk exhaustion loads next chunk
3. `ReadRaw()` → returns raw BinXML bytes (compatible with `WriteRaw`)
4. `ReadRecord()` → calls `decodeBinXML()` → parses substitution array → maps indices to `Record` fields

## `cmd/` — two fixture generators

Neither is shipped: `.goreleaser.yaml` sets `builds: [{skip: true}]` because this is a library. They exist so a CI job can produce a specific `.evtx` file and a Windows runner can report whether it parses.

| Command | Role |
|---|---|
| `gen-fixture` | **Frozen.** Produces the main measurement fixture. Every row of `docs/format-baseline.md` compares against it, so changing its output silently invalidates the comparison chain. Do not touch it. |
| `gen-fixture-minimal` | One record, one chunk, pure ASCII — the smallest file the library can produce |

**The bisection harness is gone.** Eleven further `main` packages plus `binxml_variants.go` and its test — 3067 lines — produced the shrink-ladder and real/ours graft experiments. Their results stay recorded in `docs/format-baseline.md`; the code went once the defect they were hunting was found (F15, the shape census). Deleting them also took `Format Verify` from 28 jobs to 5.

## Finding format rules: the corpus, not a sample

`corpus_scan_test.go` and `corpus_shape_test.go` are how this project now learns the format. Both are tests rather than `cmd/` packages because the facts live in unexported structures, and both skip unless pointed at a corpus.

```bash
EVTX_CORPUS=/dir/one:/dir/two go test -run TestCorpusScan -v .          # per-record facts, JSON Lines
EVTX_CORPUS=/dir/one:/dir/two go test -run TestCorpusShapeCensus -v .   # shape census -> testdata/shape-census.json
EVTX_SHAPE_TARGET=/path/to/generated.evtx go test -run TestShapeDiffTarget -v .
EVTX_FIXTURE=/path/to/real.evtx go test ./...                           # the hash-table rule tests
```

Three rules, each of which was broken at least once:

- **No `.evtx` is tracked.** `isExcludedFixture` refuses any file named `system.evtx`. Deriving the format from one sample and then asserting against that same sample is what cost this project seventeen tasks — the assertion cannot fail when the derivation is wrong.
- **Facts are recorded for records the decoder rejects.** Measuring only what already decodes is the round-trip blindness that hid every v0.6.0 defect.
- **No string values leave the corpus.** Names, types, sizes, offsets, counts. Real logs carry account names, SIDs, machine names and IP addresses, and this output gets quoted in `docs/`.

The order that follows: **the corpus derives, the specification names, the VM confirms, CI records.** A one-bit "does Windows accept this?" oracle cannot distinguish a wrong hypothesis from a right hypothesis aimed at the wrong field — which is exactly how F14 spent a whole task and concluded "unresolved".

## Measurement discipline

The release's method is a table of CI measurements compared across commits. Three rules keep that table meaningful, and each exists because it was broken at least once:

- **`docs/format-baseline.md` is append-only.** Earlier rows are the evidence later comparisons rest on. Add a row; never edit one. A correction goes in a new row or a clearly marked correction note.
- **Select a CI run by `head_sha`, never by recency.** `rtk gh api repos/fjacquet/go-evtx/actions/runs/<id> --jq '.head_sha'` must equal the commit you are measuring. A run was once cited whose head was two commits stale, so its "identical" result was mechanically guaranteed and proved nothing.
- **A message comparison is only valid across a byte-identical fixture.** Windows' rejection message is content-dependent: the same writer produced `The event log file is corrupted.` on one fixture and `The data is invalid.` on another with no code change. Whether the file *opens* is the one signal immune to this.

## Reverse-engineering discipline

This format was implemented against another parser's behaviour before it was implemented against its specification. That cost seventeen tasks. The rules below are not general advice — each is a mistake this repo actually made.

- **Check the specification before writing a rule down.** The project spec claimed templates bucket by `template_id % 32`. Measured against two real Windows files it scored 10 of 386 entries; the correct rule — SDBM over the full 16-byte GUID read as 8 little-endian `uint16` units — scores 386 of 386. Nobody had checked before writing it. `docs/evtx-format-notes.md` marks every claim as measured or read-from-source; preserve that distinction when adding to it.

- **A permissive parser passing is not the format being correct.** `binxml.go` once carried `writeUint32LE(b, 0) // data_size (unused by python-evtx)`. python-evtx's own source says `TODO: use this size() field`. Windows enforces what python-evtx ignores. Never justify an encoding choice by what a reader tolerates.

- **Normative sources first, reverse-engineered second, blogs never.** [MS-EVEN6] is Microsoft's own BinXml specification and includes a worked byte-level example; libyal/libevtx is the best reverse-engineered reference and has the complete value-type table. Both are linked from `docs/evtx-format-notes.md`. Microsoft's "Event Log File Format" Win32 page documents the *legacy* `.evt` format and says so — it does not apply here.

- **CI is the arbiter, not the hex dump.** One change "corrected" our bytes to match a real file and regressed `STAGE2 READ` from 403 records to zero. When a byte-level decode and a CI measurement disagree, the measurement wins, and the disagreement gets recorded rather than resolved by preference — see the `EventID/@Qualifiers` comment in `binxml.go` for the standing example.

## Rotation

`New(path, RotationConfig)` starts a background goroutine when any tick-driven field is set. `RotationConfig`:

| Field | Meaning |
|-------|---------|
| `FlushIntervalSec` | 0 = disabled; commit the pending chunk every N seconds |
| `MaxFileSizeMB` | 0 = disabled; rotate when the file reaches N MiB (checked on write) |
| `MaxFileCount` | 0 = unlimited; keep only the N newest archives |
| `RotationIntervalH` | 0 = disabled; rotate every N hours |
| `OnFsync func(time.Time)` | nil = none; called after each successful `f.Sync()` |

`rotate()` is transactional: flush pending records → skip if nothing was ever written → `Sync` and close the active file → commit the archive with `os.Link` then unlink the active path (`os.Rename` would silently replace an existing archive; `Link` fails atomically instead, with a `Stat`+`Rename` fallback where hard links are unsupported) → open and `Sync` a replacement file → `syncDir()` → reset counters → enforce `MaxFileCount`.

Archive names are `base-2006-01-02T15-04-05.000000000.evtx` (nanosecond-resolution UTC timestamp — one-second resolution let a burst of rotations collide); `cleanOldFiles()` finds them with the glob `base + "-*" + ext`.

## Key constraints

- **Records larger than a chunk are rejected, never truncated.** `maxChunkPayload` = 65024 (`evtxChunkSize - evtxRecordsStart`); `maxRecordPayload` = 64996 (`maxChunkPayload - evtxRecordHeaderSize - 4`). `WriteRecord`/`WriteRaw` return an error wrapping `ErrRecordTooLarge` and write nothing. Truncating would be checksum-invisible: the CRCs are computed over the corrupt bytes and verify.
- **`WriteRecord` and `WriteRaw` must not be mixed in the same session.**
- **File is only created if at least one record was written** — an empty session removes the placeholder on `Close()`.
- Reader supports multi-chunk files (Windows-generated); the decoder targets our own template format.

## Concurrency and lifecycle

- `Writer` is concurrency-safe (mutex-guarded). Unexported helpers whose name ends `Locked` require the caller to hold `w.mu` and carry a `// CALLER MUST HOLD w.mu.` comment.
- **`rotate()` requires `w.mu` held by the caller and must never acquire it itself.** Every caller (`Rotate`, `WriteRecord`, `WriteRaw`, the background rotation tick) holds it.
- `Close()` is idempotent via `closeOnce sync.Once`; concurrent callers block until the first completes and all observe the same result.
- **Sticky error.** Once durability can no longer be guaranteed (a rotation that failed after closing the active file, or a failed background flush), `w.err` is set permanently and every entry point returns it. There is no automatic recovery — a half-rotated directory needs an operator and a new `Writer`. A transient I/O failure inside `flushChunkLocked` before that point (e.g. a `WriteAt` or `Sync` that fails while the file handle is still valid) is *not* sticky and is safe to retry — `rotate()`'s Step 1 comment calls this out explicitly. `chunkCapacityLocked`'s chunk-count ceiling (`w.chunkCount >= maxChunksPerFile`, `ErrTooManyChunks`) is sticky for a different reason than durability loss: at 65535 chunks (the top of `chunkCount`'s `uint16` range) no further chunk can ever be written to this file — continuing would wrap the counter and silently overwrite chunk 0 — so there is nothing to retry, and `w.err` is set the same way a durability failure would be.
- `checkStateLocked()` gates `WriteRecord`, `WriteRaw` and `Rotate`. Precedence is part of the API contract: the sticky error outranks `ErrClosed`, so a caller learns that data was lost rather than only that the writer shut down.
- `closeFileLocked()` closes `w.f` exactly once, guarded by `w.fileClosed`; `rotate()` maintains that flag across the close/reopen.
- **`OnFsync` fires on every sync** — from `WriteRecord`, `rotate`, `Close` and the background flush tick, not only when `FlushIntervalSec > 0`. It is invoked after `w.mu` is released, so a callback may safely call most `Writer` methods — except `Close`: a callback fired from the background goroutine's own fsync drain that calls `Close` deadlocks, because `Close` waits for that same goroutine to exit while it is blocked inside the callback. A callback that itself triggers a further flush recurses on its own call stack.
- **`Reader` is also concurrency-safe:** a mutex (`r.mu`) is held for the duration of every exported method. `Open` does not lock — it constructs the `Reader` before it can be shared with another goroutine. `nextRecord` and `loadChunk` are unexported helpers carrying `// CALLER MUST HOLD r.mu.`. `nextRecord` copies each payload out of the shared chunk buffer before returning it; that copy is what makes `ReadRaw`'s returned bytes safe to retain past the next call.

## BinXML substitution index map

| Index | Field | Type |
|-------|-------|------|
| 0 | ProviderName | STRING |
| 1 | EventID | UINT16 |
| 2 | Level | UINT8 (always 0) |
| 3 | SystemTime | FILETIME |
| 4 | Computer | STRING |
| 5+2i | DataField[i] name | STRING |
| 6+2i | DataField[i] value | STRING |
| 29 | Version | UINT8 (always 0, no caller-supplied source) |
| 30 | Task | UINT16 (always 0, no caller-supplied source) |
| 31 | Opcode | UINT8 (always 0, no caller-supplied source) |
| 32 | Keywords | HEXINT64 (always 0, no caller-supplied source) |
| 33 | EventRecordID | UINT64 (the writer's own record ID) |
| 34 | Correlation/@ActivityID | NULL (no caller-supplied source) |
| 35 | Correlation/@RelatedActivityID | NULL (no caller-supplied source) |
| 36 | Execution/@ProcessID | NULL (no caller-supplied source) |
| 37 | Execution/@ThreadID | NULL (no caller-supplied source) |
| 38 | Channel | STRING (from `fields["Channel"]`) |
| 39 | Security/@UserID | NULL (no caller-supplied source) |
| 40 | Provider/@Guid | STRING (from `fields["ProviderGuid"]`) |
| 41 | EventID/@Qualifiers | NULL, declared type UINT16 (no caller-supplied source; F14 tried a NULL declared type and reverted — see below) |

The 12 data fields (indices 5–28) are hardcoded in `dataFieldNames` in `binxml.go`; they kept their original indices and semantics across v0.7.0/Task 8b/8c — nothing calling `WriteRecord` needs to change.

Indices 29–41 (v0.7.0/Task 8b's F12b, Task 8c's F13b/F13c) exist purely so the encoded `<System>` block matches a real Windows record's 14 children instead of 5, and its `Provider`/`EventID` elements carry the same attributes the real file's do; `binxml_reader.go`'s `decodeBinXML` parses them like every other substitution but does not surface most of them on `Record` — they have no caller-supplied source (except `ProviderGuid`, which round-trips through `fields["ProviderGuid"]` the same way `ProviderName` does but likewise isn't surfaced on `Record`). `EventRecordID`'s value is already exposed as `Record.RecordID` from the event record header, not from BinXML.

The seven scalar children whose sole content is one substitution value (`Version`, `Task`, `Opcode`, `Keywords`, `EventRecordID` — F12b; `EventID`, `Level` — F13a) are encoded differently from a plain `NormalSubstitution` (token `0x0D`): per `testdata/system.evtx`, every element of this shape uses `OptionalSubstitution` (token `0x0E`) with the enclosing `OpenStartElementTag`'s `dependency_id` set to that same substitution index, so `writeOpenElement`/`writeOptionalSubstitution` are called with that real index rather than `depIDNotSet`. F12b left `EventID`/`Level` as `0x0D`/`dependency_id` `0xffff` as an explicit, permitted scope decision ("elements that are genuinely always present may legitimately stay `0x0D`" — go-evtx always supplies real data for both); Task 8c/F13a closes that out to match the real file exactly — `dependency_id` is the element's own **content** substitution index (`subEventID`/`subLevel`, i.e. 1 and 2), not the index of any attribute the element also carries (real Windows ties `EventID`'s `dependency_id` to its own content, `0x0003` in the real file's numbering, not `Qualifiers`' `0x0004`). `Correlation`, `Execution` and `Security` stay `0xffff` (element itself always present, matching the real file) with their individual attribute values NULL-typed via `OptionalSubstitution` — go-evtx has no source for `ActivityID`/`RelatedActivityID`/`ProcessID`/`ThreadID`/`UserID`, so it reproduces the real file's own encoding for an event that doesn't populate them, rather than inventing forensic data. `Channel` and `Computer` stay `NormalSubstitution`/`0xffff` like the other pre-existing fields, since go-evtx always has a (possibly empty) real value for both.

`Provider` (F13b) is the first element go-evtx emits with two attributes (`Name`, `Guid`), and the real file confirms the "more attributes follow" token (`0x46`) is required for every non-final attribute in a list, not just `0x06` for a lone one: `Name`'s own attribute token becomes `0x46`, `Guid`'s (the last) stays `0x06`. `Guid`'s value is a real substitution (`fields["ProviderGuid"]`, STRING-typed like `Name`), not a literal, even though the real file happens to encode `Provider`'s own `Name`/`Guid` as literal `ValueText` — a provider GUID varies per caller, the same reasoning that already made `Name` a substitution despite the real file's own literal encoding.

`EventID/@Qualifiers` (F13c) is go-evtx's first NULL-valued `OptionalSubstitution` whose declared type is not a generic "null type" marker: `testdata/system.evtx` encodes this exact attribute as `[size 0, type UNSIGNED_WORD (0x06)]` — its own real declared type — and MS-EVEN6's own worked example shows the same shape.

**F15 (the shape census): the `<System>` NULL fields, resolved.** An
`OptionalSubstitution`'s **token** declares the field's own type; its entry in
the **substitution array** declares `NULL` when the value is absent. go-evtx
wrote `NULL` in both places. Real Windows never does — token `Null` with array
`Null` occurs **zero times in 27 million shape observations across 320 398
records**, while `Guid`/`Sid`/`UInt16`/`Binary`/`StringArray`/`UInt32`/`UInt64`
with array `Null` occurs 1.15 million times. Indices 34/35 now declare `Guid`,
36/37 declare `UInt32`, 39 declares `Sid`; their array entries stay `NULL`.

That five-byte change is what finally made `EventLogRecord.ToXml()` and
`Get-WinEvent` accept a go-evtx file — `PROP ToXml ok`, `GETWINEVENT default:
ok, 403 records`, both orderings, after seventeen tasks of rejection.

It also explains index 41: `EventID/@Qualifiers` as token `UInt16` with array
`Null` is the 226 089-occurrence shape, which is why keeping `UNSIGNED_WORD`
worked and reverting the token to `Null` regressed `STAGE2 READ`.

**F14's conclusion below is superseded; its measurements are not.** F14 changed
and re-measured the substitution *array* while reasoning about the *token* —
two different fields at opposite ends of the record. Both of its lines of
evidence were correct and they never actually contradicted each other. The
account is kept because its dead ends are worth not repeating.

**F14 (v0.7.0, Task 8e): two false starts, and where they landed.** Net
effect on the encoder, after both corrections: **none** — every byte
go-evtx writes is identical to what F12b/F13c already wrote. The value was
in what got measured, not in a code change.

*Attempt 1.* The note above led directly to code: reclassified F12b's five
NULL fields (34/35/36/37/39) from `binXMLTypeNull` (`0x00`) to their
field's own real type (GUID, SID, UINT32), trusting task-8b-report.md's
Step 1 table's claim that the real file encodes them that way. Broke
`python-evtx`'s own regression guard (`Evtx.Nodes.RootNode.substitutions()`
computes a fixed-width type's length independent of the declared size and
rejects a mismatch bigger than 4 bytes — `GUID`'s fixed 16 against a
declared `0` fails outright).

*Verification, three independent ways.* A byte-for-byte raw re-parse of the
exact real record the Step 1 table cites; `python-evtx==0.8.1`'s own
successful parse of that same real record (impossible if `ActivityID`
really were `GUID`-typed at size 0); and `UnsignedWordTypeNode`'s fixed
2-byte width explaining why `EventID/@Qualifiers`'s declared type never
broke `python-evtx` either way. Found the Step 1 table's types wrong at
exactly four positions — substitution indices 4/7/12/18 in the real file's
own numbering (`EventID/@Qualifiers`, `Correlation/@ActivityID`,
`Security/@UserID`, `Correlation/@RelatedActivityID`) are all declared type
`0x00` there. Every other row checked out exactly as stated.

*Attempt 2.* Reverted all six NULL-valued fields (the original five, plus
`EventID/@Qualifiers`) to `binXMLTypeNull`. `python-evtx`'s crash was
fixed — but `Get-WinEvent`'s `STAGE2 READ` (Task 8c's own breakthrough)
**regressed** from reading all 403 records to failing on record 0. A third
data point (the five fields `GUID`/`SID`/`UINT32`-typed, `Qualifiers` left
at `UNSIGNED_WORD` — `STAGE2 READ` failed after 384 records, a third
distinct failure mode) isolated it: of the three combinations tried,
Windows fully accepts only the original — five fields `NULL`, `Qualifiers`
`UNSIGNED_WORD`. **Reverted `Qualifiers` back to `UNSIGNED_WORD`** on that
evidence, restoring byte-for-byte parity with F12b/F13c's original output.

**Unresolved.** The two lines of evidence disagree and this was not
reconciled: either this task's identification of "`Qualifiers` = index 4 in
the real file's own numbering" doesn't hold — the Step 1 table's index
assignments, not just some of its types, may themselves be unreliable, and
this task did not independently re-derive them — or Windows' acceptance
ties to this declared type through a mechanism not yet identified.
task-8b-report.md and task-8c-report.md each carry their own correction
note; task-8e-report.md has the full investigation.
