# go-evtx: Durability and Format Correctness

**Date:** 2026-08-08
**Status:** Approved, not yet implemented
**Repo:** `github.com/fjacquet/go-evtx`
**Releases:** v0.6.0 (durability), v0.7.0 (format correctness)
**Companion spec:** the downstream SIEM adapter's `docs/superpowers/specs/2026-08-08-promise-remediation-design.md`

## Problem

An audit of v0.5.1 (source-identical to current HEAD) found that the library
silently loses and corrupts data. For a library whose only consumer is a
compliance audit pipeline, silent loss is the worst available failure mode.

Two defects destroy data with no error returned to the caller:

1. A record larger than the chunk capacity is written truncated. The CRCs are
   computed over the corrupt bytes, so both checksums verify. python-evtx drops
   the chunk without warning; the library's own reader aborts the file and
   returns zero records — including records in later, undamaged chunks.
   `WriteRecord` returns `nil`.
2. A `rotate()` that fails after closing the active file leaves a closed
   `*os.File` in `w.f` and never restores it. Every subsequent `WriteRecord`
   returns `nil` while writing nothing.

Three more defects lose data or crash: archive filename collisions overwrite
committed archives, `Close()` panics when called twice, and writes after
`Close()` are accepted and discarded.

Separately, the on-disk format is incomplete in ways that plausibly explain why
no one has ever confirmed the claim that these files open in Windows Event
Viewer: the per-chunk string and template hash tables are left entirely zero.

The root cause of all of it is the shape of the test suite. `reader_test.go`
round-trips go-evtx against go-evtx, so any shared misunderstanding of the
format is invisible. Coverage is 87.8%, `-race` is clean, and every defect
above sits in an untested path.

## Goals

- No code path returns `nil` while losing data.
- The on-disk format is either correct per the EVTX specification or the
  incompatibility is documented, not claimed away.
- Every external-compatibility claim in the README is backed by a CI job or
  deleted.

## Non-goals

- Reader performance or a streaming reader API.
- Supporting EVTX features the writer does not emit (user-defined templates,
  binary/GUID/SID typed substitutions, event correlation fields).
- Repairing already-corrupt files written by v0.5.1 or earlier.

## Release 1 — v0.6.0, durability

### D1. Reject oversized records instead of truncating

`evtx.go:187-193` and `:231-240` flush when the pending buffer cannot hold the
record, then append the record unconditionally. `flushChunkLocked`
(`evtx.go:385-390`) clamps with `records[:maxRecords]` and discards the
remainder.

Define the limit explicitly:

```
maxRecordPayload = evtxChunkCapacity - recordHeaderSize - recordTrailerSize
                 = 65024 - 24 - 4
                 = 64996
```

`WriteRecord` and `WriteRaw` compute the encoded record size before appending.
If it exceeds `maxRecordPayload`, return a typed error and write nothing:

```go
var ErrRecordTooLarge = errors.New("go_evtx: record exceeds chunk capacity")
```

The error wraps the actual and maximum size so the caller can log both.
Splitting one logical event across chunks is not valid EVTX, so rejection is
the only correct behaviour.

The `records[:maxRecords]` clamp in `flushChunkLocked` becomes unreachable
defensive code. Replace it with an error return — it must never silently
truncate, even if a future change reintroduces the path.

Related, currently masked: `binxml.go:270` writes a substitution length as
`uint16(len(s.data))`. Today any value large enough to truncate already
exceeds chunk capacity, so D1 fires first. Once D1 lands, add an explicit
per-substitution length check with the same error, so the truncation can never
become reachable.

### D2. Make rotation transactional

`evtx.go:275-302` closes the active file, renames it, then opens a replacement.
A failure at the rename or the open leaves the writer holding a closed handle.

Reorder and add a sticky error:

1. Flush and finalise the current chunk, patch the file header, `Sync()`.
2. `Close()` the active file.
3. Commit the archive (see D3 — link-then-unlink, not rename).
4. Open the replacement, write its placeholder header, and `Sync()` it. Without
   that sync the header lives only in the page cache until the first chunk
   flush, so a crash straight after rotation leaves a partial file where a
   valid empty one should be.
5. `syncDir()`, making both the archive name and the replacement durable.

Any failure in steps 2–5 sets `w.err` and leaves it set permanently.
`WriteRecord`, `WriteRaw`, `Rotate` and `Close` all check `w.err` first and
return it. A writer that cannot guarantee durability must fail loudly forever
rather than accept events it will not persist.

Step 1 is deliberately not sticky: the file handle is still valid and the error
reaches the caller, so the writer remains usable.

The background flush tick is, however, the one persistence path with **no
caller to return to** — `backgroundLoop` discards its result with `_ =`. A
failed `WriteAt`, header patch or `Sync` there must also set `w.err`, otherwise
the next `WriteRecord` reports success for data that never reached disk.

Do not attempt automatic recovery. A half-rotated directory needs an operator,
and a library that silently repairs itself is how the current defect went
unnoticed.

`Close()` must still perform its one-time shutdown when `w.err` is already set:
stop the goroutine and close the file handle before returning the sticky error.
A rotation that failed at the `Sync` step never reached its own `Close`, so
skipping cleanup would leak a descriptor on every failed rotation.

### D3. Collision-proof archive names

`archivePathFor` (`evtx.go:249-253`) formats `2006-01-02T15-04-05`. Three
rotations inside one second produce one surviving archive; `os.Rename`
destroys the other two without an error.

Use nanosecond precision, and commit the archive with **link-then-unlink**
rather than rename.

`os.Rename` replaces an existing non-directory destination on Unix, so a
collision destroys a committed archive silently. Neither obvious guard works:
`os.Stat` first is a time-of-check/time-of-use race, and an `O_CREATE|O_EXCL`
probe creates the destination without reserving it for the subsequent rename.
`os.Link` fails atomically when the destination exists, using only the standard
library — no `renameat2` and no `golang.org/x/sys`, which would cost this
library its zero-dependency property.

Link the active file to the archive name, then unlink the active path. The
window where both names point at one inode is harmless: a reader sees a
complete file either way.

Filesystems without hard-link support (FAT32, some SMB and overlay mounts) fall
back to `Stat`-then-`Rename` with a logged warning that the collision guard is
best-effort. Failing a rotation that previously worked is the worse outcome.

Losing a rotation is acceptable; silently destroying a committed archive is not.

### D4. Idempotent `Close`

`evtx.go:495` calls `close(w.done)` unconditionally, so a second `Close()`
panics with `close of closed channel`. This is reachable through the ordinary
`defer w.Close()` plus explicit-shutdown pattern.

Guard with a `closed bool` under `w.mu`. The second and later calls return the
first call's error (or nil), and do no work.

### D5. `ErrClosed` on write-after-close

`evtx.go:214` and `:173` have no closed check, so a write racing shutdown is
buffered into `w.records` and never flushed — returning `nil`.

```go
var ErrClosed = errors.New("go_evtx: writer is closed")
```

Checked under the same mutex as D4.

**Precedence.** A `Close()` that itself fails sets both the sticky error and
the closed flag. The sticky error wins: a caller needs to know data was lost,
which `ErrClosed` alone would not tell them. Callers testing for shutdown use
`errors.Is(err, ErrClosed)` and treat anything else as "may not have
persisted". Both the successful-`Close` and failed-`Close` paths are tested.

### D6. `OnFsync` outside the lock, and a corrected doc comment

`evtx.go:422-424` and `:482-484` invoke the callback while holding `w.mu`; a
callback that re-enters the writer deadlocks. Capture the value under the lock
and invoke after release.

`evtx.go:60` documents "Only fires when FlushIntervalSec > 0". False —
`flushChunkLocked` fires it from `WriteRecord`, `rotate` and `Close`
regardless. Correct the comment to match behaviour.

### D7. Tests

The fixes are cheap; these tests are the actual deliverable, because their
absence is why the defects shipped.

| Test | Asserts |
|---|---|
| Oversized record | `ErrRecordTooLarge`, file still readable, no partial bytes written |
| Boundary record | Exactly `maxRecordPayload` succeeds; `+1` fails |
| Double `Close` | Second call returns same result, no panic |
| Write-after-`Close` | `ErrClosed`, record count unchanged |
| Rotate failure | Read-only directory; sticky error on every subsequent call |
| Sub-second rotation burst | N rotations produce N archives, or an error — never silent loss |
| Reader concurrency | Documents the `reader.go` race (see D8) |
| Crash-recovery | Kill after tick flush; all flushed records recoverable |

### D8. Reader race — decide and align the docs

`reader.go:110`, `:118` and `:140` race on `r.recOff`, `r.chunkIdx`, `r.freeOff`
and the shared `r.buf`. `reader.go:47` claims "All exported methods are safe
for concurrent use". The repo's own `-race` run passes only because no test
reads concurrently.

The downstream adapter does not use the Reader, so either resolution is
acceptable — but the doc and the code must agree. Take the cheap one: add a
mutex to `Reader` so the existing claim becomes true, and add the concurrency
test from D7 to keep it true.

### v0.6.0 exit criteria

- All D7 tests pass under `-race`.
- No code path returns `nil` after failing to persist a record.
- `golangci-lint run` clean.
- CHANGELOG entry naming each defect and its user-visible symptom, so
  downstream consumers can tell whether they were affected.

## Release 2 — v0.7.0, format correctness

Everything here exists to answer one question: do these files open in Windows
Event Viewer? Until the CI job in F6 is green, the answer is unknown and the
README must say so.

### F1. Populate the chunk string and template hash tables

`buildChunkHeader` (`evtx.go:523-533`) allocates 512 bytes and populates only
offsets up to 52. Bytes `[128:384]` — the 64-entry common-string offset array —
and `[384:512]` — the 32-entry template offset array — are left entirely zero
on every chunk of every file.

python-evtx tolerates this because it follows the inline `template_offset` in
each record. A parser that resolves names or templates through the chunk hash
tables finds nothing. This is the single most likely reason Event Viewer
rejects the files.

Implement both tables using the EVTX name hash — `hash = hash*65599 + c`, the
SDBM rolling hash, as already used by the static NameNode table introduced in
`67f8312`. Write the chunk-relative offset of the first entry in each bucket,
and chain subsequent entries through the `next_offset` field already present in
the name and template structures.

**Bucket rules, corrected 2026-08-08 against real Windows files.** An earlier
revision of this section asserted that templates bucket by `template_id % 32`,
where `template_id` is the first four bytes of the GUID read as a little-endian
`uint32`. That is wrong, and was never checked before being written down.

| Table | Hash input | Bucket |
|---|---|---|
| Common strings (64) | The name's UTF-16 code units | `hash % 64` |
| Templates (32) | The **full 16-byte GUID, read as 8 little-endian `uint16` units** | `hash % 32` |

Both tables use the same SDBM routine. The template rule is not a special case
so much as the general one: Windows feeds the hash 16-bit units, and a GUID is
simply eight of them.

Measured against two independent Windows-generated files from python-evtx's
test corpus, walking every populated bucket and re-deriving the assignment:

| Fixture | Chunks | Template entries | `template_id % 32` | SDBM over 8 LE uint16 |
|---|---|---|---|---|
| `system.evtx` | 17 | 146 | 10 | **146** |
| `security.evtx` | 33 | 240 | 0 | **240** |

The discredited rule scores at chance. Hashing the 16 GUID bytes individually,
rather than as 16-bit units, scores zero on both files.

Note also that hashing **UTF-16 code units, not UTF-8 bytes**, is what the
format requires for names. The two agree for ASCII — which is every name
go-evtx emits — and diverge above U+007F.

Both rules must be re-confirmed against a real Windows-generated `.evtx` file
before F6 is trusted, and that check belongs in the test suite rather than in a
one-off script: extract chunks from a known-good file, recompute the bucket
assignments, and assert they match. The correction above exists because that
check was specified but deferred; when it finally ran, it failed immediately.

### F2. 8-byte record alignment

`binformat.go:133` computes `size := uint32(24 + len(binXMLPayload) + 4)` with
no padding, so records land at arbitrary offsets. Round the size up to the next
multiple of 8. The size prefix and the trailing size copy both carry the padded
value.

The padding bytes go **between the end of the BinXML payload and the trailing
size copy**, never inside the payload. BinXML is a token stream: appending zero
bytes inside it introduces `EndOfStream`/invalid tokens and corrupts parsing.
The record layout becomes header, payload, padding, trailing size — and the
`maxRecordPayload` limit from D1 must account for up to 7 padding bytes.

### F3. Correct `LastEventRecordDataOffset`

`evtx.go:531` writes `freeSpaceOffset` into `buf[44:]`, the same value it
writes into `buf[48:]`. Field 44 must hold the offset of the last record's
start. Track it while appending and write the real value.

### F4. Dirty and full flags

`binformat.go:82-99` never writes `buf[120:124]`. A forensic consumer cannot
distinguish a cleanly closed log from one truncated by a crash — which for an
audit tool is a meaningful loss of signal.

Set the dirty flag when the file is opened or rotated, clear it on a clean
`Close()`, and set the full flag when the file reaches its configured size
limit.

### F5. `chunkCount` overflow guard

`chunkCount` is `uint16` (`evtx.go:73`, `:404`, `:413`). At 65536 chunks — 4 GiB
— it wraps, `chunkOffset` recomputes to 4096 and overwrites chunk 0. Reachable
whenever `MaxFileSizeMB == 0`, which is the zero value.

Return a sticky error at the limit rather than wrapping. Also fix the related
`LastChunkNumber` underflow at `binformat.go:87`, where `uint64(chunkCount-1)`
with `chunkCount == 0` writes `0xFFFF` into every placeholder header.

Finally, `flushChunkLocked` increments `w.chunkCount` (`:413`) before patching
the header (`:414`). If the patch fails the count has already advanced. Patch
first, then increment.

### F6. CI that proves the claims

This is the part that prevents a repeat. Two jobs:

**Linux — python-evtx differential.** Generate a fixture covering multiple
chunks, non-ASCII and non-BMP strings, boundary-sized records, and a rotated
set. Parse with python-evtx. Assert record count, field values, and all three
CRC ranges. This must be a real external parse, not a go-evtx self-round-trip.

**`windows-latest` — the Event Viewer claim.** Generate a file on the Linux
job, upload as an artifact, download on the Windows job, and run:

```powershell
# $expected is written by the Linux generator alongside the fixture, so the
# two cannot drift. Get-WinEvent returns a scalar for a single record, so the
# result is coerced to an array before counting.
$expected = [int](Get-Content expected-count.txt)
$events   = @(Get-WinEvent -Path generated.evtx -ErrorAction Stop)
if ($events.Count -ne $expected) {
    throw "record count mismatch: got $($events.Count), want $expected"
}
```

Assert on content as well as count — a parser that returns the right number of
empty records proves nothing. Check that a known `ObjectName` survives the
round trip.

Add a direct structural assertion for F1 alongside it: read the generated file
back and fail if any chunk's string table (bytes `[128:384]`) or template table
(`[384:512]`) is still entirely zero. That catches a regression immediately,
without waiting for a Windows runner to disagree.

`Get-WinEvent -Path` uses the same Windows Event Log parsing stack as Event
Viewer. If it parses, the claim is earned. **This job is the definition of
OUT-06** in the companion adapter spec.

### F7. README honesty pass — do this in v0.6.0, not v0.7.0

`README.md:12` claims python-evtx, Velociraptor and Windows Event Viewer
compatibility. Today python-evtx is true but untested in CI, Velociraptor has
zero supporting evidence anywhere in the repo, and Event Viewer is
contradicted by F1–F4.

Ship the corrected claims with v0.6.0 so the false statements are not live for
however long v0.7.0 takes. State plainly what is verified and by which CI job.
Restore each claim only when its job is green. Drop Velociraptor entirely
unless someone runs it.

### v0.7.0 exit criteria

- Both F6 jobs green.
- If the `Get-WinEvent` job cannot be made to pass, v0.7.0 still ships the
  other fixes and the README states Event Viewer is unsupported. Deleting the
  claim is an acceptable outcome; keeping an unproven one is not.

## Deferred

Recorded so they are not rediscovered as new:

- `binformat.go:37` uses `t.UTC().UnixNano()` for FILETIME, undefined outside
  ~[1678, 2262]. `parseTimeCreated` (`evtx.go:543`) accepts any RFC3339Nano
  year, so a malformed year-3000 timestamp yields a garbage FILETIME. Validate
  the range at parse time.
- `reader.go:81` rejects a valid zero-chunk file, propagating
  `ErrNoMoreRecords` from `loadChunk(0)` as an open failure.
- The Reader validates no checksums, so it cannot classify corruption — it just
  aborts.
- Embedded NUL in a field round-trips through go-evtx correctly but produces
  XML that is not well-formed under XML 1.0. Decide whether to reject or
  escape; the caller should probably sanitise.
- `encodeUTF16LE` (`binformat.go:53`) is referenced only by its own test.
- `go.mod` declares `go 1.24`; the consumer is on 1.26.5.

## Inherited knowledge from the downstream adapter

The downstream adapter is retiring its `.planning/` process directory, which
holds roughly 7,200 lines of phase research — a large share of it EVTX binary
format knowledge written while the writer still lived in that repo: BinXML
encoding, chunk layout, CRC ordering constraints, the rotation design, and a
pitfalls catalogue.

That material belongs here now, since this repo owns the format. Receive it
during the v0.6.0 cycle as reference documentation under `docs/`, and prune
what the audit has since disproven — several of those notes describe
placeholder-header and flush behaviour that this spec changes.

Treat it as prior art to verify, not as truth. The pitfalls catalogue predates
every finding in this document and caught none of them.

The corresponding work item is T8 in the adapter spec.

## Coupling to the downstream adapter

Two sync points only:

1. The adapter bumps to **v0.6.0** whenever it lands. Nothing blocks on it.
2. The adapter's v5.0 Event Viewer claim requires **v0.7.0** with F6 green.
   If F6 cannot pass, the adapter ships v5.0 with the claim deleted.

The format proof lives here, not in the adapter. go-evtx is the artifact that
must open in Event Viewer, so it owns that assertion. The adapter's own
Windows job proves only its message-resource rendering.
