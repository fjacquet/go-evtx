# ADR-007: Incremental Tick Flush (v0.10.0)

**Date:** 2026-08-22
**Status:** Accepted — refines ADR-004

## Context

ADR-004 established the open-handle incremental flush model and listed one
consequence as a known negative: "`tickFlushLocked` overwrites the same chunk
slot repeatedly." Measurement made the cost concrete.

On darwin/arm64 with APFS, `f.Sync()` is `F_FULLFSYNC` and costs ~5.1 ms for a
64 KiB write; the write itself costs 2.6 µs. `WriteRecord` runs at 74 µs per
record, of which ~61 µs is the amortized fsync — 82% of wall clock. The
background tick paid a full one of those every interval regardless of arrivals.

At `FlushIntervalSec: 1` and 10 events/sec that is roughly 5.5 GB written and
86 400 fsyncs per day to persist about 600 KB of events. At true idle it is the
same cost to persist nothing at all.

The driving workload is a Dell CEE (Common Event Enabler) receiver taking CEPA
audit events from PowerScale/Unity/PowerStore, which must survive both a
long-running low-rate receiver and a cluster burst.

## Decision

The background tick writes only what it must, skips entirely when nothing
changed, and never allocates or fsyncs more than a sealed chunk flush already
does.

1. **Skip entirely when nothing was appended.** `w.tickWrittenLen` records how
   many bytes of `w.records` the previous tick persisted; when it equals
   `len(w.records)` the tick returns immediately — no write, no fsync.

2. **Build the full `evtxChunkSize` buffer, then write only the used prefix.**
   The tick constructs the chunk exactly as `flushChunkLocked` does — header at
   offset 0, `w.records` copied in at `evtxRecordsStart` — patches it with
   `fillHashTables` and both CRCs, and then writes only two `WriteAt` calls
   sourced from that patched buffer: the records region
   `chunk[512 : 512+len(w.records)]` first, then the 512-byte header
   `chunk[0:512]`. Only the unwritten tail padding of the chunk slot is
   skipped.

   **The buffer must be full-size, not header-size, and here is why.**
   `fillHashTables` does not confine itself to `chunk[128:512]`. `fillOneTable`
   (`chunkhash.go`) also writes a 4-byte chain terminator at
   `chunk[ref.offset:]`, and — when chaining a new node onto a bucket whose
   tail is an *earlier* node — a 4-byte chain patch at `chunk[prev:]`. Both are
   chunk-absolute offsets into already-copied record bytes, at or beyond
   `evtxRecordsStart+evtxRecordHeaderSize` (>= 536), which is inside the
   records region a delta write would treat as immutable. This was not
   discovered by inspection: an earlier attempt at this design used a
   512-byte header buffer, and every one of those writes silently failed
   `fillOneTable`'s own bounds guard (`int(ref.offset)+4 > len(chunk)`) —
   no panic, no returned error, just an untouched byte. See "Alternatives
   Considered" for the full story and how it was caught.

   Because the chain patch can rewrite bytes at the offset of an earlier
   node, "records are append-only on disk" is false once hash chaining is
   considered — a later record's chain patch can mutate record bytes a
   previous tick already wrote. A header-plus-delta write can therefore never
   be correct by construction, independent of buffer size; only writing from
   a fully-patched full-size buffer is.

3. **The records CRC is maintained incrementally.** `w.recordsCRC` is updated
   with `crc32.Update` at each append. This is bit-identical to the rescan it
   replaces and removes an O(chunk) scan from both flush paths.

4. **The chunk slot is pre-extended.** Before its first partial write the tick
   calls `Truncate(chunkOffset + evtxChunkSize)`. Without it the file would end
   mid-chunk and `loadChunk`, which reads a whole `evtxChunkSize`, would hit
   EOF — as would Windows. The sparse tail reads back as zeros, which is what
   the sealing write puts there anyway.

5. **Records are written before the header that advertises them.** A crash
   between the two leaves a header describing fewer records than are on disk,
   which reads back cleanly. The reverse ordering would advertise records whose
   bytes never landed.

6. **Neither `w.chunkCount` nor `w.records` is reset.** The chunk stays open
   for further appends — ADR-004's flush-without-reset, unchanged.

`flushChunkLocked` is unchanged in what it puts on disk: it still writes the
full 64 KiB when sealing a chunk.

## Consequences

**Positive:**

- Idle: 86 400 fsyncs/day become zero, and cost nothing to detect —
  `BenchmarkTickFlushIdle` measures 13.84 ns/op with 0 allocations, doing no
  I/O at all. This is the larger win for the driving workload, which is
  bursty with gaps between arrivals.
- Non-idle, the per-tick byte saving is real but roughly half, not the
  order-of-magnitude the original delta design would have given: a tick now
  writes `512 + len(w.records)` bytes of the used prefix instead of a flat
  65536, which is smaller on average across a chunk's fill but is not a
  small constant — it grows toward the full records region as the chunk
  fills. There is no measured bytes/day figure for the non-idle case; see
  `docs/perf-baseline.md`'s "Derived figures" section, which states plainly
  that its own arithmetic there is unmeasured.
- One O(chunk) CRC rescan per tick removed regardless of idle/non-idle.
- No API change and no on-disk format change.

**Negative:**

- Three more pieces of `Writer` state (`recordsCRC`, `tickWrittenLen`,
  `slotExtended`) that must be reset in lockstep with `w.records`. They are
  reset in exactly two places, `flushChunkLocked`'s commit block and `rotate`
  Step 7; missing either corrupts the following chunk.
- A non-idle tick still allocates and patches a full `evtxChunkSize` buffer —
  the delta design's allocation saving did not survive; only the write-size
  and idle-skip savings did.
- The file now carries a sparse tail on the in-progress chunk. Tools that
  measure allocated rather than apparent size will report less than the file
  length. This is invisible to every reader.

**Not covered by tests:** the header-after-records write ordering. `w.f` is a
concrete `*os.File`, so there is no injection seam to fail a write between the
two calls. `TestTickFlush_CrashSnapshot` covers the outcome — a mid-session copy
parses — but not the ordering itself. This is stated rather than implied.
`TestTickFlush_SnapshotHashTablesPopulated` closes a different, previously
open gap: it is the regression guard for the failure mode a header-size
buffer produced (hash tables silently left all-zero), asserting
`chunk[128:512]` is non-zero after a mid-session tick and that a snapshot
copy of the file still reads back every record.

## The invariant

Bytes on disk after `Close()` are byte-identical to v0.9.0's.
`TestTickFlush_ByteIdenticalToNoTick` asserts it directly by writing the same
records with and without a background tick and comparing the finished files.
The conformance tests and the Format Verify CI gate continue to apply unchanged.

## Alternatives Considered

- **Header plus delta (the original design; abandoned).** Write only a
  512-byte chunk header buffer plus `w.records[w.tickWrittenLen:]`, on the
  premise that `fillHashTables` writes only `chunk[128:384]` and
  `chunk[384:512]` and that `w.records` is append-only, so bytes already in
  the slot would remain valid. Both premises looked obviously true and
  neither was: `fillOneTable` also writes a 4-byte chain terminator and, when
  chaining onto a bucket's tail, a 4-byte patch at an *earlier* node's
  offset — both chunk-absolute and inside the records region. Against a
  512-byte buffer, every one of those writes failed `fillOneTable`'s own
  `int(ref.offset)+4 > len(chunk)` bounds guard and was silently skipped: no
  panic, no error, a CRC computed over the resulting zeros so nothing flagged
  it. It was caught in code review, not by a test, and confirmed by probing a
  mid-session chunk directly: `chunk[128:512]` held 0 non-zero bytes with the
  delta design against 44 with the fix. Because the chain-patch write can
  mutate a byte an earlier tick already wrote to disk, this design's second
  premise — records are append-only on disk — is also false once hash
  chaining is considered, which means no buffer size makes header-plus-delta
  correct; only writing from a full, patched buffer is. This is the most
  important entry in this list, because it recorded a design that looked
  correct by inspection and was not, and precisely why.
- **Skip-when-idle only, keep the full-chunk write.** Fixes true idle and
  nothing else: at 10 events/sec every tick still has new records, so the
  full 65536-byte write and its fsync stay on every non-idle tick.
- **Partial write without `Truncate`.** Leaves the file ending mid-chunk. Both
  `loadChunk` and Windows read a whole chunk and hit EOF.
- **Drop the tick and fsync only when a chunk fills.** Removes the amplification
  by removing the durability guarantee ADR-004 exists to provide.
