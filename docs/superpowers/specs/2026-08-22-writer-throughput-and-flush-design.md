# Writer Throughput and Flush Policy — Design

**Date:** 2026-08-22
**Status:** Approved, not yet implemented
**Releases:** v0.10.0 (flush amplification), v0.11.0 (throughput)

## Context

go-evtx is used as a sink for Dell CEE (Common Event Enabler) audit events
published by PowerScale/Unity/PowerStore via CEPA. That workload has two ends
and the writer must survive both: a long-running receiver at tens of events per
second, and a burst from a busy cluster at thousands to tens of thousands per
second.

A measurement spike on 2026-08-22 (Apple M1 Pro, APFS, darwin/arm64, Go
benchmarks, throwaway harness) produced the numbers this design rests on:

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `buildBinXML`, shared template | 3 301 | 5 608 | 56 |
| `buildBinXML`, inline template (first record of a chunk) | 13 960 | 20 968 | 180 |
| `WriteRecord` to a real file | 74 269 | 6 747 | 58 |
| `WriteRecord`, 10 goroutines | 83 912 | 6 751 | 58 |
| raw 64 KiB `WriteAt` + `Sync` | 5 352 391 | — | — |
| raw 64 KiB `WriteAt`, no `Sync` | 2 632 | — | — |

Measured 83.7 records per fsync at ~780 bytes/record. Decomposed per record:
encode 3.3 µs, chunk build and write ~0.03 µs, fsync 61 µs. **82% of wall clock
is one `f.Sync()`.** Throughput is 13.5k rec/s serial and 12k rec/s with ten
goroutines — the single writer mutex is held across a 5 ms `F_FULLFSYNC`, so
concurrency buys safety and nothing else.

Two findings reframed the work:

1. `WriteRecord` already does not fsync per record; it fsyncs once per full
   64 KiB chunk. A batch API therefore saves a lock acquire and some
   allocations, not the fsync. **Fsync frequency is the only throughput lever.**
2. `tickFlushLocked` rewrites the entire 64 KiB chunk and fsyncs on every tick
   regardless of how few records arrived. At `FlushIntervalSec: 1` and 10
   events/sec that is roughly 5.5 GB written and 86 400 fsyncs per day to
   persist about 600 KB of events. ADR-004 already lists this rewrite as a known
   negative.

The darwin fsync cost is `F_FULLFSYNC`, a barrier through the drive cache.
Linux `fsync` on NVMe is substantially cheaper, so the 82% figure is an upper
bound and the CPU/IO balance may differ there. This is stated as unmeasured; no
decision below depends on it, because group commit makes encode the bottleneck
on any platform.

### Thread safety (audited, no changes proposed)

`go test -race ./... -count=1` passes. `Writer` guards every entry point with
one mutex; `rotate()` never self-locks; `drainFsyncCallbacks` is deferred before
`mu.Unlock()` so `OnFsync` fires outside the lock as documented. `Reader` holds
`r.mu` for every exported method and copies each payload out of the shared chunk
buffer. Coverage is real: `TestWriter_Concurrent`, `TestWriter_RotateRace`,
`TestWriter_Close_ConcurrentCallers`, three reader concurrency tests.

Two gaps found, neither a defect, both documentation-only and folded into this
work:

- The caller's `fields` map is read under `w.mu` but not owned by the writer. A
  caller mutating it from another goroutine races. Not currently documented.
- `Reader` against a file a `Writer` is actively writing, in the same process,
  is untested and unsafe: `tickFlushLocked` writes a partial chunk and nothing
  cross-locks the two types.

## Goals

- Remove tick-flush write amplification without changing a single on-disk byte
  of a sealed file.
- Give callers an opt-in way to exceed the fsync-bound throughput ceiling,
  without changing the default durability contract.
- Reduce per-record allocation, which becomes the bottleneck once fsync is
  amortized.
- Record the reasoning in ADRs, not only in commit messages.

## Non-goals

- Changing the sealed EVTX chunk format. Format Verify remains the gate.
- Making `Reader` safe against a concurrent `Writer` on the same file.
- Inventing forensic data. Unchanged from the existing rules.
- A Linux CI benchmark gate. Explicitly dropped from scope.

## Release 1 — v0.10.0: incremental tick flush

No API change. No on-disk format change.

### New `Writer` state

| Field | Meaning |
|---|---|
| `tickWrittenLen int` | Bytes of `w.records` already persisted into the current chunk slot by a previous tick |
| `recordsCRC uint32` | Running CRC32 of `w.records`, updated incrementally with `crc32.Update` on each append |
| `slotExtended bool` | The current chunk slot has been pre-extended to its full size |

All three reset alongside `w.records` in `flushChunkLocked` and in `rotate`.

### New `tickFlushLocked`

```go
if len(w.records) == 0                 { return nil }
if len(w.records) == w.tickWrittenLen  { return nil }   // idle: no write, no fsync
if err := w.chunkCapacityLocked(); err != nil { return err }

if !w.slotExtended {                                    // keep the file chunk-aligned
    if err := w.f.Truncate(chunkOffset + evtxChunkSize); err != nil { return err }
    w.slotExtended = true
}

hdr := buildChunkHeader(w.firstID, w.recordID-1, w.lastRecordOffset, freeSpaceOffset)
fillHashTables(hdr, w.chunkNames, w.chunkTemplates)     // writes [128:512] only
binary.LittleEndian.PutUint32(hdr[52:], w.recordsCRC)
patchChunkCRC(hdr)                                      // reads [0:120] + [128:512] only

w.f.WriteAt(w.records[w.tickWrittenLen:],
    chunkOffset+int64(evtxRecordsStart)+int64(w.tickWrittenLen))
w.f.WriteAt(hdr, chunkOffset)                           // header AFTER the records
w.f.WriteAt(buildFileHeader(...), 0)
w.f.Sync()
w.tickWrittenLen = len(w.records)
w.queueFsyncLocked()
```

### Why each piece is safe

- **Records are append-only.** `w.records` is only ever appended to and reset
  wholesale; bytes already written to the slot never change, so writing only the
  delta is equivalent to rewriting the whole region.
- **A 512-byte header buffer suffices.** `fillHashTables` writes only
  `[128:512]`; `patchChunkCRC` reads `[0:120]` and `[128:512]` and writes
  `[120:128]`. Neither touches anything above 512. The tick path therefore
  allocates no 64 KiB buffer at all.
- **The records CRC is incremental.** `patchEventRecordsCRC` currently rescans
  the whole records region; `crc32.Update` over the appended bytes yields the
  identical value, removing an O(chunk) scan per tick.
- **Header is written after the records it advertises.** A crash between the two
  leaves a header describing fewer records than are on disk, never more. The
  reverse ordering would advertise records whose bytes never landed.
- **`Truncate` keeps the file chunk-aligned.** Writing only `512 + len(records)`
  bytes into the slot would end the file mid-chunk; `loadChunk` reads a full
  `evtxChunkSize` and would hit EOF, as would Windows. Pre-extending leaves a
  sparse tail that reads as zeros — the same bytes the current full-chunk write
  produces. The target size is always strictly greater than the current file
  length at the moment `slotExtended` flips, so `Truncate` can never shorten the
  file.

`flushChunkLocked` is untouched: it still writes the full 64 KiB when sealing a
chunk, once per ~84 records.

### The invariant

**The bytes on disk after `Close()` are byte-identical to today's.** Nothing
about the sealed-chunk format changes. Conformance tests and the Format Verify
CI gate continue to apply unchanged.

### Expected effect

- Idle (no new records): 86 400 fsyncs/day → 0.
- 10 events/sec: ~64 KiB/tick → ~1 KiB/tick, i.e. ~5.5 GB/day → ~90 MB/day.
- One O(chunk) CRC rescan per tick removed.

## Release 2 — v0.11.0: throughput

### a) `SyncPolicy`

```go
type SyncPolicy int

const (
    SyncEveryChunk SyncPolicy = iota // zero value: today's behavior
    SyncOnTick
)

// RotationConfig gains:
//     SyncPolicy SyncPolicy
```

The zero value is today's semantics, so every existing caller is unaffected by
construction.

Under `SyncOnTick`, `flushChunkLocked` writes the chunk and patches the file
header but skips `f.Sync()`. Durability comes from the tick, from `rotate()`,
and from `Close()`, all of which sync unconditionally under every policy. One
tick fsync covers every chunk written since the previous one — that is the group
commit.

`New()` returns an error for `SyncOnTick` with `FlushIntervalSec == 0`: with no
tick there is no sync until `Close()`, an unbounded loss window. This is a hard
error, not a silently applied default.

Two consequences to document:

- The crash-loss window becomes `FlushIntervalSec` rather than one chunk.
- A `Sync` failure surfaces at tick time rather than at the write that filled
  the chunk, so the sticky error can land on a caller that wrote nothing.
  `OnFsync` fires correspondingly less often.

Expected burst-path cost: encode 3.3 µs + amortized write ~0.03 µs ≈ 3.4 µs per
record, against 74 µs today.

### b) `WriteRecords`

```go
type RecordInput struct {
    EventID int
    Fields  map[string]string
}

func (w *Writer) WriteRecords(recs []RecordInput) error
```

One lock acquire, one `checkStateLocked`, one size-based rotation check for the
whole slice. Then **every** record is validated before **any** is encoded:
`ProviderName` non-empty, `validateSystemFields`, and a payload-size upper
bound. Errors name the offending index, e.g. `go_evtx: record 3: ...`.

An empty slice is a no-op returning nil.

**The size bound.** `ErrRecordTooLarge` is otherwise only knowable after
encoding, which would break all-or-nothing when discovered mid-batch. So the
pre-pass uses `estimateMaxPayload(fields)`: the constant template size, the
inline-template worst case, plus the sum of 2 × UTF-16 length of each field
value. It is analytic, cheap, and a strict upper bound, so any record that could
exceed `maxRecordPayload` is rejected before anything is written. The existing
post-encode check stays inside the loop as an assertion on the estimator; if it
ever fires the estimator is wrong, and the fuzz target below exists to keep that
from happening.

**Scope of the guarantee.** All-or-nothing is a guarantee against *validation*
failures, which are fully pre-checked. It is not a transaction against the disk:
a chunk flush partway through a batch is normal and expected, and an I/O error
at that point leaves earlier records of the batch written. The doc comment says
this plainly.

`WriteRecord` keeps its current behavior and implementation; it is not
reimplemented in terms of `WriteRecords`.

### c) Allocation reuse

Writer-owned scratch buffers replace per-call allocation:

- 64 KiB `chunkScratch` for `flushChunkLocked`
- 512 B `hdrScratch` for the tick path
- a reused `bytes.Buffer` and substitution backing array inside `buildBinXML`

All encoding happens under `w.mu`, so Writer-owned buffers beat a `sync.Pool` —
no pool overhead and no escape-analysis surprises. Target: 56 allocs/record to
under 10, ~5.6 KB to near zero in steady state.

**The hazard is aliasing.** `res.payload` will point into the shared buffer, so
`wrapEventRecord` must copy before the next encode reuses it. This gets its own
test rather than a comment.

## Testing

### v0.10.0 (`tickflush_test.go`)

The load-bearing test is **byte identity**: write a fixed record set with
`FlushIntervalSec: 1` and again with `0`, using a pinned `TimeCreated`, and
compare the finished files byte-for-byte. Nothing in the sealed format carries
wall-clock data, so this is deterministic, and it proves the invariant the whole
release rests on.

Also:

- Idle writes nothing: one record, three tick intervals, `OnFsync` count is 1.
- Incremental round-trip: records written across several ticks read back in
  order after `Close()`.
- File stays chunk-aligned after a tick: size equals
  `4096 + (chunkCount+1) * 65536`. This is the EOF regression guard.
- Crash snapshot: copy the file mid-session, open the copy with `Reader`, read
  every record written before the last tick.
- The existing race suite and goroutine tests continue to apply.

**Not covered:** the header-after-records write ordering. `w.f` is a concrete
`*os.File`, so there is no injection seam. Code review plus the crash-snapshot
test is the coverage, and ADR-005 says so rather than implying it is tested.

### v0.11.0

- `WriteRecords(N)` produces a byte-identical file to N × `WriteRecord`, same
  pinned-timestamp technique.
- An invalid record at index k leaves the file, `recordID`, and the error's
  reported index mutually consistent, with nothing written.
- `estimateMaxPayload` gets a fuzz target asserting `estimate >= actual` over
  random field maps. This property is what makes all-or-nothing true.
- `SyncPolicy`: `New` rejects `SyncOnTick` with no tick; fsync count under
  `SyncOnTick` tracks tick count rather than chunk count; `Close` and `rotate`
  sync under every policy; the output file is byte-identical across policies.
- Allocation ceiling asserted with `testing.AllocsPerRun` inside a real test, so
  a regression fails the build rather than only moving a benchmark number.
- Aliasing: two differing records in one chunk, both read back intact.
- A concurrent `WriteRecords` + `WriteRecord` race test.

## Measurement

New `docs/perf-baseline.md`, append-only, under the same discipline as
`docs/format-baseline.md`: add a row, never edit one; select CI runs by
`head_sha`, never by recency. Columns: commit, platform, benchmark, ns/op,
allocs/op, fsyncs per record, bytes/day at 10 events/sec.

## Documentation

Three ADRs, matching the existing pattern in `docs/adr/`:

- **ADR-005, incremental tick flush.** Refines ADR-004, which already lists the
  full-chunk rewrite as a known negative. Records the measured amplification,
  the header-after-records ordering, the `Truncate` constraint, and the untested
  ordering gap.
- **ADR-006, sync policy and group commit.** The durability-for-throughput
  trade, why the default stays fsync-per-chunk in a forensic-artifact library,
  why `SyncOnTick` requires a tick, and the sticky-error timing shift.
- **ADR-007, batch write API.** The all-or-nothing contract, its exact scope,
  and why it needs an analytic size bound rather than encode-and-rollback.

Also:

- `mkdocs.yml`: nav entries for ADR-005/006/007, and `extra.version`, which is
  stale at v0.5.1.
- `docs/user-guide.md`: a section on choosing `FlushIntervalSec` and
  `SyncPolicy`, with the measured numbers.
- `CLAUDE.md`: the write data-flow section, the file and test-file tables, and
  the concurrency section (the `SyncPolicy` sticky-error timing shift).
- `WriteRecord` doc comment: the caller must not mutate `fields` concurrently.
- `Reader` doc comment: reading a file that a `Writer` is actively writing is
  unsupported.
- `CHANGELOG.md`: one entry per release.

## Rollout

Both releases are minor and non-breaking.

- v0.10.0 changes no on-disk bytes and no API.
- v0.11.0 adds a `RotationConfig` field, a type, and a method. Source-compatible
  for keyed struct literals, which is the documented usage throughout. An
  unkeyed `RotationConfig{...}` literal in caller code would break; this is
  noted in the changelog.

## Risks

| Risk | Mitigation |
|---|---|
| Partial tick write corrupts the in-progress chunk | Byte-identity test plus crash-snapshot test |
| File left mid-chunk, unreadable by `loadChunk` or Windows | `Truncate` pre-extension, asserted by the chunk-alignment test |
| `SyncOnTick` used without understanding the loss window | `New()` hard-errors on the unbounded configuration; ADR-006 and the user guide state the window |
| `estimateMaxPayload` under-counts, breaking all-or-nothing | Fuzz target on the bound; post-encode check retained as an assertion |
| Shared encode buffer aliased into `w.records` | Explicit aliasing test |
| Four write-path changes make a regression unattributable | Two releases, each with its own `perf-baseline.md` rows |
