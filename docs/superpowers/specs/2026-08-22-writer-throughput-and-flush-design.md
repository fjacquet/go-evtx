# Writer Throughput and Flush Policy — Design

**Date:** 2026-08-22
**Status:** Both releases shipped. Release 1 (v0.10.0, flush amplification) shipped 2026-08-22; Release 2 (v0.11.0 — `SyncPolicy`, `WriteRecords`, allocation reuse) implemented 2026-08-23 on `feat/v0.11.0-impl`, recorded in [ADR-008](../../adr/ADR-008-sync-policy-group-commit.md) and [ADR-009](../../adr/ADR-009-batch-write-api.md). Two claims below did not survive implementation; both carry dated notes in place.
**Releases:** v0.10.0 (flush amplification), v0.11.0 (throughput)

## Context

go-evtx is used as a sink for network-attached-storage audit events. That
workload has two ends and the writer must survive both: a long-running receiver
at tens of events per second, and a burst from a busy cluster at thousands to
tens of thousands per second.

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
   regardless of how few records arrived. At true idle that is 86 400 fsyncs
   per day to persist nothing at all — pure waste. At `FlushIntervalSec: 1`
   and 10 events/sec it is also redundant, if less dramatically so: roughly
   5.5 GB written and 86 400 fsyncs per day to persist about 674 MB of
   events, an amplification of roughly 8.4x. ADR-004 already lists this
   rewrite as a known negative.

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

**Superseded by implementation — see the correction note at the end of this
section.** This section is kept as originally written, for the record; the
design it describes (a 512-byte header buffer plus the appended delta) was
implemented, failed review, and was abandoned. What shipped instead is a
full-size chunk buffer with only the used prefix written to disk. Read the
correction note before relying on anything below it as current.

No API change. No on-disk format change.

### New `Writer` state

| Field | Meaning |
|---|---|
| `tickWrittenLen int` | Bytes of `w.records` already persisted into the current chunk slot by a previous tick |
| ~~`recordsCRC uint32`~~ | ~~Running CRC32 of `w.records`, updated incrementally with `crc32.Update` on each append~~ — **false, reverted**; see the second correction note below |
| `slotExtended bool` | The current chunk slot has been pre-extended to its full size |

The two that survived (`tickWrittenLen`, `slotExtended`) reset alongside
`w.records` in `flushChunkLocked` and in `rotate`.

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

**The first two bullets below are false — see the "Correction note" at the
end of this section.** `fillHashTables` patches offsets inside the records
region, not only `[128:512]`, so records are not in fact append-only on
disk once hash chaining is considered, and a 512-byte buffer is not
sufficient. Kept as originally written for the record.

- ~~**Records are append-only.**~~ `w.records` is only ever appended to and
  reset wholesale; bytes already written to the slot never change, so
  writing only the delta is equivalent to rewriting the whole region. —
  **False.** `fillOneTable`'s chain-patch write can rewrite a byte at an
  *earlier* node's offset, inside record bytes a previous tick already
  wrote to disk.
- ~~**A 512-byte header buffer suffices.**~~ `fillHashTables` writes only
  `[128:512]`; `patchChunkCRC` reads `[0:120]` and `[128:512]` and writes
  `[120:128]`. Neither touches anything above 512. The tick path therefore
  allocates no 64 KiB buffer at all. — **False.** `fillOneTable` also writes
  a 4-byte chain terminator at `chunk[ref.offset:]` and, when chaining, a
  4-byte patch at `chunk[prev:]`, both of which land at or beyond
  `evtxRecordsStart+evtxRecordHeaderSize` (>= 536) — inside the records
  region, outside any 512-byte buffer.
- ~~**The records CRC is incremental.**~~ `patchEventRecordsCRC` currently
  rescans the whole records region; `crc32.Update` over the appended bytes
  yields the identical value, removing an O(chunk) scan per tick. — **False,
  and reverted.** `crc32.Update` does yield the checksum of the concatenation,
  but the concatenation is the wrong input: `chunk[52:56]` covers
  `chunk[512:FreeSpaceOffset]`, the **patched** buffer, and `fillOneTable`'s
  chain patches land inside it. Same false premise as the two bullets above.
  See the second correction note below.
- **Header is written after the records it advertises.** A *process* crash
  between the two leaves a header describing fewer records than are on disk,
  never more. The reverse ordering would advertise records whose bytes never
  landed. — **Narrowed 2026-08-22:** there is no fsync between the two
  `WriteAt` calls, so this ordering is not preserved across power loss;
  writeback may commit them in either order. The exposure predates v0.10.0.
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

### Expected effect (superseded — see correction note below)

- Idle (no new records): 86 400 fsyncs/day → 0. **This figure held.**
- 10 events/sec: ~64 KiB/tick → ~1 KiB/tick, i.e. ~5.5 GB/day → ~90 MB/day.
  **This figure did not hold** — it assumed the delta design below, which was
  abandoned. What shipped writes the used prefix of a full chunk buffer, a
  saving that is real but roughly half on average across a chunk's fill, not
  an order of magnitude. See the correction note.
- ~~One O(chunk) CRC rescan per tick removed.~~ **This figure did not hold
  either.** The claim that it did — "the CRC is incremental regardless of which
  write-size design carries it to disk" — was written in the same correction
  pass that caught the delta design, and repeats its false premise. The rescan
  is back. See the second correction note below.

## Correction note (v0.10.0 implementation, 2026-08-22)

**The false premise.** "A 512-byte header buffer suffices" and "records are
append-only on disk" above are both wrong. `fillHashTables` does not confine
itself to `chunk[128:512]`: `fillOneTable` (`chunkhash.go`) also writes a
4-byte chain terminator at `chunk[ref.offset:]`, and — when chaining a new
node onto a bucket whose tail is an *earlier* node — a 4-byte chain patch at
`chunk[prev:]`. Both are chunk-absolute offsets that land inside the records
region (>= `evtxRecordsStart+evtxRecordHeaderSize`, i.e. >= 536), which the
delta design above treated as immutable once written.

**How it was found.** The header-plus-delta design above was implemented
(`ceb9531`) against a 512-byte header buffer. It passed `go build`/`go vet`
and the existing suite, because every one of `fillOneTable`'s out-of-range
writes silently failed its own bounds guard
(`int(ref.offset)+4 > len(chunk)`) instead of panicking or returning an
error — the hash tables were left entirely zero, with a CRC computed over
the zeros, so nothing already in the suite could flag it. It was caught in
code review, not by an existing test, and confirmed by probing a
mid-session chunk directly: `chunk[128:512]` held 0 non-zero bytes under the
delta design against 44 once the fix (`916e843`) landed. A regression test,
`TestTickFlush_SnapshotHashTablesPopulated`, now guards exactly this failure
mode.

**What this means for the numbers above.** Because a later record's chain
patch can rewrite a byte an earlier tick already wrote to disk, "records are
append-only on disk" does not hold once hash chaining is considered — no
buffer size makes header-plus-delta correct, not just 512 bytes. What
shipped instead builds the full chunk buffer, patches it exactly as
`flushChunkLocked` does, and writes only the used prefix (records region
then 512-byte header) to disk, skipping just the unwritten tail. The idle
result above is unaffected and is the larger win for the driving workload;
the non-idle "~64 KiB → ~1 KiB" and "~5.5 GB/day → ~90 MB/day" figures are
wrong and are restated in `docs/perf-baseline.md`'s "Derived figures"
section and in [ADR-007](../../adr/ADR-007-incremental-tick-flush.md),
which also carries the full "Alternatives Considered" account of the
abandoned design.

**A second correction, same root cause: the incremental records CRC
(2026-08-22, pre-merge).** The bullet "the records CRC is incremental" above,
and the "this figure held" line that survived the first correction pass, are
both wrong, and wrong for the *identical* reason: `fillHashTables` patches
bytes inside the records region. The records CRC at `chunk[52:56]` covers
`chunk[512:FreeSpaceOffset]` — the patched buffer — so a checksum accumulated
over `w.records` disagrees with the bytes on disk as soon as two keys collide
on a bucket, which 64 buckets make near-certain within about 30 distinct names,
fewer than one record emits. Measured through the public API with a fixed
`TimeCreated`, the stored `chunk[52:56]` differed from
`crc32.Checksum(chunk[512:FreeSpaceOffset])` for 1, 5 and 30 records, while the
recomputed values matched v0.9.0's stored values exactly — the record bytes
never moved, only the checksum field did. Every chunk this branch wrote
therefore shipped a wrong records CRC, violating the byte-identity invariant
above and producing exactly the checksum-invisible corruption this repository
treats as unacceptable.

`patchEventRecordsCRC` is restored at both call sites, ordered after
`fillHashTables`, and `TestWrittenFile_EventRecordsCRCMatchesRecords` asserts
the property against the finished file. **The generalisable lesson, since this
spec produced the same mistake twice:** no optimisation may treat `w.records`
as equivalent to the bytes at `chunk[512:]` — not writing them, not checksuming
them, not reasoning about their immutability. The first correction note below
framed its finding as being about delta *writes*; that framing was too narrow
and is why the CRC claim survived it. A v0.11.0 plan drawn from this spec must
apply the wider rule.

**A second, unrelated correction: ADR numbering.** The Documentation section
below says this release's ADR is "ADR-005, incremental tick flush" and
plans "ADR-006, sync policy" and "ADR-007, batch write API" for release 2.
At the time this spec was written, `docs/adr/ADR-005-ship-cli-binaries.md`
and `docs/adr/ADR-006-corpus-derived-format-method.md` already existed in
the repository — this spec's author did not check the current highest ADR
number before assigning new ones. The incremental-tick-flush ADR shipped as
**ADR-007**, not ADR-005. A v0.11.0 plan written from this spec must number
its own new ADRs from the next available number at the time it is written
(ADR-008 onward), not reuse 006/007 as stated below.

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

> **Note, 2026-08-23 (v0.11.0 implementation).** "Durability comes from the
> tick" above is **incomplete as written**, and the gap is a real one the
> implementation had to close. `tickFlushLocked` does not always flush: since
> v0.10.0 (ADR-007) it returns early when `len(w.records) == 0` and again when
> `len(w.records) == w.tickWrittenLen`. Under `SyncOnTick` a burst that fills
> and seals a chunk leaves `w.records` empty, so every subsequent tick takes
> the first early return and the sealed — written, not durable — chunk would
> have waited for `Close()`. On a daemon that is hours or days: precisely the
> unbounded window `New` refuses to let a caller configure, reintroduced
> through the one code path this section names as the fix.
>
> The fix is a `w.pendingSync` flag, set by `flushChunkLocked` when it skips
> the sync and discharged as `tickFlushLocked`'s **first** action, ahead of
> both early returns — ordering is the whole point, since a flag consulted
> after them would never be reached in the case that needs it. Cleared by
> every successful `f.Sync()`, including `rotate()`'s and
> `finalizeLocked`'s. Pinned by
> `TestSyncPolicy_TickSyncsASealedChunkWithNoPendingRecords`, which exists
> separately from the general policy tests because those write continuously
> and so never reach the quiet state.
>
> The generic lesson, recorded because it is not specific to this feature:
> composing a new mechanism onto an existing one requires re-reading the
> existing one's **early returns**, not only its main path. The tick's fast
> paths were added for reasons unrelated to durability and became a
> durability hole the moment durability started depending on the tick.

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

> **Correction, 2026-08-23 (v0.11.0 implementation).** "512 B `hdrScratch` for
> the tick path" describes v0.10.0's **abandoned** header-only tick write, and
> is wrong for the same reason that design was abandoned: `fillHashTables`
> back-patches node offsets that live inside the records region, so the tick
> must build and patch a full `evtxChunkSize` buffer even though it writes
> only the used prefix to disk. See the v0.10.0 correction note above and
> ADR-007. There is therefore **no `hdrScratch`**: both flush paths share the
> one 64 KiB `w.chunkScratch`, obtained through `chunkScratchLocked()`, which
> clears it before each use — a reused buffer still holding the previous
> chunk's records would write those bytes into this chunk's padding tail,
> leaking data into the file and breaking byte-identity with v0.10.0's
> freshly allocated, zero-filled buffers.
>
> The substitution "backing array" shipped as a per-call arena inside
> `collectSubstitutionsFromFields`, not as `Writer`-owned state — so unlike
> `chunkScratch` and `encodeScratch` it adds nothing to the writer's resident
> memory. The target of "56 allocs/record to under 10" was met: 54.0 measured
> before, 5.0 after (`testing.AllocsPerRun`).

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
test is the coverage, and ADR-007 (shipped number — see the correction note
above; this said ADR-005 originally) says so rather than implying it is
tested.

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

Three ADRs, matching the existing pattern in `docs/adr/`. **Numbering below is
as originally planned; see the correction note above — ADR-005 and ADR-006
were already taken by existing ADRs, so the first of these shipped as
ADR-007, and the two v0.11.0 ADRs must take the next available numbers when
that release is planned (ADR-008 onward), not 006/007 as written here:**

- **Incremental tick flush** (shipped as **ADR-007**, not ADR-005 as
  originally planned). Refines ADR-004, which already lists the full-chunk
  rewrite as a known negative. Records the measured amplification, the
  header-after-records ordering, the `Truncate` constraint, and the untested
  ordering gap.
- **Sync policy and group commit** (originally planned as ADR-006; renumber
  at write time). The durability-for-throughput trade, why the default stays
  fsync-per-chunk in a forensic-artifact library, why `SyncOnTick` requires a
  tick, and the sticky-error timing shift.
- **Batch write API** (originally planned as ADR-007; renumber at write
  time). The all-or-nothing contract, its exact scope, and why it needs an
  analytic size bound rather than encode-and-rollback.

Also:

- `mkdocs.yml`: nav entry for the incremental-tick-flush ADR (added as
  `ADR-007-incremental-tick-flush.md`), and `extra.version`, which was stale
  at v0.5.1 and is now v0.10.0.
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
| `SyncOnTick` used without understanding the loss window | `New()` hard-errors on the unbounded configuration; the sync-policy ADR (see the correction note's renumbering) and the user guide state the window |
| `estimateMaxPayload` under-counts, breaking all-or-nothing | Fuzz target on the bound; post-encode check retained as an assertion |
| Shared encode buffer aliased into `w.records` | Explicit aliasing test |
| Four write-path changes make a regression unattributable | Two releases, each with its own `perf-baseline.md` rows |
