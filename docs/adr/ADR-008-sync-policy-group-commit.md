# ADR-008: Sync Policy and Group Commit (v0.11.0)

**Date:** 2026-08-23
**Status:** Accepted — extends ADR-007

## Context

`docs/perf-baseline.md`'s v0.10.0 rows put `WriteRecord` at 68 307 ns/op on
`darwin/arm64 M1 Pro, APFS, go1.27.0` while `BenchmarkEncodeShared` — the
whole BinXML encode, the part of the work that actually produces the bytes —
ran at 3 274 ns/op. Encoding is not the cost. The fsync is: on darwin,
`f.Sync()` is `F_FULLFSYNC`, a device cache-flush barrier, and it is
amortized across roughly 81 records because that is how many fit in a 64 KiB
chunk. Measured at approximately **82% of `WriteRecord`'s wall clock**.

That leaves exactly one lever. Making the encoder faster, removing
allocations, or shrinking the bytes written cannot move a number that is
five-sixths waiting on a platter. The only change that moves the ceiling is
calling `f.Sync()` less often, and the only honest way to call it less often
is to trade durability for it.

ADR-007 removed *wasted* fsyncs — a tick with nothing new to write now does
nothing. That was free, because nothing was being persisted by those syncs in
the first place. This decision is not free, and it is not a default.

## Decision

### 1. `SyncPolicy`, with the zero value unchanged

```go
type SyncPolicy int

const (
    SyncEveryChunk SyncPolicy = iota // zero value: the behaviour go-evtx has always had
    SyncOnTick                       // group commit
)
```

`RotationConfig` gains a `SyncPolicy` field. Its zero value is
`SyncEveryChunk`, so **every existing caller is unaffected by construction**,
not by care: a `RotationConfig{}` literal selects today's semantics, and a
file written under it is byte-identical to one written by v0.10.0.

`SyncEveryChunk` stays the default because this is a forensic-artifact
library. An `.evtx` file is evidence about events that happened on someone
else's system; the consumer of that file has no way to tell a short file from
a complete one, and the events that are missing are exactly the ones nearest
whatever caused the crash. A library whose default silently widened that
window would be trading someone else's evidence for our benchmark number. A
caller who understands their own workload can make that trade; we cannot make
it for them.

### 2. Under `SyncOnTick`, `flushChunkLocked` skips the sync

`flushChunkLocked` still writes the complete padded chunk, still patches the
file header to `chunkCount+1`, and still commits its in-memory state
(`chunkCount`, `currentSize`, `records`, `firstID`, …) together. It simply
does not call `f.Sync()`. Instead it sets `w.pendingSync = true` to record
the fsync debt.

Durability then comes from the three paths that sync unconditionally under
every policy: the background flush tick, `rotate()` (Step 3, before it closes
the active handle), and `Close()`/`finalizeLocked`. Each clears
`w.pendingSync`. One tick fsync covers every chunk written since the previous
one — that is the group commit.

The commit-ordering property ADR-007 relies on shifts subtly here. Under
`SyncEveryChunk` the in-memory commit happens *after a successful sync*, so a
failed flush leaves nothing mutated and the call is genuinely retriable.
Under `SyncOnTick` the commit happens after a successful *write*. The write
is still all-or-nothing with respect to in-memory state; what moves is when a
sync failure can be observed.

### 3. `New` rejects `SyncOnTick` without a tick — a hard error

```go
if cfg.SyncPolicy == SyncOnTick && cfg.FlushIntervalSec <= 0 {
    return nil, fmt.Errorf(
        "go_evtx: SyncOnTick requires FlushIntervalSec > 0, otherwise nothing " +
            "syncs until Close and the crash-loss window is unbounded")
}
```

With no tick, the only remaining sync points are `rotate()` and `Close()`.
A long-running daemon may not call either for hours or days, so the loss
window would not be "large" — it would be *unbounded*, which is a different
kind of statement and not one a durability setting is allowed to make
quietly.

This is a hard error rather than a silently applied default (say, forcing
`FlushIntervalSec: 1`). A caller who wrote `SyncOnTick` with no tick has a
belief about their own durability that is wrong; substituting a value we
invented would leave that belief in place and make the code appear to work.
Failing at `New` is the only point at which the caller is still present to be
told.

## Consequences

### The loss window becomes `FlushIntervalSec`

Under `SyncEveryChunk` at most one chunk of events — up to roughly 81
records — is at risk. Under `SyncOnTick` the window is a *time*:
`FlushIntervalSec` seconds of arrivals, however many records that is. At
`FlushIntervalSec: 1` and 10 events/sec that is about 10 records; at 10 000
events/sec it is 10 000. The setting a caller reaches for to bound their loss
window is now the same setting that bounds it — which is at least
comprehensible — but the units changed from records to seconds, and a caller
reasoning in records will get it wrong.

### A `Sync` failure surfaces at tick time, on a caller that wrote nothing

Under `SyncEveryChunk`, a failing `f.Sync()` is returned to whichever
`WriteRecord` call filled the chunk. Under `SyncOnTick` that same failure now
surfaces inside `tickFlushLocked`, running on the background goroutine, which
has no caller to return an error to — so it does what ADR-004's background
flush already does and sets the sticky `w.err`. The next `WriteRecord`,
`WriteRaw` or `Rotate`, from *any* goroutine, gets that error back.

The practical shape: the call that lost the data succeeded, and a later,
unrelated call fails. That is not new — the background flush has always had
this property — but `SyncOnTick` makes it the normal path for chunk
durability rather than an edge case. `OnFsync` fires correspondingly less
often, and its timestamps are no longer per-chunk.

### The `pendingSync` hole — a defect the design spec contained

**This is the paragraph worth reading.**

The design spec
(`docs/superpowers/specs/2026-08-22-writer-throughput-and-flush-design.md`,
Release 2(a)) asserted: "Durability comes from the tick, from `rotate()`, and
from `Close()`, all of which sync unconditionally under every policy." The
first clause is where it went wrong. It reasoned about the tick as though the
tick always runs a flush, and v0.10.0 had already made that false.

`tickFlushLocked` has two early returns, both introduced by ADR-007 and both
correct on their own terms:

```go
if len(w.records) == 0 { return nil }
if len(w.records) == w.tickWrittenLen { return nil }   // nothing new since the last tick
```

Now consider the exact workload `SyncOnTick` exists to serve — a burst. The
burst fills a chunk. `flushChunkLocked` writes it, patches the file header,
sets `pendingSync`, and resets `w.records` to empty. The burst ends. The next
tick fires, finds `len(w.records) == 0`, and returns. So does every tick after
it.

That sealed chunk — real events, already written, not yet durable — would
have waited for `Close()`. On a daemon, that is hours or days. **It is
precisely the unbounded window `New` refuses to let a caller configure**,
reintroduced through the back door by the one code path the spec named as the
fix.

The fix is `w.pendingSync`, discharged as `tickFlushLocked`'s **first**
action, ahead of both early returns:

```go
if w.pendingSync && (len(w.records) == 0 || len(w.records) == w.tickWrittenLen) {
    if err := w.f.Sync(); err != nil { ... }
    w.pendingSync = false
    w.queueFsyncLocked()
    return nil
}
```

Ordering is the whole point: a flag consulted after the early returns would
never be reached in the case that needs it.
`TestSyncPolicy_TickSyncsASealedChunkWithNoPendingRecords` pins this
specifically, rather than relying on the general policy tests, because every
general test writes continuously and therefore never reaches the quiet state.

Two things are worth naming about how this was found. It was found by
implementing the spec and asking what each branch does under the new policy —
not by a test failing, because no test existed that could fail. And its root
cause is generic: a design that composes a new mechanism onto an existing one
must re-read the existing one's *early returns*, not just its main path. The
tick's fast paths were added for a reason that had nothing to do with
durability, and they silently became a durability hole the moment durability
started depending on the tick.

### Crash consistency under `SyncOnTick`: a different failure *shape*

The spec framed this trade as bounded data loss. That framing is incomplete
and an operator choosing this policy must be told the rest.

`flushChunkLocked` performs two writes with no sync between them and, under
`SyncOnTick`, no sync after them either:

1. the complete 65 536-byte chunk, at its offset;
2. the file header at offset 0, patched to `chunkCount+1`.

Under `SyncEveryChunk` the `f.Sync()` that follows makes both durable
together. Under `SyncOnTick` neither is durable until the next tick, and
writeback may commit them to the platter **in either order**. A power loss in
that window can therefore leave a file whose header advertises a chunk whose
bytes never landed.

That is not "missing the tail". A parser reading that file finds a chunk slot
containing zeros or stale data where a signed, checksummed chunk should be —
a file that looks **corrupt**, not merely short. Windows' own reader is the
consumer that matters here, and it will reject it rather than read fewer
records.

This is consistent with, and an extension of, ADR-007's narrowing of its own
ordering claim to "process-crash ordering only": a process crash is fine
under both policies, because the page cache still holds both writes and the
file reads back coherently. It is power loss and hard kernel failure that
differ. What `SyncOnTick` changes is the *width* of that exposure — under
`SyncEveryChunk` the window is the microseconds between the header write and
the sync; under `SyncOnTick` it is up to `FlushIntervalSec`.

An operator picking `SyncOnTick` is buying throughput with "up to
`FlushIntervalSec` of events, and a small chance of a file the parser
rejects", not with "up to `FlushIntervalSec` of events" alone. Closing the
second half would require an fsync between the two writes — which is the cost
this decision exists to avoid — or a header that never advertises a chunk
before that chunk is durable, which is a larger change than this release
makes.

### Measured effect

From `docs/perf-baseline.md`, commit `717e122`, `darwin/arm64 M1 Pro, APFS,
go1.27.0`:

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `WriteRecord` (`SyncEveryChunk`, default) | 77 373 | 5 033 | 5 |
| `WriteRecordSyncOnTick` | 2 770 | 5 025 | 5 |

**~27.9x**, with 1 total fsync across the whole run (from `Close()`) against
one per ~80.79 records. The benchmark uses `FlushIntervalSec: 3600` so that no
tick fires during the run; a real deployment pays one fsync per tick instead
of zero, which is still amortized across every record that arrived in that
interval.

Two caveats the baseline file states and this ADR repeats rather than hides.
The measurement machine's load average was 20-29 and `ns/op` was not stable —
the rows are medians of repeated runs at `-benchtime 3s`, with
`WriteRecordSyncOnTick` ranging 2 591-2 827 ns/op. And the ratio is
darwin-specific: `F_FULLFSYNC` is roughly an order of magnitude more
expensive than a Linux `fsync`, so a Linux row would be expected to show a
smaller multiple. The *shape* of the result — fsync dominates, amortizing it
is the only lever — is not platform-specific; the number 27.9 is.

## The invariant

A file written with `RotationConfig{}` is byte-identical to one written by
v0.10.0, and a file written under `SyncOnTick` is byte-identical to one
written under `SyncEveryChunk` with the same records. `SyncPolicy` changes
*when* bytes are made durable and nothing about *which* bytes are written.
`TestSyncPolicy_ByteIdenticalAcrossPolicies` asserts the second half
directly.

## Alternatives Considered

**Make `SyncOnTick` the default.** Rejected on the grounds in Decision 1. The
27.9x is real and it is not ours to take on a caller's behalf in a library
whose output is evidence.

**Silently default `FlushIntervalSec` to 1 when `SyncOnTick` is set.**
Rejected: it leaves a wrong belief about durability in place and makes the
misconfiguration work, which is worse than failing.

**A `SyncEveryRecord` policy at the other end.** Not added. Nothing asked for
it, and it would be strictly worse than `SyncEveryChunk` on every axis except
a loss window nobody specified — a chunk is already the smallest unit the
format lets us commit.

**An explicit `Sync()` method on `Writer` so callers can checkpoint by
hand.** Deferred, not rejected. It composes with `SyncOnTick` and would give
a caller a way to bound the window around specific events rather than by
time. It was out of scope for this release and no caller has asked for it.

**Sync between the chunk write and the header write, under `SyncOnTick`, to
close the corrupt-file window.** Rejected for this release: it reintroduces
a per-chunk fsync, which is the entire cost being removed. The honest
alternative is to document the exposure, which is what the consequences
section above does.
