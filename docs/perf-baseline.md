# Performance baseline

Append-only, under the same discipline as `docs/format-baseline.md`:

- **Add a row; never edit one.** Earlier rows are the evidence later
  comparisons rest on. A correction goes in a new row with a note.
- **The append-only rule binds from the moment this file merges to `main`.**
  Rows corrected on the branch before that point were never evidence anyone
  relied on; once merged, a row is public history and only a new row may
  correct it. Stated because this file was created on a branch whose own
  pre-merge review changed the code the first rows measure.
- **Select a CI run by `head_sha`, never by recency.** A run whose head is
  stale measures a different tree than the one you are attributing it to.
- **Record the platform.** fsync cost is not portable: darwin's `File.Sync` is
  `F_FULLFSYNC`, a barrier through the drive cache, and is roughly an order of
  magnitude more expensive than a Linux `fsync` on NVMe. A row without a
  platform is not comparable to anything.
- **Record the Go toolchain version in the platform cell, for the same
  reason.** A compiler change can move `ns/op`/`B/op`/`allocs/op` on its own,
  with zero change to this repo's code. A row measured on a toolchain other
  than the `go.mod` pin must say so, so a later reader does not attribute a
  compiler-driven delta to the code under test.

Reproduce with:

```bash
go test -run XXX -bench . -benchtime 3s -benchmem .
```

## Rows

| Date | Commit | Platform | Benchmark | ns/op | B/op | allocs/op | Note |
|---|---|---|---|---|---|---|---|
| 2026-08-22 | v0.9.0 | darwin/arm64 M1 Pro, APFS | WriteRecord | 74269 | 6747 | 58 | Spike harness, throwaway; 83.7 rec/fsync |
| 2026-08-22 | v0.9.0 | darwin/arm64 M1 Pro, APFS | WriteRecordParallel (10) | 83912 | 6751 | 58 | Slower than serial: one mutex across a 5 ms F_FULLFSYNC |
| 2026-08-22 | v0.9.0 | darwin/arm64 M1 Pro, APFS | EncodeShared | 3301 | 5608 | 56 | Spike harness |
| 2026-08-22 | v0.9.0 | darwin/arm64 M1 Pro, APFS | EncodeInline | 13960 | 20968 | 180 | Spike harness |
| 2026-08-22 | v0.9.0 | darwin/arm64 M1 Pro, APFS | raw 64 KiB WriteAt + Sync | 5352391 | — | — | Spike harness; 2632 ns/op without the Sync |
| 2026-08-22 | 98cc202 | darwin/arm64 M1 Pro, APFS, go1.27.0 | EncodeShared | 3146 | 5656 | 58 | v0.10.0, `bench_test.go` |
| 2026-08-22 | 98cc202 | darwin/arm64 M1 Pro, APFS, go1.27.0 | EncodeInline | 12744 | 21016 | 182 | v0.10.0, `bench_test.go` |
| 2026-08-22 | 98cc202 | darwin/arm64 M1 Pro, APFS, go1.27.0 | WriteRecord | 72199 | 6822 | 60 | v0.10.0, `bench_test.go`; 81.86 rec/fsync |
| 2026-08-22 | 98cc202 | darwin/arm64 M1 Pro, APFS, go1.27.0 | WriteRecordParallel (10) | 65862 | 6827 | 60 | v0.10.0, `bench_test.go` |
| 2026-08-22 | 98cc202 | darwin/arm64 M1 Pro, APFS, go1.27.0 | TickFlushIdle | 13.84 | 0 | 0 | v0.10.0, `bench_test.go`; a tick with no new records since the previous one is a no-op — the pre-release (v0.9.0) tick instead performed a full-chunk write and fsync on every interval regardless of arrivals |
| 2026-08-22 | d8a85e4 | darwin/arm64 M1 Pro, APFS, go1.27.0 | EncodeShared | 3274 | 5656 | 58 | **After the records-CRC fix.** Encode path untouched by the fix; delta vs 98cc202 is run-to-run noise |
| 2026-08-22 | d8a85e4 | darwin/arm64 M1 Pro, APFS, go1.27.0 | EncodeInline | 13150 | 21016 | 182 | **After the records-CRC fix.** Encode path untouched by the fix |
| 2026-08-22 | d8a85e4 | darwin/arm64 M1 Pro, APFS, go1.27.0 | WriteRecord | 68307 | 6822 | 60 | **After the records-CRC fix**; 81.84 rec/fsync. This row restores the O(chunk) `patchEventRecordsCRC` rescan per flush that 98cc202's row was measured without. It is *faster* than 98cc202's 72199, which is not a speed-up from the fix — a 64 KiB CRC32 is a few µs against a ~61 µs amortized `F_FULLFSYNC`, so the rescan is inside this benchmark's run-to-run spread. Do not read either row as evidence about the rescan's cost; the fsync dominates |
| 2026-08-22 | d8a85e4 | darwin/arm64 M1 Pro, APFS, go1.27.0 | WriteRecordParallel (10) | 72424 | 6827 | 60 | **After the records-CRC fix.** Same caveat as the serial row |
| 2026-08-22 | d8a85e4 | darwin/arm64 M1 Pro, APFS, go1.27.0 | TickFlushIdle | 13.49 | 0 | 0 | **After the records-CRC fix.** The idle skip does not touch the CRC path, so this is unchanged from 98cc202's 13.84 within noise. Harness change in the same commit: the priming tick's error is now fatal, so this row cannot silently be measuring the `len(w.records) == 0` branch instead of the idle-skip branch — which 98cc202's row, whose harness discarded that error, could not rule out |

### Note on the d8a85e4 rows

These five rows follow the records-CRC fix (`d8a85e4`): v0.10.0 briefly
replaced `patchEventRecordsCRC`'s full rescan with a checksum maintained
incrementally over `w.records`, which is unsound because `fillHashTables`
patches bytes inside the records region. The rescan is restored on both flush
paths. The 98cc202 rows above are **not** superseded — they correctly describe
the code as it was measured — but any comparison against them must account for
one extra O(chunk) CRC32 per flush, which the numbers show is below this
benchmark's noise floor on an fsync-bound path.

## Derived figures

The design that shipped differs from the one that motivated this release.
The original plan was for the tick to write only the *delta* — the
512-byte header plus the record bytes appended since the previous tick.
That design turned out to be unimplementable: `fillHashTables` patches
bytes inside the records region, including at the offset of an *earlier*
node when chaining onto a hash bucket, so appending a record can mutate
record bytes already written to disk. "Records are append-only on disk" is
false, so delta-only writing can never be correct.

What v0.10.0 actually does: build the full chunk buffer, patch it, then
write the **used prefix** — the records region `[512 : 512+len(w.records)]`
followed by the 512-byte header — skipping only the unwritten tail padding.
When no records arrived since the previous tick, it writes nothing at all.

The paragraph below is arithmetic, not measurement, and should be read as
such — it has not itself been benchmarked. At `FlushIntervalSec: 1` and
roughly 10 events/sec with ~780-byte records, a chunk fills in roughly 83
records (~8 ticks), so a non-idle tick writes `512 + len(w.records)` bytes,
growing from a few KB right after a chunk starts to close to the full
65024-byte records region just before it fills — not a flat 65536 bytes on
every tick regardless of arrivals, which is what the v0.9.0 tick wrote (per
the `TickFlushIdle` row's note above, describing the pre-release code path).
The larger win for the driving workload is the idle case, and that one *is*
measured above: `BenchmarkTickFlushIdle`
shows a tick with no new records completing in nanoseconds with zero
allocations and doing no I/O, so a workload with gaps between arrivals — the
motivating case, bursty log activity under a 1-second tick — turns what
would have been up to 86 400 fsyncs/day into zero on every tick where
nothing arrived.
