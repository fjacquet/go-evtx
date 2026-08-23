# User Guide

This guide walks through installing go-evtx, reading and writing `.evtx`
files from Go, configuring rotation, using the `evtx` CLI, and the errors you
are actually likely to hit. For the full API, see
[pkg.go.dev/github.com/fjacquet/go-evtx](https://pkg.go.dev/github.com/fjacquet/go-evtx).
For what is and isn't implemented, see [the PRD](PRD.md).

## 1. Install

As a library:

```bash
go get github.com/fjacquet/go-evtx@latest
```

As a CLI (requires a Go toolchain):

```bash
go install github.com/fjacquet/go-evtx/cmd/evtx@latest
```

Or download a prebuilt binary from the
[releases page](https://github.com/fjacquet/go-evtx/releases/latest) —
linux/darwin/windows, amd64 and arm64, with a checksums file (see
[ADR-005](adr/ADR-005-ship-cli-binaries.md)).

## 2. Read a file

```go
package main

import (
	"errors"
	"fmt"
	"log"

	evtx "github.com/fjacquet/go-evtx"
)

func main() {
	r, err := evtx.Open("/var/log/audit.evtx")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	fi := r.FileInfo()
	fmt.Printf("format %d.%d, %d chunks, dirty=%t full=%t\n",
		fi.Major, fi.Minor, fi.Chunks, fi.Dirty, fi.Full)

	for {
		ev, err := r.ReadEvent()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		if err != nil {
			log.Printf("skipping record: %v", err)
			continue
		}
		fmt.Println(ev.System.EventID, ev.System.Provider.Name)
		for _, d := range ev.EventData {
			fmt.Printf("  %s = %s\n", d.Name, d.Value)
		}
	}
}
```

`ReadEvent` returns `evtx.ErrNoMoreRecords` once every record has been
read — that is the loop's normal exit, not a failure. Other errors come in
two kinds, and they leave the reader in different places.

A **decode** failure — the record header parsed, its BinXML payload did not
— is attached to the single record it came from; the reader stays positioned
on the next record, so a `log.Printf` and `continue` (as above) walks past a
record the decoder cannot handle and still reads every remaining one.

A **framing** failure — a bad record signature, an impossible size, a record
running past the end of the records region — is reported once and the rest
of that chunk is abandoned, because the fields that say where the next
record begins are the ones that cannot be trusted. The loop resumes at the
next chunk. Records after the corrupt point in that chunk are not reported;
the same `continue` still terminates.

A third kind ends the loop rather than continuing it: an error matching
`errors.Is(err, evtx.ErrChunkUnreadable)` means a chunk could not be loaded
at all — a truncated file, a failing read, a chunk with no signature. The
stream ends there and every later call returns `ErrNoMoreRecords`, so a
`continue` loop still terminates, but it has *not* read the file to the end.
Check for it if the difference between "finished" and "stopped" matters.

`FileInfo()` reads the file header directly — no decode pass is required to
see the format version, chunk count, or the dirty/full flags.

## 3. Write records

```go
package main

import (
	"log"
	"time"

	evtx "github.com/fjacquet/go-evtx"
)

func main() {
	w, err := evtx.New("/var/log/audit.evtx", evtx.RotationConfig{FlushIntervalSec: 30})
	if err != nil {
		log.Fatal(err)
	}
	defer w.Close()

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "myhost",
		"Channel":      "Security",
		"TimeCreated":  time.Now().Format(time.RFC3339Nano),
		"ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
		"ObjectName":   "/mnt/share/file.txt",
		"AccessMask":   "0x2",
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		log.Fatal(err)
	}
}
```

The reserved keys `WriteRecord` reads directly, outside the 12-field
`EventData` schema, are `ProviderName`, `Computer`, `Channel`, `TimeCreated`
(RFC3339Nano; defaults to `time.Now()` when absent) and `ProviderGuid`.

**`ProviderName` is mandatory.** An empty or missing value returns
`ErrMissingProviderName` and writes nothing — see
[§7](#7-errors-you-will-actually-meet) for why.

Since v0.7.4, `Level`, `Version`, `Task`, `Opcode` and `Keywords` are also
read from `fields`, each parsed as a fixed-width unsigned integer in decimal
or with an `0x` prefix (`Level` and `Version` and `Opcode` are `uint8`,
`Task` is `uint16`, `Keywords` is `uint64`), defaulting to `0` when the key is
absent. A value that does not fit its field's width returns
`ErrInvalidFieldValue` and writes nothing.

Use `WriteRaw` instead of `WriteRecord` when you already have a pre-encoded
BinXML payload — for example, one read back out with `ReadRaw` from another
file. Do not mix `WriteRecord` and `WriteRaw` calls within the same `Writer`
session.

### Writing a batch: `WriteRecords`

Since v0.11.0, `WriteRecords` takes a slice of events and writes them under a
single lock acquisition:

```go
recs := []evtx.RecordInput{
    {EventID: 4663, Fields: fields},
    {EventID: 4625, Fields: otherFields},
}
if err := w.WriteRecords(recs); err != nil {
    // e.g. "go_evtx: record 1: go_evtx: ProviderName must not be empty"
    log.Fatal(err)
}
```

`RecordInput` is exactly `WriteRecord`'s two arguments in a struct, and a nil
or empty slice is a no-op returning nil.

**All-or-nothing validation.** Every record in the slice is validated before
any record is encoded, so a batch containing one bad record writes *nothing*
and returns an error naming that record's index — `go_evtx: record 3: …`. The
checks are the same ones `WriteRecord` makes: a non-empty `ProviderName`, the
numeric `<System>` fields parsing, and a payload that fits in a chunk.

**The guarantee covers validation, not I/O.** A batch larger than one chunk
seals chunks as it goes, which is normal. If a *write* fails partway through,
the records already committed to earlier chunks stay written, and the error
says which record was reached. `WriteRecords` is not a transaction against the
disk.

**`WriteRecords` is not faster per record — it is measurably slower.** At a
batch size of 100 it runs roughly **1.4x slower per record** than 100
sequential `WriteRecord` calls (3934 vs 2770 ns/op under an identical sync
policy), because the validation pre-pass builds each record's substitution
values once to size them and the encode then builds them again. What
`WriteRecords` buys is the all-or-nothing guarantee and one lock acquisition
per batch. Choose it for the contract, not for throughput. See
[ADR-009](adr/ADR-009-batch-write-api.md) and
[`perf-baseline.md`](perf-baseline.md).

One deliberate divergence: `WriteRecords`'s size check is stricter than
`WriteRecord`'s. It validates against an analytic upper bound sized for the
worst case where the record's template must be inlined rather than referencing
one already in the chunk, which runs roughly 2 KB larger. A record whose
payload lands in approximately the top 2 KB of the 64 996-byte limit is
therefore accepted by `WriteRecord` and rejected by `WriteRecords`.

Like `WriteRecord`, `WriteRecords` must not be mixed with `WriteRaw` in the
same session.

## 4. Rotation

`New(path, cfg)` starts a background goroutine whenever any tick-driven field
of `RotationConfig` is set:

| Field | Meaning |
|-------|---------|
| `FlushIntervalSec` | 0 = disabled; commit the pending chunk every N seconds |
| `MaxFileSizeMB` | 0 = disabled; rotate when the file reaches N MiB (checked on write) |
| `MaxFileCount` | 0 = unlimited; keep only the N newest archives |
| `RotationIntervalH` | 0 = disabled; rotate every N hours |
| `SyncPolicy` | `SyncEveryChunk` (zero value) or `SyncOnTick`; see [§8](#8-choosing-a-syncpolicy) |
| `OnFsync func(time.Time)` | nil = none; called after each successful `f.Sync()` |

`RotationConfig` gained `SyncPolicy` in v0.11.0. Keyed struct literals — which
is how every example here and in the godoc writes it — are unaffected; an
unkeyed literal would not compile.

A rotation flushes any pending records, syncs and closes the active file,
commits it as an archive, then opens and syncs a fresh replacement at the
original path. Archive files are named:

```
base-2006-01-02T15-04-05.000000000.evtx
```

— a nanosecond-resolution UTC timestamp. `MaxFileCount`, when set, deletes
the oldest archives matching `base-*.evtx` after each rotation.

`OnFsync` fires after every successful sync — from `WriteRecord`'s chunk
flush, from rotation, from `Close`, and from the background flush tick, not
only when `FlushIntervalSec > 0` — and is invoked after the writer's internal
lock is released, so it may safely call most `Writer` methods.

**One exception: a callback must not call `Close`.** If `OnFsync` is invoked
from the background goroutine's own fsync and calls `Close`, it deadlocks —
`Close` waits for that same goroutine to exit, but the goroutine is blocked
inside the callback and can never reach its shutdown path.

## 5. The CLI

```
evtx dump [--in FILE] [--out FILE] [--shape=event|flat] [--allow-errors] [FILE]
evtx info [--in FILE] [FILE]
```

The input file may be given as `--in FILE` or as a bare positional argument,
not both.

### `evtx dump`

Writes one JSON object per record (NDJSON) to stdout, or to `--out` when
given. `--shape=event` (the default) mirrors `Event` faithfully, nested
`System`/`Provider` objects included. `--shape=flat` projects each event onto
a single JSON level; an `EventData` key that collides with a reserved
top-level key (or repeats) is renamed to `data_<i>` or `data_<i>_<Name>`.

A record that fails to decode is reported on stderr, with its position, and
skipped — `dump` keeps going rather than stopping at the first bad record.

```bash
$ evtx dump --shape=flat security.evtx
{"AccessList":null,"AccessMask":"0x2","HandleId":null,"ObjectName":"/mnt/share/file.txt","ObjectServer":null,"ObjectType":null,"ProcessId":null,"ProcessName":null,"SubjectDomainName":null,"SubjectLogonId":null,"SubjectUserName":null,"SubjectUserSid":null,"channel":"Security","computer":"myhost","event_id":4663,"event_record_id":1,"level":0,"provider":"Microsoft-Windows-Security-Auditing","record_id":1,"time_created":"2026-08-10T09:00:00Z","timestamp":"2026-08-10T09:00:00Z"}
```

The same record with the default `event` shape, for comparison:

```bash
$ evtx dump security.evtx
{"record_id":1,"timestamp":"2026-08-10T09:00:00Z","system":{"provider":{"name":"Microsoft-Windows-Security-Auditing"},"event_id":4663,"level":0,"time_created":"2026-08-10T09:00:00Z","event_record_id":1,"channel":"Security","computer":"myhost"},"event_data":[{"name":"SubjectUserSid","value":null},{"name":"SubjectUserName","value":null},{"name":"SubjectDomainName","value":null},{"name":"SubjectLogonId","value":null},{"name":"ObjectServer","value":null},{"name":"ObjectType","value":null},{"name":"ObjectName","value":"/mnt/share/file.txt"},{"name":"HandleId","value":null},{"name":"AccessList","value":null},{"name":"AccessMask","value":"0x2"},{"name":"ProcessId","value":null},{"name":"ProcessName","value":null}],"binary":null}
```

### `evtx info`

Reports the file header and the result of a full decode pass, with failures
grouped by cause. The grouping is `info`'s alone: `dump` writes each error to
stderr as the library phrased it, one line per skipped record, while `info`
strips the position each error carries — its chunk, record and offset — so
that failures of the same kind are counted together instead of printed
separately. Numbers that are part of the cause rather than the position, such
as an unsupported type code, are kept, so two different causes never merge
into one line:

```bash
$ evtx info security.evtx
file       security.evtx
format     3.1
chunks     1
flags      dirty=false full=false
records    1
decode     1/1 records, 0 failures
```

On a file with records the decoder rejects, the failure causes are grouped
and counted rather than printed one line per record:

```
decode     1813/1818 records, 5 failures
             5  AnsiString is not supported: the format carries no codepage, so any decoding would be a guess
```

### Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `dump` | every record decoded | usage error, or the input could not be read | at least one record was skipped (suppress with `--allow-errors`) |
| `info` | always, unless the input can't be read | input could not be read | — |

"Could not be read" covers a file that fails part-way as well as one that
fails to open: if a chunk cannot be loaded, the file has not been read to the
end, and both commands say so and exit 1 rather than reporting a clean pass
over the records they did get. `--allow-errors` does not suppress this — it
means "some records were skipped is acceptable", never "the file was not
finished is acceptable". `dump` still writes the records it read before the
failure, and `info` still prints the header and the tally, followed by a
`read incomplete after N records` line.

Also rejected with exit 1: `--out` naming the input file. `os.Create`
truncates, so it would destroy the file being read. Both paths are compared
by identity, so a relative and an absolute spelling of one file are caught.

### A `jq` one-liner

Pull every distinct `EventID` out of an NDJSON dump:

```bash
$ evtx dump security.evtx | jq -s 'map(.system.event_id) | unique'
[
  4663
]
```

## 6. What this library cannot do

- **The writer emits one event shape.** One fixed template, the same twelve
  `<Data>` names every time, and no `UserData` or `Binary`. It cannot
  represent an arbitrary Windows event — only this one shape, which Windows
  does accept.
- **`AnsiString` values are not decoded.** The format stores them without a
  codepage, so decoding one would mean guessing at an encoding rather than
  reading it. Measured impact: 26 records across 4 of a 285-file, 333 100
  -record corpus.
- **The template hash-table bucket rule this library writes is unverified for
  format 3.2.** go-evtx always writes 3.1, and reading is unaffected — the
  reader resolves templates by offset, never by bucket.
- **`WriteRecord` and `WriteRaw` must not be mixed in one `Writer` session.**
  This is a caller contract; nothing at runtime enforces it.
- **The reader validates structure, not checksums.** It checks the file magic,
  the chunk magic, record signatures and record sizes, and it stops there —
  the CRC32s the writer computes (the file header's own CRC, each chunk
  header's CRC, and one CRC over a chunk's whole records region — there is no
  per-record CRC) are never recomputed on the way back in. A payload whose
  bits have been flipped but which still parses is returned as if it were
  valid, with no complaint. Do not read §7's "checksum-invisible" as implying
  that checksums are otherwise verified: on the read path none of them are.

## 7. Errors you will actually meet

**`ErrMissingProviderName`** — `WriteRecord` rejects an empty or absent
`ProviderName` before writing anything. A NULL substitution — the encoding an
absent field gets — omits its element entirely, so a missing provider name
produces `<Provider></Provider>`, and `Get-WinEvent`'s formatter throws
dereferencing a provider that has no name. The file is otherwise valid:
`EventLogReader` reads every record and `wevtutil` exits 0, which is what
makes this failure mode hard to trace back to its cause without the check.
Better to fail at the call site than ship a file with this specific,
hard-to-diagnose defect.

**`ErrRecordTooLarge`** — a single record's BinXML payload exceeds the
64 996-byte capacity of one chunk (`maxChunkPayload` less the record header
and its trailing size copy). The record is rejected and nothing is written.
Records are never truncated to fit: truncation would be checksum-invisible,
since the CRC would be computed over the corrupt bytes and would verify
regardless.

**The sticky error** — once durability can no longer be guaranteed (a
rotation that failed after closing the active file, or a background flush
that failed), the `Writer`'s internal error is set permanently, and every
subsequent call — `WriteRecord`, `WriteRaw`, `Rotate`, `Close` — returns it.
There is no automatic recovery. A half-rotated directory needs an operator to
inspect it and a new `Writer` to resume writing.

Under `SyncOnTick` ([§8](#8-choosing-a-syncpolicy)) this error arrives later
than you might expect. A chunk's fsync happens on the background tick, so a
failing sync has no caller to be returned to and sets the sticky error there —
the write that lost the data succeeded, and a later, unrelated call fails.
That has always been true of the background flush; `SyncOnTick` makes it the
normal path for chunk durability rather than an edge case.

## Choosing FlushIntervalSec

`FlushIntervalSec` sets how long a record can sit in memory before it is
guaranteed to be on disk. It is a durability window, and since v0.10.0 it is
no longer also a write-amplification setting to the degree it once was.

Before v0.10.0 each tick rewrote the whole 64 KiB chunk and fsynced, whether
or not anything had arrived. At true idle that was 86 400 fsyncs a day —
each one a wakeup, a syscall, and a device cache-flush barrier — to persist
nothing at all: pure waste. At `FlushIntervalSec: 1` and 10 events/sec it was
also doing more work than it needed to, if less dramatically: roughly 5.5 GB
written and 86 400 fsyncs a day to persist about 674 MB of events, an
amplification of roughly 8.4x — not a disk-wear problem on any reasonable
SSD, just redundant work.

Since v0.10.0 a tick with no new records does nothing at all — no write, no
fsync — which is where the largest win lands: a workload with gaps between
arrivals turns what would have been up to 86 400 fsyncs/day into zero on every
tick where nothing arrived. A tick with new records still builds and patches
a full chunk buffer internally (`fillHashTables` back-patches offsets inside
the records region, so a smaller buffer cannot be used safely — see
[ADR-007](adr/ADR-007-incremental-tick-flush.md)), but writes only the used
prefix to disk — the records region plus the 512-byte header, skipping the
unwritten tail. That is a real reduction versus the flat 65536 bytes every
tick used to write, but it is roughly half on average across a chunk's fill,
not close to the size of what arrived — see the "Derived figures" section of
[`perf-baseline.md`](perf-baseline.md) for the honest, labeled-as-arithmetic
estimate.

```go
w, err := evtx.New("/var/log/audit.evtx", evtx.RotationConfig{
    FlushIntervalSec: 1, // at most one second of events lost on a crash
})
```

`FlushIntervalSec: 0` disables the background goroutine entirely. Records then
reach disk only when a chunk fills (roughly every 64 KiB), on `Rotate()`, or
on `Close()`.

Measured figures are in [`perf-baseline.md`](perf-baseline.md); the reasoning is
in [ADR-007](adr/ADR-007-incremental-tick-flush.md).

## 8. Choosing a `SyncPolicy`

`SyncPolicy` decides when the writer calls `f.Sync()`. It is new in v0.11.0
and its zero value is the behaviour go-evtx has always had, so doing nothing
keeps today's semantics exactly.

| Policy | When it fsyncs | Crash-loss window |
|---|---|---|
| `SyncEveryChunk` (zero value, default) | every sealed 64 KiB chunk, before committing it | at most one chunk — roughly 81 records |
| `SyncOnTick` | on the flush tick, on `Rotate()`, and on `Close()` | up to `FlushIntervalSec` seconds of arrivals |

```go
w, err := evtx.New("/var/log/audit.evtx", evtx.RotationConfig{
    SyncPolicy:       evtx.SyncOnTick,
    FlushIntervalSec: 1, // required: SyncOnTick without a tick is rejected by New
})
```

**`SyncOnTick` requires `FlushIntervalSec > 0`.** `New` returns an error
otherwise, rather than picking a default: with no tick the only remaining sync
points are `Rotate()` and `Close()`, which a long-running daemon may not reach
for hours, and the loss window would be unbounded rather than merely large.

**What it buys.** Measured on `darwin/arm64 M1 Pro, APFS, go1.27.0`:
2770 ns/op under `SyncOnTick` against 77 373 ns/op under `SyncEveryChunk` —
**about 27.9x** — with 1 total fsync across the benchmark run instead of one
per ~81 records. The ratio is darwin-specific (`f.Sync()` there is
`F_FULLFSYNC`, roughly an order of magnitude more expensive than a Linux
`fsync`), and the measurement machine was loaded; see
[`perf-baseline.md`](perf-baseline.md) for the methodology note.

**What it costs.** Three things, and all three matter:

1. **The loss window widens to `FlushIntervalSec`.** It is now a *time*, not a
   record count: at 10 events/sec and `FlushIntervalSec: 1` that is about 10
   records, but at 10 000 events/sec it is 10 000.
2. **A `Sync` failure surfaces at tick time**, on the background goroutine,
   which has no caller to return it to — so it sets the sticky error, and the
   *next* `WriteRecord`, `WriteRaw` or `Rotate` from any goroutine gets it
   back. The call that actually lost the data succeeded. `OnFsync`
   correspondingly fires less often and its timestamps are no longer
   per-chunk.
3. **A power loss can leave a file a parser rejects, not merely a short one.**
   Under `SyncOnTick` the chunk bytes and the file header that advertises them
   are both written with no sync in between and none after, so writeback may
   commit them in either order. A torn power-loss image can show a header
   claiming a chunk whose bytes never landed. A process crash is fine under
   both policies — the page cache still holds both writes.

Keep `SyncEveryChunk` for anything that is evidence. Choose `SyncOnTick` when
the writer is on the hot path of a high-rate collector, the events are
reproducible or replayable upstream, and you have set `FlushIntervalSec` to a
window you are willing to lose. The reasoning is in
[ADR-008](adr/ADR-008-sync-policy-group-commit.md).

## 9. Memory per `Writer`

v0.11.0's allocation work moved per-call scratch onto the `Writer`, which cut
`BenchmarkWriteRecord` from **60 to 5 allocs/op** (`B/op` from 6822 to 5033) on
`darwin/arm64 M1 Pro, APFS, go1.27.0` — the v0.10.0 row at commit `d8a85e4`
against the v0.11.0 row, both in
[`docs/perf-baseline.md`](perf-baseline.md). The buffers are retained for the
`Writer`'s lifetime:

- **64 KiB** for the chunk assembly buffer, allocated on the first flush.
- A BinXML encode buffer grown to the **largest record encoded so far** and
  never shrunk — typically a few KiB, bounded above by the 64 996-byte maximum
  record payload.

So budget roughly **64 KiB per `Writer`** in steady state, rising toward
**128 KiB** for a writer that has encoded a near-chunk-sized record. This was
previously near zero between calls, so a process holding many concurrent
`Writer`s — one per channel, one per tenant — should size for it.
