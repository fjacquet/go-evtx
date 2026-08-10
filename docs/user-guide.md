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
read — that is the loop's normal exit, not a failure. Any other error is
attached to the single record it came from; the reader stays positioned on
the next record, so a `log.Printf` and `continue` (as above) is enough to
walk past a record the decoder cannot handle rather than aborting the whole
file. `FileInfo()` reads the file header directly — no decode pass is
required to see the format version, chunk count, or the dirty/full flags.

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

## 4. Rotation

`New(path, cfg)` starts a background goroutine whenever any tick-driven field
of `RotationConfig` is set:

| Field | Meaning |
|-------|---------|
| `FlushIntervalSec` | 0 = disabled; commit the pending chunk every N seconds |
| `MaxFileSizeMB` | 0 = disabled; rotate when the file reaches N MiB (checked on write) |
| `MaxFileCount` | 0 = unlimited; keep only the N newest archives |
| `RotationIntervalH` | 0 = disabled; rotate every N hours |
| `OnFsync func(time.Time)` | nil = none; called after each successful `f.Sync()` |

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
grouped by cause (the same reduction `dump`'s stderr uses, but tallied):

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
| `dump` | every record decoded | usage error, or the input could not be opened | at least one record was skipped (suppress with `--allow-errors`) |
| `info` | always, unless the input can't be opened | input could not be opened | — |

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
  the CRC32s the writer computes over each chunk and each record are never
  recomputed on the way back in. A payload whose bits have been flipped but
  which still parses is returned as if it were valid, with no complaint. Do
  not read §7's "checksum-invisible" as implying that checksums are otherwise
  verified: on the read path none of them are.

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
