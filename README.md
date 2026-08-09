# go-evtx

[![CI](https://github.com/fjacquet/go-evtx/actions/workflows/ci.yml/badge.svg)](https://github.com/fjacquet/go-evtx/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/fjacquet/go-evtx.svg)](https://pkg.go.dev/github.com/fjacquet/go-evtx)
[![Go Report Card](https://goreportcard.com/badge/github.com/fjacquet/go-evtx)](https://goreportcard.com/report/github.com/fjacquet/go-evtx)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/fjacquet/go-evtx?sort=semver)](https://github.com/fjacquet/go-evtx/releases/latest)
[![License](https://img.shields.io/github/license/fjacquet/go-evtx)](https://github.com/fjacquet/go-evtx/blob/HEAD/LICENSE)

A pure Go library for reading and writing Windows Event Log (`.evtx`) binary files — no Windows, no CGO, no external dependencies.

**Files this library writes are read by Windows itself.** Every CI run
generates a 403-record file and hands it to a Windows runner, which opens it
with `EventLogReader`, reads every record, renders each one through
`EventLogRecord.ToXml()`, and enumerates the log with `Get-WinEvent` in both
orderings. The same file is parsed by
[python-evtx](https://github.com/williballenthin/python-evtx) 0.8.1 on a Linux
runner. All of it is a merge gate — see
[`docs/format-baseline.md`](docs/format-baseline.md) for the measurement
record, which includes the seventeen tasks where this did *not* work.

**Files Windows writes are read by this library.** The decoder is generic and
strict: it reads 320 382 of 320 398 records across a 281-file corpus of real
logs in both format versions (3.1 and 3.2). The 16 it refuses carry
`AnsiString`, which the format stores without a codepage — decoding it would
mean guessing.

Velociraptor compatibility is untested — do not rely on it.

> Full requirements and roadmap: [docs/PRD.md](docs/PRD.md)

## Format references

- **[MS-EVEN6]**, Microsoft's EventLog Remoting Protocol v6.0 —
  <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/> —
  the *normative* BinXml specification; read this when a byte-level format
  question needs an authoritative answer.
- **libyal / libevtx** format documentation —
  <https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc> —
  the most detailed reverse-engineered EVTX reference available, including a
  complete value-type table; read this for structural detail MS-EVEN6 leaves
  implicit.

See [docs/evtx-format-notes.md](docs/evtx-format-notes.md) for what this
project has verified about the format so far, source by source and measured
claim by claim.

## Install

```bash
go get github.com/fjacquet/go-evtx@latest
```

## Write events

```go
w, err := evtx.New("/var/log/audit.evtx", evtx.RotationConfig{FlushIntervalSec: 30})
if err != nil {
    log.Fatal(err)
}
defer w.Close()

w.WriteRecord(4663, map[string]string{
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Computer":     "myhost",
    "TimeCreated":  time.Now().Format(time.RFC3339Nano),
    "ObjectName":   "/mnt/share/file.txt",
    "AccessMask":   "0x2",
})
```

Use `WriteRaw` when you have a pre-encoded BinXML payload (e.g. forwarded from another source). Do not mix `WriteRecord` and `WriteRaw` in the same session.

### Errors

| Error | Cause |
|---|---|
| `ErrRecordTooLarge` | A single record's BinXML payload exceeds 64,996 bytes — the chunk payload capacity less the record header and trailing size. The record is rejected and nothing is written. |
| `ErrClosed` | `WriteRecord`, `WriteRaw` or `Rotate` was called after `Close`. |

A rotation that fails after closing the active file, or a background flush
that fails, records a permanent error. Every subsequent call returns it — the
writer never silently accepts events it cannot persist. Recovery requires
operator intervention and a new `Writer`.

## Read events

```go
r, err := evtx.Open("/var/log/audit.evtx")
if err != nil {
    log.Fatal(err)
}
defer r.Close()

for {
    ev, err := r.ReadEvent()
    if errors.Is(err, evtx.ErrNoMoreRecords) {
        break
    }
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(ev.System.EventID, ev.System.Provider.Name, ev.System.Computer)
    for _, d := range ev.EventData {
        fmt.Printf("  %s = %s\n", d.Name, d.Value)
    }
}
```

`Event` carries a typed `System` block — provider, event ID, level, keywords,
channel, computer, process and thread — plus `EventData` as an ordered slice of
named values, and `UserData` for events that use it instead.

Every value keeps the type the file declared it with, rather than being
flattened to a string. That matters for JSON: `json.Marshal(ev)` renders a
`FileTime` as an RFC3339 timestamp, a `HexInt64` as `0x…`, a SID and a GUID in
their canonical text forms, `Binary` as base64, and a `uint64` too large for a
double as a quoted string rather than silently losing precision.

Use `ReadRaw` to retrieve the raw BinXML payload, which can be passed directly to `WriteRaw` to copy records between files.

## Field reference

**System fields** (reserved keys for `WriteRecord`):

| Key | Description |
|-----|-------------|
| `ProviderName` | Event provider name |
| `Computer` | Computer name |
| `TimeCreated` | Timestamp in RFC3339Nano format (defaults to `time.Now()`) |

**EventData fields** (12, written in this order):

`SubjectUserSid` · `SubjectUserName` · `SubjectDomainName` · `SubjectLogonId` · `ObjectServer` · `ObjectType` · `ObjectName` · `HandleId` · `AccessList` · `AccessMask` · `ProcessId` · `ProcessName`

Missing keys default to `""`.

## Common Event IDs

| ID | Description |
|----|-------------|
| 4663 | Object access attempt |
| 4660 | Object deleted |
| 4670 | Object permissions changed |

## Limitations

Reading is general; writing is not. The asymmetry is deliberate and worth
knowing before you choose this library.

**Writing**

- `WriteRecord` emits one fixed template: a `<System>` block plus a 12-field
  `EventData` schema. Arbitrary Windows event schemas are not supported. Use
  `WriteRaw` to copy records verbatim from an existing file.
- `WriteRecord` and `WriteRaw` must not be mixed in the same session.
- Each record re-declares its template inline. Real Windows writes the
  definition once per chunk and points later records at it, so a go-evtx file
  is larger than it needs to be. Tracked for v0.7.1.
- Records are not 8-byte aligned and carry no fragment EOF token, where real
  Windows does both on every record measured. Windows reads our files anyway;
  this is a conformance gap, not a defect. Tracked for v0.7.1.

**Reading**

- `AnsiString` values are rejected rather than guessed at: the format carries
  no codepage. 16 records in a 320 398-record corpus.
- The template hash-table bucket rule this library writes is correct for
  format 3.1 and does not hold for 3.2 — the 3.2 rule is not known. Reading is
  unaffected; only files go-evtx *writes* use it.
- CI checks the hash-table rules against no real file, because the repository
  tracks none. See [`testdata/README.md`](testdata/README.md) for why that is
  the lesser evil, and how to run those tests locally.

## License

MIT — see [LICENSE](LICENSE).
