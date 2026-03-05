# go-evtx

[![CI](https://github.com/fjacquet/go-evtx/actions/workflows/ci.yml/badge.svg)](https://github.com/fjacquet/go-evtx/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/fjacquet/go-evtx.svg)](https://pkg.go.dev/github.com/fjacquet/go-evtx)
[![Go Report Card](https://goreportcard.com/badge/github.com/fjacquet/go-evtx)](https://goreportcard.com/report/github.com/fjacquet/go-evtx)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A pure Go library for reading and writing Windows Event Log (`.evtx`) binary files — no Windows, no CGO, no external dependencies.

Generated files are parseable by [python-evtx](https://github.com/williballenthin/python-evtx), Velociraptor, and Windows Event Viewer.

> Full requirements and roadmap: [docs/PRD.md](docs/PRD.md)

## Install

```bash
go get github.com/fjacquet/go-evtx@latest
```

## Write events

```go
w, err := evtx.New("/var/log/audit.evtx")
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

## Read events

```go
r, err := evtx.Open("/var/log/audit.evtx")
if err != nil {
    log.Fatal(err)
}
defer r.Close()

for {
    rec, err := r.ReadRecord()
    if errors.Is(err, evtx.ErrNoMoreRecords) {
        break
    }
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(rec.EventID, rec.Provider, rec.Fields["ObjectName"])
}
```

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

- **Single-chunk write model**: max ~2,400 events per session; all buffered records are lost on crash. Multi-chunk support is planned for v0.2.0.
- `WriteRecord` and `WriteRaw` must not be mixed in the same session.

## License

MIT — see [LICENSE](LICENSE).
