# go-evtx

A Go library for writing Windows Event Log (.evtx) binary files without Windows dependencies.

## Overview

`go-evtx` encodes events as template-based BinXML, the format used by the Windows Event Log subsystem. Generated files are parseable by forensics tools such as [python-evtx](https://github.com/williballenthin/python-evtx) and the Windows Event Viewer.

The library has **zero external dependencies** — it uses only the Go standard library.

## Install

```bash
go get github.com/fjacquet/go-evtx@v0.1.0
```

## Usage

### WriteRecord — high-level API

```go
package main

import (
    "log"
    "time"

    "github.com/fjacquet/go-evtx"
)

func main() {
    w, err := evtx.New("/var/log/audit.evtx")
    if err != nil {
        log.Fatal(err)
    }
    defer w.Close()

    fields := map[string]string{
        // System fields
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Computer":     "myhost.example.com",
        "TimeCreated":  time.Now().Format(time.RFC3339Nano),

        // Data fields
        "SubjectUserSid":    "S-1-5-21-1234567890-1234567890-1234567890-1001",
        "SubjectUserName":   "alice",
        "SubjectDomainName": "EXAMPLE",
        "SubjectLogonId":    "0x12345",
        "ObjectServer":      "Security",
        "ObjectType":        "File",
        "ObjectName":        "/mnt/share/document.docx",
        "HandleId":          "0x1a2b",
        "AccessList":        "%%4416",
        "AccessMask":        "0x2",
        "ProcessId":         "0x0",
        "ProcessName":       "",
    }

    if err := w.WriteRecord(4663, fields); err != nil {
        log.Fatal(err)
    }
}
```

### WriteRaw — pre-encoded BinXML payload

Use `WriteRaw` when you have a pre-encoded BinXML payload (e.g. forwarded from another source):

```go
// payload must be a valid BinXML fragment (without the event record header).
// go-evtx wraps it with the record header automatically.
if err := w.WriteRaw(payload); err != nil {
    log.Fatal(err)
}
```

**Note:** Do not mix `WriteRecord` and `WriteRaw` calls in the same Writer session. Use one or the other.

## Reserved Field Keys

| Key | Description | Type |
|-----|-------------|------|
| `ProviderName` | Event provider name | STRING |
| `Computer` | Computer name | STRING |
| `TimeCreated` | Timestamp (RFC3339Nano format) | FILETIME |

## Data Field Keys

The following 12 data fields are written to the `<EventData>` section in the order shown:

| Key | Description |
|-----|-------------|
| `SubjectUserSid` | Security identifier of the subject |
| `SubjectUserName` | Username of the subject |
| `SubjectDomainName` | Domain name of the subject |
| `SubjectLogonId` | Logon session identifier |
| `ObjectServer` | Server that owns the object |
| `ObjectType` | Type of the object (e.g. File) |
| `ObjectName` | Name/path of the object |
| `HandleId` | Handle identifier |
| `AccessList` | List of access rights |
| `AccessMask` | Hexadecimal access mask |
| `ProcessId` | Process identifier |
| `ProcessName` | Name of the process |

Missing keys default to empty string.

## Common Windows Event IDs

| EventID | Description |
|---------|-------------|
| 4663 | An attempt was made to access an object |
| 4660 | An object was deleted |
| 4670 | Permissions on an object were changed |

## Limitations

- Single-chunk model: the writer buffers all records in memory and writes them in a single 64 KB chunk on `Close()`. Events beyond ~2,400 per session are silently truncated (logged as a warning). Multi-chunk support is planned for a future release.
- `WriteRaw` and `WriteRecord` should not be mixed in the same session.

## License

MIT — see [LICENSE](LICENSE).
