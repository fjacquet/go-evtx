# Product Requirements Document — go-evtx

**Status:** Active
**Version:** 0.1.0
**Last updated:** 2026-03-04

---

## 1. Purpose

`go-evtx` is a pure Go library for reading and writing Windows Event Log (`.evtx`) binary files without any Windows dependency, CGO, or third-party packages. It targets systems that produce structured audit events (SIEM adapters, log forwarders, forensics tools) and need interoperability with the Windows event log ecosystem.

---

## 2. Target Users

| User | Workflow |
|------|----------|
| **SIEM adapters** (e.g. `cee-exporter`) | Write structured audit events as `.evtx` for ingestion into Windows-native tooling |
| **Forensics engineers** | Read `.evtx` files from disk; replay or filter event records |
| **Log forwarders** | Forward BinXML payloads between systems using `ReadRaw` / `WriteRaw` |
| **Security researchers** | Generate synthetic EVTX fixtures for tooling tests |

---

## 3. Functional Requirements

### 3.1 Writer (v0.1.0 — delivered)

| ID | Requirement |
|----|-------------|
| W-01 | `New(path)` creates a `Writer`; parent directories are created automatically |
| W-02 | `WriteRecord(eventID, fields)` encodes structured fields as template-based BinXML |
| W-03 | `WriteRaw(payload)` accepts a pre-encoded BinXML payload and wraps it with a record header |
| W-04 | `Close()` assembles the EVTX file header + chunk header with correct CRC32 and writes to disk |
| W-05 | `Close()` with no writes produces no file and returns `nil` |
| W-06 | All `Writer` methods are safe for concurrent use |
| W-07 | Reserved field keys: `ProviderName`, `Computer`, `TimeCreated` (RFC3339Nano) |
| W-08 | 12 `EventData` fields supported: `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `ObjectServer`, `ObjectType`, `ObjectName`, `HandleId`, `AccessList`, `AccessMask`, `ProcessId`, `ProcessName` |

### 3.2 Reader (v0.1.0 — delivered)

| ID | Requirement |
|----|-------------|
| R-01 | `Open(path)` opens an `.evtx` file; validates file magic and chunk count |
| R-02 | `ReadRecord()` returns the next decoded event as a `Record` struct |
| R-03 | `ReadRaw()` returns the next raw BinXML payload (symmetric with `WriteRaw`) |
| R-04 | `ErrNoMoreRecords` is returned when all records have been read |
| R-05 | Reader supports multi-chunk files (Windows-generated) |
| R-06 | `Record` exposes: `RecordID`, `Timestamp`, `EventID`, `Level`, `Provider`, `Computer`, `TimeCreated`, `Fields` |

### 3.3 Planned — v0.2.0

| ID | Requirement |
|----|-------------|
| W-09 | Multi-chunk write model: persist an open file handle and flush records incrementally per chunk |
| W-10 | `f.Sync()` after each chunk flush for durability |
| W-11 | Configurable chunk size or automatic rotation |
| R-07 | Streaming read mode (iterator/channel) for large files |

---

## 4. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NF-01 | Zero external dependencies (`go.mod` references only stdlib) |
| NF-02 | `CGO_ENABLED=0` compatible; no C compiler required |
| NF-03 | Cross-platform: Linux, macOS, Windows (GOARCH amd64 and arm64) |
| NF-04 | Output files parseable by `python-evtx`, Windows Event Viewer, and Velociraptor |
| NF-05 | CI on every push/PR: `go test ./...`, `go vet`, `golangci-lint` |

---

## 5. Known Limitations (v0.1.0)

| Limitation | Impact | Planned fix |
|------------|--------|-------------|
| Single-chunk write model | Max ~2,400 events per session; all records lost on crash | v0.2.0 (ADR-004) |
| `WriteRecord`/`WriteRaw` must not be mixed in one session | Caller contract only; not enforced at runtime | v0.2.0 |
| Fixed 12-field `EventData` schema | Cannot represent arbitrary Windows event schemas | Post-v0.2.0 |
| BinXML decoder targets our own template format | May misparse complex Windows-native templates | Post-v0.2.0 |

---

## 6. Architecture Decisions

See [`docs/adr/`](adr/) for the full decision log:

- [ADR-001](adr/ADR-001-pure-go-stdlib-only.md) — Pure Go, stdlib-only, CGO_ENABLED=0
- [ADR-002](adr/ADR-002-layered-api-writeraw-writerecord.md) — Layered API: WriteRaw + WriteRecord
- [ADR-003](adr/ADR-003-write-on-close-model.md) — Write-on-Close model (superseded in v0.2.0)
