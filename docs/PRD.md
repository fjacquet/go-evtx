# Product Requirements Document — go-evtx

**Status:** Active
**Version:** 0.8.0
**Last updated:** 2026-08-10

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
| **Operators / analysts** | Inspect and export `.evtx` files from a shell, without writing Go, via the `evtx` CLI |

---

## 3. Functional Requirements

### 3.1 Delivered

**Writer**

| ID | Requirement |
|----|-------------|
| W-01 | `New(path, RotationConfig)` creates a `Writer`; parent directories are created automatically; the file is only created once at least one record is written |
| W-02 | `WriteRecord(eventID, fields)` encodes structured fields as template-based BinXML |
| W-03 | `WriteRaw(payload)` accepts a pre-encoded BinXML payload and wraps it with a record header |
| W-04 | `Close()` flushes any pending chunk, patches CRC32s, and closes the file handle; idempotent via `sync.Once` |
| W-05 | `Close()` with no writes removes the placeholder file and returns `nil` |
| W-06 | All `Writer` methods are safe for concurrent use (mutex-guarded) |
| W-07 | Reserved field keys: `ProviderName` (mandatory — see `ErrMissingProviderName`), `Computer`, `Channel`, `TimeCreated` (RFC3339Nano), `ProviderGuid` |
| W-08 | 12 `EventData` fields supported: `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `ObjectServer`, `ObjectType`, `ObjectName`, `HandleId`, `AccessList`, `AccessMask`, `ProcessId`, `ProcessName` |
| W-09 | Open-handle incremental flush: the file handle is held from `New()` to `Close()`; records are flushed per chunk, not accumulated for a single write-on-close |
| W-10 | `f.Sync()` after each chunk flush, each rotation, and each background tick, for durability |
| W-11 | `RotationConfig`: `FlushIntervalSec` (periodic checkpoint), `MaxFileSizeMB` (size-based rotation), `MaxFileCount` (archive retention), `RotationIntervalH` (time-based rotation), `OnFsync` (a callback fired after every successful sync) |
| W-12 | `WriteRecord`/`WriteRaw` mutual exclusion is a caller contract; not enforced at runtime |
| W-13 | `Level`, `Version`, `Task`, `Opcode` and `Keywords` are read from the `fields` map as fixed-width unsigned integers (decimal or `0x`-prefixed), defaulting to 0; a value that does not fit its field's width returns `ErrInvalidFieldValue` and writes nothing (v0.7.4, issue #13) |

**Reader**

| ID | Requirement |
|----|-------------|
| R-01 | `Open(path)` opens an `.evtx` file; validates file magic and chunk count |
| R-02 | `ReadEvent()` returns the next decoded event as an `Event` struct |
| R-03 | `ReadRaw()` returns the next raw BinXML payload (symmetric with `WriteRaw`) |
| R-04 | `ErrNoMoreRecords` is returned when all records have been read |
| R-05 | Reader supports multi-chunk files (Windows-generated), in both format versions 3.1 and 3.2 |
| R-06 | `Event` exposes: `RecordID`, `Timestamp`, `System` (typed `<System>` fields including `EventID`, `Provider`, `Level`, `Task`, `Opcode`, `Keywords`, `Computer`, `Channel`), `EventData` (ordered `Data` slice), `Binary`, `UserData` |
| R-07 | The BinXML decoder is generic, not tied to go-evtx's own template shape: it decodes records written by real Windows across a corpus of 285 files and 333 100 records |
| R-08 | `Reader.FileInfo()` returns the file header's `Major`/`Minor` format version, `Chunks` count, and the `Dirty`/`Full` flags |

**CLI (`cmd/evtx`)**

| ID | Requirement |
|----|-------------|
| C-01 | `evtx dump [--in FILE] [--out FILE] [--shape=event\|flat] [--allow-errors] [FILE]` writes one JSON object per record (NDJSON) to stdout or `--out` |
| C-02 | `dump --shape=flat` projects each event onto a single JSON level, renaming any `EventData` key that collides with a reserved `System` key |
| C-03 | `evtx info [--in FILE] [FILE]` reports the file header (format version, chunk count, dirty/full flags) and the result of a full decode pass, with failures grouped by cause |
| C-04 | Exit codes for `dump`: 0 — every record decoded; 2 — at least one record was skipped (unless `--allow-errors`); 1 — usage error or unreadable input |
| C-05 | Exit codes for `info`: 0 unless the input file itself cannot be opened, in which case 1 |

### 3.2 Planned

| ID | Requirement |
|----|-------------|
| R-09 | Streaming read mode (iterator/channel) for large files |
| W-14 | Configurable `EventData` schema beyond the fixed 12-field template |

---

## 4. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NF-01 | Zero external dependencies (`go.mod` references only stdlib) |
| NF-02 | `CGO_ENABLED=0` compatible; no C compiler required |
| NF-03 | Cross-platform: Linux, macOS, Windows (GOARCH amd64 and arm64) |
| NF-04 | Every CI run measures acceptance on Windows against `EventLogReader`, `EventLogRecord.ToXml()`, `Get-WinEvent` (both orderings), and `wevtutil`, plus parsing by `python-evtx` 0.8.1 on Linux — all merge gates |
| NF-05 | CI on every push/PR: `go test -race ./...`, `go vet`, `golangci-lint` |

---

## 5. Known Limitations

| Limitation | Impact | Status |
|---|---|---|
| The writer emits one event shape: one template, twelve fixed `<Data>` names, no `UserData`, no `Binary`, no typed values | Cannot represent an arbitrary Windows event. What it writes is accepted by Windows; what it can write is a fraction of what Windows writes | Largest open item; needs its own design |
| `AnsiString` (type 0x02) is not decoded | 26 records across 4 of 285 corpus files fail to decode | Deliberate: the format carries no codepage, so any decoding would be a guess |
| The 3.2 template bucket rule is unknown | None. go-evtx writes 3.1, and the reader resolves templates by offset, never by bucket | Documented gap |
| `WriteRecord` and `WriteRaw` must not be mixed in one session | Caller contract, not enforced at runtime | Open |
| The reader verifies no checksum: it validates magic, record signatures and sizes, never the chunk or record CRC32 the writer computes | A corrupted payload that still parses is returned as if valid, with no complaint. Structural corruption is caught; silent bit rot is not | Open; turning verification on is its own release |

---

## 6. Architecture Decisions

See [`docs/adr/`](adr/) for the full decision log:

- [ADR-001](adr/ADR-001-pure-go-stdlib-only.md) — Pure Go, stdlib-only, CGO_ENABLED=0
- [ADR-002](adr/ADR-002-layered-api-writeraw-writerecord.md) — Layered API: WriteRaw + WriteRecord
- [ADR-003](adr/ADR-003-write-on-close-model.md) — Write-on-Close model (superseded in v0.2.0)
- [ADR-004](adr/ADR-004-open-handle-incremental-flush.md) — Open-handle incremental flush model (v0.2.0)
- [ADR-005](adr/ADR-005-ship-cli-binaries.md) — Ship CLI binaries
- [ADR-006](adr/ADR-006-corpus-derived-format-method.md) — Derive format rules from a corpus, not from one sample
