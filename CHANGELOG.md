# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Reader` struct with `Open(path)`, `ReadRecord()`, `ReadRaw()`, `Close()`, and `ErrNoMoreRecords` — symmetric read API for `.evtx` files
- `fromFILETIME` — converts Windows FILETIME to `time.Time`
- `docs/PRD.md` — Product Requirements Document with functional requirements, limitations, and roadmap
- GitHub Actions `release.yml` — GoReleaser-based release workflow triggered on `v*` tags
- GitHub Actions `pages.yml` — Builds and deploys landing page + API docs to GitHub Pages on every push to `main`
- `.goreleaser.yaml` — GoReleaser v2 configuration (library mode: source archives + auto-changelog)
- Simplified README with CI / Go Reference / Go Report Card / License badges

## [0.1.0] - 2026-03-04

### Added

- `Writer` struct with `New(path string) (*Writer, error)` constructor
- `WriteRecord(eventID int, fields map[string]string) error` — high-level API; handles BinXML encoding, record wrapping, and timestamp parsing internally
- `WriteRaw(chunk []byte) error` — low-level API; accepts a pre-encoded BinXML payload; go-evtx wraps it with record header and monotonic record ID
- `Close() error` — flushes all buffered records to disk as a valid `.evtx` file (write-on-close model)
- Reserved field keys for `WriteRecord`: `ProviderName`, `Computer`, `TimeCreated` (RFC3339Nano), plus 12 Windows audit data fields (`SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `ObjectServer`, `ObjectType`, `ObjectName`, `HandleId`, `AccessList`, `AccessMask`, `ProcessId`, `ProcessName`)
- BinXML template-based encoding with static NameNode string table (template reuse per chunk)
- EVTX file header and chunk header generation with correct CRC32 patching
- FILETIME conversion from `time.Time`
- UTF-16LE encoding for string values
- 12 unit and integration tests; zero external dependencies (stdlib only)
- MIT license
- GitHub Actions CI: `go test ./...` + `go vet` + `golangci-lint` on push/PR

[Unreleased]: https://github.com/fjacquet/go-evtx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fjacquet/go-evtx/releases/tag/v0.1.0
