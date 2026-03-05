# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-03-05

### Added

- `RotationConfig.MaxFileSizeMB` — size-based rotation: when the active file reaches N MiB, rotate() is triggered automatically after each `WriteRecord`/`WriteRaw` call
- `RotationConfig.MaxFileCount` — archive retention: after rotation, archives exceeding N are deleted oldest-first
- `RotationConfig.RotationIntervalH` — time-based rotation: `backgroundLoop` fires `rotate()` on a per-hour ticker when this field is > 0
- `Rotate()` public method — manually trigger rotation from any goroutine; safe for concurrent use
- `rotate()` private method — core rotation logic: flush pending chunk, fsync, close, rename to timestamped archive, open fresh file, reset state, call `cleanOldFiles()`
- `archivePathFor()` helper — derives archive name: `base-YYYY-MM-DDTHH-MM-SS.evtx` (UTC, hyphens instead of colons)
- `cleanOldFiles()` helper — glob `base-*.evtx`, sort by mtime, delete oldest beyond `MaxFileCount`
- `Writer.currentSize int64` — approximate file size tracked via `flushChunkLocked()` for size-based rotation
- `evtx_unix.go` (!windows) — `syncDir()` using `syscall.Open` + `syscall.Fsync` for directory durability after rename
- `evtx_windows.go` (windows) — `syncDir()` no-op (NTFS rename is durable without fsync)
- `rotation_test.go` — 6 TDD tests: `TestWriter_SizeRotation`, `TestWriter_CountRetention`, `TestWriter_TimeRotation`, `TestWriter_ManualRotate`, `TestWriter_RotatedFileValid`, `TestWriter_RotateRace`

### Changed

- `New()` goroutine start condition: `FlushIntervalSec > 0 || RotationIntervalH > 0` (was `FlushIntervalSec > 0` only)
- `backgroundLoop()` uses nil-channel idiom for optional rotation ticker: receive on nil channel never fires, so disabled tickers add zero overhead
- `flushChunkLocked()` now updates `w.currentSize += evtxChunkSize` after each committed chunk

## [0.3.0] - 2026-03-05

### Added

- Multi-chunk EVTX support — sessions exceeding ~2,400 events now write correctly (EVTX-01)
- `flushChunkLocked()` — writes complete 65,536-byte chunks incrementally via `f.WriteAt`; patches file header after each chunk; calls `f.Sync()`
- `tickFlushLocked()` — goroutine tick writes partial chunk to disk without advancing chunk count (Option A flush-without-reset)
- Open-handle model: `f *os.File` held open from `New()` through `Close()`, enabling incremental writes
- Pre-append capacity check in `WriteRecord()` and `WriteRaw()` — triggers `flushChunkLocked()` when buffer reaches 65,024 bytes
- `goroutine_test.go` — lifecycle and concurrency tests: flush ticker, graceful shutdown, goroutine leak detection, race-condition coverage
- `docs/adr/ADR-004` — Open-handle incremental flush model decision record

### Changed

- `WriteRecord()` and `WriteRaw()` now call `flushChunkLocked()` when buffer reaches 65,024 bytes (was warn-only in v0.2.x)
- `Close()` deletes placeholder file on empty session (zero-record backward compatibility)

### Removed

- `flushToFile()` — replaced by `flushChunkLocked()` and `tickFlushLocked()`

## [0.2.0] - 2026-03-05

### Added

- `RotationConfig` struct — configures periodic background flush via `FlushIntervalSec` (0 = disabled)
- `New()` now accepts `RotationConfig` as second argument (breaking change from v0.1.0)
- Background goroutine (`backgroundLoop`) — fires `tickFlushLocked()` on a configurable ticker interval
- `Reader` struct with `Open(path)`, `ReadRecord()`, `ReadRaw()`, `Close()`, and `ErrNoMoreRecords` — symmetric read API for `.evtx` files
- `fromFILETIME` — converts Windows FILETIME to `time.Time`
- `docs/PRD.md` — Product Requirements Document
- GitHub Actions `release.yml` — GoReleaser-based release workflow triggered on `v*` tags
- GitHub Actions `pages.yml` — Builds and deploys landing page + API docs to GitHub Pages on every push to `main`
- `.goreleaser.yaml` — GoReleaser v2 configuration (library mode: source archives + auto-changelog)
- Simplified README with CI / Go Reference / Go Report Card / License badges

### Changed

- `Close()` now signals the background goroutine via a `done` channel and waits for it with `sync.WaitGroup` before final flush

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

[Unreleased]: https://github.com/fjacquet/go-evtx/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/fjacquet/go-evtx/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/fjacquet/go-evtx/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/fjacquet/go-evtx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fjacquet/go-evtx/releases/tag/v0.1.0
