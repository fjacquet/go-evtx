# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests (race detector is required — the writer is concurrent)
go test -race ./... -count=1

# Run a single test
go test -race -run TestWriter_WriteRecord_ProducesValidFile ./...

# Build, including the Windows path (evtx_windows.go is not built on darwin/linux)
go build ./...
GOOS=windows go build ./...

# Vet and coverage
go vet ./...
go test -race -cover ./...

# Lint (requires golangci-lint)
golangci-lint run
```

## Architecture

This is a single-package Go library (`package evtx`) with zero external dependencies. It reads and writes Windows Event Log `.evtx` binary files without any Windows dependencies.

**File layout:**

| File | Purpose |
|------|---------|
| `evtx.go` | Writer API: `Writer`, `New()`, `WriteRecord()`, `WriteRaw()`, `Rotate()`, `Close()`, `RotationConfig`, rotation and background-goroutine logic |
| `errors.go` | Sentinel errors (`ErrClosed`, `ErrRecordTooLarge`) and capacity limits (`maxChunkPayload`, `maxRecordPayload`) |
| `reader.go` | Reader API: `Reader`, `Record`, `Open()`, `ReadRecord()`, `ReadRaw()`, `Close()`, `ErrNoMoreRecords` |
| `binformat.go` | Binary format helpers: file/chunk headers, event record wrapper, CRC32, `toFILETIME`/`fromFILETIME`, UTF-16LE encoding |
| `binxml.go` | BinXML encoder: template body, substitution array, token writers |
| `binxml_reader.go` | BinXML decoder: `decodeBinXML()`, substitution array parser, UTF-16LE decoder |
| `evtx_unix.go` | `syncDir()` — fsyncs the containing directory so a rename is durable (`//go:build !windows`) |
| `evtx_windows.go` | `syncDir()` no-op — NTFS makes the directory entry durable on `MoveFileEx` (`//go:build windows`) |

**Test files:**

| File | Covers |
|------|--------|
| `evtx_test.go` | Writer integration |
| `reader_test.go` | Reader integration (round-trip, `ErrNoMoreRecords`, multi-record) |
| `binformat_test.go` | Binary format helpers |
| `rotation_test.go` | Rotation happy path, `MaxFileSizeMB`, `MaxFileCount` |
| `rotate_failure_test.go` | Rotation failure poisons the writer; archive-name collisions |
| `goroutine_test.go` | Background flush/rotation ticks, `OnFsync` |
| `openhandle_test.go` | File-handle lifecycle across rotation |
| `state_test.go` | Writer lifecycle guards: double `Close`, write-after-`Close`, sticky-error precedence |
| `oversize_test.go` | Oversized records rejected, not truncated |
| `example_test.go` | Godoc examples |

**Write data flow:**

1. `buildBinXML()` → constructs a BinXML fragment using a fixed template with 29 substitution slots (ProviderName, EventID, Level, SystemTime, Computer, 12×data name+value)
2. `wrapEventRecord()` → wraps BinXML payload in a 24-byte event record header (signature, size, recordID, FILETIME timestamp)
3. Records appended to the `Writer.records` byte buffer (the pending chunk)
4. The buffer is committed as a chunk by `flushChunkLocked()` when it fills, by `tickFlushLocked()` on the background flush tick, by `rotate()`, and by `Close()`

**Read data flow:**

1. `Open()` → validates file magic, reads chunk count, loads first chunk into memory buffer
2. `nextRecord()` → reads 24-byte event record header from buffer, slices BinXML payload, advances offset; on chunk exhaustion loads next chunk
3. `ReadRaw()` → returns raw BinXML bytes (compatible with `WriteRaw`)
4. `ReadRecord()` → calls `decodeBinXML()` → parses substitution array → maps indices to `Record` fields

## Rotation

`New(path, RotationConfig)` starts a background goroutine when any tick-driven field is set. `RotationConfig`:

| Field | Meaning |
|-------|---------|
| `FlushIntervalSec` | 0 = disabled; commit the pending chunk every N seconds |
| `MaxFileSizeMB` | 0 = disabled; rotate when the file reaches N MiB (checked on write) |
| `MaxFileCount` | 0 = unlimited; keep only the N newest archives |
| `RotationIntervalH` | 0 = disabled; rotate every N hours |
| `OnFsync func(time.Time)` | nil = none; called after each successful `f.Sync()` |

`rotate()` is transactional: flush pending records → skip if nothing was ever written → `Sync` and close the active file → commit the archive with `os.Link` then unlink the active path (`os.Rename` would silently replace an existing archive; `Link` fails atomically instead, with a `Stat`+`Rename` fallback where hard links are unsupported) → open and `Sync` a replacement file → `syncDir()` → reset counters → enforce `MaxFileCount`.

Archive names are `base-2006-01-02T15-04-05.000000000.evtx` (nanosecond-resolution UTC timestamp — one-second resolution let a burst of rotations collide); `cleanOldFiles()` finds them with the glob `base + "-*" + ext`.

## Key constraints

- **Records larger than a chunk are rejected, never truncated.** `maxChunkPayload` = 65024 (`evtxChunkSize - evtxRecordsStart`); `maxRecordPayload` = 64996 (`maxChunkPayload - evtxRecordHeaderSize - 4`). `WriteRecord`/`WriteRaw` return an error wrapping `ErrRecordTooLarge` and write nothing. Truncating would be checksum-invisible: the CRCs are computed over the corrupt bytes and verify.
- **`WriteRecord` and `WriteRaw` must not be mixed in the same session.**
- **File is only created if at least one record was written** — an empty session removes the placeholder on `Close()`.
- Reader supports multi-chunk files (Windows-generated); the decoder targets our own template format.

## Concurrency and lifecycle

- `Writer` is concurrency-safe (mutex-guarded). Unexported helpers whose name ends `Locked` require the caller to hold `w.mu` and carry a `// CALLER MUST HOLD w.mu.` comment.
- **`rotate()` requires `w.mu` held by the caller and must never acquire it itself.** Every caller (`Rotate`, `WriteRecord`, `WriteRaw`, the background rotation tick) holds it.
- `Close()` is idempotent via `closeOnce sync.Once`; concurrent callers block until the first completes and all observe the same result.
- **Sticky error.** Once durability can no longer be guaranteed (a rotation that failed after closing the active file, or a failed background flush), `w.err` is set permanently and every entry point returns it. There is no automatic recovery — a half-rotated directory needs an operator and a new `Writer`.
- `checkStateLocked()` gates `WriteRecord`, `WriteRaw` and `Rotate`. Precedence is part of the API contract: the sticky error outranks `ErrClosed`, so a caller learns that data was lost rather than only that the writer shut down.
- `closeFileLocked()` closes `w.f` exactly once, guarded by `w.fileClosed`; `rotate()` maintains that flag across the close/reopen.
- **`OnFsync` fires on every sync** — from `WriteRecord`, `rotate`, `Close` and the background flush tick, not only when `FlushIntervalSec > 0`. It is invoked after `w.mu` is released, so a callback may safely call any `Writer` method; a callback that itself triggers a further flush recurses on its own call stack.
- **`Reader` is also concurrency-safe:** a mutex (`r.mu`) is held for the duration of every exported method. `Open` does not lock — it constructs the `Reader` before it can be shared with another goroutine. `nextRecord` and `loadChunk` are unexported helpers carrying `// CALLER MUST HOLD r.mu.`. `nextRecord` copies each payload out of the shared chunk buffer before returning it; that copy is what makes `ReadRaw`'s returned bytes safe to retain past the next call.

## BinXML substitution index map

| Index | Field | Type |
|-------|-------|------|
| 0 | ProviderName | STRING |
| 1 | EventID | UINT16 |
| 2 | Level | UINT16 (always 0) |
| 3 | SystemTime | FILETIME |
| 4 | Computer | STRING |
| 5+2i | DataField[i] name | STRING |
| 6+2i | DataField[i] value | STRING |

The 12 data fields (indices 5–28) are hardcoded in `dataFieldNames` in `binxml.go`.
