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
| `reader_concurrency_test.go` | `Reader` is safe for concurrent use: parallel callers, `r.mu` held for each exported method |
| `flush_atomicity_test.go` | `flushChunkLocked` commits `chunkCount`/`currentSize`/`records`/`firstID` together or not at all |

**Write data flow:**

1. `buildBinXML()` → constructs a BinXML fragment using a fixed template with 42 substitution slots (ProviderName, EventID, Level, SystemTime, Computer, 12×data name+value, plus 13 more added in v0.7.0/Task 8b/8c to round `<System>` out to match a real Windows record — see the index map below)
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
- **Sticky error.** Once durability can no longer be guaranteed (a rotation that failed after closing the active file, or a failed background flush), `w.err` is set permanently and every entry point returns it. There is no automatic recovery — a half-rotated directory needs an operator and a new `Writer`. A transient I/O failure inside `flushChunkLocked` before that point (e.g. a `WriteAt` or `Sync` that fails while the file handle is still valid) is *not* sticky and is safe to retry — `rotate()`'s Step 1 comment calls this out explicitly. `chunkCapacityLocked`'s chunk-count ceiling (`w.chunkCount >= maxChunksPerFile`, `ErrTooManyChunks`) is sticky for a different reason than durability loss: at 65535 chunks (the top of `chunkCount`'s `uint16` range) no further chunk can ever be written to this file — continuing would wrap the counter and silently overwrite chunk 0 — so there is nothing to retry, and `w.err` is set the same way a durability failure would be.
- `checkStateLocked()` gates `WriteRecord`, `WriteRaw` and `Rotate`. Precedence is part of the API contract: the sticky error outranks `ErrClosed`, so a caller learns that data was lost rather than only that the writer shut down.
- `closeFileLocked()` closes `w.f` exactly once, guarded by `w.fileClosed`; `rotate()` maintains that flag across the close/reopen.
- **`OnFsync` fires on every sync** — from `WriteRecord`, `rotate`, `Close` and the background flush tick, not only when `FlushIntervalSec > 0`. It is invoked after `w.mu` is released, so a callback may safely call most `Writer` methods — except `Close`: a callback fired from the background goroutine's own fsync drain that calls `Close` deadlocks, because `Close` waits for that same goroutine to exit while it is blocked inside the callback. A callback that itself triggers a further flush recurses on its own call stack.
- **`Reader` is also concurrency-safe:** a mutex (`r.mu`) is held for the duration of every exported method. `Open` does not lock — it constructs the `Reader` before it can be shared with another goroutine. `nextRecord` and `loadChunk` are unexported helpers carrying `// CALLER MUST HOLD r.mu.`. `nextRecord` copies each payload out of the shared chunk buffer before returning it; that copy is what makes `ReadRaw`'s returned bytes safe to retain past the next call.

## BinXML substitution index map

| Index | Field | Type |
|-------|-------|------|
| 0 | ProviderName | STRING |
| 1 | EventID | UINT16 |
| 2 | Level | UINT8 (always 0) |
| 3 | SystemTime | FILETIME |
| 4 | Computer | STRING |
| 5+2i | DataField[i] name | STRING |
| 6+2i | DataField[i] value | STRING |
| 29 | Version | UINT8 (always 0, no caller-supplied source) |
| 30 | Task | UINT16 (always 0, no caller-supplied source) |
| 31 | Opcode | UINT8 (always 0, no caller-supplied source) |
| 32 | Keywords | HEXINT64 (always 0, no caller-supplied source) |
| 33 | EventRecordID | UINT64 (the writer's own record ID) |
| 34 | Correlation/@ActivityID | NULL, declared type GUID (no caller-supplied source) |
| 35 | Correlation/@RelatedActivityID | NULL, declared type GUID (no caller-supplied source) |
| 36 | Execution/@ProcessID | NULL, declared type UINT32 (no caller-supplied source) |
| 37 | Execution/@ThreadID | NULL, declared type UINT32 (no caller-supplied source) |
| 38 | Channel | STRING (from `fields["Channel"]`) |
| 39 | Security/@UserID | NULL, declared type SID (no caller-supplied source) |
| 40 | Provider/@Guid | STRING (from `fields["ProviderGuid"]`) |
| 41 | EventID/@Qualifiers | NULL, declared type UINT16 (no caller-supplied source) |

The 12 data fields (indices 5–28) are hardcoded in `dataFieldNames` in `binxml.go`; they kept their original indices and semantics across v0.7.0/Task 8b/8c — nothing calling `WriteRecord` needs to change.

Indices 29–41 (v0.7.0/Task 8b's F12b, Task 8c's F13b/F13c) exist purely so the encoded `<System>` block matches a real Windows record's 14 children instead of 5, and its `Provider`/`EventID` elements carry the same attributes the real file's do; `binxml_reader.go`'s `decodeBinXML` parses them like every other substitution but does not surface most of them on `Record` — they have no caller-supplied source (except `ProviderGuid`, which round-trips through `fields["ProviderGuid"]` the same way `ProviderName` does but likewise isn't surfaced on `Record`). `EventRecordID`'s value is already exposed as `Record.RecordID` from the event record header, not from BinXML.

The seven scalar children whose sole content is one substitution value (`Version`, `Task`, `Opcode`, `Keywords`, `EventRecordID` — F12b; `EventID`, `Level` — F13a) are encoded differently from a plain `NormalSubstitution` (token `0x0D`): per `testdata/system.evtx`, every element of this shape uses `OptionalSubstitution` (token `0x0E`) with the enclosing `OpenStartElementTag`'s `dependency_id` set to that same substitution index, so `writeOpenElement`/`writeOptionalSubstitution` are called with that real index rather than `depIDNotSet`. F12b left `EventID`/`Level` as `0x0D`/`dependency_id` `0xffff` as an explicit, permitted scope decision ("elements that are genuinely always present may legitimately stay `0x0D`" — go-evtx always supplies real data for both); Task 8c/F13a closes that out to match the real file exactly — `dependency_id` is the element's own **content** substitution index (`subEventID`/`subLevel`, i.e. 1 and 2), not the index of any attribute the element also carries (real Windows ties `EventID`'s `dependency_id` to its own content, `0x0003` in the real file's numbering, not `Qualifiers`' `0x0004`). `Correlation`, `Execution` and `Security` stay `0xffff` (element itself always present, matching the real file) with their individual attribute values NULL-typed via `OptionalSubstitution` — go-evtx has no source for `ActivityID`/`RelatedActivityID`/`ProcessID`/`ThreadID`/`UserID`, so it reproduces the real file's own encoding for an event that doesn't populate them, rather than inventing forensic data. `Channel` and `Computer` stay `NormalSubstitution`/`0xffff` like the other pre-existing fields, since go-evtx always has a (possibly empty) real value for both.

`Provider` (F13b) is the first element go-evtx emits with two attributes (`Name`, `Guid`), and the real file confirms the "more attributes follow" token (`0x46`) is required for every non-final attribute in a list, not just `0x06` for a lone one: `Name`'s own attribute token becomes `0x46`, `Guid`'s (the last) stays `0x06`. `Guid`'s value is a real substitution (`fields["ProviderGuid"]`, STRING-typed like `Name`), not a literal, even though the real file happens to encode `Provider`'s own `Name`/`Guid` as literal `ValueText` — a provider GUID varies per caller, the same reasoning that already made `Name` a substitution despite the real file's own literal encoding.

`EventID/@Qualifiers` (F13c) is go-evtx's first NULL-valued `OptionalSubstitution` whose declared type is not a generic "null type" marker: `testdata/system.evtx` encodes this exact attribute as `[size 0, type UNSIGNED_WORD (0x06)]` — its own real declared type — and MS-EVEN6's own worked example shows the same shape.

**F14 (v0.7.0, post-Task-8d): the note above was acted on.** F12b's five NULL fields at 34–37/39 all declared `binXMLTypeNull` (`0x00`) — a claim task-8b-report.md's own prose asserted was "reproducing exactly how the real file itself encodes these fields," directly contradicted by that same report's own Step 1 table two paragraphs above it, which shows `Correlation/@ActivityID`/`@RelatedActivityID` typed GUID (`0x0f`) and `Security/@UserID` typed SID (`0x13`), both at size 0 — never `0x00`. No real record sampled anywhere in this release ever emits `binXMLTypeNull`; it has been removed from the codebase. All five fields now declare their own real type at size 0 (`Execution/@ProcessID`/`@ThreadID` → UINT32, by extension from the one real sample found, which happens to populate both non-null) — the same convention `EventID/@Qualifiers` already used. This did not change any byte's *width* (every affected entry stays size 0); only the declared type byte moved, in both the substitution array's value-spec and the `OptionalSubstitution` token's own type byte in the template body.
