# ADR-004: Open-Handle Incremental Flush Model (v0.2.0)

**Date:** 2026-03-05
**Status:** Accepted — supersedes ADR-003

## Context

ADR-003 (write-on-close model) accumulated all records in memory and wrote the file atomically in `Close()`. This meant:
- All records were lost on process crash
- Memory grew unbounded for long-running sessions
- Periodic `f.Sync()` was impossible

v0.2.0 targets SIEM adapters and log forwarders that run continuously and require crash-resilient output.

## Decision

Replace the write-on-close model with an **open-handle incremental flush** model:

1. **`New()` opens the file immediately** and writes a 4096-byte placeholder file header (`ChunkCount=0`). The `*os.File` handle is held until `Close()`.

2. **`flushChunkLocked()`** seals the current in-progress chunk: pads it to 65536 bytes, patches both CRCs, writes it at the correct file offset via `WriteAt`, increments `chunkCount`, patches the file header at offset 0, and calls `f.Sync()`.

3. **`tickFlushLocked()`** performs a *flush-without-reset* on each background ticker interval: writes the current partial chunk bytes to the in-progress slot (same offset as the next `flushChunkLocked`) and patches the file header to reflect `chunkCount+1`, then calls `f.Sync()`. `w.records` and `w.firstID` are **not** reset — the in-progress chunk remains open for further writes. On the next tick, the same slot is overwritten with an updated snapshot.

4. **Background goroutine (`backgroundLoop`)** runs when `RotationConfig.FlushIntervalSec > 0`. It calls `tickFlushLocked()` under `w.mu` on every ticker interval. It exits when `w.done` is closed.

5. **`Close()`** closes `w.done`, waits for the goroutine via `sync.WaitGroup`, then calls `flushChunkLocked()` for any remaining records.

6. **Empty session** (no records written, no chunks committed): `Close()` removes the placeholder file and returns `nil`.

## Consequences

**Positive:**
- Records are visible on disk within `FlushIntervalSec` seconds, surviving process crashes
- `f.Sync()` guarantees durability at each flush point
- Multi-chunk files: supports more than ~2,400 events per session
- `RotationConfig{FlushIntervalSec: 0}` disables the goroutine; behaviour is identical to ADR-003 for callers that do not need durability

**Negative:**
- `New()` now creates a file immediately (even if no records are written); empty-session cleanup added to `Close()`
- `New()` signature is a breaking change: accepts `RotationConfig` as second parameter
- Two flush paths (`flushChunkLocked` / `tickFlushLocked`) must be kept in sync
- `tickFlushLocked` overwrites the same chunk slot repeatedly; a crash mid-tick may leave a partially written chunk visible to readers (acceptable: next tick or `Close()` will overwrite with a complete snapshot)

## Alternatives Considered

- **Append-only model (no `WriteAt`)** — simpler but requires readers to handle incomplete trailing chunks; incompatible with the EVTX file header CRC patch pattern.
- **Rotate to a new file per chunk** — avoids in-place header patching but breaks the single-file contract expected by callers.
- **`f.Sync()` only in `Close()`** — no crash resilience; equivalent to ADR-003 without the write-on-close simplicity.
