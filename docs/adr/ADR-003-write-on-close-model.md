# ADR-003: Write-on-Close Model (v0.1.0)

**Date:** 2026-03-04
**Status:** Accepted — superseded in v0.2.0 by open-handle incremental flush (see future ADR-004)

## Context

`Writer` must produce a valid `.evtx` file that forensics tools (`python-evtx`, Velociraptor, Event Viewer) can parse. EVTX requires a file header and chunk header with correct CRC32 values that depend on the complete record payload. This creates a tension:

- Writing CRCs correctly requires knowing the full payload at write time
- Keeping a file handle open for incremental appends requires careful header-update bookkeeping

For v0.1.0, the priority is correctness over durability.

## Decision

`Writer` accumulates all records in memory (`w.records []byte`). On `Close()`, it assembles the complete chunk, patches the CRC, writes the file header, and calls `os.WriteFile` atomically. No file handle is held open between `New()` and `Close()`.

## Consequences

**Positive:**
- Simplest possible implementation; correctness is easy to reason about
- No open file handle means no cleanup on crash; no partial writes
- CRC is always computed over the complete, final payload

**Negative:**
- **All records are lost on process crash** — the entire session is in memory until `Close()`
- Memory grows unbounded for long-running sessions
- Periodic fsync is impossible without a persistent file handle

## Superseded by

ADR-004 (planned, v0.2.0): Open-handle incremental flush model — switches to a persistent `*os.File` with periodic `f.Sync()` calls and rotation support. The write-on-close model is replaced once the incremental flush path is validated with `python-evtx`.
