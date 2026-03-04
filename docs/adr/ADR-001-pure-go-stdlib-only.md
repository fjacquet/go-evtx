# ADR-001: Pure Go, stdlib-only, CGO_ENABLED=0

**Date:** 2026-03-04
**Status:** Accepted

## Context

`go-evtx` is a library for generating Windows EVTX binary files from Go. It needs to run on Linux, macOS, and Windows without requiring a C compiler or external services. Callers (like `cee-exporter`) set `CGO_ENABLED=0` for static cross-compilation.

## Decision

`go-evtx` uses only Go standard library packages. No external dependencies are permitted in `go.mod`. CGO is not used anywhere in the codebase.

## Consequences

**Positive:**
- Zero dependency conflicts for callers
- Works in `CGO_ENABLED=0` build environments (static Linux ELF, cross-compile to Windows PE)
- No supply-chain risk from third-party packages
- `go get github.com/fjacquet/go-evtx` has no transitive downloads

**Negative:**
- BinXML encoding must be implemented from scratch (no libevtx bindings)
- CRC32 uses `hash/crc32` (acceptable — correct and fast)

## Alternatives Considered

- `golang.org/x/sys` — Not needed; all EVTX operations are pure byte manipulation
- CGO bindings to `libevtx` — Rejected: breaks static linking, requires host toolchain, complex cross-compilation
