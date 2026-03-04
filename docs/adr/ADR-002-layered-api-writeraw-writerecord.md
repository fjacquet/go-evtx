# ADR-002: Layered API — WriteRaw + WriteRecord

**Date:** 2026-03-04
**Status:** Accepted

## Context

Consumers of `go-evtx` have different needs:
- High-level callers (like `cee-exporter`) have structured event data and want BinXML encoding handled automatically.
- Low-level callers (forensics tools, custom encoders) may produce their own BinXML payloads and only need record wrapping and file management.

A single API cannot serve both without either over-constraining the high-level caller or exposing too much internal detail.

## Decision

Expose two complementary methods on `Writer`:

1. **`WriteRecord(eventID int, fields map[string]string) error`** — High-level. Accepts structured fields, handles BinXML template encoding, CRC patching, and record wrapping internally. Reserved keys: `ProviderName`, `Computer`, `TimeCreated` (RFC3339Nano); 12 Windows audit data fields by name.

2. **`WriteRaw(chunk []byte) error`** — Low-level. Accepts a pre-encoded BinXML payload. `go-evtx` wraps it with a record header (signature, size, record ID, timestamp) so the caller does not need to manage record sequencing.

The two methods should not be mixed in a single writer session (record ID sequencing assumes a consistent encoding path).

## Consequences

**Positive:**
- `cee-exporter` uses `WriteRecord`; no BinXML knowledge required in the adapter
- Forensics tools and custom encoders can use `WriteRaw` with full control
- Record ID management stays inside the library regardless of which path is used
- Future: `WriteRaw` enables direct replay of captured BinXML from existing EVTX files

**Negative:**
- Two paths to maintain; tests must cover both
- WriteRaw/WriteRecord mutual exclusion is a caller contract, not enforced at runtime (v0.1.0)

## Alternatives Considered

- Single `Write([]byte)` accepting raw bytes — Too low-level; forces every caller to implement BinXML
- Single `WriteRecord(fields)` only — Insufficient for forensics/replay use cases
- Options struct pattern — Considered for future extensibility; deferred to v1.0
