# go-evtx

Pure Go library for reading and writing Windows Event Log (`.evtx`) files.

No Windows. No CGO. No external dependencies.

## Install

```bash
go get github.com/fjacquet/go-evtx@latest
```

## Links

- [API Reference](https://pkg.go.dev/github.com/fjacquet/go-evtx)
- [GitHub](https://github.com/fjacquet/go-evtx)
- [Product Requirements (PRD)](PRD.md)
- [User Guide](user-guide.md) — install, read/write examples, rotation, the
  CLI, and the errors you will actually meet

## Architecture Decisions

- [ADR-001 — Pure Go / stdlib only](adr/ADR-001-pure-go-stdlib-only.md)
- [ADR-002 — Layered API (WriteRaw / WriteRecord)](adr/ADR-002-layered-api-writeraw-writerecord.md)
- [ADR-003 — Write-on-close model](adr/ADR-003-write-on-close-model.md)
- [ADR-004 — Open-handle incremental flush](adr/ADR-004-open-handle-incremental-flush.md)
- [ADR-005 — Ship CLI binaries](adr/ADR-005-ship-cli-binaries.md)
- [ADR-006 — Derive format rules from a corpus, not from one sample](adr/ADR-006-corpus-derived-format-method.md)
