# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
go test ./... -count=1

# Run a single test
go test -run TestWriter_WriteRecord_ProducesValidFile ./...

# Vet
go vet ./...

# Lint (requires golangci-lint)
golangci-lint run
```

## Architecture

This is a single-package Go library (`package evtx`) with zero external dependencies. It reads and writes Windows Event Log `.evtx` binary files without any Windows dependencies.

**File layout:**

| File | Purpose |
|------|---------|
| `evtx.go` | Writer API: `Writer`, `New()`, `WriteRecord()`, `WriteRaw()`, `Close()` |
| `reader.go` | Reader API: `Reader`, `Record`, `Open()`, `ReadRecord()`, `ReadRaw()`, `Close()`, `ErrNoMoreRecords` |
| `binformat.go` | Binary format helpers: file/chunk headers, event record wrapper, CRC32, `toFILETIME`/`fromFILETIME`, UTF-16LE encoding |
| `binxml.go` | BinXML encoder: template body, substitution array, token writers |
| `binxml_reader.go` | BinXML decoder: `decodeBinXML()`, substitution array parser, UTF-16LE decoder |
| `evtx_test.go` | Writer integration tests |
| `reader_test.go` | Reader integration tests (round-trip, ErrNoMoreRecords, multi-record) |
| `binformat_test.go` | Unit tests for binary format helpers |

**Write data flow:**

1. `buildBinXML()` → constructs a BinXML fragment using a fixed template with 29 substitution slots (ProviderName, EventID, Level, SystemTime, Computer, 12×data name+value)
2. `wrapEventRecord()` → wraps BinXML payload in a 24-byte event record header (signature, size, recordID, FILETIME timestamp)
3. Records buffered in `Writer.records` (in-memory)
4. `Close()` → assembles file header (4096 bytes) + single chunk header (512 bytes) + all records → writes to disk

**Read data flow:**

1. `Open()` → validates file magic, reads chunk count, loads first chunk into memory buffer
2. `nextRecord()` → reads 24-byte event record header from buffer, slices BinXML payload, advances offset; on chunk exhaustion loads next chunk
3. `ReadRaw()` → returns raw BinXML bytes (compatible with `WriteRaw`)
4. `ReadRecord()` → calls `decodeBinXML()` → parses substitution array → maps indices to `Record` fields

**Key constraints:**

- Writer is single-chunk: all records buffered in memory, written as one 64 KB chunk on `Close()`. Records beyond ~60,000 bytes trigger a warning; content beyond 64 KB is truncated.
- `WriteRecord` and `WriteRaw` must not be mixed in the same session.
- `Writer` is concurrency-safe (mutex-guarded); `Reader` is not.
- File is only created if at least one record was written.
- Reader supports multi-chunk files (Windows-generated); decoder targets our own template format.

**BinXML substitution index map:**

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
