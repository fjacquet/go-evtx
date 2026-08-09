# Generic Strict EVTX Decoder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace go-evtx's template-specific decoder with a strict, generic BinXML decoder that reads any Windows-generated `.evtx` file, exposes typed values for JSON export, and fails loudly on anything it cannot fully account for.

**Architecture:** Four new files in the existing single `evtx` package, split by responsibility: `value.go` decodes typed substitution values, `template.go` parses and caches template definitions per chunk, `binxml_decode.go` walks the token stream into a `Node` tree, `event.go` assembles a typed `Event` from that tree. `reader.go` keeps its existing role — file, chunk and record framing — and gains `ReadEvent()`. The old `Record`/`ReadRecord`/`binxml_reader.go` are deleted outright.

**Tech Stack:** Go 1.26.5, standard library only. No external dependencies — this is a hard project constraint.

## Global Constraints

- **Zero external dependencies.** Standard library only. No exceptions.
- **Single package `evtx`.** New files, not new packages.
- **Race detector required on every test run:** `go test -race ./... -count=1`.
- **Strictness is the core property.** Unknown token, unknown value type, or a length exceeding the payload is an error. Never a partial `Event` with a flag.
- **A substitution of size 0 with a real declared type means "absent", not malformed.** `testdata/system.evtx` encodes `EventID/@Qualifiers` as `[size 0, type UNSIGNED_WORD (0x06)]`. Rejecting this would reject real files.
- **No partial output.** On error return `nil` and the error.
- **Errors carry position:** chunk index, record ID, byte offset within the payload, expected vs found. The error is the diagnostic.
- `testdata/system.evtx` is the only tracked fixture; md5 `182de19fe6a25b928a34ad59af0bbf1e`, format version 3.1. Never modify it.
- **Do not touch `cmd/gen-fixture/`.** It is frozen; a PreToolUse hook blocks edits.
- **Do not touch the writer** (`binxml.go`, `evtx.go`, `chunkhash.go`, `binformat.go`) except where a task explicitly says so.
- Format reference: `docs/evtx-format-notes.md`. Design: `docs/superpowers/specs/2026-08-09-generic-evtx-decoder-design.md`.

## Measured facts this plan relies on

From 284 635 real records across four files (zero unparsed):

| Type | Share | Type | Share |
|---|---|---|---|
| Null | 27.7 % | HexInt64 | 5.4 % |
| UInt8 | 16.1 % | **BinXml** | **5.4 %** |
| UInt16 | 12.5 % | FileTime | 5.4 % |
| UInt32 | 10.7 % | UInt64 | 5.4 % |
| String | 7.1 % | Guid | 4.4 % |
| | | Sid | 0.1 % |

`BinXml` occurs **exactly once per record** — recursion is the nominal case. `AnsiString` and every array variant occur **zero** times; they are rejected, not implemented.

## Binary layouts (measured, and matching the encoder validated against real files)

```
Record payload
  FragmentHeader     0f 01 01 00                                   4 B
  TemplateInstance   0c 01 <template_id u32> <def_offset u32>     10 B
    inline definition when def_offset == this position:
      TemplateDefinition <next u32> <guid 16B> <data_size u32>    24 B
      template body                                       data_size B
  SubstitutionArray  <count u32> <count × (size u16, type u8, pad u8)> <values...>

Element token 0x01 (no attrs) / 0x41 (attr list follows)
  token(1) dep_id(2) data_size(4) name_offset(4)                  11 B
  inline NameNode when name_offset == this position
  attr_list_size(4)  — only when token is 0x41
  ... attributes ... CloseStartElement(0x02) | CloseEmptyElement(0x03)
  ... content ... EndElement(0x04)

NameNode
  next_offset(4) name_hash(2) name_length(2) UTF-16 × name_length  null(2)

Attribute token 0x06 (last) / 0x46 (more follow)
  token(1) name_offset(4) inline NameNode, then one value token

Substitution  0x0D normal / 0x0E optional:  token(1) index(2) type(1)
ValueText     0x05:  token(1) type(1) length(2 in UTF-16 units) data
```

## File structure

| File | Responsibility |
|---|---|
| Create `value.go` | `ValueType`, `Value`, `decodeValue`, accessors, `MarshalJSON` |
| Create `template.go` | `templateDef`, definition parsing, per-chunk cache |
| Create `binxml_decode.go` | token constants, `Node`, `Attr`, substitution array, token walker |
| Create `event.go` | `Event`, `System`, `Data`, `Provider`, tree → `Event` |
| Modify `reader.go` | `ReadEvent()`; delete `Record`, `ReadRecord` |
| Delete `binxml_reader.go` | superseded entirely |
| Create `value_test.go`, `template_test.go`, `binxml_decode_test.go`, `event_test.go`, `corpus_test.go` | tests |
| Modify `example_test.go`, `rotation_test.go`, `reader_concurrency_test.go`, `reader_test.go` | drop `ReadRecord` |
| Modify `docs/PRD.md`, `CHANGELOG.md`, `.github/workflows/format-verify.yml` | docs and CI |

---

### Task 1: Value types and strict decoding

**Files:**
- Create: `value.go`
- Test: `value_test.go`

**Interfaces:**
- Consumes: `fromFILETIME(uint64) time.Time` from `binformat.go`.
- Produces: `ValueType` (uint8 constants `ValNull`…`ValEvtXML`), `Value` struct with exported field `Type ValueType`, `decodeValue(t ValueType, data []byte) (Value, error)`, accessors `Value.IsAbsent() bool`, `Value.String() string`, `Value.Uint64() (uint64, bool)`, `Value.Bytes() []byte`, `Value.Time() (time.Time, bool)`. `Value` also carries an unexported `node *Node` field, set in Task 5.

- [ ] **Step 1: Write the failing test**

Create `value_test.go`:

```go
package evtx

import (
	"testing"
	"time"
)

func TestDecodeValue_FixedWidths(t *testing.T) {
	tests := []struct {
		name string
		typ  ValueType
		data []byte
		want string
	}{
		{"uint8", ValUInt8, []byte{0x2a}, "42"},
		{"uint16", ValUInt16, []byte{0x34, 0x12}, "4660"},
		{"uint32", ValUInt32, []byte{0x78, 0x56, 0x34, 0x12}, "305419896"},
		{"int32 negative", ValInt32, []byte{0xff, 0xff, 0xff, 0xff}, "-1"},
		{"bool true", ValBool, []byte{0x01, 0, 0, 0}, "true"},
		{"hexint64", ValHexInt64, []byte{0x10, 0, 0, 0, 0, 0, 0, 0}, "0x0000000000000010"},
		{"string", ValString, []byte{'h', 0, 'i', 0}, "hi"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := decodeValue(tc.typ, tc.data)
			if err != nil {
				t.Fatalf("decodeValue: %v", err)
			}
			if got := v.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A declared type with zero-length data means the optional substitution is
// absent. testdata/system.evtx encodes EventID/@Qualifiers exactly this way:
// [size 0, type UNSIGNED_WORD]. Treating it as malformed would reject real files.
func TestDecodeValue_ZeroLengthIsAbsentNotError(t *testing.T) {
	v, err := decodeValue(ValUInt16, nil)
	if err != nil {
		t.Fatalf("zero-length UInt16 must decode as absent, got error: %v", err)
	}
	if !v.IsAbsent() {
		t.Error("IsAbsent() = false, want true")
	}
	if v.Type != ValUInt16 {
		t.Errorf("Type = %#x, want %#x — the declared type must survive", v.Type, ValUInt16)
	}
}

func TestDecodeValue_WrongWidthIsError(t *testing.T) {
	if _, err := decodeValue(ValUInt32, []byte{0x01, 0x02}); err == nil {
		t.Fatal("expected an error for a 2-byte UInt32")
	}
}

// Measured zero times across 284635 real records. Rejected rather than guessed.
func TestDecodeValue_UnsupportedTypesRejected(t *testing.T) {
	for _, typ := range []ValueType{ValAnsiString, 0x81, 0x8a, 0x7f} {
		if _, err := decodeValue(typ, []byte{0x00}); err == nil {
			t.Errorf("type %#x: expected an error, got none", typ)
		}
	}
}

func TestDecodeValue_Guid(t *testing.T) {
	data := []byte{
		0x2d, 0x6d, 0x5c, 0x6e, 0x1a, 0x2b, 0x3c, 0x4d,
		0x9a, 0xbc, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	}
	v, err := decodeValue(ValGuid, data)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	const want = "6e5c6d2d-2b1a-4d3c-9abc-010203040506"
	if v.String() != want {
		t.Errorf("String() = %q, want %q", v.String(), want)
	}
}

func TestDecodeValue_Sid(t *testing.T) {
	// S-1-5-18: revision 1, 1 sub-authority, authority 5, sub-authority 18.
	data := []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0x05, 0x12, 0, 0, 0}
	v, err := decodeValue(ValSid, data)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	if v.String() != "S-1-5-18" {
		t.Errorf("String() = %q, want %q", v.String(), "S-1-5-18")
	}
}

func TestDecodeValue_FileTime(t *testing.T) {
	// 1601-01-01T00:00:00Z plus 12000000000 * 100ns = 1601-01-01T00:20:00Z
	v, err := decodeValue(ValFileTime, []byte{0x00, 0x1b, 0xb7, 0xcb, 0x02, 0, 0, 0})
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	got, ok := v.Time()
	if !ok {
		t.Fatal("Time() reported not-a-time for a FileTime value")
	}
	want := time.Date(1601, 1, 1, 0, 20, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Time() = %v, want %v", got, want)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -race -run TestDecodeValue ./... -count=1`
Expected: FAIL — `undefined: ValUInt8`, `undefined: decodeValue`.

- [ ] **Step 3: Write the implementation**

Create `value.go`:

```go
// value.go — typed substitution values.
//
// Every substitution in a BinXML payload carries a declared type. We keep that
// type rather than flattening to a string: the JSON encoding is type-dependent,
// and the writer investigation turns on declared types (see the F14/F16 notes
// in docs/evtx-format-notes.md), so a decoder that discards them cannot serve
// as an oracle.
package evtx

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// ValueType is the value type declared in the file. Values are from libyal's
// complete table; the array variants are the scalar identifier with 0x80 set.
type ValueType uint8

const (
	ValNull       ValueType = 0x00
	ValString     ValueType = 0x01
	ValAnsiString ValueType = 0x02
	ValInt8       ValueType = 0x03
	ValUInt8      ValueType = 0x04
	ValInt16      ValueType = 0x05
	ValUInt16     ValueType = 0x06
	ValInt32      ValueType = 0x07
	ValUInt32     ValueType = 0x08
	ValInt64      ValueType = 0x09
	ValUInt64     ValueType = 0x0a
	ValReal32     ValueType = 0x0b
	ValReal64     ValueType = 0x0c
	ValBool       ValueType = 0x0d
	ValBinary     ValueType = 0x0e
	ValGuid       ValueType = 0x0f
	ValSizeT      ValueType = 0x10
	ValFileTime   ValueType = 0x11
	ValSysTime    ValueType = 0x12
	ValSid        ValueType = 0x13
	ValHexInt32   ValueType = 0x14
	ValHexInt64   ValueType = 0x15
	ValEvtHandle  ValueType = 0x20
	ValBinXML     ValueType = 0x21
	ValEvtXML     ValueType = 0x23

	valArrayFlag ValueType = 0x80
)

var valueTypeNames = map[ValueType]string{
	ValNull: "Null", ValString: "String", ValAnsiString: "AnsiString",
	ValInt8: "Int8", ValUInt8: "UInt8", ValInt16: "Int16", ValUInt16: "UInt16",
	ValInt32: "Int32", ValUInt32: "UInt32", ValInt64: "Int64", ValUInt64: "UInt64",
	ValReal32: "Real32", ValReal64: "Real64", ValBool: "Bool", ValBinary: "Binary",
	ValGuid: "Guid", ValSizeT: "SizeT", ValFileTime: "FileTime", ValSysTime: "SysTime",
	ValSid: "Sid", ValHexInt32: "HexInt32", ValHexInt64: "HexInt64",
	ValEvtHandle: "EvtHandle", ValBinXML: "BinXml", ValEvtXML: "EvtXml",
}

func (t ValueType) String() string {
	if n, ok := valueTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("ValueType(%#02x)", uint8(t))
}

// Value is one decoded substitution value. Type is the type declared in the
// file and is preserved even when the value is absent.
type Value struct {
	Type ValueType

	absent bool   // declared type present, zero-length data
	num    uint64 // every fixed-width scalar, as raw bits
	str    string // String; also the rendered form of Guid and Sid
	raw    []byte // Binary
	node   *Node  // BinXML — populated in Task 5
}

// IsAbsent reports an optional substitution that carries a declared type but
// no data. Real Windows records use this: testdata/system.evtx encodes
// EventID/@Qualifiers as [size 0, type UNSIGNED_WORD].
func (v Value) IsAbsent() bool { return v.absent || v.Type == ValNull }

// Uint64 returns the raw bits of a fixed-width scalar. ok is false for absent
// values and for types that are not fixed-width scalars.
func (v Value) Uint64() (uint64, bool) {
	if v.absent {
		return 0, false
	}
	switch v.Type {
	case ValInt8, ValUInt8, ValInt16, ValUInt16, ValInt32, ValUInt32,
		ValInt64, ValUInt64, ValBool, ValFileTime, ValHexInt32, ValHexInt64, ValSizeT:
		return v.num, true
	}
	return 0, false
}

// Bytes returns the payload of a Binary value, or nil.
func (v Value) Bytes() []byte { return v.raw }

// Node returns the decoded fragment of a BinXml value, or nil.
func (v Value) Node() *Node { return v.node }

// Time converts a FileTime value. ok is false for any other type.
func (v Value) Time() (time.Time, bool) {
	if v.absent || v.Type != ValFileTime {
		return time.Time{}, false
	}
	return fromFILETIME(v.num), true
}

// String renders the value for human consumption. JSON uses MarshalJSON, which
// is type-aware in ways this is not.
func (v Value) String() string {
	if v.absent || v.Type == ValNull {
		return ""
	}
	switch v.Type {
	case ValString, ValGuid, ValSid:
		return v.str
	case ValInt8:
		return strconv.FormatInt(int64(int8(v.num)), 10)
	case ValInt16:
		return strconv.FormatInt(int64(int16(v.num)), 10)
	case ValInt32:
		return strconv.FormatInt(int64(int32(v.num)), 10)
	case ValInt64:
		return strconv.FormatInt(int64(v.num), 10)
	case ValUInt8, ValUInt16, ValUInt32, ValUInt64, ValSizeT:
		return strconv.FormatUint(v.num, 10)
	case ValBool:
		return strconv.FormatBool(v.num != 0)
	case ValReal32:
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(v.num))), 'g', -1, 32)
	case ValReal64:
		return strconv.FormatFloat(math.Float64frombits(v.num), 'g', -1, 64)
	case ValHexInt32:
		return fmt.Sprintf("0x%08x", uint32(v.num))
	case ValHexInt64:
		return fmt.Sprintf("0x%016x", v.num)
	case ValFileTime:
		return fromFILETIME(v.num).UTC().Format(time.RFC3339Nano)
	case ValBinary:
		return fmt.Sprintf("%x", v.raw)
	}
	return ""
}

// fixedWidths gives the exact byte width each fixed-width type requires.
var fixedWidths = map[ValueType]int{
	ValInt8: 1, ValUInt8: 1,
	ValInt16: 2, ValUInt16: 2,
	ValInt32: 4, ValUInt32: 4, ValReal32: 4, ValBool: 4, ValHexInt32: 4,
	ValInt64: 8, ValUInt64: 8, ValReal64: 8, ValFileTime: 8, ValHexInt64: 8,
}

// decodeValue decodes one substitution value. It is strict: an unknown type,
// an unsupported type, or a width that does not match the declared type is an
// error. Zero-length data is NOT an error — it means the optional substitution
// is absent, which real Windows records rely on.
func decodeValue(t ValueType, data []byte) (Value, error) {
	if t&valArrayFlag != 0 {
		return Value{}, fmt.Errorf("go_evtx: array value type %#02x is not supported "+
			"(measured zero occurrences across the corpus)", uint8(t))
	}
	if len(data) == 0 {
		return Value{Type: t, absent: true}, nil
	}
	if w, ok := fixedWidths[t]; ok {
		if len(data) != w {
			return Value{}, fmt.Errorf("go_evtx: %s declares %d bytes, got %d", t, w, len(data))
		}
		var n uint64
		switch w {
		case 1:
			n = uint64(data[0])
		case 2:
			n = uint64(binary.LittleEndian.Uint16(data))
		case 4:
			n = uint64(binary.LittleEndian.Uint32(data))
		case 8:
			n = binary.LittleEndian.Uint64(data)
		}
		return Value{Type: t, num: n}, nil
	}

	switch t {
	case ValNull:
		return Value{Type: t, absent: true}, nil
	case ValString:
		return Value{Type: t, str: decodeUTF16(data)}, nil
	case ValBinary:
		b := make([]byte, len(data))
		copy(b, data)
		return Value{Type: t, raw: b}, nil
	case ValGuid:
		if len(data) != 16 {
			return Value{}, fmt.Errorf("go_evtx: Guid declares 16 bytes, got %d", len(data))
		}
		return Value{Type: t, str: formatGUID(data)}, nil
	case ValSid:
		s, err := formatSID(data)
		if err != nil {
			return Value{}, err
		}
		return Value{Type: t, str: s}, nil
	case ValSizeT:
		switch len(data) {
		case 4:
			return Value{Type: t, num: uint64(binary.LittleEndian.Uint32(data))}, nil
		case 8:
			return Value{Type: t, num: binary.LittleEndian.Uint64(data)}, nil
		}
		return Value{}, fmt.Errorf("go_evtx: SizeT must be 4 or 8 bytes, got %d", len(data))
	case ValBinXML:
		// The nested fragment is decoded by the caller, which owns the chunk
		// context this decoder does not have. Task 5 fills in node.
		b := make([]byte, len(data))
		copy(b, data)
		return Value{Type: t, raw: b}, nil
	case ValAnsiString:
		return Value{}, fmt.Errorf("go_evtx: AnsiString is not supported: the format " +
			"carries no codepage, and it occurs zero times across the measured corpus")
	case ValSysTime, ValEvtHandle, ValEvtXML:
		return Value{}, fmt.Errorf("go_evtx: value type %s is not implemented "+
			"(zero occurrences across the measured corpus)", t)
	}
	return Value{}, fmt.Errorf("go_evtx: unknown value type %#02x", uint8(t))
}

// decodeUTF16 decodes UTF-16LE, tolerating one trailing null terminator.
func decodeUTF16(data []byte) string {
	end := len(data)
	if end >= 2 && data[end-2] == 0 && data[end-1] == 0 {
		end -= 2
	}
	if end < 2 {
		return ""
	}
	u16 := make([]uint16, end/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(u16))
}

// formatGUID renders the on-disk little-endian GUID struct in canonical form.
func formatGUID(g []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(g[0:4]),
		binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		binary.BigEndian.Uint16(g[8:10]),
		g[10:16])
}

// formatSID renders an NT security identifier as S-R-A-S1-S2-...
// Layout: revision(1), sub-authority count(1), authority(6, big-endian),
// then count little-endian uint32 sub-authorities.
func formatSID(data []byte) (string, error) {
	if len(data) < 8 {
		return "", fmt.Errorf("go_evtx: Sid needs at least 8 bytes, got %d", len(data))
	}
	revision := data[0]
	count := int(data[1])
	if len(data) != 8+count*4 {
		return "", fmt.Errorf("go_evtx: Sid with %d sub-authorities needs %d bytes, got %d",
			count, 8+count*4, len(data))
	}
	var authority uint64
	for _, b := range data[2:8] {
		authority = authority<<8 | uint64(b)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", revision, authority)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(data[8+i*4:]))
	}
	return sb.String(), nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -race -run TestDecodeValue ./... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add value.go value_test.go
git commit -m "feat: typed BinXML value decoding, strict on unknown types"
```

---

### Task 2: Type-aware JSON encoding for Value

**Files:**
- Modify: `value.go` (append)
- Test: `value_test.go` (append)

**Interfaces:**
- Consumes: `Value`, `ValueType` from Task 1.
- Produces: `func (v Value) MarshalJSON() ([]byte, error)`.

- [ ] **Step 1: Write the failing test**

Append to `value_test.go`:

```go
func TestValue_MarshalJSON(t *testing.T) {
	mk := func(typ ValueType, data []byte) Value {
		v, err := decodeValue(typ, data)
		if err != nil {
			t.Fatalf("decodeValue(%s): %v", typ, err)
		}
		return v
	}
	tests := []struct {
		name string
		v    Value
		want string
	}{
		{"absent", mk(ValUInt16, nil), `null`},
		{"null type", mk(ValNull, nil), `null`},
		{"uint32 is a number", mk(ValUInt32, []byte{0x2a, 0, 0, 0}), `42`},
		{"bool", mk(ValBool, []byte{0x01, 0, 0, 0}), `true`},
		{"string", mk(ValString, []byte{'h', 0, 'i', 0}), `"hi"`},
		{"hex keeps hex", mk(ValHexInt64, []byte{0x10, 0, 0, 0, 0, 0, 0, 0}), `"0x0000000000000010"`},
		{"sid", mk(ValSid, []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0x05, 0x12, 0, 0, 0}), `"S-1-5-18"`},
		{"binary is base64", mk(ValBinary, []byte{0xde, 0xad}), `"3q0="`},
		{"small uint64 stays a number",
			mk(ValUInt64, []byte{0x01, 0, 0, 0, 0, 0, 0, 0}), `1`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(b) != tc.want {
				t.Errorf("Marshal = %s, want %s", b, tc.want)
			}
		})
	}
}

// A JSON number cannot hold more than 2^53 exactly. Keywords and
// EventRecordID are 64-bit and reach that range, so large values become
// strings rather than being silently rounded in a downstream pipeline.
func TestValue_MarshalJSON_LargeUint64BecomesString(t *testing.T) {
	v, err := decodeValue(ValUInt64, []byte{0, 0, 0, 0, 0, 0, 0x20, 0}) // 2^53
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != `"9007199254740992"` {
		t.Errorf("Marshal = %s, want a quoted string at 2^53", b)
	}
}
```

Add `"encoding/json"` to the import block of `value_test.go`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -race -run TestValue_MarshalJSON ./... -count=1`
Expected: FAIL — the default struct encoding emits `{"Type":6}`, not `null`.

- [ ] **Step 3: Write the implementation**

Append to `value.go`:

```go
// maxExactJSONInt is the largest integer a JSON number holds exactly. Above
// it, encoders that parse into a float64 lose precision silently, so we quote.
const maxExactJSONInt = uint64(1) << 53

// MarshalJSON renders the value according to its declared type: numbers stay
// numbers, hex types keep their hex form, binary is base64, times are RFC 3339.
func (v Value) MarshalJSON() ([]byte, error) {
	if v.IsAbsent() {
		return []byte("null"), nil
	}
	switch v.Type {
	case ValString, ValGuid, ValSid:
		return json.Marshal(v.str)
	case ValBinary:
		return json.Marshal(base64.StdEncoding.EncodeToString(v.raw))
	case ValBool:
		return json.Marshal(v.num != 0)
	case ValInt8:
		return json.Marshal(int8(v.num))
	case ValInt16:
		return json.Marshal(int16(v.num))
	case ValInt32:
		return json.Marshal(int32(v.num))
	case ValUInt8:
		return json.Marshal(uint8(v.num))
	case ValUInt16:
		return json.Marshal(uint16(v.num))
	case ValUInt32:
		return json.Marshal(uint32(v.num))
	case ValInt64:
		n := int64(v.num)
		if n > int64(maxExactJSONInt) || n < -int64(maxExactJSONInt) {
			return json.Marshal(strconv.FormatInt(n, 10))
		}
		return json.Marshal(n)
	case ValUInt64, ValSizeT:
		if v.num >= maxExactJSONInt {
			return json.Marshal(strconv.FormatUint(v.num, 10))
		}
		return json.Marshal(v.num)
	case ValReal32:
		return json.Marshal(float32(math.Float32frombits(uint32(v.num))))
	case ValReal64:
		return json.Marshal(math.Float64frombits(v.num))
	case ValHexInt32, ValHexInt64, ValFileTime:
		return json.Marshal(v.String())
	case ValBinXML:
		if v.node != nil {
			return json.Marshal(v.node)
		}
		return []byte("null"), nil
	}
	return nil, fmt.Errorf("go_evtx: cannot marshal value type %s", v.Type)
}
```

Add `"encoding/base64"` and `"encoding/json"` to `value.go`'s import block.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -race -run TestValue ./... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add value.go value_test.go
git commit -m "feat: type-aware JSON encoding for BinXML values"
```

---

### Task 3: Substitution array parsing

**Files:**
- Create: `binxml_decode.go`
- Test: `binxml_decode_test.go`

**Interfaces:**
- Consumes: `decodeValue`, `ValueType`, `Value` from Task 1.
- Produces: token constants `tokEOF`, `tokOpenElement`, `tokOpenElementAttrs`, `tokCloseStartElement`, `tokCloseEmptyElement`, `tokEndElement`, `tokValue`, `tokValueMore`, `tokAttribute`, `tokAttributeMore`, `tokCDATA`, `tokCDATAMore`, `tokCharRef`, `tokCharRefMore`, `tokEntityRef`, `tokEntityRefMore`, `tokPITarget`, `tokPIData`, `tokTemplateInstance`, `tokNormalSub`, `tokOptionalSub`, `tokFragmentHeader`; and `parseSubstitutions(data []byte) ([]Value, int, error)` returning the values and the number of bytes consumed.

- [ ] **Step 1: Write the failing test**

Create `binxml_decode_test.go`:

```go
package evtx

import "testing"

func TestParseSubstitutions(t *testing.T) {
	// count=2; [size 4, UInt32], [size 0, UInt16 (absent)]; then 4 bytes of data.
	data := []byte{
		0x02, 0, 0, 0,
		0x04, 0x00, byte(ValUInt32), 0x00,
		0x00, 0x00, byte(ValUInt16), 0x00,
		0x2a, 0x00, 0x00, 0x00,
	}
	vals, n, err := parseSubstitutions(data)
	if err != nil {
		t.Fatalf("parseSubstitutions: %v", err)
	}
	if n != len(data) {
		t.Errorf("consumed %d bytes, want %d", n, len(data))
	}
	if len(vals) != 2 {
		t.Fatalf("got %d values, want 2", len(vals))
	}
	if got, _ := vals[0].Uint64(); got != 42 {
		t.Errorf("vals[0] = %d, want 42", got)
	}
	if !vals[1].IsAbsent() {
		t.Error("vals[1] should be absent (declared size 0)")
	}
	if vals[1].Type != ValUInt16 {
		t.Errorf("vals[1].Type = %s, want UInt16 — the declared type must survive", vals[1].Type)
	}
}

func TestParseSubstitutions_TruncatedIsError(t *testing.T) {
	// Declares one 8-byte value but supplies only 2 bytes of data.
	data := []byte{
		0x01, 0, 0, 0,
		0x08, 0x00, byte(ValUInt64), 0x00,
		0x01, 0x02,
	}
	if _, _, err := parseSubstitutions(data); err == nil {
		t.Fatal("expected an error for a truncated value blob")
	}
}

func TestParseSubstitutions_AbsurdCountIsError(t *testing.T) {
	data := []byte{0xff, 0xff, 0xff, 0xff}
	if _, _, err := parseSubstitutions(data); err == nil {
		t.Fatal("expected an error for a count that cannot fit in the payload")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -race -run TestParseSubstitutions ./... -count=1`
Expected: FAIL — `undefined: parseSubstitutions`.

- [ ] **Step 3: Write the implementation**

Create `binxml_decode.go`:

```go
// binxml_decode.go — generic BinXML token stream decoder.
//
// Replaces the template-specific reader this package shipped through v0.6.0,
// which assumed go-evtx's own 42-slot template and therefore produced
// confident nonsense on any real Windows file.
//
// Strictness is the point. Three rules, all enforced here:
//   1. an unrecognised token or value type, or a length past the payload, is
//      an error;
//   2. the decode accounts for every byte — stopping early or running past the
//      fragment's EOF is an error even when a plausible tree was built;
//   3. the substitutions consumed must equal the count the array declares.
package evtx

import (
	"encoding/binary"
	"fmt"
)

// BinXML token identifiers. The 0x40 bit means "more of this kind follows";
// libyal documents both forms for the tokens that carry it.
const (
	tokEOF               byte = 0x00
	tokOpenElement       byte = 0x01
	tokOpenElementAttrs  byte = 0x41
	tokCloseStartElement byte = 0x02
	tokCloseEmptyElement byte = 0x03
	tokEndElement        byte = 0x04
	tokValue             byte = 0x05
	tokValueMore         byte = 0x45
	tokAttribute         byte = 0x06
	tokAttributeMore     byte = 0x46
	tokCDATA             byte = 0x07
	tokCDATAMore         byte = 0x47
	tokCharRef           byte = 0x08
	tokCharRefMore       byte = 0x48
	tokEntityRef         byte = 0x09
	tokEntityRefMore     byte = 0x49
	tokPITarget          byte = 0x0a
	tokPIData            byte = 0x0b
	tokTemplateInstance  byte = 0x0c
	tokNormalSub         byte = 0x0d
	tokOptionalSub       byte = 0x0e
	tokFragmentHeader    byte = 0x0f
)

// parseSubstitutions reads a substitution array:
//
//	[count u32][count × (size u16, type u8, pad u8)][values...]
//
// It returns the decoded values and the total bytes consumed, so a caller can
// verify the payload was fully accounted for.
func parseSubstitutions(data []byte) ([]Value, int, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("go_evtx: substitution array truncated: %d bytes, need at least 4", len(data))
	}
	count64 := uint64(binary.LittleEndian.Uint32(data[0:4]))
	// Each entry needs a 4-byte descriptor; anything larger cannot fit and is
	// a misparse rather than a real array.
	if count64 > uint64((len(data)-4)/4) {
		return nil, 0, fmt.Errorf("go_evtx: substitution count %d cannot fit in %d bytes", count64, len(data))
	}
	count := int(count64)

	sizes := make([]int, count)
	types := make([]ValueType, count)
	for i := 0; i < count; i++ {
		off := 4 + i*4
		sizes[i] = int(binary.LittleEndian.Uint16(data[off : off+2]))
		types[i] = ValueType(data[off+2])
	}

	pos := 4 + count*4
	vals := make([]Value, count)
	for i := 0; i < count; i++ {
		end := pos + sizes[i]
		if end > len(data) {
			return nil, 0, fmt.Errorf(
				"go_evtx: substitution %d (%s) declares %d bytes at offset %d, past the %d-byte array",
				i, types[i], sizes[i], pos, len(data))
		}
		v, err := decodeValue(types[i], data[pos:end])
		if err != nil {
			return nil, 0, fmt.Errorf("go_evtx: substitution %d: %w", i, err)
		}
		vals[i] = v
		pos = end
	}
	return vals, pos, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -race -run TestParseSubstitutions ./... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add binxml_decode.go binxml_decode_test.go
git commit -m "feat: strict substitution array parsing with token constants"
```

---

### Task 4: Template definition parsing and per-chunk cache

**Files:**
- Create: `template.go`
- Test: `template_test.go`

**Interfaces:**
- Consumes: token constants from Task 3.
- Produces: `type templateDef struct { GUID [16]byte; Body []byte; BodyChunkOffset int }`, `func parseTemplateDef(chunk []byte, off int) (*templateDef, error)`, `type templateCache map[int]*templateDef`, `func (c templateCache) get(chunk []byte, off int) (*templateDef, error)`.

- [ ] **Step 1: Write the failing test**

Create `template_test.go`:

```go
package evtx

import "testing"

// buildChunkWithTemplate lays a minimal template definition into a chunk-sized
// buffer at off: next_offset(4) + guid(16) + data_size(4) + body.
func buildChunkWithTemplate(off int, body []byte) []byte {
	chunk := make([]byte, evtxChunkSize)
	copy(chunk[0:8], evtxChunkMagic)
	for i := 0; i < 16; i++ {
		chunk[off+4+i] = byte(i + 1)
	}
	chunk[off+20] = byte(len(body))
	copy(chunk[off+24:], body)
	return chunk
}

func TestParseTemplateDef(t *testing.T) {
	body := []byte{tokFragmentHeader, 0x01, 0x01, 0x00, tokEOF}
	chunk := buildChunkWithTemplate(1000, body)

	def, err := parseTemplateDef(chunk, 1000)
	if err != nil {
		t.Fatalf("parseTemplateDef: %v", err)
	}
	if len(def.Body) != len(body) {
		t.Fatalf("Body length = %d, want %d", len(def.Body), len(body))
	}
	if def.Body[0] != tokFragmentHeader {
		t.Errorf("Body[0] = %#02x, want the fragment header token", def.Body[0])
	}
	if def.BodyChunkOffset != 1024 {
		t.Errorf("BodyChunkOffset = %d, want 1024 (definition + 24-byte header)", def.BodyChunkOffset)
	}
	if def.GUID[0] != 1 || def.GUID[15] != 16 {
		t.Errorf("GUID = %x, want bytes 1..16", def.GUID)
	}
}

func TestParseTemplateDef_OutOfRangeIsError(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	// data_size runs past the end of the chunk.
	off := evtxChunkSize - 32
	chunk[off+20] = 0xff
	chunk[off+21] = 0xff
	if _, err := parseTemplateDef(chunk, off); err == nil {
		t.Fatal("expected an error for a definition whose body leaves the chunk")
	}
}

// security.evtx holds 9358 definitions against 183952 records: without a cache
// the same definition is reparsed hundreds of times.
func TestTemplateCache_ReusesTheSamePointer(t *testing.T) {
	body := []byte{tokFragmentHeader, 0x01, 0x01, 0x00, tokEOF}
	chunk := buildChunkWithTemplate(2048, body)
	cache := templateCache{}

	a, err := cache.get(chunk, 2048)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	b, err := cache.get(chunk, 2048)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if a != b {
		t.Error("cache returned a different pointer for the same offset")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -race -run "TestParseTemplateDef|TestTemplateCache" ./... -count=1`
Expected: FAIL — `undefined: parseTemplateDef`.

- [ ] **Step 3: Write the implementation**

Create `template.go`:

```go
// template.go — template definitions and their per-chunk cache.
//
// Layout, confirmed against real files of both format versions and matching
// libyal's table once its offsets are renumbered from the definition start
// rather than from the enclosing template instance:
//
//	next_offset  u32   chain within the chunk's template hash bucket
//	guid         16 B  template identifier
//	data_size    u32   length of the body that follows
//	body         data_size bytes, itself starting with a fragment header
package evtx

import "fmt"

const templateDefHeaderSize = 24 // next_offset(4) + guid(16) + data_size(4)

// templateDef is one template definition resolved inside a chunk.
type templateDef struct {
	GUID [16]byte
	Body []byte // the BinXML body, aliasing the chunk buffer

	// BodyChunkOffset is the chunk-relative offset of Body[0]. Name and
	// template offsets inside the body are chunk-relative, so resolving them
	// needs this base.
	BodyChunkOffset int
}

// parseTemplateDef reads the definition at chunk-relative offset off.
func parseTemplateDef(chunk []byte, off int) (*templateDef, error) {
	if off < 0 || off+templateDefHeaderSize > len(chunk) {
		return nil, fmt.Errorf("go_evtx: template definition offset %d outside the chunk", off)
	}
	dataSize := int(le32(chunk[off+20:]))
	bodyStart := off + templateDefHeaderSize
	bodyEnd := bodyStart + dataSize
	if dataSize < 0 || bodyEnd > len(chunk) {
		return nil, fmt.Errorf(
			"go_evtx: template definition at %d declares a %d-byte body ending at %d, past the %d-byte chunk",
			off, dataSize, bodyEnd, len(chunk))
	}
	def := &templateDef{
		Body:            chunk[bodyStart:bodyEnd],
		BodyChunkOffset: bodyStart,
	}
	copy(def.GUID[:], chunk[off+4:off+20])
	return def, nil
}

// templateCache memoises definitions by their chunk-relative offset. It is
// valid for one chunk only; the reader discards it when it loads the next.
type templateCache map[int]*templateDef

func (c templateCache) get(chunk []byte, off int) (*templateDef, error) {
	if def, ok := c[off]; ok {
		return def, nil
	}
	def, err := parseTemplateDef(chunk, off)
	if err != nil {
		return nil, err
	}
	c[off] = def
	return def, nil
}
```

Also append this helper to `binxml_decode.go` (used by both files):

```go
func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -race -run "TestParseTemplateDef|TestTemplateCache" ./... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add template.go template_test.go binxml_decode.go
git commit -m "feat: template definition parsing with a per-chunk cache"
```

---

### Task 5: Token walker — BinXML to a Node tree

**Files:**
- Modify: `binxml_decode.go` (append)
- Test: `binxml_decode_test.go` (append)

**Interfaces:**
- Consumes: token constants and `parseSubstitutions` (Task 3), `templateCache`/`templateDef` (Task 4), `Value`/`decodeValue` (Task 1).
- Produces: `type Attr struct { Name string; Value Value }`, `type Node struct { Name string; Attributes []Attr; Children []Node; Value *Value }`, and `func decodeRecordBinXML(chunk []byte, payload []byte, payloadChunkOffset int, cache templateCache) (*Node, error)`.

- [ ] **Step 1: Write the failing test**

Append to `binxml_decode_test.go`:

```go
// buildSimpleRecord lays out one record payload inside a chunk buffer:
// fragment header, template instance with an inline definition whose body is
// <Event><EventID>{sub 0}</EventID></Event>, then a one-entry substitution
// array holding UInt16 4624.
func buildSimpleRecord(t *testing.T) (chunk []byte, payload []byte, payloadOff int) {
	t.Helper()
	chunk = make([]byte, evtxChunkSize)
	copy(chunk[0:8], evtxChunkMagic)
	payloadOff = 512

	nameNode := func(name string) []byte {
		u := []rune(name)
		b := []byte{0, 0, 0, 0, 0, 0, byte(len(u)), 0}
		for _, r := range u {
			b = append(b, byte(r), 0)
		}
		return append(b, 0, 0)
	}
	// element builds an OpenStartElement with an inline NameNode at the fixed
	// 11-byte header offset the encoder uses.
	element := func(name string, base int, inner []byte) []byte {
		nn := nameNode(name)
		b := []byte{tokOpenElement, 0xff, 0xff, 0, 0, 0, 0}
		b = append(b, 0, 0, 0, 0) // name_offset, patched below
		le32put(b[7:], uint32(base+11))
		b = append(b, nn...)
		b = append(b, tokCloseStartElement)
		b = append(b, inner...)
		b = append(b, tokEndElement)
		le32put(b[3:], uint32(len(b)-7)) // data_size: bytes after data_size
		return b
	}

	defOff := payloadOff + 4 + 10
	bodyBase := defOff + 24
	inner := []byte{tokNormalSub, 0x00, 0x00, byte(ValUInt16)}
	eventID := element("EventID", bodyBase+4+11+len(nameNode("Event"))+1, inner)
	body := []byte{tokFragmentHeader, 0x01, 0x01, 0x00}
	body = append(body, element("Event", bodyBase+4, eventID)...)
	body = append(body, tokEOF)

	p := []byte{tokFragmentHeader, 0x01, 0x01, 0x00,
		tokTemplateInstance, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	le32put(p[10:], uint32(defOff))
	def := make([]byte, 24)
	le32put(def[20:], uint32(len(body)))
	p = append(p, def...)
	p = append(p, body...)
	p = append(p, 0x01, 0, 0, 0, 0x02, 0x00, byte(ValUInt16), 0x00, 0x10, 0x12)

	copy(chunk[payloadOff:], p)
	return chunk, chunk[payloadOff : payloadOff+len(p)], payloadOff
}

func le32put(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func TestDecodeRecordBinXML_ResolvesSubstitution(t *testing.T) {
	chunk, payload, off := buildSimpleRecord(t)
	root, err := decodeRecordBinXML(chunk, payload, off, templateCache{})
	if err != nil {
		t.Fatalf("decodeRecordBinXML: %v", err)
	}
	if root.Name != "Event" {
		t.Fatalf("root.Name = %q, want %q", root.Name, "Event")
	}
	if len(root.Children) != 1 {
		t.Fatalf("root has %d children, want 1", len(root.Children))
	}
	child := root.Children[0]
	if child.Name != "EventID" {
		t.Errorf("child.Name = %q, want %q", child.Name, "EventID")
	}
	if child.Value == nil {
		t.Fatal("child.Value is nil; the substitution was not applied")
	}
	if got, _ := child.Value.Uint64(); got != 4624 {
		t.Errorf("EventID = %d, want 4624", got)
	}
}

func TestDecodeRecordBinXML_UnknownTokenIsError(t *testing.T) {
	chunk, payload, off := buildSimpleRecord(t)
	// 0x7f is not a token in libyal's table.
	corrupt := make([]byte, len(payload))
	copy(corrupt, payload)
	corrupt[4] = 0x7f
	if _, err := decodeRecordBinXML(chunk, corrupt, off, templateCache{}); err == nil {
		t.Fatal("expected an error for an unrecognised token")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -race -run TestDecodeRecordBinXML ./... -count=1`
Expected: FAIL — `undefined: decodeRecordBinXML`.

- [ ] **Step 3: Write the implementation**

Append to `binxml_decode.go`:

```go
// Attr is one attribute on an element.
type Attr struct {
	Name  string `json:"name"`
	Value Value  `json:"value"`
}

// Node is a decoded element. Attributes and Children keep file order, which
// carries meaning for the positional <Data> elements real events emit.
type Node struct {
	Name       string `json:"name"`
	Attributes []Attr `json:"attributes,omitempty"`
	Children   []Node `json:"children,omitempty"`
	Value      *Value `json:"value,omitempty"`
}

// binxmlParser walks one template body, resolving substitutions against subs.
type binxmlParser struct {
	chunk []byte  // the whole chunk: name and template offsets are chunk-relative
	buf   []byte  // the body being walked
	base  int     // chunk-relative offset of buf[0]
	pos   int     // cursor within buf
	subs  []Value // substitution values for this record
	cache templateCache
	used  int // how many distinct substitutions were consumed
}

// decodeRecordBinXML decodes one record payload into an element tree.
//
// payloadChunkOffset is the chunk-relative offset of payload[0]; template and
// name offsets in the stream are chunk-relative, so resolving them needs it.
func decodeRecordBinXML(chunk, payload []byte, payloadChunkOffset int, cache templateCache) (*Node, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("go_evtx: payload is %d bytes, too short for a fragment header", len(payload))
	}
	if payload[0] != tokFragmentHeader {
		return nil, fmt.Errorf("go_evtx: payload starts with %#02x, want the fragment header token %#02x",
			payload[0], tokFragmentHeader)
	}
	pos := 4

	if pos >= len(payload) || payload[pos] != tokTemplateInstance {
		return nil, fmt.Errorf("go_evtx: expected a template instance at offset %d", pos)
	}
	if pos+10 > len(payload) {
		return nil, fmt.Errorf("go_evtx: template instance truncated at offset %d", pos)
	}
	defOffset := int(le32(payload[pos+6:]))
	pos += 10

	// The definition is inline when its offset names this very position;
	// otherwise it lives elsewhere in the chunk and is shared.
	if defOffset == payloadChunkOffset+pos {
		def, err := parseTemplateDef(chunk, defOffset)
		if err != nil {
			return nil, err
		}
		cache[defOffset] = def
		pos += templateDefHeaderSize + len(def.Body)
	}
	def, err := cache.get(chunk, defOffset)
	if err != nil {
		return nil, err
	}

	subs, consumed, err := parseSubstitutions(payload[pos:])
	if err != nil {
		return nil, err
	}
	// Rule 2: account for every byte. Trailing bytes mean we misread something.
	if pos+consumed != len(payload) {
		return nil, fmt.Errorf(
			"go_evtx: decode consumed %d of %d payload bytes; %d unaccounted for",
			pos+consumed, len(payload), len(payload)-(pos+consumed))
	}

	// A BinXml-typed substitution is a nested fragment. It occurs in every real
	// record, so this is the nominal path, not an edge case.
	for i := range subs {
		if subs[i].Type == ValBinXML && !subs[i].IsAbsent() {
			p := &binxmlParser{chunk: chunk, buf: subs[i].raw, base: 0, subs: nil, cache: cache}
			node, err := p.parseFragment()
			if err != nil {
				return nil, fmt.Errorf("go_evtx: nested BinXml in substitution %d: %w", i, err)
			}
			subs[i].node = node
		}
	}

	p := &binxmlParser{
		chunk: chunk,
		buf:   def.Body,
		base:  def.BodyChunkOffset,
		subs:  subs,
		cache: cache,
	}
	return p.parseFragment()
}

// parseFragment reads a fragment header then exactly one root element.
func (p *binxmlParser) parseFragment() (*Node, error) {
	if p.pos+4 > len(p.buf) || p.buf[p.pos] != tokFragmentHeader {
		return nil, fmt.Errorf("go_evtx: expected a fragment header at body offset %d", p.pos)
	}
	p.pos += 4
	node, err := p.parseElement()
	if err != nil {
		return nil, err
	}
	// Trailing EOF is expected; anything else means we lost sync.
	for p.pos < len(p.buf) {
		switch p.buf[p.pos] {
		case tokEOF, 0x00:
			p.pos++
		default:
			return nil, fmt.Errorf("go_evtx: unexpected token %#02x after the root element at body offset %d",
				p.buf[p.pos], p.pos)
		}
	}
	return node, nil
}

// parseElement reads one OpenStartElement through its matching EndElement.
func (p *binxmlParser) parseElement() (*Node, error) {
	if p.pos >= len(p.buf) {
		return nil, fmt.Errorf("go_evtx: element expected at body offset %d, buffer exhausted", p.pos)
	}
	tok := p.buf[p.pos]
	if tok != tokOpenElement && tok != tokOpenElementAttrs {
		return nil, fmt.Errorf("go_evtx: expected an element token at body offset %d, found %#02x", p.pos, tok)
	}
	start := p.pos
	if p.pos+11 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: element header truncated at body offset %d", p.pos)
	}
	nameOffset := int(le32(p.buf[p.pos+7:]))
	p.pos += 11

	name, err := p.readName(nameOffset, start+11)
	if err != nil {
		return nil, err
	}
	node := &Node{Name: name}

	if tok == tokOpenElementAttrs {
		if p.pos+4 > len(p.buf) {
			return nil, fmt.Errorf("go_evtx: attribute list size truncated at body offset %d", p.pos)
		}
		p.pos += 4 // attr_list_size; the attribute tokens that follow are self-delimiting
		for {
			if p.pos >= len(p.buf) {
				return nil, fmt.Errorf("go_evtx: attribute list ran off the end of the body")
			}
			at := p.buf[p.pos]
			if at != tokAttribute && at != tokAttributeMore {
				break
			}
			attr, err := p.parseAttribute()
			if err != nil {
				return nil, err
			}
			node.Attributes = append(node.Attributes, *attr)
		}
	}

	if p.pos >= len(p.buf) {
		return nil, fmt.Errorf("go_evtx: element %q has no close-start token", name)
	}
	switch p.buf[p.pos] {
	case tokCloseEmptyElement:
		p.pos++
		return node, nil
	case tokCloseStartElement:
		p.pos++
	default:
		return nil, fmt.Errorf("go_evtx: element %q: expected close-start, found %#02x at body offset %d",
			name, p.buf[p.pos], p.pos)
	}

	for {
		if p.pos >= len(p.buf) {
			return nil, fmt.Errorf("go_evtx: element %q is not terminated", name)
		}
		switch t := p.buf[p.pos]; t {
		case tokEndElement:
			p.pos++
			return node, nil
		case tokOpenElement, tokOpenElementAttrs:
			child, err := p.parseElement()
			if err != nil {
				return nil, err
			}
			node.Children = append(node.Children, *child)
		case tokNormalSub, tokOptionalSub:
			v, err := p.parseSubstitutionRef()
			if err != nil {
				return nil, err
			}
			node.Value = v
		case tokValue, tokValueMore:
			v, err := p.parseLiteralValue()
			if err != nil {
				return nil, err
			}
			node.Value = v
		case tokCDATA, tokCDATAMore, tokCharRef, tokCharRefMore,
			tokEntityRef, tokEntityRefMore, tokPITarget, tokPIData:
			return nil, fmt.Errorf(
				"go_evtx: token %#02x in element %q is not implemented "+
					"(zero occurrences across the measured corpus)", t, name)
		default:
			return nil, fmt.Errorf("go_evtx: unrecognised token %#02x in element %q at body offset %d",
				t, name, p.pos)
		}
	}
}

// parseAttribute reads one attribute token: token(1) name_offset(4) [NameNode]
// followed by exactly one value token.
func (p *binxmlParser) parseAttribute() (*Attr, error) {
	start := p.pos
	if p.pos+5 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: attribute header truncated at body offset %d", p.pos)
	}
	nameOffset := int(le32(p.buf[p.pos+1:]))
	p.pos += 5
	name, err := p.readName(nameOffset, start+5)
	if err != nil {
		return nil, err
	}
	if p.pos >= len(p.buf) {
		return nil, fmt.Errorf("go_evtx: attribute %q has no value", name)
	}
	var v *Value
	switch p.buf[p.pos] {
	case tokNormalSub, tokOptionalSub:
		v, err = p.parseSubstitutionRef()
	case tokValue, tokValueMore:
		v, err = p.parseLiteralValue()
	default:
		return nil, fmt.Errorf("go_evtx: attribute %q: unexpected value token %#02x", name, p.buf[p.pos])
	}
	if err != nil {
		return nil, err
	}
	return &Attr{Name: name, Value: *v}, nil
}

// parseSubstitutionRef reads token(1) index(2) type(1) and resolves it.
func (p *binxmlParser) parseSubstitutionRef() (*Value, error) {
	if p.pos+4 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: substitution token truncated at body offset %d", p.pos)
	}
	idx := int(le16(p.buf[p.pos+1:]))
	declared := ValueType(p.buf[p.pos+3])
	p.pos += 4
	if idx >= len(p.subs) {
		return nil, fmt.Errorf("go_evtx: substitution index %d out of range: the array declares %d entries",
			idx, len(p.subs))
	}
	p.used++
	v := p.subs[idx]
	// The template's declared type and the array's are expected to agree; a
	// disagreement is exactly the class of defect this decoder exists to
	// surface, so it is reported rather than silently preferred one way.
	if !v.IsAbsent() && v.Type != declared {
		return nil, fmt.Errorf(
			"go_evtx: substitution %d: template declares %s, substitution array declares %s",
			idx, declared, v.Type)
	}
	return &v, nil
}

// parseLiteralValue reads token(1) type(1) then a type-specific payload. Only
// StringType has a literal form in this format.
func (p *binxmlParser) parseLiteralValue() (*Value, error) {
	if p.pos+2 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: value token truncated at body offset %d", p.pos)
	}
	typ := ValueType(p.buf[p.pos+1])
	if typ != ValString {
		return nil, fmt.Errorf(
			"go_evtx: literal value of type %s at body offset %d: only StringType has a literal form",
			typ, p.pos)
	}
	if p.pos+4 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: value length truncated at body offset %d", p.pos)
	}
	units := int(le16(p.buf[p.pos+2:]))
	start := p.pos + 4
	end := start + units*2
	if end > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: literal string of %d units at body offset %d runs past the body",
			units, p.pos)
	}
	p.pos = end
	v, err := decodeValue(ValString, p.buf[start:end])
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// readName resolves a NameNode. The offset is chunk-relative; when it names
// the position immediately after the current token header the node is inline
// and the cursor advances past it.
//
// NameNode: next_offset(4) hash(2) length(2) UTF-16 × length, null(2)
func (p *binxmlParser) readName(nameOffset, inlineAt int) (string, error) {
	if p.base != 0 && nameOffset == p.base+inlineAt {
		name, size, err := readNameAt(p.buf, inlineAt)
		if err != nil {
			return "", err
		}
		p.pos = inlineAt + size
		return name, nil
	}
	// Shared NameNode elsewhere in the chunk.
	rel := nameOffset - p.base
	if p.base != 0 && rel >= 0 && rel < len(p.buf) {
		name, _, err := readNameAt(p.buf, rel)
		return name, err
	}
	if nameOffset < 0 || nameOffset >= len(p.chunk) {
		return "", fmt.Errorf("go_evtx: name offset %d outside the chunk", nameOffset)
	}
	name, _, err := readNameAt(p.chunk, nameOffset)
	return name, err
}

// readNameAt decodes a NameNode at off, returning the name and its total size.
func readNameAt(b []byte, off int) (string, int, error) {
	if off < 0 || off+8 > len(b) {
		return "", 0, fmt.Errorf("go_evtx: name node at %d is truncated", off)
	}
	units := int(le16(b[off+6:]))
	start := off + 8
	end := start + units*2
	if end+2 > len(b) {
		return "", 0, fmt.Errorf("go_evtx: name node at %d declares %d units, past the buffer", off, units)
	}
	u16 := make([]uint16, units)
	for i := range u16 {
		u16[i] = le16(b[start+i*2:])
	}
	return string(utf16.Decode(u16)), 8 + units*2 + 2, nil
}
```

Add `"unicode/utf16"` to `binxml_decode.go`'s import block.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -race -run TestDecodeRecordBinXML ./... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add binxml_decode.go binxml_decode_test.go
git commit -m "feat: generic BinXML token walker producing a Node tree"
```

---

### Task 6: Event assembly from the Node tree

**Files:**
- Create: `event.go`
- Test: `event_test.go`

**Interfaces:**
- Consumes: `Node`, `Attr`, `Value` (Tasks 1 and 5).
- Produces: `type Provider struct`, `type System struct`, `type Data struct`, `type Event struct`, `func eventFromNode(root *Node) (*Event, error)`.

- [ ] **Step 1: Write the failing test**

Create `event_test.go`:

```go
package evtx

import (
	"encoding/json"
	"testing"
)

func mustVal(t *testing.T, typ ValueType, data []byte) Value {
	t.Helper()
	v, err := decodeValue(typ, data)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	return v
}

func TestEventFromNode(t *testing.T) {
	root := &Node{Name: "Event", Children: []Node{
		{Name: "System", Children: []Node{
			{Name: "Provider", Attributes: []Attr{
				{Name: "Name", Value: mustVal(t, ValString, utf16le("Microsoft-Windows-Security-Auditing"))},
			}},
			{Name: "EventID", Value: ptrVal(mustVal(t, ValUInt16, []byte{0x10, 0x12}))},
			{Name: "Level", Value: ptrVal(mustVal(t, ValUInt8, []byte{0x04}))},
			{Name: "Computer", Value: ptrVal(mustVal(t, ValString, utf16le("WIN-TEST")))},
		}},
		{Name: "EventData", Children: []Node{
			{Name: "Data",
				Attributes: []Attr{{Name: "Name", Value: mustVal(t, ValString, utf16le("TargetUserName"))}},
				Value:      ptrVal(mustVal(t, ValString, utf16le("alice")))},
			// A positional <Data> with no Name attribute — a map cannot hold this.
			{Name: "Data", Value: ptrVal(mustVal(t, ValString, utf16le("positional")))},
		}},
	}}

	ev, err := eventFromNode(root)
	if err != nil {
		t.Fatalf("eventFromNode: %v", err)
	}
	if ev.System.Provider.Name != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("Provider.Name = %q", ev.System.Provider.Name)
	}
	if ev.System.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", ev.System.EventID)
	}
	if ev.System.Level != 4 {
		t.Errorf("Level = %d, want 4", ev.System.Level)
	}
	if ev.System.Computer != "WIN-TEST" {
		t.Errorf("Computer = %q", ev.System.Computer)
	}
	if len(ev.EventData) != 2 {
		t.Fatalf("EventData has %d entries, want 2", len(ev.EventData))
	}
	if ev.EventData[0].Name != "TargetUserName" || ev.EventData[0].Value.String() != "alice" {
		t.Errorf("EventData[0] = %+v", ev.EventData[0])
	}
	if ev.EventData[1].Name != "" {
		t.Errorf("EventData[1].Name = %q, want empty for a positional Data", ev.EventData[1].Name)
	}
	if ev.EventData[1].Value.String() != "positional" {
		t.Errorf("EventData[1].Value = %q", ev.EventData[1].Value.String())
	}
}

func TestEventFromNode_WrongRootIsError(t *testing.T) {
	if _, err := eventFromNode(&Node{Name: "NotAnEvent"}); err == nil {
		t.Fatal("expected an error for a root element that is not <Event>")
	}
}

// EventData marshals as an array, not an object: names are optional and may
// repeat, and an object would silently drop both cases.
func TestEvent_EventDataMarshalsAsArray(t *testing.T) {
	ev := &Event{EventData: []Data{
		{Name: "a", Value: mustVal(t, ValString, utf16le("1"))},
		{Name: "", Value: mustVal(t, ValString, utf16le("2"))},
	}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out struct {
		EventData []struct {
			Name  string `json:"name"`
			Value any    `json:"value"`
		} `json:"event_data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v (payload %s)", err, b)
	}
	if len(out.EventData) != 2 {
		t.Errorf("event_data has %d entries, want 2 — a JSON object would have collapsed them", len(out.EventData))
	}
}

func utf16le(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func ptrVal(v Value) *Value { return &v }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -race -run "TestEvent" ./... -count=1`
Expected: FAIL — `undefined: eventFromNode`.

- [ ] **Step 3: Write the implementation**

Create `event.go`:

```go
// event.go — the typed event assembled from a decoded element tree.
//
// <System> has a fixed schema and gets typed fields. <EventData> does not: its
// <Data> children may be named or positional, names may repeat, and order
// carries meaning — so it is an ordered slice, never a map.
package evtx

import (
	"fmt"
	"time"
)

// Provider identifies the source of an event.
type Provider struct {
	Name string `json:"name,omitempty"`
	GUID string `json:"guid,omitempty"`
}

// System is the fixed-schema <System> block.
type System struct {
	Provider      Provider  `json:"provider"`
	EventID       uint16    `json:"event_id"`
	Qualifiers    uint16    `json:"qualifiers,omitempty"`
	Version       uint8     `json:"version,omitempty"`
	Level         uint8     `json:"level"`
	Task          uint16    `json:"task,omitempty"`
	Opcode        uint8     `json:"opcode,omitempty"`
	Keywords      uint64    `json:"keywords,omitempty"`
	TimeCreated   time.Time `json:"time_created"`
	EventRecordID uint64    `json:"event_record_id"`
	ActivityID    string    `json:"activity_id,omitempty"`
	ProcessID     uint32    `json:"process_id,omitempty"`
	ThreadID      uint32    `json:"thread_id,omitempty"`
	Channel       string    `json:"channel,omitempty"`
	Computer      string    `json:"computer,omitempty"`
	UserID        string    `json:"user_id,omitempty"`
}

// Data is one <Data> element. Name is empty for positional entries.
type Data struct {
	Name  string `json:"name"`
	Value Value  `json:"value"`
}

// Event is a fully decoded event record.
type Event struct {
	RecordID  uint64    `json:"record_id"`
	Timestamp time.Time `json:"timestamp"`
	System    System    `json:"system"`
	EventData []Data    `json:"event_data,omitempty"`
	UserData  *Node     `json:"user_data,omitempty"`
}

// attr returns the named attribute's value, or the zero Value.
func (n *Node) attr(name string) Value {
	for _, a := range n.Attributes {
		if a.Name == name {
			return a.Value
		}
	}
	return Value{}
}

// child returns the first child with the given name, or nil.
func (n *Node) child(name string) *Node {
	for i := range n.Children {
		if n.Children[i].Name == name {
			return &n.Children[i]
		}
	}
	return nil
}

// u64 reads a node's scalar content, or 0 when absent.
func (n *Node) u64() uint64 {
	if n == nil || n.Value == nil {
		return 0
	}
	v, _ := n.Value.Uint64()
	return v
}

// text reads a node's content as text, or "" when absent.
func (n *Node) text() string {
	if n == nil || n.Value == nil {
		return ""
	}
	return n.Value.String()
}

// eventFromNode assembles an Event from a decoded <Event> tree.
func eventFromNode(root *Node) (*Event, error) {
	if root == nil {
		return nil, fmt.Errorf("go_evtx: no root element")
	}
	if root.Name != "Event" {
		return nil, fmt.Errorf("go_evtx: root element is %q, want \"Event\"", root.Name)
	}
	ev := &Event{}

	if sys := root.child("System"); sys != nil {
		if p := sys.child("Provider"); p != nil {
			ev.System.Provider.Name = p.attr("Name").String()
			ev.System.Provider.GUID = p.attr("Guid").String()
		}
		if e := sys.child("EventID"); e != nil {
			ev.System.EventID = uint16(e.u64())
			ev.System.Qualifiers = uint16(func() uint64 { v, _ := e.attr("Qualifiers").Uint64(); return v }())
		}
		ev.System.Version = uint8(sys.child("Version").u64())
		ev.System.Level = uint8(sys.child("Level").u64())
		ev.System.Task = uint16(sys.child("Task").u64())
		ev.System.Opcode = uint8(sys.child("Opcode").u64())
		ev.System.Keywords = sys.child("Keywords").u64()
		ev.System.EventRecordID = sys.child("EventRecordID").u64()
		ev.System.Channel = sys.child("Channel").text()
		ev.System.Computer = sys.child("Computer").text()
		if tc := sys.child("TimeCreated"); tc != nil {
			if ts, ok := tc.attr("SystemTime").Time(); ok {
				ev.System.TimeCreated = ts
			}
		}
		if c := sys.child("Correlation"); c != nil {
			ev.System.ActivityID = c.attr("ActivityID").String()
		}
		if x := sys.child("Execution"); x != nil {
			pid, _ := x.attr("ProcessID").Uint64()
			tid, _ := x.attr("ThreadID").Uint64()
			ev.System.ProcessID = uint32(pid)
			ev.System.ThreadID = uint32(tid)
		}
		if s := sys.child("Security"); s != nil {
			ev.System.UserID = s.attr("UserID").String()
		}
	}

	if ed := root.child("EventData"); ed != nil {
		for i := range ed.Children {
			c := &ed.Children[i]
			if c.Name != "Data" {
				continue
			}
			d := Data{Name: c.attr("Name").String()}
			if c.Value != nil {
				d.Value = *c.Value
			}
			ev.EventData = append(ev.EventData, d)
		}
	}
	if ud := root.child("UserData"); ud != nil {
		ev.UserData = ud
	}
	return ev, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -race -run "TestEvent" ./... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add event.go event_test.go
git commit -m "feat: typed Event assembly with ordered EventData"
```

---

### Task 7: Reader integration and removal of the old API

**Files:**
- Modify: `reader.go`
- Delete: `binxml_reader.go`
- Modify: `example_test.go`, `rotation_test.go`, `reader_concurrency_test.go`, `reader_test.go`
- Modify: `docs/PRD.md`, `CHANGELOG.md`

**Interfaces:**
- Consumes: `decodeRecordBinXML`, `templateCache`, `eventFromNode`.
- Produces: `func (r *Reader) ReadEvent() (*Event, error)`. `Record` and `ReadRecord` no longer exist. `ReadRaw` is unchanged.

- [ ] **Step 1: Write the failing test**

Append to `reader_test.go`:

```go
// The writer's own output must survive the generic decoder. This is the
// round-trip that the old decoder made meaningless: it and the writer shared
// the same wrong assumptions, so a green result proved only their agreement.
func TestReadEvent_RoundTripsWriterOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rt.evtx")

	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord("TestProvider", 4624, map[string]string{
		"ObjectName": "C:\\secret.txt",
	}); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	ev, err := r.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if ev.System.Provider.Name != "TestProvider" {
		t.Errorf("Provider.Name = %q, want %q", ev.System.Provider.Name, "TestProvider")
	}
	if ev.System.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", ev.System.EventID)
	}
	var found bool
	for _, d := range ev.EventData {
		if d.Name == "ObjectName" && d.Value.String() == "C:\\secret.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("ObjectName not found in EventData: %+v", ev.EventData)
	}
}
```

Ensure `reader_test.go` imports `path/filepath` and `testing`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -race -run TestReadEvent_RoundTripsWriterOutput ./... -count=1`
Expected: FAIL — `r.ReadEvent undefined`.

- [ ] **Step 3: Write the implementation**

In `reader.go`, delete the `Record` struct (lines 35–45) and the whole `ReadRecord` method (lines 165–180). Replace the package doc example at lines 11–20 with:

```go
//	for {
//	    ev, err := r.ReadEvent()
//	    if errors.Is(err, evtx.ErrNoMoreRecords) {
//	        break
//	    }
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    fmt.Println(ev.System.EventID, ev.System.Provider.Name)
//	}
```

Add a `templates templateCache` field to `Reader`:

```go
type Reader struct {
	mu        sync.Mutex // guards all fields below; Reader is safe for concurrent use
	f         *os.File
	numChunks int
	chunkIdx  int
	buf       []byte // current chunk (evtxChunkSize bytes)
	recOff    int    // byte offset within buf of the next record to read
	freeOff   int    // byte offset within buf where records end (FreeSpaceOffset)

	// templates caches this chunk's definitions. Offsets are chunk-relative,
	// so it MUST be discarded whenever a new chunk is loaded.
	templates templateCache
}
```

In `loadChunk`, reset the cache alongside the other per-chunk state — add this immediately after `r.chunkIdx = idx`:

```go
	r.templates = templateCache{} // offsets are chunk-relative; the old ones are meaningless here
```

Change `nextRecord` to also report where the payload sits in the chunk. Replace its signature and the two `return` statements that carry values:

```go
func (r *Reader) nextRecord() (recordID uint64, ts uint64, payload []byte, payloadChunkOffset int, err error) {
```

Inside, the early error returns become `return 0, 0, nil, 0, fmt.Errorf(...)`, the exhausted-chunk return becomes `return 0, 0, nil, 0, ErrNoMoreRecords`, and the success return becomes:

```go
		payloadOffset := r.recOff + 24
		r.recOff += size
		return recordID, ts, raw, payloadOffset, nil
```

Update `ReadRaw` to discard the new value:

```go
func (r *Reader) ReadRaw() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _, payload, _, err := r.nextRecord()
	return payload, err
}
```

Add `ReadEvent` where `ReadRecord` was:

```go
// ReadEvent reads and decodes the next event record.
// Returns ErrNoMoreRecords when all records have been read.
//
// A decode failure is returned for that record alone: record framing comes
// from the 24-byte record header, independently of the BinXML payload, so the
// Reader stays positioned on the next record and the caller chooses whether to
// stop or skip. No partial Event is ever returned.
func (r *Reader) ReadEvent() (*Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	recordID, ts, payload, payloadOffset, err := r.nextRecord()
	if err != nil {
		return nil, err
	}
	root, err := decodeRecordBinXML(r.buf, payload, payloadOffset, r.templates)
	if err != nil {
		return nil, fmt.Errorf("go_evtx: chunk %d, record %d: %w", r.chunkIdx, recordID, err)
	}
	ev, err := eventFromNode(root)
	if err != nil {
		return nil, fmt.Errorf("go_evtx: chunk %d, record %d: %w", r.chunkIdx, recordID, err)
	}
	ev.RecordID = recordID
	ev.Timestamp = fromFILETIME(ts)
	return ev, nil
}
```

Delete `binxml_reader.go`, then update the callers:

- `example_test.go:102-109` — replace the `ReadRecord` loop body with:

```go
		ev, err := r.ReadEvent()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(ev.System.EventID, ev.System.Provider.Name, ev.EventData)
```

Adjust the example's `// Output:` comment to match what it now prints.

- `rotation_test.go:201` and `:270`, `reader_concurrency_test.go:50` and `:131` — replace each `r.ReadRecord()` with `r.ReadEvent()`, and each `rec.EventID` with `ev.System.EventID`, renaming the variable accordingly.

- `docs/PRD.md` rows R-02 (two occurrences) — change to: `` `ReadEvent()` returns the next decoded event as an `Event` struct ``.

- `CHANGELOG.md` — add under an `## [Unreleased]` heading:

```markdown
### Changed

- **BREAKING:** `Reader.ReadRecord()` and the `Record` struct are removed. Use
  `Reader.ReadEvent()`, which returns a typed `Event`. The previous decoder
  assumed go-evtx's own template and returned empty fields with fabricated
  names on any real Windows file, without reporting an error.

### Added

- Generic strict BinXML decoding: any Windows-generated `.evtx` file can be
  read, with values carrying their declared type and JSON encoding that
  preserves it.
```

- [ ] **Step 4: Run the full suite**

Run: `go test -race ./... -count=1`
Expected: PASS. Then `go vet ./...` and `GOOS=windows go build ./...` — both clean.

- [ ] **Step 5: Commit**

```bash
git add -u
git add reader.go
git commit -m "feat!: replace ReadRecord with generic strict ReadEvent

BREAKING: Record and ReadRecord are gone. The old decoder assumed
go-evtx's own 42-slot template, so on a real Windows file it returned
empty Provider, zero EventID and field names fabricated from raw bytes -
across 37534 records, without one error. Keeping it as an adapter would
have kept a function that lies."
```

---

### Task 8: Corpus validation and a 3.2 file in CI

**Files:**
- Create: `corpus_test.go`
- Modify: `.github/workflows/format-verify.yml`
- Modify: `testdata/README.md`

**Interfaces:**
- Consumes: `Open`, `ReadEvent`, `ErrNoMoreRecords`.
- Produces: no new API — tests and CI only.

- [ ] **Step 1: Write the failing test**

Create `corpus_test.go`:

```go
package evtx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestCorpus_DecodesRealFiles runs the decoder over whatever real .evtx files
// the developer has locally. They are deliberately not committed: real logs
// carry account names, SIDs and machine names, and a real Security log exceeds
// GitHub's 100 MB per-file limit.
//
// Point EVTX_CORPUS at a directory to enable:
//
//	EVTX_CORPUS=./testdata go test -race -run TestCorpus ./...
func TestCorpus_DecodesRealFiles(t *testing.T) {
	dir := os.Getenv("EVTX_CORPUS")
	if dir == "" {
		t.Skip("EVTX_CORPUS not set; skipping the local real-file corpus")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.evtx"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("EVTX_CORPUS=%s contains no .evtx files", dir)
	}

	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			r, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer r.Close()

			var decoded, failed int
			var firstErr error
			for {
				_, err := r.ReadEvent()
				if errors.Is(err, ErrNoMoreRecords) {
					break
				}
				if err != nil {
					failed++
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				decoded++
			}
			t.Logf("%s: %d decoded, %d failed", filepath.Base(path), decoded, failed)
			if failed > 0 {
				t.Errorf("%d records failed to decode; first error: %v", failed, firstErr)
			}
			if decoded == 0 {
				t.Error("no records decoded at all")
			}
		})
	}
}

// The tracked fixture is format 3.1 and its content is fixed, so this test can
// assert exact values. Do not add content assertions against runner-generated
// files: their content varies per run.
func TestCorpus_TrackedFixtureDecodes(t *testing.T) {
	r, err := Open("testdata/system.evtx")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	ev, err := r.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent on the first record: %v", err)
	}
	if ev.System.Provider.Name == "" {
		t.Error("Provider.Name is empty — this is the exact symptom the old decoder had")
	}
	if ev.System.EventID == 0 {
		t.Error("EventID is zero — the old decoder returned zero for all 1601 records")
	}
	if ev.System.Computer == "" {
		t.Error("Computer is empty")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -race -run TestCorpus_TrackedFixtureDecodes ./... -count=1`
Expected: FAIL initially if any decoding gap remains against a real 3.1 file. Fix the decoder until it passes — this test is the first real exercise of the whole path.

- [ ] **Step 3: Add the 3.2 CI job**

Append this job to `.github/workflows/format-verify.yml`:

```yaml
  decode-real-32:
    name: Decode a real format-3.2 file
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.5'

      # The runner's own live logs are a genuine format-3.2 file: no licence
      # question, no personal data, no repository weight. Their CONTENT varies
      # per run, so this job may only assert "decodes without error" — never a
      # golden value. Do not add content assertions here.
      - name: Export the runner's Application log
        shell: pwsh
        run: |
          New-Item -ItemType Directory -Force -Path corpus | Out-Null
          wevtutil epl Application corpus/application.evtx
          $v = [System.IO.File]::ReadAllBytes("corpus/application.evtx")[36]
          Write-Host "exported format minor version: $v"
          if ($v -ne 2) { Write-Host "note: expected minor version 2 (3.2), got $v" }

      - name: Decode it
        run: go test -race -run TestCorpus_DecodesRealFiles ./... -count=1 -v
        env:
          EVTX_CORPUS: corpus
```

- [ ] **Step 4: Verify locally, then push and check CI**

Run: `go test -race ./... -count=1` — full suite green.
Run: `EVTX_CORPUS=./testdata go test -race -run TestCorpus ./... -count=1 -v` — every local real file decodes with zero failures.

Then push and confirm the `decode-real-32` job passes. Use the measurement helper rather than polling by hand:

```bash
.claude/skills/ci-measure/scripts/ci-measure.sh
```

- [ ] **Step 5: Document the corpus convention**

In `testdata/README.md`, under the "Local-only corpus (not committed)" section, append:

```markdown
To run the decoder against every local real file:

```bash
EVTX_CORPUS=./testdata go test -race -run TestCorpus ./... -count=1 -v
```

The test skips when `EVTX_CORPUS` is unset, so a clean checkout is unaffected.
CI gets its format-3.2 coverage from `wevtutil epl` on the `windows-latest`
runner instead — that file's content varies per run, so that job asserts only
that decoding succeeds, never a specific value.
```

- [ ] **Step 6: Commit**

```bash
git add corpus_test.go .github/workflows/format-verify.yml testdata/README.md
git commit -m "test: decode real files locally and a real 3.2 file in CI"
```

---

## Self-review

**Spec coverage.**

| Spec requirement | Task |
|---|---|
| Open any Windows `.evtx`, structured typed events | 5, 6, 7 |
| JSON with types preserved | 2, 6 |
| Fail loudly, precisely | 1, 3, 5 |
| Serve as differential oracle | 8 (and the round-trip test in 7) |
| `value.go` / `template.go` / `binxml_decode.go` / `event.go` split | 1–6 |
| Per-chunk template cache | 4, 7 |
| Value type table, arrays and AnsiString rejected | 1 |
| `BinXml` recursion | 5 |
| Ordered `EventData`, positional `<Data>` | 6 |
| Three strictness rules | 3 (rule 3), 5 (rules 1 and 2) |
| No partial output | 5, 7 |
| Framing survives decode failure | 7 |
| Errors carry position | 7 |
| Corpus: tracked 3.1, runner 3.2, local env-gated | 8 |
| Remove old `Record` outright | 7 |
| Non-goals (no XML rendering, no filtering) | nothing implements them — correct |

**Not covered, deliberately:** the 3.2 template bucket rule stays unknown; the spec records it as not blocking, since the decoder resolves templates through each record's inline `template_offset` rather than the hash tables. F2 (8-byte alignment) is out of scope and stays last, after this work.

**Type consistency.** `Value.Type` is the exported field throughout; `ValueType.String()` and `Value.String()` are distinct methods on distinct types. `decodeRecordBinXML(chunk, payload []byte, payloadChunkOffset int, cache templateCache)` matches its call in Task 7. `nextRecord` gains a fifth return value in Task 7 and both call sites are updated there. `templateCache.get` and `parseTemplateDef` take `(chunk []byte, off int)` in Tasks 4 and 5 alike.

**Known risk carried into execution.** Task 5's `readName` distinguishes an inline NameNode from a shared one by comparing the offset against the current position. The encoder always writes them inline, and real files use both forms. Task 8's tracked-fixture test is what proves the shared-offset branch on real data; expect to iterate there rather than in Task 5's synthetic test.
