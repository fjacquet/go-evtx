package evtx

import (
	"encoding/json"
	"strings"
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
	// 2020-01-01T00:00:00Z. A 1601-era FILETIME would overflow int64 inside
	// fromFILETIME; real records carry modern timestamps, and the overflow is
	// tracked separately as a robustness gap in binformat.go.
	v, err := decodeValue(ValFileTime, []byte{0x00, 0x00, 0x05, 0x69, 0x36, 0xc0, 0xd5, 0x01})
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	got, ok := v.Time()
	if !ok {
		t.Fatal("Time() reported not-a-time for a FileTime value")
	}
	want := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Time() = %v, want %v", got, want)
	}
}

// Test rejection of malformed variable-length types
func TestDecodeValue_GuidWrongLength(t *testing.T) {
	if _, err := decodeValue(ValGuid, []byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for Guid with wrong length")
	}
}

func TestDecodeValue_SidLengthMismatch(t *testing.T) {
	// Declares 2 sub-authorities but only provides 1 (missing 4 bytes)
	data := []byte{0x01, 0x02, 0, 0, 0, 0, 0, 0x05, 0x12, 0, 0, 0}
	if _, err := decodeValue(ValSid, data); err == nil {
		t.Fatal("expected error for Sid with mismatched length")
	}
}

func TestDecodeValue_SizeTWrongWidth(t *testing.T) {
	if _, err := decodeValue(ValSizeT, []byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("expected error for SizeT with non-4/8 byte width")
	}
}

func TestDecodeValue_NullWithData(t *testing.T) {
	if _, err := decodeValue(ValNull, []byte{0x01}); err == nil {
		t.Fatal("expected error for Null with data")
	}
}

func TestDecodeValue_UTF16OddLength(t *testing.T) {
	if _, err := decodeValue(ValString, []byte{'h', 0, 'i'}); err == nil {
		t.Fatal("expected error for UTF-16 with odd length")
	}
}

func TestDecodeValue_Real64(t *testing.T) {
	// IEEE 754 double for 3.14159...
	data := []byte{0x6e, 0x2d, 0x44, 0x54, 0xfb, 0x21, 0x09, 0x40}
	v, err := decodeValue(ValReal64, data)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	// Just verify it decodes and produces a string
	if s := v.String(); s == "" {
		t.Error("Real64 String() returned empty")
	}
}

func TestDecodeValue_Binary(t *testing.T) {
	data := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}
	v, err := decodeValue(ValBinary, data)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	if s := v.String(); s != "48656c6c6f" {
		t.Errorf("String() = %q, want %q", s, "48656c6c6f")
	}
}

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

// Int64 at the 2^53 boundary must also quote to maintain precision.
func TestValue_MarshalJSON_Int64At2Pow53Quotes(t *testing.T) {
	// 2^53 = 0x0000000020000000 in little-endian bytes
	v, err := decodeValue(ValInt64, []byte{0, 0, 0, 0, 0, 0, 0x20, 0})
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

// Int64 just inside the boundary stays a bare number.
func TestValue_MarshalJSON_Int64JustInside2Pow53(t *testing.T) {
	// 2^53 - 1 = 0x00000000ffffff1f in little-endian
	v, err := decodeValue(ValInt64, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0})
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) == `"9007199254740991"` {
		t.Errorf("Marshal = %s, but 2^53-1 should stay a bare number", b)
	}
	if string(b) != `9007199254740991` {
		t.Errorf("Marshal = %s, want bare number", b)
	}
}

// Int64 at -2^53 must quote.
func TestValue_MarshalJSON_Int64AtNeg2Pow53Quotes(t *testing.T) {
	// -2^53 = 0xffffffffe0000000 in little-endian two's complement
	v, err := decodeValue(ValInt64, []byte{0, 0, 0, 0, 0, 0, 0xe0, 0xff})
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != `"-9007199254740992"` {
		t.Errorf("Marshal = %s, want a quoted string at -2^53", b)
	}
}

// BinXml present-but-undecoded must error, not silently produce null.
func TestValue_MarshalJSON_BinXmlUndecoded(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	v, err := decodeValue(ValBinXML, data)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	_, err = json.Marshal(v)
	if err == nil {
		t.Fatal("Marshal should error for undecoded BinXml, not return null")
	}
	if !strings.Contains(err.Error(), "BinXml value has no decoded fragment") {
		t.Errorf("error message = %q, want to contain 'BinXml value has no decoded fragment'", err.Error())
	}
}

// Guid marshals to its canonical string form.
func TestValue_MarshalJSON_Guid(t *testing.T) {
	data := []byte{
		0x2d, 0x6d, 0x5c, 0x6e, 0x1a, 0x2b, 0x3c, 0x4d,
		0x9a, 0xbc, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	}
	v, err := decodeValue(ValGuid, data)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != `"6e5c6d2d-2b1a-4d3c-9abc-010203040506"` {
		t.Errorf("Marshal = %s, want canonical GUID form", b)
	}
}

// FileTime marshals via String() to RFC 3339 form.
func TestValue_MarshalJSON_FileTime(t *testing.T) {
	// 2020-01-01T00:00:00Z
	v, err := decodeValue(ValFileTime, []byte{0x00, 0x00, 0x05, 0x69, 0x36, 0xc0, 0xd5, 0x01})
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// String() returns RFC3339Nano format
	if !strings.Contains(string(b), "2020") {
		t.Errorf("Marshal = %s, want RFC 3339 time format", b)
	}
}

// HexInt32 marshals to hex notation.
func TestValue_MarshalJSON_HexInt32(t *testing.T) {
	v, err := decodeValue(ValHexInt32, []byte{0xef, 0xbe, 0xad, 0xde})
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != `"0xdeadbeef"` {
		t.Errorf("Marshal = %s, want hex notation", b)
	}
}

// Real64 (double precision float) marshals as a JSON number.
func TestValue_MarshalJSON_Real64(t *testing.T) {
	// IEEE 754 double for pi ≈ 3.14159...
	v, err := decodeValue(ValReal64, []byte{0x6e, 0x2d, 0x44, 0x54, 0xfb, 0x21, 0x09, 0x40})
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Should be a JSON number close to 3.14
	if !strings.Contains(string(b), "3.14") {
		t.Errorf("Marshal = %s, want a JSON number close to 3.14", b)
	}
}

// Unknown value type returns an error.
func TestValue_MarshalJSON_UnknownType(t *testing.T) {
	v := Value{Type: ValEvtHandle}
	_, err := json.Marshal(v)
	if err == nil {
		t.Fatal("Marshal should error for unknown type")
	}
	if !strings.Contains(err.Error(), "cannot marshal value type") {
		t.Errorf("error message = %q, want to contain 'cannot marshal value type'", err.Error())
	}
}
