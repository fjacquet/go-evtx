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
