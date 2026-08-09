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
