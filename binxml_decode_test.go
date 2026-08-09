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
	root, err := decodeRecordBinXML(chunk, payload, off, newTemplateCache(chunk))
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
	if _, err := decodeRecordBinXML(chunk, corrupt, off, newTemplateCache(chunk)); err == nil {
		t.Fatal("expected an error for an unrecognised token")
	}
}
