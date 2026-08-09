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

func TestParseTemplateDef_HeaderTooSmall(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	// offset where the header doesn't fit in the chunk.
	off := evtxChunkSize - 10
	if _, err := parseTemplateDef(chunk, off); err == nil {
		t.Fatal("expected an error when header doesn't fit in the chunk")
	}
}

func TestParseTemplateDef_NegativeOffset(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	if _, err := parseTemplateDef(chunk, -1); err == nil {
		t.Fatal("expected an error for a negative offset")
	}
}

func TestParseTemplateDef_EmptyBodySucceeds(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	copy(chunk[0:8], evtxChunkMagic)
	off := 500
	// data_size = 0 (no body bytes follow)
	chunk[off+20] = 0
	for i := 0; i < 16; i++ {
		chunk[off+4+i] = byte(i + 1)
	}

	def, err := parseTemplateDef(chunk, off)
	if err != nil {
		t.Fatalf("parseTemplateDef with empty body: %v", err)
	}
	if len(def.Body) != 0 {
		t.Fatalf("Body length = %d, want 0", len(def.Body))
	}
	if def.BodyChunkOffset != off+templateDefHeaderSize {
		t.Errorf("BodyChunkOffset = %d, want %d", def.BodyChunkOffset, off+templateDefHeaderSize)
	}
}

func TestParseTemplateDef_HeaderAtChunkEnd(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	copy(chunk[0:8], evtxChunkMagic)
	// offset where the header exactly fits with no body.
	off := evtxChunkSize - templateDefHeaderSize
	chunk[off+20] = 0 // data_size = 0
	for i := 0; i < 16; i++ {
		chunk[off+4+i] = byte(i + 1)
	}

	def, err := parseTemplateDef(chunk, off)
	if err != nil {
		t.Fatalf("parseTemplateDef at chunk end: %v", err)
	}
	if len(def.Body) != 0 {
		t.Fatalf("Body length = %d, want 0", len(def.Body))
	}
	if def.BodyChunkOffset != evtxChunkSize {
		t.Errorf("BodyChunkOffset = %d, want %d", def.BodyChunkOffset, evtxChunkSize)
	}
}

// security.evtx holds 9358 definitions against 183952 records: without a cache
// the same definition is reparsed hundreds of times.
func TestTemplateCache_ReusesTheSamePointer(t *testing.T) {
	body := []byte{tokFragmentHeader, 0x01, 0x01, 0x00, tokEOF}
	chunk := buildChunkWithTemplate(2048, body)
	cache := newTemplateCache(chunk)

	a, err := cache.get(2048)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	b, err := cache.get(2048)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if a != b {
		t.Error("cache returned a different pointer for the same offset")
	}
}
