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
