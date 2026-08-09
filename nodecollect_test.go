// nodecollect_test.go — buildBinXML must report where it emitted every
// NameNode and TemplateNode, as chunk-relative offsets, without changing the
// bytes it emits.
package evtx

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"unicode/utf16"
)

// TestBuildBinXML_ReportsNameOffsets checks that every reported name offset
// really points at a NameNode whose decoded string and stored hash match the
// reported key.
func TestBuildBinXML_ReportsNameOffsets(t *testing.T) {
	const base = uint32(evtxRecordsStart + evtxRecordHeaderSize)
	res := buildBinXML(4663, 1, testFields(), base)

	if len(res.names) == 0 {
		t.Fatal("buildBinXML reported no NameNodes")
	}
	if len(res.templates) != 1 {
		t.Fatalf("reported %d templates, want exactly 1", len(res.templates))
	}

	for _, ref := range res.names {
		// Offsets are chunk-relative; the payload starts at `base`.
		rel := int(ref.offset) - int(base)
		if rel < 0 || rel+8 > len(res.payload) {
			t.Fatalf("name offset %d outside payload [%d, %d)", ref.offset, base, int(base)+len(res.payload))
		}
		storedHash := binary.LittleEndian.Uint16(res.payload[rel+4:])
		n := int(binary.LittleEndian.Uint16(res.payload[rel+6:]))
		u16 := make([]uint16, n)
		for i := 0; i < n; i++ {
			u16[i] = binary.LittleEndian.Uint16(res.payload[rel+8+2*i:])
		}
		name := string(utf16.Decode(u16))

		if uint16(ref.key) != storedHash {
			t.Errorf("name %q: reported key 0x%08x (low 0x%04x), NameNode stores 0x%04x",
				name, ref.key, uint16(ref.key), storedHash)
		}
		if sdbmHash(name) != ref.key {
			t.Errorf("name %q: reported key 0x%08x, sdbmHash gives 0x%08x", name, ref.key, sdbmHash(name))
		}
	}
}

// TestBuildBinXML_TemplateSelfPointer asserts the structural precondition the
// template table requires, and that Task 2 confirmed against the real fixture:
// the dword at templateOffset-4 equals templateOffset, and templateOffset-10
// holds the 0x0C TemplateInstance token.
func TestBuildBinXML_TemplateSelfPointer(t *testing.T) {
	const base = uint32(evtxRecordsStart + evtxRecordHeaderSize)
	res := buildBinXML(4663, 1, testFields(), base)

	ref := res.templates[0]
	rel := int(ref.offset) - int(base)
	if rel < 10 {
		t.Fatalf("template offset %d leaves no room for the 10-byte instance preamble", ref.offset)
	}
	if tok := res.payload[rel-10]; tok != 0x0C {
		t.Errorf("byte before template instance = 0x%02x, want 0x0C", tok)
	}
	if ptr := binary.LittleEndian.Uint32(res.payload[rel-4:]); ptr != ref.offset {
		t.Errorf("template self-pointer = %d, want %d", ptr, ref.offset)
	}
}

// goldenFields returns testFields() with a frozen TimeCreated, matching the
// fields the golden file in testdata/binxml-golden.bin was captured with.
//
// testFields() stamps TimeCreated with time.Now(), which is exactly right for
// every other test in this package but wrong here: buildBinXML encodes it
// into the payload as a FILETIME substitution value, so a live timestamp
// would make TestBuildBinXML_PayloadUnchangedByCollection compare against a
// different value on every run and fail regardless of whether the encoder
// actually changed anything. Freezing TimeCreated for this one comparison
// keeps the golden file meaningful without touching the shared helper.
func goldenFields() map[string]string {
	f := testFields()
	f["TimeCreated"] = "2024-01-01T00:00:00.000000000Z"
	return f
}

// TestBuildBinXML_PayloadUnchangedByCollection compares against bytes captured
// from the pre-refactor encoder. Task 4 was plumbing: it did not alter a
// single byte of the payload, nor did Task 6 (which changed the chunk header,
// not the payload). Task 7 briefly changed it — buildBinXML appended the
// fragment EOF token and 8-aligned the record (W1/W2) — and that was reverted
// in cfa5f9b when it regressed Windows' STAGE2 READ from 403 records to
// failing on record 0. The payload is therefore byte-identical to the
// pre-Task-7 encoder again, and the golden file was regenerated back in that same
// commit; this comparison protects the encoding from here forward.
//
// If a later change deliberately alters the encoding, it regenerates the golden
// file in the same commit and says so in the commit message.
func TestBuildBinXML_PayloadUnchangedByCollection(t *testing.T) {
	want, err := os.ReadFile("testdata/binxml-golden.bin")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	res := buildBinXML(4663, 1, goldenFields(), uint32(evtxRecordsStart+evtxRecordHeaderSize))
	if !bytes.Equal(res.payload, want) {
		t.Errorf("payload changed: got %d bytes, want %d", len(res.payload), len(want))
		for i := 0; i < len(want) && i < len(res.payload); i++ {
			if res.payload[i] != want[i] {
				t.Fatalf("first difference at byte %d: got 0x%02x, want 0x%02x",
					i, res.payload[i], want[i])
			}
		}
	}
}
