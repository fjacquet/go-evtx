package evtx

// conformance_test.go — the encoder's output must obey the rules measured on
// real Windows output, asserted against a file this package writes right here.
//
// This replaces what cmd/gen-fixture used to be for. That generator was frozen
// so every row of docs/format-baseline.md could be compared against one
// unchanging input, but the comparison it enabled was never really
// reproducible: rerunning it after an encoder change produces different bytes,
// so reproducing an old row always needed the library of the time, not just
// the generator of the time. It was removed once ErrMissingProviderName made
// it unrunnable.
//
// What is worth keeping is not the old bytes but the rules they taught us.
// Each assertion below is a measurement over the derivation corpus, cited with
// its count, and each one was violated by this encoder at some point:
//
//   - W2: 37 364 of 37 364 real records are 8-aligned in size and in offset.
//   - W1: 37 364 of 37 364 carry 1 to 8 trailing bytes after their
//     substitution array — the fragment EOF token plus 0 to 7 padding.
//   - F18a: of 1 686 434 zero-length substitution descriptors, every one
//     declares NULL; a zero-length String occurs zero times.
//   - F18b: a NormalSubstitution paired with a NULL array entry occurs zero
//     times in 27 million shape observations. NULL is only legal for a value
//     the template also marks optional.
//
// A change that breaks one of these fails here, in seconds, rather than on a
// Windows runner several steps later with "The data is invalid."

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConformanceFixture writes a multi-chunk file exercising the shapes that
// have actually broken: empty values, non-ASCII, non-BMP, and a record close
// to the chunk ceiling.
func writeConformanceFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "conformance.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 120; i++ {
		objectName := fmt.Sprintf(`C:\logs\file-%03d.txt`, i)
		switch i % 4 {
		case 1:
			objectName = `C:\journaux\fichier-é-à-ü.txt` // non-ASCII, BMP
		case 2:
			objectName = `C:\logs\emoji-🔥-` + fmt.Sprint(i) // non-BMP, surrogate pair
		case 3:
			objectName = `C:\logs\` + strings.Repeat("w", 3000)
		}
		// Only some fields are supplied: the unsupplied ones are what exercise
		// the NULL encoding, which is the rule most recently got wrong.
		if err := w.WriteRecord(4663, map[string]string{
			"ProviderName":    "Microsoft-Windows-Security-Auditing",
			"Computer":        "TESTHOST",
			"SubjectUserName": "verifier",
			"ObjectName":      objectName,
			"TimeCreated":     "2026-08-10T12:00:00Z",
		}); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// walkChunkRecords calls fn for each record in a chunk, and is strict about
// boundaries on purpose. An earlier version of these tests broke out of the
// loop on an implausible size, so a malformed record would silently shorten
// the walk and the test would pass having checked fewer records than it
// thought — the same "stopped testing without saying so" failure this
// repository has hit three times. A bad boundary is fatal, and the walk must
// end exactly at the chunk's free-space offset.
func walkChunkRecords(t *testing.T, chunk []byte, chunkIndex int, fn func(off, size int)) {
	t.Helper()
	free := int(binary.LittleEndian.Uint32(chunk[48:52]))
	if free < int(evtxChunkHeaderSize) || free > len(chunk) {
		t.Fatalf("chunk %d: free space offset %d outside the chunk", chunkIndex, free)
	}
	off := int(evtxChunkHeaderSize)
	for off < free {
		if off+24 > free {
			t.Fatalf("chunk %d: %d bytes before free space offset %d — too few for a record header",
				chunkIndex, free-off, free)
		}
		size := int(binary.LittleEndian.Uint32(chunk[off+4:]))
		if size < 28 || off+size > free {
			t.Fatalf("chunk %d: record at %d declares size %d, which does not fit before free space offset %d",
				chunkIndex, off, size, free)
		}
		fn(off, size)
		off += size
	}
	if off != free {
		t.Fatalf("chunk %d: record walk ended at %d, free space offset is %d", chunkIndex, off, free)
	}
}

// TestConformance_RecordsAreAlignedAndTerminated walks every record of a
// freshly written file and checks W1 and W2 at the byte level.
func TestConformance_RecordsAreAlignedAndTerminated(t *testing.T) {
	raw, err := os.ReadFile(writeConformanceFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	chunks := int(binary.LittleEndian.Uint16(raw[42:44]))
	if chunks < 2 {
		t.Fatalf("fixture has %d chunks, want at least 2 — it must cross a chunk boundary", chunks)
	}

	records := 0
	for ci := 0; ci < chunks; ci++ {
		start := int(evtxFileHeaderSize) + ci*int(evtxChunkSize)
		chunk := raw[start : start+int(evtxChunkSize)]
		cache := newTemplateCache(chunk)

		if free := int(binary.LittleEndian.Uint32(chunk[48:52])); free > 65528 {
			t.Errorf("chunk %d: free space offset %d — real Windows never exceeds 65528 in 2900 measured chunks",
				ci, free)
		}
		walkChunkRecords(t, chunk, ci, func(off, size int) {
			// W2.
			if size%8 != 0 {
				t.Errorf("chunk %d record at %d: size %d is not a multiple of 8", ci, off, size)
			}
			if off%8 != 0 {
				t.Errorf("chunk %d: record offset %d is not a multiple of 8", ci, off)
			}
			// W1: the decoder's own top-level rule is exactly this, so a
			// successful decode proves the EOF token and padding are present
			// and correctly counted.
			if _, err := decodeRecordBinXML(cache, off+24, size-28); err != nil {
				t.Errorf("chunk %d record at %d: %v", ci, off, err)
			}
			records++
		})
	}
	if records != 120 {
		t.Fatalf("walked %d records, want 120", records)
	}
}

// TestConformance_AbsentValuesDeclareNull checks F18 at both ends of the
// record: the substitution array never declares a real type for a zero-length
// value, and no NormalSubstitution is paired with a NULL array entry.
func TestConformance_AbsentValuesDeclareNull(t *testing.T) {
	raw, err := os.ReadFile(writeConformanceFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	chunks := int(binary.LittleEndian.Uint16(raw[42:44]))

	zeroLength, absent := 0, 0
	for ci := 0; ci < chunks; ci++ {
		start := int(evtxFileHeaderSize) + ci*int(evtxChunkSize)
		chunk := raw[start : start+int(evtxChunkSize)]
		cache := newTemplateCache(chunk)
		cache.onShape = func(e shapeEvent) {
			if e.Kind != shapeKindSubstitution {
				return
			}
			// F18b.
			if e.Token == tokNormalSub && e.Actual == ValNull {
				t.Errorf("NormalSubstitution paired with a NULL array entry (declared %s) — "+
					"zero occurrences in 27 million real observations; NULL is only legal "+
					"for a value the template also marks optional", e.Declared)
			}
			if e.Actual == ValNull {
				absent++
			}
		}
		walkChunkRecords(t, chunk, ci, func(off, size int) {
			// The decode is what drives the shape hook above, which is how
			// F18b gets checked. F18a is checked separately below, straight
			// from the descriptors, so a wrong declared type cannot hide
			// behind a successful decode.
			if _, err := decodeRecordBinXML(cache, off+24, size-28); err != nil {
				t.Fatalf("chunk %d record at %d: %v", ci, off, err)
			}
			zeroLength += countZeroLengthDescriptors(t, chunk, off, size)
		})
	}
	if absent == 0 {
		t.Fatal("no NULL substitution values seen — the fixture must leave some fields unsupplied")
	}
	if zeroLength == 0 {
		t.Fatal("no zero-length descriptors seen — the fixture must leave some fields unsupplied")
	}
	t.Logf("%d zero-length descriptors, all declaring NULL; %d absent substitution values", zeroLength, absent)
}

// countZeroLengthDescriptors reads one record's substitution-array descriptors
// directly and fails on any zero-length entry that declares something other
// than NULL.
func countZeroLengthDescriptors(t *testing.T, chunk []byte, recOff, size int) int {
	t.Helper()
	payload := chunk[recOff+24 : recOff+size-4]
	pos := 0
	if len(payload) > 0 && payload[0] == tokFragmentHeader {
		pos = 4
	}
	if pos+10 > len(payload) || payload[pos] != tokTemplateInstance {
		t.Fatalf("record at %d: no template instance", recOff)
	}
	defOff := int(le32(payload[pos+6:]))
	pos += 10
	if defOff == recOff+24+pos {
		dataSize := int(le32(chunk[defOff+20:]))
		pos += templateDefHeaderSize + dataSize
	}
	if pos+4 > len(payload) {
		t.Fatalf("record at %d: substitution array truncated", recOff)
	}
	count := int(le32(payload[pos:]))
	pos += 4
	zero := 0
	for i := 0; i < count; i++ {
		if pos+4 > len(payload) {
			t.Fatalf("record at %d: descriptor %d truncated", recOff, i)
		}
		sz := int(le16(payload[pos:]))
		typ := ValueType(payload[pos+2])
		pos += 4
		if sz != 0 {
			continue
		}
		zero++
		if typ != ValNull {
			t.Errorf("record at %d: substitution %d is zero-length but declares %s — "+
				"every one of 1 686 434 zero-length descriptors in the corpus declares NULL, "+
				"and a zero-length String occurs zero times", recOff, i, typ)
		}
	}
	return zero
}

// TestConformance_TemplateDeclaredOncePerChunk pins F19. Real Windows declares
// a template definition once and points every later instance in the chunk
// backward at it: 545 definitions across the derivation corpus against 36 819
// backward references, and not one forward reference. go-evtx inlined a full
// copy in every record until v0.7.3, which cost 46% of the file.
func TestConformance_TemplateDeclaredOncePerChunk(t *testing.T) {
	raw, err := os.ReadFile(writeConformanceFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	chunks := int(binary.LittleEndian.Uint16(raw[42:44]))

	inline, backward := 0, 0
	for ci := 0; ci < chunks; ci++ {
		start := int(evtxFileHeaderSize) + ci*int(evtxChunkSize)
		chunk := raw[start : start+int(evtxChunkSize)]
		cache := newTemplateCache(chunk)
		perChunkInline := 0
		walkChunkRecords(t, chunk, ci, func(off, size int) {
			rf := recordFact{}
			fragScan(cache, off+24, size-28, &rf)
			if !rf.HasDef {
				t.Fatalf("chunk %d record at %d: no template instance found", ci, off)
			}
			switch {
			case rf.Inline:
				perChunkInline++
				inline++
			case rf.DefOff < off:
				backward++
			default:
				t.Errorf("chunk %d record at %d: template offset %d points forward — "+
					"zero forward references occur in the derivation corpus", ci, off, rf.DefOff)
			}
		})
		if perChunkInline != 1 {
			t.Errorf("chunk %d declares %d template definitions, want exactly 1", ci, perChunkInline)
		}
	}
	if backward == 0 {
		t.Fatal("no record referenced a shared definition — the fixture must put several records in a chunk")
	}
	t.Logf("%d inline definitions, %d backward references across %d chunks", inline, backward, chunks)
}
