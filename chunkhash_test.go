// chunkhash_test.go — validates go-evtx's chunk hash table rules against a
// real Windows-generated file. See testdata/README.md for provenance.
package evtx

import (
	"encoding/binary"
	"os"
	"testing"
	"unicode/utf16"
)

// readFixtureChunk returns chunk n of testdata/system.evtx as a 65536-byte
// slice, failing the test if it is absent or not a chunk.
func readFixtureChunk(t *testing.T, n int) []byte {
	t.Helper()
	chunk, ok := readFixtureChunkOK(t, n)
	if !ok {
		t.Fatalf("fixture has no chunk %d", n)
	}
	return chunk
}

// readFixtureChunkOK is readFixtureChunk for callers that walk until the file
// runs out. It reports ok=false past the last chunk instead of failing, and
// still fails hard on a chunk within the file's own advertised chunk count
// that has bad magic — that would mean the fixture is damaged, not that the
// walk finished.
//
// "The file's own advertised chunk count" is load-bearing here, not "the
// file's byte length". A real Windows-generated .evtx pre-allocates chunk
// slots beyond what it has actually written: this fixture is 17
// evtxChunkSize slots long by byte size, but its file header's ChunkCount
// field (offset 42, uint16 LE — the same field reader.go's Open reads at
// reader.go:76) says 9. Chunks 9-16 are legitimately all-zero, unused
// capacity, not corruption; walking past ChunkCount and hard-failing on
// their absent magic would mistake normal EVTX layout for a damaged fixture.
func readFixtureChunkOK(t *testing.T, n int) ([]byte, bool) {
	t.Helper()
	raw, err := os.ReadFile("testdata/system.evtx")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	numChunks := int(binary.LittleEndian.Uint16(raw[42:44]))
	if n >= numChunks {
		return nil, false
	}
	off := evtxFileHeaderSize + n*evtxChunkSize
	if off+evtxChunkSize > len(raw) {
		return nil, false
	}
	chunk := raw[off : off+evtxChunkSize]
	if string(chunk[0:8]) != "ElfChnk\x00" {
		t.Fatalf("chunk %d: bad magic %q", n, chunk[0:8])
	}
	return chunk, true
}

// nameNodeAt decodes a NameNode at a chunk-relative offset.
// Layout: next_offset(4) hash(2) char_count(2) UTF-16LE chars null(2)
func nameNodeAt(t *testing.T, chunk []byte, off uint32) (next uint32, storedHash uint16, name string) {
	t.Helper()
	if int(off)+8 > len(chunk) {
		t.Fatalf("NameNode offset %d out of range", off)
	}
	next = binary.LittleEndian.Uint32(chunk[off:])
	storedHash = binary.LittleEndian.Uint16(chunk[off+4:])
	n := int(binary.LittleEndian.Uint16(chunk[off+6:]))
	u16 := make([]uint16, n)
	for i := 0; i < n; i++ {
		u16[i] = binary.LittleEndian.Uint16(chunk[int(off)+8+2*i:])
	}
	return next, storedHash, string(utf16.Decode(u16))
}

// TestFixture_StringTableBucketRule walks the 64-entry common-string table of
// several real chunks and asserts every chained name hashes into the bucket it
// was found in. This is what proves `hash % 64` and the SDBM constant.
func TestFixture_StringTableBucketRule(t *testing.T) {
	checked := 0
	for chunkNo := 0; chunkNo < 5; chunkNo++ {
		chunk := readFixtureChunk(t, chunkNo)
		for bucket := 0; bucket < numStringBuckets; bucket++ {
			off := getBucket(chunk, stringTableStart, bucket)
			for seen := 0; off > 0; seen++ {
				if seen > 512 {
					t.Fatalf("chunk %d bucket %d: chain does not terminate", chunkNo, bucket)
				}
				next, storedHash, name := nameNodeAt(t, chunk, off)
				h := sdbmHash(name)
				if got := nameBucket(h); got != bucket {
					t.Errorf("chunk %d: name %q hashes to bucket %d, found in bucket %d",
						chunkNo, name, got, bucket)
				}
				if uint16(h) != storedHash {
					t.Errorf("chunk %d: name %q computed hash 0x%04x, stored 0x%04x",
						chunkNo, name, uint16(h), storedHash)
				}
				checked++
				off = next
			}
		}
	}
	if checked == 0 {
		t.Fatal("no NameNodes found in any fixture chunk — the table walk is wrong")
	}
	t.Logf("validated %d NameNodes across 5 chunks", checked)
}

// TestFixture_TemplateTableBucketRule does the same for the 32-entry template
// table, and additionally asserts the structural precondition python-evtx
// relies on: the dword immediately before a template node equals that node's
// own offset, and the byte 10 before it is the 0x0C TemplateInstance token.
//
// The bucket rule here is the CORRECTED one — SDBM over the full 16-byte GUID
// read as 8 little-endian uint16 units. The original spec said the bucket was
// `template_id % 32` over the first four GUID bytes; measured against this very
// fixture that scores 10 of 146, i.e. chance. Do not "simplify" it back.
//
// Every chunk is walked, not the first five: the whole point of this test is
// coverage of real-world template shapes, and the fixture has 17 chunks.
func TestFixture_TemplateTableBucketRule(t *testing.T) {
	checked := 0
	for chunkNo := 0; ; chunkNo++ {
		chunk, ok := readFixtureChunkOK(t, chunkNo)
		if !ok {
			break
		}
		for bucket := 0; bucket < numTemplateBuckets; bucket++ {
			off := getBucket(chunk, templateTableStart, bucket)
			for seen := 0; off > 0; seen++ {
				if seen > 256 {
					t.Fatalf("chunk %d bucket %d: template chain does not terminate", chunkNo, bucket)
				}
				if int(off) < 10 || int(off)+24 > len(chunk) {
					t.Fatalf("chunk %d: template offset %d out of range", chunkNo, off)
				}
				if tok := chunk[off-10]; tok != 0x0C {
					t.Errorf("chunk %d: template at %d preceded by token 0x%02x, want 0x0C",
						chunkNo, off, tok)
				}
				if ptr := binary.LittleEndian.Uint32(chunk[off-4:]); ptr != off {
					t.Errorf("chunk %d: template at %d has self-pointer %d", chunkNo, off, ptr)
				}
				next := binary.LittleEndian.Uint32(chunk[off:])
				guid := chunk[off+4 : off+20]
				if got := templateBucket(guid); got != bucket {
					t.Errorf("chunk %d: GUID % x hashes to bucket %d, found in bucket %d",
						chunkNo, guid, got, bucket)
				}
				checked++
				off = next
			}
		}
	}
	// The fixture is known to hold 146 template entries across 17 chunks. An
	// exact pin turns a silently-truncated walk into a failure.
	if checked != 146 {
		t.Errorf("validated %d TemplateNodes, want 146 — the table walk changed", checked)
	}
}

// TestFillHashTables_FirstOccurrenceWins registers three distinct names and
// one duplicate. The duplicate must not appear in any chain: records point at
// their own inline NameNodes, so a second copy of the same name is reachable
// without being in the table, and chaining it would make lookups return
// arbitrary duplicates.
func TestFillHashTables_FirstOccurrenceWins(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	h := sdbmHash("Provider")
	names := []chunkRef{
		{key: h, offset: 600},
		{key: h, offset: 900}, // same name, later record — must be ignored
	}
	fillHashTables(chunk, names, nil)

	b := nameBucket(h)
	if got := getBucket(chunk, stringTableStart, b); got != 600 {
		t.Errorf("bucket %d = %d, want 600 (first occurrence)", b, got)
	}
	if next := binary.LittleEndian.Uint32(chunk[600:]); next != 0 {
		t.Errorf("first node next_offset = %d, want 0 — the duplicate must not be chained", next)
	}
}

// TestFillHashTables_CollidingNamesChain builds two keys that land in the same
// bucket and asserts they form a chain in insertion order.
func TestFillHashTables_CollidingNamesChain(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	// Two distinct keys, same bucket: k and k+numStringBuckets.
	k := uint32(7)
	names := []chunkRef{
		{key: k, offset: 600},
		{key: k + numStringBuckets, offset: 700},
	}
	fillHashTables(chunk, names, nil)

	b := nameBucket(k)
	if got := getBucket(chunk, stringTableStart, b); got != 600 {
		t.Fatalf("bucket %d = %d, want 600", b, got)
	}
	if next := binary.LittleEndian.Uint32(chunk[600:]); next != 700 {
		t.Errorf("first node next_offset = %d, want 700", next)
	}
	if next := binary.LittleEndian.Uint32(chunk[700:]); next != 0 {
		t.Errorf("last node next_offset = %d, want 0 (chain terminator)", next)
	}
}

// TestFillHashTables_EmptyBucketsStayZero guards the invariant a parser relies
// on to know a bucket is empty.
func TestFillHashTables_EmptyBucketsStayZero(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	h := sdbmHash("Provider")
	fillHashTables(chunk, []chunkRef{{key: h, offset: 600}}, nil)

	occupied := nameBucket(h)
	for i := 0; i < numStringBuckets; i++ {
		if i == occupied {
			continue
		}
		if got := getBucket(chunk, stringTableStart, i); got != 0 {
			t.Errorf("bucket %d = %d, want 0", i, got)
		}
	}
}

// TestFillHashTables_Templates covers the 32-entry array with the same rules.
//
// chunkRef.key is already a hash by the time it reaches fillHashTables — the
// caller ran guidHash — so this test supplies a key directly and reduces it the
// same way fillHashTables does. It deliberately does NOT call templateBucket,
// which takes raw GUID bytes rather than a key.
func TestFillHashTables_Templates(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	key := uint32(0xDEADBEEF)
	fillHashTables(chunk, nil, []chunkRef{{key: key, offset: 1000}, {key: key, offset: 2000}})

	b := int(key % numTemplateBuckets)
	if got := getBucket(chunk, templateTableStart, b); got != 1000 {
		t.Errorf("template bucket %d = %d, want 1000", b, got)
	}
	if next := binary.LittleEndian.Uint32(chunk[1000:]); next != 0 {
		t.Errorf("template next_offset = %d, want 0", next)
	}
}

// TestFillHashTables_NoRefsLeavesTablesZero is the WriteRaw case: an opaque
// payload registers nothing, and the tables must stay exactly as they were.
func TestFillHashTables_NoRefsLeavesTablesZero(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	fillHashTables(chunk, nil, nil)
	for i := stringTableStart; i < evtxChunkHeaderSize; i++ {
		if chunk[i] != 0 {
			t.Fatalf("byte %d = 0x%02x, want 0", i, chunk[i])
		}
	}
}
