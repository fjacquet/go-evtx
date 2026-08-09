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
	raw, err := os.ReadFile(fixturePath(t)) // #nosec G304 — a developer-supplied corpus path
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
// coverage of real-world template shapes. readFixtureChunkOK stops at the
// file header's ChunkCount, which is 9 for this fixture -- not the 17
// pre-allocated evtxChunkSize slots the file is long by byte size (see
// readFixtureChunkOK's comment above).
func TestFixture_TemplateTableBucketRule(t *testing.T) {
	// The GUID bucket rule is format-3.1-only, and that is a measured fact,
	// not a suspicion: it places 386 of 386 entries correctly on 3.1 files and
	// 0 of 1387 (app.evtx), 0 of 9358 (security.evtx) and 39 of 3465
	// (system2.evtx) on 3.2 ones — at or below the 1-in-32 chance rate. The
	// 3.2 rule is not known; see the "template bucket rule is 3.1-only" note
	// in docs/evtx-format-notes.md.
	//
	// This check used to run against a tracked 3.1 fixture and so could never
	// surface the limitation. Now that the fixture is whatever EVTX_FIXTURE
	// names, the version guard has to be explicit.
	if v := fixtureMinorVersion(t); v != 1 {
		t.Skipf("EVTX_FIXTURE is format 3.%d; the GUID bucket rule is 3.1-only", v)
	}
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
	// This used to pin an exact 146, the count for testdata/system.evtx, so a
	// silently-truncated walk would fail. The pin went with the file: the
	// fixture is now whatever EVTX_FIXTURE names, and an exact count would
	// only assert which file the developer happened to point at. The walk is
	// still guarded — every entry it does find must hash into the bucket it
	// was found in, and a chain that does not terminate is fatal.
	if checked == 0 {
		t.Fatal("no TemplateNodes found in any chunk — the table walk is wrong")
	}
	t.Logf("validated %d TemplateNodes", checked)
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

// TestFillHashTables_TerminatorIsActuallyWritten guards against a gap every
// other test in this file leaves open: they all start from a chunk built
// with make([]byte, evtxChunkSize), which is already zero, and the encoder
// pre-zeros a fresh NameNode/TemplateNode's next_offset field before
// fillHashTables ever runs. So a chain-terminator assertion of "next_offset
// == 0" passes whether fillOneTable actually executed
// `binary.LittleEndian.PutUint32(chunk[ref.offset:], 0)` or the line were
// deleted entirely — nothing distinguishes "wrote 0" from "was already 0".
//
// That gap is inert today only because both flush paths in evtx.go allocate
// chunkBytes fresh with make() on every call. It stops being inert the
// moment anyone pools that 64 KiB allocation and reuses a buffer that still
// carries stale, non-zero bytes from a previous chunk — at which point a
// silently-deleted terminator write would leave a dangling pointer into the
// old chunk's contents.
//
// This test pre-fills the node offset with non-zero bytes before calling
// fillHashTables, so only a genuine write proves the terminator behavior.
func TestFillHashTables_TerminatorIsActuallyWritten(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	const off = 600
	// Poison the node's next_offset field (and a little beyond, to catch an
	// off-by-few in the write width) with a value that is emphatically not
	// zero and could not be mistaken for an unrelated field's coincidental 0.
	for i := off; i < off+8; i++ {
		chunk[i] = 0xFF
	}

	h := sdbmHash("Provider")
	fillHashTables(chunk, []chunkRef{{key: h, offset: off}}, nil)

	if next := binary.LittleEndian.Uint32(chunk[off:]); next != 0 {
		t.Errorf("tail node next_offset = 0x%08x, want 0 — fillHashTables did not "+
			"write the chain terminator over the pre-existing non-zero bytes", next)
	}
}

// TestFillHashTables_SkipsInvalidOffset exercises fillOneTable's defensive
// bounds check (chunkhash.go: "A zero offset is not addressable ... and an
// out-of-range one would corrupt the chunk. Neither can happen for nodes the
// encoder emitted; skip defensively rather than panic"). No test supplied a
// ref tripping that check before this one, so an off-by-one in the bound
// (e.g. using >= instead of > against len(chunk)) would pass the whole suite
// silently. Each bad ref here is paired with a good one sharing the same
// bucket, so a skip that is too aggressive (dropping the good ref too) or
// too lax (writing out of bounds / registering the bad one) both fail.
func TestFillHashTables_SkipsInvalidOffset(t *testing.T) {
	good := uint32(600)

	t.Run("zero offset", func(t *testing.T) {
		chunk := make([]byte, evtxChunkSize)
		// Same key for both refs, so if the zero-offset ref were wrongly
		// registered it would win the bucket instead of the good ref.
		k := uint32(11)
		refs := []chunkRef{
			{key: k, offset: 0},    // must be skipped: not addressable
			{key: k, offset: good}, // must still be registered
		}
		fillHashTables(chunk, refs, nil)

		b := nameBucket(k)
		if got := getBucket(chunk, stringTableStart, b); got != good {
			t.Errorf("bucket %d = %d, want %d — zero-offset ref must be skipped, "+
				"not registered, and must not block the following valid ref", b, got, good)
		}
	})

	t.Run("out of range offset", func(t *testing.T) {
		chunk := make([]byte, evtxChunkSize)
		k := uint32(13)
		// One byte past what a 4-byte next_offset write at the tail of the
		// chunk can hold: int(offset)+4 > len(chunk) must reject this without
		// panicking on the PutUint32 that would otherwise follow.
		badOff := uint32(len(chunk) - 3)
		refs := []chunkRef{
			{key: k, offset: badOff}, // must be skipped: out of range
			{key: k, offset: good},   // must still be registered
		}
		fillHashTables(chunk, refs, nil)

		b := nameBucket(k)
		if got := getBucket(chunk, stringTableStart, b); got != good {
			t.Errorf("bucket %d = %d, want %d — out-of-range ref must be skipped, "+
				"not registered, and must not block the following valid ref", b, got, good)
		}
	})
}

// trackedFixture is the one real .evtx this repository commits: a System log
// exported from a disposable Windows Server 2025 instance the project
// controls. Format 3.2, 11 chunks, 1818 records. See testdata/README.md for
// its provenance and for exactly what it contains.
//
// It is a CI fixture and nothing more. Format rules come from the corpus
// census over hundreds of files (corpus_shape_test.go), never from this file
// — that separation is the whole lesson of the deleted testdata/system.evtx,
// where a rule derived from one sample was then asserted against that same
// sample and so could not fail.
const trackedFixture = "testdata/win2025-system.evtx"

// fixturePath returns the .evtx the hash-table rule tests measure against:
// $EVTX_FIXTURE when set — point it at a 3.1 file to exercise the template
// bucket rule, which trackedFixture's 3.2 format skips — otherwise the
// tracked fixture.
func fixturePath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("EVTX_FIXTURE"); p != "" {
		return p
	}
	if _, err := os.Stat(trackedFixture); err != nil {
		t.Skipf("%s is absent and EVTX_FIXTURE is unset", trackedFixture)
	}
	return trackedFixture
}

// fixtureMinorVersion reads the fixture's format minor version from its file
// header (offset 36, uint16 LE). 1 is Vista-era 3.1; 2 is Windows 10 2004 and
// later.
func fixtureMinorVersion(t *testing.T) uint16 {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(t)) // #nosec G304 — a developer-supplied corpus path
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if len(raw) < 40 {
		t.Fatalf("fixture is %d bytes, too short for a file header", len(raw))
	}
	return binary.LittleEndian.Uint16(raw[36:38])
}
