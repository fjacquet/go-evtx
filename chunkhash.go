// chunkhash.go — the per-chunk common-string and template hash tables.
//
// Every EVTX chunk header carries two offset arrays that a parser uses to find
// names and templates without walking every record:
//
//	[128:384]  64 × uint32  common-string buckets
//	[384:512]  32 × uint32  template buckets
//
// Each entry is a chunk-relative offset to the first node in that bucket, or 0
// if the bucket is empty. Nodes in one bucket chain through a next_offset field
// that is the first 4 bytes of both the NameNode and TemplateNode structures.
//
// go-evtx left both arrays zero through v0.6.0. python-evtx tolerates that
// because it follows each record's inline template_offset instead; a parser
// that resolves through the tables finds nothing.
package evtx

import (
	"encoding/binary"
	"unicode/utf16"
)

// sdbmHash is the EVTX name hash: h = h*65599 + c over the UTF-16 code units
// of the string, expressed as the usual shift form (h<<6 + h<<16 - h).
//
// Hashing UTF-16 code units, not UTF-8 bytes, is what the format requires.
// The two agree for ASCII — every name go-evtx emits today is ASCII — but they
// diverge above U+007F, where UTF-8 contributes several bytes and UTF-16
// contributes one unit with a value above 255.
func sdbmHash(s string) uint32 {
	var h uint32
	for _, c := range utf16.Encode([]rune(s)) {
		h = uint32(c) + (h << 6) + (h << 16) - h
	}
	return h
}

// nameBucket maps a name hash to one of the 64 common-string buckets.
//
// Only the low 16 bits of the hash are stored in a NameNode, but 64 divides
// 65536, so bucketing the truncated hash and the full hash give the same
// answer. Callers may pass either.
func nameBucket(h uint32) int { return int(h % numStringBuckets) }

// guidHash is the template equivalent of sdbmHash: the same SDBM routine, fed
// the full 16-byte GUID read as 8 little-endian uint16 units.
//
// Windows hashes 16-bit units, and a GUID is simply eight of them — the
// template rule is the general rule, not a special case. Hashing only the
// first four bytes as a uint32 "template_id", or hashing the 16 bytes
// individually, both fail against real files; see the measurement table in the
// spec's F1 section.
func guidHash(guid []byte) uint32 {
	var h uint32
	for i := 0; i+1 < len(guid); i += 2 {
		c := uint32(guid[i]) | uint32(guid[i+1])<<8
		h = c + (h << 6) + (h << 16) - h
	}
	return h
}

// templateBucket maps a template GUID to one of the 32 template buckets.
func templateBucket(guid []byte) int { return int(guidHash(guid) % numTemplateBuckets) }

const (
	numStringBuckets   = 64
	numTemplateBuckets = 32

	stringTableStart   = 128 // chunk[128:384]
	templateTableStart = 384 // chunk[384:512]
)

// putBucket writes a chunk-relative offset into bucket i of the array starting
// at tableStart.
func putBucket(chunk []byte, tableStart, i int, off uint32) {
	binary.LittleEndian.PutUint32(chunk[tableStart+i*4:], off)
}

// getBucket reads bucket i of the array starting at tableStart.
func getBucket(chunk []byte, tableStart, i int) uint32 {
	return binary.LittleEndian.Uint32(chunk[tableStart+i*4:])
}

// fillHashTables populates a chunk's common-string and template offset arrays
// from the nodes emitted into that chunk, and patches the next_offset chains.
//
// Registration rule: the FIRST node with a given key wins its bucket. Later
// nodes carrying the same key are left unregistered and unchained — each record
// references its own inline copy through its own name_offset field, so a
// duplicate is already reachable, and chaining duplicates would make a table
// lookup walk an arbitrarily long run of identical names.
//
// Distinct keys that collide on a bucket DO chain, in emission order. That is
// ordinary hash-table chaining and is what a parser expects to walk.
//
// chunk must be a full evtxChunkSize buffer with the nodes already copied in at
// the offsets the refs name. MUST be called before patchChunkCRC: the chunk
// header checksum covers chunk[128:512], which is exactly what this writes.
func fillHashTables(chunk []byte, names, templates []chunkRef) {
	fillOneTable(chunk, stringTableStart, numStringBuckets, names)
	fillOneTable(chunk, templateTableStart, numTemplateBuckets, templates)
}

func fillOneTable(chunk []byte, tableStart, buckets int, refs []chunkRef) {
	// seen maps a key to the offset already registered for it, so duplicates
	// are dropped. tail maps a bucket to the last node in its chain, so a new
	// distinct key is appended rather than replacing the head.
	seen := make(map[uint32]uint32, len(refs))
	tail := make(map[int]uint32, buckets)

	for _, ref := range refs {
		if ref.offset == 0 || int(ref.offset)+4 > len(chunk) {
			// A zero offset is not addressable (0 means "empty bucket") and an
			// out-of-range one would corrupt the chunk. Neither can happen for
			// nodes the encoder emitted; skip defensively rather than panic in
			// a writer that is holding the caller's audit data.
			continue
		}
		if _, dup := seen[ref.key]; dup {
			continue
		}
		seen[ref.key] = ref.offset

		// Reduce in uint32 before converting. int(ref.key) would be negative
		// for keys above 2^31 on a 32-bit platform, and a negative modulus
		// yields a negative bucket index — an out-of-range write in a writer
		// that is holding the caller's audit data.
		b := int(ref.key % uint32(buckets))
		if prev, ok := tail[b]; ok {
			binary.LittleEndian.PutUint32(chunk[prev:], ref.offset) // chain onto the tail
		} else {
			putBucket(chunk, tableStart, b, ref.offset) // first node: becomes the head
		}
		tail[b] = ref.offset
		binary.LittleEndian.PutUint32(chunk[ref.offset:], 0) // terminate the chain here
	}
}
