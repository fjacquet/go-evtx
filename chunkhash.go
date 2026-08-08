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
//
//nolint:unused // write-side counterpart of getBucket; Tasks 2-4 wire it into
// the chunk writer to populate these tables. getBucket already has a caller
// (chunkhash_test.go); this one doesn't yet.
func putBucket(chunk []byte, tableStart, i int, off uint32) {
	binary.LittleEndian.PutUint32(chunk[tableStart+i*4:], off)
}

// getBucket reads bucket i of the array starting at tableStart.
func getBucket(chunk []byte, tableStart, i int) uint32 {
	return binary.LittleEndian.Uint32(chunk[tableStart+i*4:])
}
