// hashtable_integration_test.go — a file written by WriteRecord must carry
// populated chunk hash tables, and they must be self-consistent: every bucket
// offset resolves to a NameNode that hashes back into that bucket.
package evtx

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

func TestWrittenFile_ChunkTablesArePopulated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tables.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 20; i++ {
		if err := w.WriteRecord(4663, testFields()); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	chunk := raw[evtxFileHeaderSize : evtxFileHeaderSize+evtxChunkSize]

	// The regression this guards: both tables entirely zero, as through v0.6.0.
	if allZero(chunk[stringTableStart:templateTableStart]) {
		t.Error("common-string table is entirely zero")
	}
	if allZero(chunk[templateTableStart:evtxChunkHeaderSize]) {
		t.Error("template table is entirely zero")
	}

	// Self-consistency: walk every chain and re-derive the bucket.
	found := 0
	for b := 0; b < numStringBuckets; b++ {
		for off := getBucket(chunk, stringTableStart, b); off > 0; {
			if int(off)+8 > len(chunk) {
				t.Fatalf("bucket %d: offset %d out of range", b, off)
			}
			n := int(binary.LittleEndian.Uint16(chunk[off+6:]))
			u16 := make([]uint16, n)
			for i := 0; i < n; i++ {
				u16[i] = binary.LittleEndian.Uint16(chunk[int(off)+8+2*i:])
			}
			name := string(utf16.Decode(u16))
			if got := nameBucket(sdbmHash(name)); got != b {
				t.Errorf("name %q found in bucket %d, hashes to %d", name, b, got)
			}
			found++
			off = binary.LittleEndian.Uint32(chunk[off:])
		}
	}
	if found == 0 {
		t.Error("no NameNodes reachable through the string table")
	}
	t.Logf("%d names reachable through the table", found)
}

// TestWrittenFile_ChunkHeaderCRCCoversTables is the ordering guard. If
// fillHashTables ever runs after patchChunkCRC, the stored checksum no longer
// matches the bytes and every validating parser rejects the chunk.
func TestWrittenFile_ChunkHeaderCRCCoversTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crc.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	chunk := make([]byte, evtxChunkSize)
	copy(chunk, raw[evtxFileHeaderSize:evtxFileHeaderSize+evtxChunkSize])

	stored := binary.LittleEndian.Uint32(chunk[124:])
	patchChunkCRC(chunk) // recompute over the bytes as written
	if recomputed := binary.LittleEndian.Uint32(chunk[124:]); recomputed != stored {
		t.Errorf("chunk header CRC = 0x%08x, recomputes to 0x%08x — the tables were "+
			"written after the checksum", stored, recomputed)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
