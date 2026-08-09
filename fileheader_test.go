// fileheader_test.go — file and chunk header fields that forensic consumers
// read: the last-record pointer, the dirty/full flags, and the chunk counter.
package evtx

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// F3: buf[44:] must hold the offset of the LAST record's start, not a second
// copy of the free-space offset.
func TestChunkHeader_LastEventRecordDataOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lastrec.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
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

	lastRec := binary.LittleEndian.Uint32(chunk[44:])
	freeSpace := binary.LittleEndian.Uint32(chunk[48:])
	if lastRec == freeSpace {
		t.Errorf("LastEventRecordDataOffset (%d) equals FreeSpaceOffset (%d) — "+
			"field 44 is still a duplicate of field 48", lastRec, freeSpace)
	}
	// It must point at a real record signature.
	if sig := binary.LittleEndian.Uint32(chunk[lastRec:]); sig != evtxRecordSignature {
		t.Errorf("offset %d does not begin a record: signature 0x%08x", lastRec, sig)
	}
	// And that record must be the last one: its size takes us to free space.
	size := binary.LittleEndian.Uint32(chunk[lastRec+4:])
	if lastRec+size != freeSpace {
		t.Errorf("last record at %d + size %d = %d, want FreeSpaceOffset %d",
			lastRec, size, lastRec+size, freeSpace)
	}
}

// F4: the dirty flag distinguishes a cleanly closed log from one truncated by
// a crash. Set while open, cleared on a clean Close.
func TestFileHeader_DirtyFlagClearedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flags.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// While open and flushed, the file on disk must be marked dirty.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile while open: %v", err)
	}
	if flags := binary.LittleEndian.Uint32(raw[120:]); flags&evtxFlagDirty == 0 {
		t.Errorf("flags = 0x%08x while open, want the dirty bit set", flags)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after close: %v", err)
	}
	if flags := binary.LittleEndian.Uint32(raw[120:]); flags&evtxFlagDirty != 0 {
		t.Errorf("flags = 0x%08x after a clean Close, want the dirty bit clear", flags)
	}
}

// F5a: LastChunkNumber must not underflow to 0xFFFFFFFFFFFFFFFF when the file
// has no chunks yet.
func TestFileHeader_LastChunkNumberNoUnderflow(t *testing.T) {
	buf := buildFileHeader(0, 1, 0)
	if got := binary.LittleEndian.Uint64(buf[16:]); got != 0 {
		t.Errorf("LastChunkNumber with chunkCount=0 is 0x%016x, want 0", got)
	}
	// And it is chunkCount-1 whenever there is at least one chunk.
	buf = buildFileHeader(3, 1, 0)
	if got := binary.LittleEndian.Uint64(buf[16:]); got != 2 {
		t.Errorf("LastChunkNumber with chunkCount=3 is %d, want 2", got)
	}
}

// F5b: chunkCount is uint16. At 65536 chunks it wraps and chunkOffset
// recomputes to 4096, overwriting chunk 0. Reachable whenever MaxFileSizeMB is
// 0, which is the zero value. Return a sticky error instead of wrapping.
func TestWriter_ChunkCountCeiling(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "ceiling.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	// Buffer a record first: the ceiling is enforced in chunkCapacityLocked,
	// which only runs on the flush path. A WriteRecord that merely buffers
	// never reaches it.
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Drive the counter to the ceiling directly — writing 65535 real chunks
	// would move 4 GiB.
	w.mu.Lock()
	w.chunkCount = maxChunksPerFile
	w.mu.Unlock()

	// Rotate forces the pending chunk to flush, which is where the guard lives.
	if err := w.Rotate(); !errors.Is(err, ErrTooManyChunks) {
		t.Fatalf("Rotate at the chunk ceiling: %v, want ErrTooManyChunks", err)
	}
	// It must be sticky: every later entry point reports the same failure
	// rather than silently accepting data it cannot durably place.
	if err := w.WriteRecord(4663, testFields()); !errors.Is(err, ErrTooManyChunks) {
		t.Errorf("WriteRecord after the ceiling: %v, want the sticky ErrTooManyChunks", err)
	}
}
