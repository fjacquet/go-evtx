package evtx

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeMultiChunkFile writes a file with at least two chunks and returns its
// path. Written through the public API so the bytes damaged by the tests below
// are the bytes this library actually produces.
func writeMultiChunkFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "multi.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 600; i++ {
		if err := w.WriteRecord(4663, map[string]string{
			"ProviderName":    "TestProvider",
			"Computer":        "testhost",
			"SubjectUserName": "user",
		}); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	chunks := r.FileInfo().Chunks
	_ = r.Close()
	if chunks < 2 {
		t.Fatalf("fixture has %d chunks, want at least 2", chunks)
	}
	return path
}

// drainReader reads until the stream ends, and returns the last non-nil error
// that was not ErrNoMoreRecords along with the number of calls made. The loop
// is bounded: a reader that neither advances nor terminates is the bug
// abandonChunkLocked was written for, and it must fail the test rather than
// hang it.
func drainReader(t *testing.T, r *Reader) (records int, fatal error) {
	t.Helper()
	const maxCalls = 5000
	for i := 0; i < maxCalls; i++ {
		_, err := r.ReadEvent()
		if errors.Is(err, ErrNoMoreRecords) {
			return records, fatal
		}
		if err != nil {
			fatal = err
			continue
		}
		records++
	}
	t.Fatalf("reader made %d calls without ending the stream", maxCalls)
	return 0, nil
}

// TestReadEvent_TruncatedFileIsNotACleanEnd covers the defect that made every
// chunk-load failure indistinguishable from the end of the file: a file cut off
// part-way through its second chunk used to report a clean finish, so a caller
// dumping it exited 0 over a partial read.
func TestReadEvent_TruncatedFileIsNotACleanEnd(t *testing.T) {
	path := writeMultiChunkFile(t)
	// Cut the second chunk in half. The file header still declares every chunk,
	// so the reader asks for one that is no longer fully there.
	if err := os.Truncate(path, int64(evtxFileHeaderSize)+int64(evtxChunkSize)+1000); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	records, fatal := drainReader(t, r)
	if records == 0 {
		t.Errorf("read %d records, want the first chunk's records before the failure", records)
	}
	if !errors.Is(fatal, ErrChunkUnreadable) {
		t.Fatalf("error = %v, want one wrapping ErrChunkUnreadable", fatal)
	}
	if errors.Is(fatal, ErrNoMoreRecords) {
		t.Errorf("a truncated file reported a clean end of stream: %v", fatal)
	}
	if _, err := r.ReadEvent(); !errors.Is(err, ErrNoMoreRecords) {
		t.Errorf("after the failure ReadEvent = %v, want ErrNoMoreRecords", err)
	}
}

// TestReadEvent_BadChunkMagicIsNotACleanEnd is the same defect reached the
// other way: the chunk is present and full-length, but is not a chunk.
func TestReadEvent_BadChunkMagicIsNotACleanEnd(t *testing.T) {
	path := writeMultiChunkFile(t)
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.WriteAt([]byte("NotAChnk"), int64(evtxFileHeaderSize)+int64(evtxChunkSize)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	records, fatal := drainReader(t, r)
	if records == 0 {
		t.Errorf("read %d records, want the first chunk's records before the failure", records)
	}
	if !errors.Is(fatal, ErrChunkUnreadable) {
		t.Fatalf("error = %v, want one wrapping ErrChunkUnreadable", fatal)
	}
	if _, err := r.ReadEvent(); !errors.Is(err, ErrNoMoreRecords) {
		t.Errorf("after the failure ReadEvent = %v, want ErrNoMoreRecords", err)
	}
}

// TestReadEvent_RecordPastFreeSpaceOffsetIsRejected covers a record whose
// declared size stays inside the 65536-byte chunk but runs past FreeSpaceOffset,
// where the records end and the chunk's padding begins. Validating against the
// buffer length alone accepted it, so padding was read as payload and a
// fabricated event could be produced instead of a framing error.
func TestReadEvent_RecordPastFreeSpaceOffsetIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize-record.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, map[string]string{
		"ProviderName": "TestProvider",
		"Computer":     "testhost",
	}); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path) // #nosec G304 — a path this test just wrote
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	chunk := raw[evtxFileHeaderSize:]
	freeOff := int(binary.LittleEndian.Uint32(chunk[48:52]))
	recOff := int(evtxChunkHeaderSize)

	// Eight bytes past the end of the records region, and comfortably inside
	// the chunk buffer: the bound that used to be the only one checked.
	size := freeOff - recOff + 8
	if recOff+size >= evtxChunkSize {
		t.Fatalf("test setup: size %d would exceed the chunk, defeating the point", size)
	}
	binary.LittleEndian.PutUint32(chunk[recOff+4:recOff+8], uint32(size)) // #nosec G115 — bounded above
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if _, err := r.ReadEvent(); err == nil {
		t.Fatal("ReadEvent accepted a record running past FreeSpaceOffset")
	}
	if _, err := r.ReadEvent(); !errors.Is(err, ErrNoMoreRecords) {
		t.Errorf("after the framing error ReadEvent = %v, want ErrNoMoreRecords", err)
	}
}
