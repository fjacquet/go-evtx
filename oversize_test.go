// oversize_test.go — records that cannot fit in a chunk must be rejected,
// never truncated. Truncation is checksum-invisible and destroys the file.
//
// White-box: package evtx. stdlib only.
package evtx

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteRecord_Oversized verifies that a field large enough to overflow the
// chunk is rejected, and that the file remains readable afterwards.
func TestWriteRecord_Oversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// One good record first, so the file has recoverable content.
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord good: %v", err)
	}

	huge := testFields()
	huge["ObjectName"] = strings.Repeat("A", 70000)
	err = w.WriteRecord(4663, huge)
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("WriteRecord oversized = %v, want ErrRecordTooLarge", err)
	}

	// A second good record must still succeed — the writer is not poisoned.
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord after rejection: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The file must be readable and contain exactly the two good records.
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	n := 0
	for {
		_, err := r.ReadRecord()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord: %v", err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("read %d records, want 2 — oversized record corrupted the file", n)
	}
}

// TestWriteRaw_Oversized verifies the same guard on the raw path.
func TestWriteRaw_Oversized(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "test.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.WriteRaw(make([]byte, maxRecordPayload+1)); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("WriteRaw oversized = %v, want ErrRecordTooLarge", err)
	}
}

// TestWriteRaw_ExactBoundary verifies the limit is inclusive: maxRecordPayload
// bytes must be accepted, one more must not.
func TestWriteRaw_ExactBoundary(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "test.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.WriteRaw(make([]byte, maxRecordPayload)); err != nil {
		t.Fatalf("WriteRaw at exactly maxRecordPayload (%d) = %v, want nil",
			maxRecordPayload, err)
	}
}

// TestMaxRecordPayload_Value pins the constant so a change to the chunk layout
// cannot silently move the limit.
func TestMaxRecordPayload_Value(t *testing.T) {
	if maxChunkPayload != 65024 {
		t.Errorf("maxChunkPayload = %d, want 65024", maxChunkPayload)
	}
	if maxRecordPayload != 64996 {
		t.Errorf("maxRecordPayload = %d, want 64996", maxRecordPayload)
	}
}
