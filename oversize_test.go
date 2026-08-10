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
		_, err := r.ReadEvent()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent: %v", err)
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

// TestWriteRecord_OversizeOnlyAfterInlineRebuild covers the gap F19 opened.
//
// Before F19 both buildBinXML calls in WriteRecord produced payloads of
// identical length, so checking the first covered the second. Now the first
// may reference the pending chunk's template definition while the rebuild —
// for a chunk that was just flushed and holds none — must inline it, roughly
// 2 KB more. A record that fits as a reference can exceed the limit as an
// inline copy, and it must be rejected rather than appended.
func TestWriteRecord_OversizeOnlyAfterInlineRebuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatal(err)
	}

	rec := func(objectName string) map[string]string {
		return map[string]string{
			"ProviderName": "Microsoft-Windows-Security-Auditing",
			"Computer":     "TESTHOST",
			"ObjectName":   objectName,
			"TimeCreated":  "2026-08-10T12:00:00Z",
		}
	}
	// First record establishes the chunk's template definition, so the next
	// one is built as a reference.
	if err := w.WriteRecord(4663, rec("seed")); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	// Find a size that fits as a reference and does not as an inline copy.
	// Probing rather than hardcoding: the exact boundary moves with any
	// encoder change, and a hardcoded length would quietly stop testing this.
	var target int
	for n := 30000; n < 33000; n += 4 {
		ref := len(buildBinXML(4663, 2, rec(strings.Repeat("w", n)), evtxRecordsStart+evtxRecordHeaderSize, 512).payload)
		inline := len(buildBinXML(4663, 2, rec(strings.Repeat("w", n)), evtxRecordsStart+evtxRecordHeaderSize, 0).payload)
		if ref <= maxRecordPayload && inline > maxRecordPayload {
			target = n
			break
		}
	}
	if target == 0 {
		t.Skip("no ObjectName length fits as a reference and overflows when inlined; " +
			"the template definition may no longer be large enough for this gap to exist")
	}

	err = w.WriteRecord(4663, rec(strings.Repeat("w", target)))
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("WriteRecord = %v, want ErrRecordTooLarge — the rebuilt inline payload exceeds the limit", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// The rejected record must not be in the file.
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	n := 0
	for {
		if _, err := r.ReadEvent(); err == ErrNoMoreRecords {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 1 {
		t.Errorf("file holds %d records, want 1 — only the seed record should have been written", n)
	}
}
