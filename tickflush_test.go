// tickflush_test.go — incremental background-tick flush (v0.10.0).
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported writer state).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"hash/crc32"
	"path/filepath"
	"testing"
)

func tickTestFields() map[string]string {
	return map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
		"TimeCreated":  "2026-08-22T12:00:00.000000000Z",
	}
}

// TestRecordsCRC_MatchesFullScan verifies the incrementally maintained
// w.recordsCRC equals a full rescan of w.records at every append. If these
// ever diverge, every chunk header written by the tick path carries a wrong
// checksum and Windows rejects the file.
func TestRecordsCRC_MatchesFullScan(t *testing.T) {
	dir := t.TempDir()
	w, err := New(filepath.Join(dir, "crc.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	for i := 0; i < 25; i++ {
		if err := w.WriteRecord(4663, tickTestFields()); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
		w.mu.Lock()
		got := w.recordsCRC
		want := crc32.Checksum(w.records, crc32.IEEETable)
		w.mu.Unlock()
		if got != want {
			t.Fatalf("after record %d: recordsCRC = %#08x, full scan = %#08x", i, got, want)
		}
	}
}

// TestRecordsCRC_ResetOnFlush verifies the running CRC is reset together with
// w.records when a chunk is sealed. A stale CRC would corrupt the next chunk.
func TestRecordsCRC_ResetOnFlush(t *testing.T) {
	dir := t.TempDir()
	w, err := New(filepath.Join(dir, "crcreset.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	if err := w.WriteRecord(4663, tickTestFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	w.mu.Lock()
	err = w.flushChunkLocked()
	crcAfter := w.recordsCRC
	nRecords := len(w.records)
	w.mu.Unlock()
	if err != nil {
		t.Fatalf("flushChunkLocked: %v", err)
	}
	if nRecords != 0 {
		t.Fatalf("records not reset: %d bytes", nRecords)
	}
	if crcAfter != 0 {
		t.Fatalf("recordsCRC = %#08x after flush, want 0", crcAfter)
	}
}
