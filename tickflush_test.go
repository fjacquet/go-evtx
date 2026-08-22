// tickflush_test.go — incremental background-tick flush (v0.10.0).
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported writer state).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"hash/crc32"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
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

// TestTickFlush_IdleWritesNothing verifies the background tick performs no
// write and no fsync when no records were appended since the previous tick.
// Before v0.10.0 this rewrote the full 64 KiB chunk on every interval.
func TestTickFlush_IdleWritesNothing(t *testing.T) {
	dir := t.TempDir()
	var syncs int64
	w, err := New(filepath.Join(dir, "idle.evtx"), RotationConfig{
		FlushIntervalSec: 1,
		OnFsync:          func(time.Time) { atomic.AddInt64(&syncs, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	if err := w.WriteRecord(4663, tickTestFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Span at least three tick intervals. Only the first has new records.
	time.Sleep(3500 * time.Millisecond)

	if got := atomic.LoadInt64(&syncs); got != 1 {
		t.Fatalf("fsync count = %d after 3 ticks with 1 record, want 1", got)
	}
}

// TestTickFlush_FileChunkAligned verifies the file length stays a whole
// number of chunks after a background tick. A file ending mid-chunk is
// unreadable: loadChunk reads a full evtxChunkSize and hits EOF, and so does
// Windows. This is the regression guard for the partial-range tick write.
func TestTickFlush_FileChunkAligned(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "aligned.evtx")
	var syncs int64
	w, err := New(outPath, RotationConfig{
		FlushIntervalSec: 1,
		OnFsync:          func(time.Time) { atomic.AddInt64(&syncs, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	for i := 0; i < 5; i++ {
		if err := w.WriteRecord(4663, tickTestFields()); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if atomic.LoadInt64(&syncs) == 0 {
		t.Fatal("tick never fired; test cannot measure alignment")
	}

	fi, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	w.mu.Lock()
	chunks := int64(w.chunkCount)
	w.mu.Unlock()

	want := int64(evtxFileHeaderSize) + (chunks+1)*int64(evtxChunkSize)
	if fi.Size() != want {
		t.Fatalf("file size = %d after tick, want %d (header + %d whole chunks)",
			fi.Size(), want, chunks+1)
	}
}
