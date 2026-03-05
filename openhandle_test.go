// openhandle_test.go — TDD tests for the open-handle incremental flush model (Phase 10).
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported helpers for verification).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestWriter_MultiChunk_EventCount verifies that 3000 events written in a single
// session are all readable back via the go-evtx Reader (no silent drops).
func TestWriter_MultiChunk_EventCount(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "multi_chunk_count.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const numEvents = 3000
	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
		"AccessMask":   "0x2",
	}
	for i := 0; i < numEvents; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify via the go-evtx Reader.
	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	var count int
	var prevID uint64
	for {
		rec, err := r.ReadRecord()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord at count=%d: %v", count, err)
		}
		count++
		if count == 1 {
			if rec.RecordID != 1 {
				t.Errorf("first RecordID = %d, want 1", rec.RecordID)
			}
		} else {
			if rec.RecordID != prevID+1 {
				t.Errorf("RecordID gap: got %d after %d", rec.RecordID, prevID)
			}
		}
		prevID = rec.RecordID
	}

	if count != numEvents {
		t.Errorf("read %d records, want %d", count, numEvents)
	}
}

// TestWriter_MultiChunk_HeaderFields verifies that the EVTX file header reflects
// the correct ChunkCount and NextRecordIdentifier after a 3000-event session.
func TestWriter_MultiChunk_HeaderFields(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "multi_chunk_hdr.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const numEvents = 3000
	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
	}
	for i := 0; i < numEvents; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// ChunkCount at bytes [42:44] must be >= 2 for 3000 events.
	chunkCount := binary.LittleEndian.Uint16(data[42:44])
	if chunkCount < 2 {
		t.Errorf("ChunkCount = %d, want >= 2 (3000 events span multiple chunks)", chunkCount)
	}

	// NextRecordIdentifier at bytes [24:32] must be 3001 (last written ID + 1).
	nextRecordID := binary.LittleEndian.Uint64(data[24:32])
	if nextRecordID != numEvents+1 {
		t.Errorf("NextRecordIdentifier = %d, want %d", nextRecordID, numEvents+1)
	}
}

// TestWriter_TwoFlushSession verifies that events written before and after a ticker
// flush are both visible in the final file.
func TestWriter_TwoFlushSession(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "two_flush.evtx")

	w, err := New(outPath, RotationConfig{FlushIntervalSec: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
	}

	// Write 5 events, wait for ticker to fire, write 5 more.
	for i := 0; i < 5; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord (first batch) %d: %v", i, err)
		}
	}
	time.Sleep(1500 * time.Millisecond)

	for i := 0; i < 5; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord (second batch) %d: %v", i, err)
		}
	}
	time.Sleep(1500 * time.Millisecond)

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify all 10 records are in the final file.
	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	var count int
	for {
		_, err := r.ReadRecord()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord at count=%d: %v", count, err)
		}
		count++
	}

	if count != 10 {
		t.Errorf("read %d records, want 10", count)
	}
}

// TestWriter_EmptyClose_NoFile verifies that Close() on a writer with zero records
// removes the file from disk (backward compatibility with evtx_test.go behavior).
func TestWriter_EmptyClose_NoFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "empty_close.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Close immediately without writing any records.
	if err := w.Close(); err != nil {
		t.Fatalf("Close on empty writer: %v", err)
	}

	// File must NOT exist (os.Remove was called in Close).
	if _, err := os.Stat(outPath); err == nil {
		t.Error("expected no file on empty close, but file was found on disk")
	}
}

// TestWriter_OpenHandle_NoRace verifies that 10 concurrent goroutines each writing
// 50 events to the same Writer produce no data races and all 500 events are visible.
// Run with: go test -race ./...
func TestWriter_OpenHandle_NoRace(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "no_race_open.evtx")

	w, err := New(outPath, RotationConfig{FlushIntervalSec: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const goroutines = 10
	const eventsPerGoroutine = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			fields := map[string]string{
				"ProviderName": "Microsoft-Windows-Security-Auditing",
				"Computer":     "testhost",
				"ObjectName":   "/nas/share/file.txt",
			}
			for j := 0; j < eventsPerGoroutine; j++ {
				if err := w.WriteRecord(4663, fields); err != nil {
					t.Errorf("goroutine %d WriteRecord %d: %v", n, j, err)
				}
			}
		}(i)
	}

	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// File must exist.
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected file to exist after writes, got: %v", err)
	}

	// All 500 records must be readable.
	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	var count int
	for {
		_, err := r.ReadRecord()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord at count=%d: %v", count, err)
		}
		count++
	}

	const wantCount = goroutines * eventsPerGoroutine
	if count != wantCount {
		t.Errorf("read %d records, want %d", count, wantCount)
	}
}
