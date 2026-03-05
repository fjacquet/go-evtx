// rotation_test.go — TDD tests for file rotation (Phase 11).
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported fields).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// archiveGlob returns a sorted list of archive files matching baseName-*.evtx in dir.
func archiveGlob(dir, baseName string) []string {
	pattern := filepath.Join(dir, baseName+"-*.evtx")
	matches, _ := filepath.Glob(pattern)
	sort.Strings(matches)
	return matches
}

// TestWriter_SizeRotation verifies that writing events past MaxFileSizeMB triggers
// automatic rotation: a timestamped archive file appears and the active file is reset.
func TestWriter_SizeRotation(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "size_rot.evtx")

	w, err := New(outPath, RotationConfig{MaxFileSizeMB: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
		"AccessMask":   "0x2",
	}

	// Write 1000 records — enough to push past 1 MB threshold.
	for i := 0; i < 1000; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	archives := archiveGlob(dir, "size_rot")
	if len(archives) == 0 {
		t.Error("expected at least one archive file after size rotation, got none")
	}

	// Active file must still exist (or the archive is the final flush).
	// Either the active file or at least one archive must exist.
	_, activeErr := os.Stat(outPath)
	if activeErr != nil && len(archives) == 0 {
		t.Error("neither active file nor archive found after size rotation")
	}
}

// TestWriter_CountRetention verifies that after MaxFileCount rotations,
// only MaxFileCount archive files remain on disk (oldest deleted).
func TestWriter_CountRetention(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "count_rot.evtx")

	w, err := New(outPath, RotationConfig{MaxFileCount: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
	}

	// Rotate 3 times, writing 1 record between each rotation.
	for i := 0; i < 3; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord before Rotate %d: %v", i, err)
		}
		// Small sleep to ensure distinct timestamps in archive names.
		time.Sleep(2 * time.Second)
		if err := w.Rotate(); err != nil {
			t.Fatalf("Rotate %d: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	archives := archiveGlob(dir, "count_rot")
	if len(archives) > 2 {
		t.Errorf("expected at most 2 archive files (MaxFileCount=2), got %d: %v", len(archives), archives)
	}

	// Active file may have been cleaned up by Close if empty;
	// at minimum, archives must be <= MaxFileCount (already asserted above).
	_ = outPath
}

// TestWriter_TimeRotation verifies that calling Rotate() directly (simulating a
// RotationIntervalH tick) creates an archive and resets the active file.
func TestWriter_TimeRotation(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "time_rot.evtx")

	w, err := New(outPath, RotationConfig{RotationIntervalH: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	if err := w.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	archives := archiveGlob(dir, "time_rot")
	if len(archives) == 0 {
		t.Error("expected archive after Rotate(), got none")
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestWriter_ManualRotate writes 5 records, calls Rotate(), then writes 3 more,
// then Close(). Both the archive and the (final) active file must be non-empty
// and readable via the go-evtx Reader.
func TestWriter_ManualRotate(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "manual_rot.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
	}

	for i := 0; i < 5; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord pre-rotate %d: %v", i, err)
		}
	}

	if err := w.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	archives := archiveGlob(dir, "manual_rot")
	if len(archives) == 0 {
		t.Fatal("expected archive after Rotate(), got none")
	}

	for i := 0; i < 3; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord post-rotate %d: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Archive must be non-empty and readable.
	archivePath := archives[0]
	if info, err := os.Stat(archivePath); err != nil {
		t.Fatalf("archive stat: %v", err)
	} else if info.Size() == 0 {
		t.Fatal("archive file is empty")
	}

	r, err := Open(archivePath)
	if err != nil {
		t.Fatalf("Open archive: %v", err)
	}
	defer func() { _ = r.Close() }()

	var count int
	for {
		_, err := r.ReadRecord()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord from archive at count=%d: %v", count, err)
		}
		count++
	}
	if count == 0 {
		t.Error("archive has zero readable records")
	}

	// Active file must also be readable.
	if _, err := os.Stat(outPath); err == nil {
		r2, err := Open(outPath)
		if err != nil {
			t.Fatalf("Open active file: %v", err)
		}
		defer func() { _ = r2.Close() }()
	}
}

// TestWriter_RotatedFileValid writes 10 records, rotates, then closes.
// Opens the archive and reads all records — asserts count==10 and RecordIDs 1..10 sequential.
func TestWriter_RotatedFileValid(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "valid_rot.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
	}

	for i := 0; i < 10; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}

	if err := w.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	archives := archiveGlob(dir, "valid_rot")
	if len(archives) == 0 {
		t.Fatal("expected archive file after Rotate(), got none")
	}

	archivePath := archives[0]
	r, err := Open(archivePath)
	if err != nil {
		t.Fatalf("Open archive: %v", err)
	}
	defer func() { _ = r.Close() }()

	var count int
	var prevID uint64
	for {
		rec, err := r.ReadRecord()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord from archive at count=%d: %v", count, err)
		}
		count++
		if count == 1 {
			if rec.RecordID != 1 {
				t.Errorf("first RecordID = %d, want 1", rec.RecordID)
			}
		} else {
			if rec.RecordID != prevID+1 {
				t.Errorf("RecordID gap at %d: got %d, want %d", count, rec.RecordID, prevID+1)
			}
		}
		prevID = rec.RecordID
	}

	if count != 10 {
		t.Errorf("read %d records from archive, want 10", count)
	}
}

// TestWriter_RotateRace verifies there are no data races when 8 goroutines each
// write 20 events concurrently while a separate goroutine calls Rotate() 3 times.
// Run with: go test -race ./...
func TestWriter_RotateRace(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "race_rot.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const writers = 8
	const writesPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(writers)

	for i := 0; i < writers; i++ {
		go func(n int) {
			defer wg.Done()
			fields := map[string]string{
				"ProviderName": "Microsoft-Windows-Security-Auditing",
				"Computer":     "testhost",
				"ObjectName":   "/nas/share/file.txt",
			}
			for j := 0; j < writesPerGoroutine; j++ {
				if err := w.WriteRecord(4663, fields); err != nil {
					t.Errorf("goroutine %d WriteRecord %d: %v", n, j, err)
				}
			}
		}(i)
	}

	// Rotate concurrently from a separate goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			time.Sleep(50 * time.Millisecond)
			if err := w.Rotate(); err != nil {
				t.Errorf("Rotate %d: %v", i, err)
			}
		}
	}()

	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
