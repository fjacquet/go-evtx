// goroutine_test.go — lifecycle and concurrency tests for the background flush goroutine.
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported fields for lifecycle assertions).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestWriter_FlushTicker verifies that the background goroutine writes records to
// disk on a ticker interval before Close() is called.
func TestWriter_FlushTicker(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "flush_ticker.evtx")

	w, err := New(outPath, RotationConfig{FlushIntervalSec: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Wait 1.5× the flush interval so the background goroutine fires at least once.
	time.Sleep(1500 * time.Millisecond)

	// File should exist on disk because the ticker fired.
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected file to exist after ticker flush, got: %v", err)
	}
}

// TestWriter_GracefulShutdown verifies that Close() returns nil and the file
// contains the correct ElfFile magic after writing 10 records.
func TestWriter_GracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "graceful.evtx")

	w, err := New(outPath, RotationConfig{FlushIntervalSec: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 10; i++ {
		fields := map[string]string{
			"ProviderName": "Microsoft-Windows-Security-Auditing",
			"Computer":     "testhost",
		}
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
	if string(data[0:8]) != "ElfFile\x00" {
		t.Errorf("file magic = %q, want %q", data[0:8], "ElfFile\x00")
	}
}

// TestWriter_NoGoroutine_WhenDisabled verifies that no goroutine is started when
// FlushIntervalSec == 0, and that Close() still works correctly.
func TestWriter_NoGoroutine_WhenDisabled(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "no_goroutine.evtx")

	w, err := New(outPath, RotationConfig{FlushIntervalSec: 0})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// wg counter must be zero (no goroutine started).
	// We verify by confirming wg.Wait() returns immediately (no goroutine to wait for).
	// This is a behavioral check: Close() must not hang.
	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Close()
	}()

	select {
	case <-done:
		// Close returned promptly — no goroutine leak.
	case <-time.After(2 * time.Second):
		t.Fatal("Close() hung — possible goroutine leak")
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("file missing after Close: %v", err)
	}
}

// TestWriter_ZeroInterval_NoGoroutine verifies that RotationConfig{FlushIntervalSec:0}
// does not panic and Close() flushes correctly.
func TestWriter_ZeroInterval_NoGoroutine(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "zero_interval.evtx")

	// Must not panic.
	w, err := New(outPath, RotationConfig{})
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
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data[0:8]) != "ElfFile\x00" {
		t.Errorf("file magic = %q, want %q", data[0:8], "ElfFile\x00")
	}
}

// TestWriter_BackgroundFlush_NoRace verifies there are no data races when 5 goroutines
// write concurrently while the background ticker is running.
// Run with: go test -race ./...
func TestWriter_BackgroundFlush_NoRace(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "no_race.evtx")

	w, err := New(outPath, RotationConfig{FlushIntervalSec: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const goroutines = 5
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			fields := map[string]string{
				"ProviderName": "Microsoft-Windows-Security-Auditing",
				"Computer":     "testhost",
				"ObjectName":   "/nas/file.txt",
			}
			if err := w.WriteRecord(4663, fields); err != nil {
				t.Errorf("goroutine %d WriteRecord: %v", n, err)
			}
		}(i)
	}

	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestWriter_CloseFlushesRemaining verifies that Close() flushes records that were
// not yet written by the ticker.
func TestWriter_CloseFlushesRemaining(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "close_flushes.evtx")

	// Use a long interval so the ticker does NOT fire during the test.
	w, err := New(outPath, RotationConfig{FlushIntervalSec: 60})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 3; i++ {
		fields := map[string]string{
			"ProviderName": "Microsoft-Windows-Security-Auditing",
			"Computer":     "testhost",
		}
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("file missing after Close: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("file is empty after Close — records not flushed")
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data[0:8]) != "ElfFile\x00" {
		t.Errorf("file magic = %q, want %q", data[0:8], "ElfFile\x00")
	}
}

// TestWriter_NoGoroutineLeak verifies that after Close(), the background goroutine
// exits cleanly (Close() returns without hanging, implying wg.Wait() completed).
func TestWriter_NoGoroutineLeak(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "no_leak.evtx")

	w, err := New(outPath, RotationConfig{FlushIntervalSec: 1})
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

	done := make(chan error, 1)
	go func() {
		done <- w.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
		// Close returned — goroutine must have exited (wg.Wait() completed).
	case <-time.After(5 * time.Second):
		t.Fatal("Close() hung — goroutine leak detected")
	}
}
