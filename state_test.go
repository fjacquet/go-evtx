// state_test.go — writer lifecycle guards: double Close, write-after-Close.
//
// White-box: package evtx. stdlib only.
package evtx

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testFields returns a minimal valid field map for WriteRecord.
func testFields() map[string]string {
	return map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"TimeCreated":  time.Now().Format(time.RFC3339Nano),
		"ObjectName":   "/mnt/share/file.txt",
	}
}

// TestWriter_Close_Idempotent verifies that a second Close returns the first
// call's result instead of panicking on close of a closed channel.
func TestWriter_Close_Idempotent(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "test.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	first := w.Close()
	if first != nil {
		t.Fatalf("first Close: %v", first)
	}

	// Must not panic.
	if second := w.Close(); second != nil {
		t.Fatalf("second Close returned %v, want nil (same as first)", second)
	}
}

// TestWriter_Close_ConcurrentCallers verifies that Close() is safe to call
// from multiple goroutines at once: every caller observes the identical
// result, never a premature nil racing ahead of the real outcome.
//
// Each trial closes the underlying file handle out from under the writer
// first, so finalizeLocked's flush is guaranteed to fail with a non-nil
// error. This makes the bug observable: before the sync.Once fix, a
// goroutine could see w.closed == true (set early) and read w.closeErr
// while it was still the zero value, returning a wrong nil instead of
// waiting for the real error — a caller acting on that nil would believe
// the data was durable when it was not. It is a lock-protected logic race,
// not a data race, so -race alone cannot catch it; this test pins the
// observable behavior instead. With a successful Close (nil on every path)
// a premature nil is indistinguishable from the correct result, so forcing
// a failure is what makes the assertion meaningful.
//
// The buggy critical section is only a few instructions with no real
// blocking (RotationConfig{} runs no background goroutine, so wg.Wait()
// returns immediately), so any single trial rarely lands in the vulnerable
// window. Repeating many trials, each with many concurrent callers, is what
// makes this reliably catch a regression: verified empirically against the
// pre-fix implementation, a single trial of 500 callers missed the race
// most of the time, but looping trials inside one test process reproduced
// the mismatch on the very first trial.
func TestWriter_Close_ConcurrentCallers(t *testing.T) {
	const trials = 20
	const goroutines = 500

	for trial := 0; trial < trials; trial++ {
		path := filepath.Join(t.TempDir(), "test.evtx")
		w, err := New(path, RotationConfig{})
		if err != nil {
			t.Fatalf("trial %d: New: %v", trial, err)
		}
		if err := w.WriteRecord(4663, testFields()); err != nil {
			t.Fatalf("trial %d: WriteRecord: %v", trial, err)
		}

		// Force the flush inside Close to fail: close w.f directly (bypassing
		// closeFileLocked/fileClosed bookkeeping) so the pending record can
		// never be written out.
		w.mu.Lock()
		_ = w.f.Close()
		w.mu.Unlock()

		results := make([]error, goroutines)
		var wg sync.WaitGroup
		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			i := i
			go func() {
				defer wg.Done()
				results[i] = w.Close()
			}()
		}
		wg.Wait()

		for i, r := range results {
			if r == nil {
				t.Fatalf("trial %d: Close() call %d = nil, want the forced flush failure to surface as a non-nil error", trial, i)
			}
			if r != results[0] {
				t.Fatalf("trial %d: Close() call %d = %v, want the identical error every other caller got (%v)", trial, i, r, results[0])
			}
		}
	}
}

// TestWriter_WriteAfterClose verifies that a write racing shutdown is rejected
// rather than buffered into a chunk that will never be flushed.
func TestWriter_WriteAfterClose(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "test.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := w.WriteRecord(4663, testFields()); !errors.Is(err, ErrClosed) {
		t.Fatalf("WriteRecord after Close = %v, want ErrClosed", err)
	}
	if err := w.WriteRaw([]byte{0x0f, 0x01, 0x01, 0x00}); !errors.Is(err, ErrClosed) {
		t.Fatalf("WriteRaw after Close = %v, want ErrClosed", err)
	}
	if err := w.Rotate(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Rotate after Close = %v, want ErrClosed", err)
	}
}

// TestWriter_StickyErrorOutranksErrClosed pins the documented precedence: when
// a writer is both poisoned and closed, callers get the durability error, not
// ErrClosed. Reporting only ErrClosed would hide the fact that data was lost.
//
// The sticky error is set directly here rather than by provoking a rotation
// failure, so the assertion holds identically on every platform.
func TestWriter_StickyErrorOutranksErrClosed(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "test.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// w.f is never released by this test's assertions (w.err/w.closed are set
	// directly, not via Close()). t.TempDir's cleanup removes the directory
	// and fails the test if removal fails; Windows refuses to delete a file
	// with an open handle. Close() after the assertions releases it — it
	// runs against the already-poisoned writer, which is harmless and does
	// not affect anything already asserted above.
	t.Cleanup(func() { _ = w.Close() })

	sentinel := errors.New("durability lost")
	w.mu.Lock()
	w.err = sentinel
	w.closed = true
	w.mu.Unlock()

	got := w.WriteRecord(4663, testFields())
	if !errors.Is(got, sentinel) {
		t.Fatalf("WriteRecord = %v, want the sticky error %v", got, sentinel)
	}
	if errors.Is(got, ErrClosed) {
		t.Fatal("ErrClosed masked the durability error: callers would not learn data was lost")
	}
}

// TestWriter_Close_FinalFlushFailureSetsStickyError drives Close into the
// path where finalizeLocked's own final flush fails, and verifies that
// checkStateLocked's documented precedence — the sticky durability error
// outranks ErrClosed — actually holds afterward. Before this fix,
// finalizeLocked returned the flush error to Close's immediate caller but
// never set w.err, so a later call would see only w.closed and report
// ErrClosed: "the writer shut down," not "data was lost."
func TestWriter_Close_FinalFlushFailureSetsStickyError(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "test.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Force the final flush inside Close (finalizeLocked -> flushChunkLocked)
	// to fail: close w.f directly, bypassing closeFileLocked/fileClosed
	// bookkeeping, so the buffered record can never be written out. Same
	// technique as TestWriter_Close_ConcurrentCallers and
	// flush_atomicity_test.go.
	w.mu.Lock()
	_ = w.f.Close()
	w.mu.Unlock()

	closeErr := w.Close()
	if closeErr == nil {
		t.Fatal("Close with a failing final flush returned nil, want the flush error")
	}

	w.mu.Lock()
	stickyErr := w.err
	w.mu.Unlock()
	if stickyErr == nil {
		t.Fatal("w.err is nil after Close's final flush failed: checkStateLocked will report ErrClosed instead of the durability error")
	}

	// The point of the fix: a caller inspecting the writer after this failed
	// Close must learn that data was lost, not merely that it is closed.
	got := w.WriteRecord(4663, testFields())
	if errors.Is(got, ErrClosed) {
		t.Fatalf("WriteRecord after a Close whose final flush failed = %v (ErrClosed); want the sticky durability error — the caller is being told only that the writer is shut down, not that data never reached disk", got)
	}
	if !errors.Is(got, stickyErr) {
		t.Fatalf("WriteRecord after failed Close = %v, want the sticky error %v", got, stickyErr)
	}
}

// TestWriteRecord_RejectsEmptyProviderName pins the one field validated at
// write time, and pins that it is the only one.
//
// Measured on Windows Server 2025, one variable at a time: with an empty
// ProviderName, Get-WinEvent throws a NullReferenceException on the whole
// file; with an empty Computer or an empty Channel it reads every record.
// Since v0.7.1 an unsupplied value is a NULL substitution, which omits its
// element — so an empty provider name yields <Provider></Provider>, and the
// reader dereferences a provider that has no name. Reported downstream as
// issue #10, where it cost a full investigation.
//
// Computer and Channel are deliberately NOT validated. Rejecting them would
// be a rule nothing measured.
func TestWriteRecord_RejectsEmptyProviderName(t *testing.T) {
	valid := func() map[string]string {
		return map[string]string{
			"ProviderName": "Microsoft-Windows-Security-Auditing",
			"Computer":     "TESTHOST",
			"Channel":      "Security",
			"ObjectName":   `C:\test\file.txt`,
		}
	}
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr error
	}{
		{"all set", func(map[string]string) {}, nil},
		{"empty ProviderName", func(f map[string]string) { f["ProviderName"] = "" }, ErrMissingProviderName},
		{"absent ProviderName", func(f map[string]string) { delete(f, "ProviderName") }, ErrMissingProviderName},
		{"empty Computer", func(f map[string]string) { f["Computer"] = "" }, nil},
		{"empty Channel", func(f map[string]string) { f["Channel"] = "" }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(filepath.Join(t.TempDir(), "w.evtx"), RotationConfig{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			f := valid()
			tc.mutate(f)
			err = w.WriteRecord(4663, f)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("WriteRecord = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestWriteRecord_EmptyProviderNameWritesNothing pins that a rejected record
// leaves the writer untouched — the same contract ErrRecordTooLarge has.
func TestWriteRecord_EmptyProviderNameWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRecord(4663, map[string]string{"ObjectName": "x"}); !errors.Is(err, ErrMissingProviderName) {
		t.Fatalf("WriteRecord = %v, want ErrMissingProviderName", err)
	}
	if err := w.WriteRecord(4663, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"ObjectName":   "x",
	}); err != nil {
		t.Fatalf("second WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
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
		t.Errorf("file holds %d records, want 1 — the rejected record must not have been written", n)
	}
}
