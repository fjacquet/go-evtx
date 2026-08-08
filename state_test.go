// state_test.go — writer lifecycle guards: double Close, write-after-Close.
//
// White-box: package evtx. stdlib only.
package evtx

import (
	"errors"
	"path/filepath"
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
