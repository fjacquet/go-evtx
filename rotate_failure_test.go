// rotate_failure_test.go — a rotation that fails must poison the writer,
// not silently accept events it will never persist.
//
// White-box: package evtx. stdlib only.
package evtx

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRotate_FailurePoisonsWriter makes the parent directory read-only so the
// rename in rotate() fails, then verifies the writer refuses all further work
// instead of accepting events into a closed file handle.
func TestRotate_FailurePoisonsWriter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not block rename on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: read-only directory does not block rename")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Make the directory read-only so os.Rename fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	rotErr := w.Rotate()
	if rotErr == nil {
		t.Fatal("Rotate on read-only directory returned nil, want an error")
	}

	// Every subsequent call must return an error — never nil.
	if err := w.WriteRecord(4663, testFields()); err == nil {
		t.Fatal("WriteRecord after failed rotate returned nil: events are being silently discarded")
	}
	if err := w.WriteRaw([]byte{0x0f, 0x01}); err == nil {
		t.Fatal("WriteRaw after failed rotate returned nil")
	}
	if err := w.Rotate(); err == nil {
		t.Fatal("second Rotate after failed rotate returned nil")
	}
	if err := w.Close(); err == nil {
		t.Fatal("Close after failed rotate returned nil")
	}
}

// TestRotate_StickyErrorIsStable verifies the same error value is returned by
// every entry point, so a caller can compare against a single cause.
func TestRotate_StickyErrorIsStable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not block rename on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}

	dir := t.TempDir()
	w, err := New(filepath.Join(dir, "test.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	first := w.Rotate()
	second := w.WriteRecord(4663, testFields())
	if !errors.Is(second, first) && second.Error() != first.Error() {
		t.Fatalf("sticky error changed: rotate gave %q, write gave %q", first, second)
	}
	if !strings.Contains(first.Error(), "rotate") {
		t.Errorf("sticky error %q does not mention the failing operation", first)
	}
}
