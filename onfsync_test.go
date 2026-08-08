// onfsync_test.go — the OnFsync callback must not run under the writer lock.
//
// White-box: package evtx. stdlib only.
package evtx

import (
	"path/filepath"
	"testing"
	"time"
)

// TestOnFsync_NotCalledUnderLock verifies a callback can re-enter the Writer.
// Before the fix this deadlocked: OnFsync ran while flushChunkLocked held w.mu.
func TestOnFsync_NotCalledUnderLock(t *testing.T) {
	var w *Writer
	reentered := make(chan struct{}, 1)

	cfg := RotationConfig{
		OnFsync: func(time.Time) {
			// Rotate takes w.mu. If OnFsync runs under the lock this blocks
			// forever and the test times out.
			_ = w.Rotate()
			select {
			case reentered <- struct{}{}:
			default:
			}
		},
	}

	var err error
	w, err = New(filepath.Join(t.TempDir(), "test.evtx"), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Close triggers a final flush, which fires OnFsync.
	done := make(chan error, 1)
	go func() { done <- w.Close() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close timed out: OnFsync is still being called under w.mu")
	}

	select {
	case <-reentered:
	default:
		t.Fatal("OnFsync was never invoked")
	}
}
