// onfsync_test.go — the OnFsync callback must not run under the writer lock.
//
// White-box: package evtx. stdlib only.
package evtx

import (
	"path/filepath"
	"sync"
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

// TestOnFsync_RotateReportsItsOwnSync covers the hole SyncOnTick opened.
//
// rotate's Step 3 f.Sync() is what makes the archived file durable. Under
// SyncEveryChunk it was invisible that this sync went unreported, because
// Step 1's flushChunkLocked had already fired the callback for the same
// rotation. Under SyncOnTick that flush defers its sync, so before the fix a
// rotation fired no callback at all — a caller counting durability points
// would never learn the archive had landed.
func TestOnFsync_RotateReportsItsOwnSync(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy SyncPolicy
		tick   int
	}{
		{"SyncEveryChunk", SyncEveryChunk, 0},
		{"SyncOnTick", SyncOnTick, 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var calls int
			cfg := RotationConfig{
				FlushIntervalSec: tc.tick,
				SyncPolicy:       tc.policy,
				OnFsync: func(time.Time) {
					mu.Lock()
					calls++
					mu.Unlock()
				},
			}
			w, err := New(filepath.Join(t.TempDir(), "rot.evtx"), cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer w.Close() //nolint:errcheck

			if err := w.WriteRecord(4663, testFields()); err != nil {
				t.Fatalf("WriteRecord: %v", err)
			}

			mu.Lock()
			before := calls
			mu.Unlock()

			if err := w.Rotate(); err != nil {
				t.Fatalf("Rotate: %v", err)
			}

			mu.Lock()
			after := calls
			mu.Unlock()

			if after <= before {
				t.Errorf("Rotate fired no OnFsync callback (count stayed at %d); "+
					"rotate's Step 3 sync makes the archive durable and must be reported",
					before)
			}
		})
	}
}
