// syncpolicy_test.go — group-commit fsync policy (v0.11.0).
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported writer state).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"path/filepath"
	"testing"
)

// TestSyncPolicy_ZeroValueIsEveryChunk pins the compatibility invariant: a
// caller who never mentions SyncPolicy gets exactly today's durability.
func TestSyncPolicy_ZeroValueIsEveryChunk(t *testing.T) {
	var cfg RotationConfig
	if cfg.SyncPolicy != SyncEveryChunk {
		t.Fatalf("zero value = %v, want SyncEveryChunk", cfg.SyncPolicy)
	}
	if SyncEveryChunk != 0 {
		t.Fatalf("SyncEveryChunk = %d, want 0 — the zero value must be the safe policy", SyncEveryChunk)
	}
}

// TestSyncPolicy_RejectsUnboundedWindow verifies New refuses SyncOnTick with no
// flush tick. With no tick there is no sync until Close, so the crash-loss
// window would be the whole session rather than FlushIntervalSec.
func TestSyncPolicy_RejectsUnboundedWindow(t *testing.T) {
	dir := t.TempDir()
	w, err := New(filepath.Join(dir, "bad.evtx"), RotationConfig{
		SyncPolicy:       SyncOnTick,
		FlushIntervalSec: 0,
	})
	if err == nil {
		_ = w.Close()
		t.Fatal("New accepted SyncOnTick with FlushIntervalSec=0; want an error")
	}
	if w != nil {
		t.Fatal("New returned a non-nil Writer alongside an error")
	}
}

// TestSyncPolicy_AcceptsBoundedWindow verifies the valid combination is accepted.
func TestSyncPolicy_AcceptsBoundedWindow(t *testing.T) {
	dir := t.TempDir()
	w, err := New(filepath.Join(dir, "good.evtx"), RotationConfig{
		SyncPolicy:       SyncOnTick,
		FlushIntervalSec: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
