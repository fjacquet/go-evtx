// syncpolicy_test.go — group-commit fsync policy (v0.11.0).
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported writer state).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"bytes"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
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

// TestSyncPolicy_RejectsOutOfRangeValue verifies New refuses a SyncPolicy
// value outside the two defined constants, rather than silently treating it
// as SyncEveryChunk (every check in the codebase tests only == SyncOnTick or
// != SyncOnTick, so an unrecognized value would otherwise pass through
// unnoticed as the more durable policy).
func TestSyncPolicy_RejectsOutOfRangeValue(t *testing.T) {
	dir := t.TempDir()
	w, err := New(filepath.Join(dir, "bad-policy.evtx"), RotationConfig{
		SyncPolicy: SyncPolicy(2),
	})
	if err == nil {
		_ = w.Close()
		t.Fatal("New accepted SyncPolicy(2); want an error")
	}
	if w != nil {
		t.Fatal("New returned a non-nil Writer alongside an error")
	}
}

// TestSyncPolicy_StringerFormatsKnownAndUnknownValues verifies SyncPolicy's
// String method names the two defined constants and falls back to a
// SyncPolicy(%d) form for anything else.
func TestSyncPolicy_StringerFormatsKnownAndUnknownValues(t *testing.T) {
	cases := []struct {
		p    SyncPolicy
		want string
	}{
		{SyncEveryChunk, "SyncEveryChunk"},
		{SyncOnTick, "SyncOnTick"},
		{SyncPolicy(2), "SyncPolicy(2)"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("SyncPolicy(%d).String() = %q, want %q", int(c.p), got, c.want)
		}
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

// syncCountingWriter returns a Writer whose fsyncs are counted.
func syncCountingWriter(t *testing.T, path string, cfg RotationConfig, n *int64) *Writer {
	t.Helper()
	cfg.OnFsync = func(time.Time) { atomic.AddInt64(n, 1) }
	w, err := New(path, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

func syncTestFields() map[string]string {
	return map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
		"TimeCreated":  "2026-08-22T12:00:00.000000000Z",
	}
}

// recordsPerChunkApprox is enough records to seal several chunks. Records run
// roughly 780 bytes and maxChunkPayload is 65024, so ~83 records fill a chunk.
const recordsForSeveralChunks = 300

// TestSyncPolicy_OnTickFsyncsFewerTimes verifies group commit: with SyncOnTick,
// sealing chunks does not fsync, so the count is far below the number of chunks.
func TestSyncPolicy_OnTickFsyncsFewerTimes(t *testing.T) {
	dir := t.TempDir()

	var everyChunk, onTick int64
	we := syncCountingWriter(t, filepath.Join(dir, "every.evtx"),
		RotationConfig{FlushIntervalSec: 3600}, &everyChunk)
	wt := syncCountingWriter(t, filepath.Join(dir, "tick.evtx"),
		RotationConfig{FlushIntervalSec: 3600, SyncPolicy: SyncOnTick}, &onTick)

	for i := 0; i < recordsForSeveralChunks; i++ {
		if err := we.WriteRecord(4663, syncTestFields()); err != nil {
			t.Fatalf("every-chunk WriteRecord %d: %v", i, err)
		}
		if err := wt.WriteRecord(4663, syncTestFields()); err != nil {
			t.Fatalf("on-tick WriteRecord %d: %v", i, err)
		}
	}

	// Read the counts before Close, which syncs under both policies.
	gotEvery := atomic.LoadInt64(&everyChunk)
	gotTick := atomic.LoadInt64(&onTick)

	if gotEvery < 2 {
		t.Fatalf("SyncEveryChunk fsynced %d times; expected one per sealed chunk", gotEvery)
	}
	if gotTick != 0 {
		t.Fatalf("SyncOnTick fsynced %d times while sealing chunks; expected 0 "+
			"(the tick interval is an hour, so no tick can have fired)", gotTick)
	}

	if err := we.Close(); err != nil {
		t.Fatalf("every-chunk Close: %v", err)
	}
	if err := wt.Close(); err != nil {
		t.Fatalf("on-tick Close: %v", err)
	}

	// Close syncs under every policy.
	if atomic.LoadInt64(&onTick) == 0 {
		t.Fatal("SyncOnTick never fsynced even at Close")
	}
}

// TestSyncPolicy_ByteIdenticalAcrossPolicies pins the compatibility invariant:
// the policy changes when bytes are made durable, never which bytes land.
func TestSyncPolicy_ByteIdenticalAcrossPolicies(t *testing.T) {
	write := func(name string, cfg RotationConfig) []byte {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		w, err := New(p, cfg)
		if err != nil {
			t.Fatalf("%s New: %v", name, err)
		}
		defer w.Close() //nolint:errcheck
		for i := 0; i < recordsForSeveralChunks; i++ {
			if err := w.WriteRecord(4663, syncTestFields()); err != nil {
				t.Fatalf("%s WriteRecord %d: %v", name, i, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("%s Close: %v", name, err)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s ReadFile: %v", name, err)
		}
		return raw
	}

	every := write("every.evtx", RotationConfig{FlushIntervalSec: 3600})
	tick := write("tick.evtx", RotationConfig{FlushIntervalSec: 3600, SyncPolicy: SyncOnTick})

	if len(every) != len(tick) {
		t.Fatalf("sizes differ: SyncEveryChunk %d, SyncOnTick %d", len(every), len(tick))
	}
	if !bytes.Equal(every, tick) {
		for i := range every {
			if every[i] != tick[i] {
				t.Fatalf("files differ at offset %d (0x%x): every %#02x, tick %#02x",
					i, i, every[i], tick[i])
			}
		}
	}
}

// TestSyncPolicy_TickSyncsASealedChunkWithNoPendingRecords is the regression
// guard for the defect this task fixes. Under SyncOnTick a burst can seal a
// chunk and then stop. The tick's early returns (no records at all, or nothing
// appended since last tick) must not skip the fsync that chunk is still owed,
// or the data sits in the page cache until Close and the loss window is
// unbounded — the very thing New refuses to allow.
func TestSyncPolicy_TickSyncsASealedChunkWithNoPendingRecords(t *testing.T) {
	dir := t.TempDir()
	var syncs int64
	w := syncCountingWriter(t, filepath.Join(dir, "pending.evtx"),
		RotationConfig{FlushIntervalSec: 1, SyncPolicy: SyncOnTick}, &syncs)
	defer w.Close() //nolint:errcheck

	// Seal at least one chunk, then leave nothing pending.
	w.mu.Lock()
	for len(w.records) == 0 || w.chunkCount == 0 {
		w.mu.Unlock()
		if err := w.WriteRecord(4663, syncTestFields()); err != nil {
			t.Fatalf("WriteRecord: %v", err)
		}
		w.mu.Lock()
	}
	w.mu.Unlock()

	// Drain the pending records into the sealed chunk so w.records is empty.
	w.mu.Lock()
	if err := w.flushChunkLocked(); err != nil {
		w.mu.Unlock()
		t.Fatalf("flushChunkLocked: %v", err)
	}
	pending := w.pendingSync
	w.mu.Unlock()
	w.drainFsyncCallbacks()

	if !pending {
		t.Fatal("pendingSync is false after sealing a chunk under SyncOnTick")
	}
	before := atomic.LoadInt64(&syncs)

	// Wait for a tick with nothing appended.
	time.Sleep(2500 * time.Millisecond)

	if atomic.LoadInt64(&syncs) <= before {
		t.Fatalf("no fsync after %d ticks with a chunk owed one: count stayed at %d",
			2, before)
	}
	w.mu.Lock()
	still := w.pendingSync
	w.mu.Unlock()
	if still {
		t.Fatal("pendingSync still set after the tick fsynced")
	}
}
