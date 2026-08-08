// flush_atomicity_test.go — flushChunkLocked must commit persistent state
// (w.chunkCount, w.currentSize, w.records, w.firstID) atomically: either all
// of it moves together once every I/O step (chunk write, header patch, sync)
// has succeeded, or none of it moves at all when a step fails. A partial
// mutation would make a retry unsafe: rotate()'s Step 1 comment says a
// flushChunkLocked failure "is not sticky — the file handle is still valid,"
// i.e. safe to retry. If chunkCount/currentSize had already advanced, a retry
// would recompute chunkOffset from the advanced chunkCount and write the same
// records into a second chunk slot — duplicate records on WriteRecord's path,
// or an on-disk chunk the file header never acknowledges on Close's path.
//
// White-box: package evtx. stdlib only.
package evtx

import (
	"bytes"
	"path/filepath"
	"testing"
)

// TestFlushChunkLocked_SuccessCommitsTogether drives a real flush and checks
// that chunkCount, currentSize, the reset records buffer, and firstID all
// reflect the same completed flush.
func TestFlushChunkLocked_SuccessCommitsTogether(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "success.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	w.mu.Lock()
	if len(w.records) == 0 {
		w.mu.Unlock()
		t.Fatal("expected buffered records before flush")
	}
	if len(w.chunkNames) == 0 {
		w.mu.Unlock()
		t.Fatal("expected buffered chunkNames before flush")
	}
	wantFirstID := w.recordID // flushChunkLocked sets firstID = recordID on success
	flushErr := w.flushChunkLocked()
	gotChunkCount := w.chunkCount
	gotCurrentSize := w.currentSize
	gotRecordsLen := len(w.records)
	gotNamesLen := len(w.chunkNames)
	gotTemplatesLen := len(w.chunkTemplates)
	gotFirstID := w.firstID
	w.mu.Unlock()

	if flushErr != nil {
		t.Fatalf("flushChunkLocked: %v", flushErr)
	}
	if gotChunkCount != 1 {
		t.Errorf("chunkCount = %d, want 1", gotChunkCount)
	}
	if gotCurrentSize != int64(evtxFileHeaderSize+evtxChunkSize) {
		t.Errorf("currentSize = %d, want %d", gotCurrentSize, int64(evtxFileHeaderSize+evtxChunkSize))
	}
	if gotRecordsLen != 0 {
		t.Errorf("records not reset after successful flush: len=%d", gotRecordsLen)
	}
	if gotNamesLen != 0 {
		t.Errorf("chunkNames not reset after successful flush: len=%d", gotNamesLen)
	}
	if gotTemplatesLen != 0 {
		t.Errorf("chunkTemplates not reset after successful flush: len=%d", gotTemplatesLen)
	}
	if gotFirstID != wantFirstID {
		t.Errorf("firstID = %d, want %d", gotFirstID, wantFirstID)
	}
}

// TestFlushChunkLocked_TotalIOFailureMutatesNothing forces every I/O call in
// flushChunkLocked to fail by closing the file handle out from under the
// writer first (the state_test.go technique: an already-closed *os.File makes
// WriteAt and Sync fail with a real os.ErrClosed, no mocking needed). It then
// asserts chunkCount, currentSize and firstID did not advance, and the
// unflushed bytes are still sitting in w.records.
//
// CAVEAT, recorded deliberately: closing the handle before calling
// flushChunkLocked makes the very first WriteAt inside the function fail.
// Both the pre-fix and post-fix orderings return immediately on that first
// error without mutating anything, so this specific construction cannot
// distinguish the two — it was verified empirically (see the durability
// fix report) that this test passes unchanged against the pre-fix ordering.
// The historical bug required the first WriteAt (chunk body) to SUCCEED and
// a later WriteAt (header patch) or Sync to FAIL — the only window where the
// old code had already mutated w.currentSize/w.chunkCount before durability
// was confirmed. That window could not be reproduced with a real *os.File
// without either an interface seam (out of scope for this fix) or a fragile,
// platform-specific trick that was tried and rejected:
//   - RLIMIT_FSIZE only ever blocks the *larger* write that extends the file
//     (the chunk body); the header patch reuses already-allocated space at
//     offset 0 and is never blocked by a size limit once the chunk write
//     already grew the file.
//   - Opening the file O_APPEND makes every WriteAt fail unconditionally
//     (Go's os.File documents this), not just the second one.
//   - Racing a Close() from another goroutine to land between the two
//     WriteAt calls is not deterministic against real disk I/O timing, and
//     reliably hitting the window would require a synchronization hook
//     inside flushChunkLocked itself — the same seam this fix avoids adding.
//   - A size-capped filesystem relying on delayed fsync-time ENOSPC/EIO
//     reporting is Linux-specific, requires a privileged mount not available
//     in this environment, and would not run under the Windows build target.
//
// This test is kept as real regression coverage for a related invariant —
// total I/O failure must not partially mutate state — but it does not by
// itself prove the ordering fix; that is established by code inspection
// (the mutations textually follow every fallible I/O call) plus this test's
// success-path sibling above.
func TestFlushChunkLocked_TotalIOFailureMutatesNothing(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "failure.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := w.WriteRecord(4663, testFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	w.mu.Lock()

	wantRecords := append([]byte(nil), w.records...)
	wantChunkCount := w.chunkCount
	wantCurrentSize := w.currentSize
	wantFirstID := w.firstID
	wantNames := len(w.chunkNames)
	wantTemplates := len(w.chunkTemplates)
	if len(wantRecords) == 0 {
		w.mu.Unlock()
		t.Fatal("expected buffered records before the forced failure")
	}
	if wantNames == 0 {
		w.mu.Unlock()
		t.Fatal("expected buffered chunkNames before the forced failure")
	}

	// Close the handle directly (bypassing closeFileLocked/fileClosed
	// bookkeeping), so every subsequent I/O call on w.f fails for real.
	_ = w.f.Close()

	flushErr := w.flushChunkLocked()

	gotChunkCount := w.chunkCount
	gotCurrentSize := w.currentSize
	gotFirstID := w.firstID
	gotRecords := append([]byte(nil), w.records...)
	gotNames := len(w.chunkNames)
	gotTemplates := len(w.chunkTemplates)

	w.mu.Unlock()

	if flushErr == nil {
		t.Fatal("flushChunkLocked on a closed file handle returned nil, want an error")
	}
	if gotChunkCount != wantChunkCount {
		t.Errorf("chunkCount advanced on failure: got %d, want %d (unchanged)", gotChunkCount, wantChunkCount)
	}
	if gotCurrentSize != wantCurrentSize {
		t.Errorf("currentSize advanced on failure: got %d, want %d (unchanged)", gotCurrentSize, wantCurrentSize)
	}
	if gotFirstID != wantFirstID {
		t.Errorf("firstID advanced on failure: got %d, want %d (unchanged)", gotFirstID, wantFirstID)
	}
	if !bytes.Equal(gotRecords, wantRecords) {
		t.Errorf("records buffer changed on failure: got %d bytes, want the %d unflushed bytes still buffered", len(gotRecords), len(wantRecords))
	}
	if gotNames != wantNames {
		t.Errorf("chunkNames reset on failure: got %d, want %d", gotNames, wantNames)
	}
	if gotTemplates != wantTemplates {
		t.Errorf("chunkTemplates reset on failure: got %d, want %d", gotTemplates, wantTemplates)
	}
}
