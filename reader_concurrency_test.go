// reader_concurrency_test.go — Reader claims to be safe for concurrent use.
// This test makes that claim testable.
//
// White-box: package evtx. stdlib only.
package evtx

import (
	"bytes"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// TestReader_ConcurrentReadRecord runs several readers against one Reader and
// verifies that every record is delivered exactly once with no data race.
// Run with -race for this to be meaningful.
func TestReader_ConcurrentReadRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const records = 50
	for i := 0; i < records; i++ {
		if err := w.WriteRecord(4663, testFields()); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		count int
	)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, err := r.ReadEvent()
				if errors.Is(err, ErrNoMoreRecords) {
					return
				}
				if err != nil {
					return
				}
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if count != records {
		t.Fatalf("concurrent readers saw %d records, want %d", count, records)
	}
}

// recordCountForChunks derives a record count that forces the writer to span
// several chunks, computed from the actual encoded size of a testFields()
// record rather than a guessed constant. Chunk payload capacity is
// maxChunkPayload (65024) bytes; the result crosses n full chunk boundaries
// and leaves a further partial chunk, so multi-chunk tests actually exercise
// loadChunk more than once.
func recordCountForChunks(t *testing.T, n int) int {
	t.Helper()
	payload := buildBinXML(4663, 1, testFields(), evtxRecordsStart+evtxRecordHeaderSize, 0).payload
	rec := wrapEventRecord(1, 0, payload)
	recSize := len(rec)
	if recSize == 0 {
		t.Fatal("computed record size is 0")
	}
	perChunk := maxChunkPayload / recSize
	if perChunk == 0 {
		t.Fatalf("record size %d exceeds chunk payload capacity %d", recSize, maxChunkPayload)
	}
	return perChunk*n + perChunk/2
}

// TestReader_ConcurrentReadRecord_MultiChunk writes enough records to span
// several chunks and reads them back with multiple goroutines calling
// ReadRecord concurrently. TestReader_ConcurrentReadRecord fits in a single
// chunk and never runs loadChunk a second time; this test forces concurrent
// chunk transitions, which is where the interesting races live. It asserts
// every record is delivered exactly once (by RecordID, not just by count),
// with no data race under -race.
func TestReader_ConcurrentReadRecord_MultiChunk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	records := recordCountForChunks(t, 3)
	for i := 0; i < records; i++ {
		if err := w.WriteRecord(4663, testFields()); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	seen := make([]bool, records)
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				ev, err := r.ReadEvent()
				if errors.Is(err, ErrNoMoreRecords) {
					return
				}
				if err != nil {
					t.Errorf("ReadEvent: %v", err)
					return
				}
				idx := int(ev.RecordID) - 1
				mu.Lock()
				switch {
				case idx < 0 || idx >= len(seen):
					mu.Unlock()
					t.Errorf("RecordID %d out of range [1,%d]", ev.RecordID, records)
				case seen[idx]:
					mu.Unlock()
					t.Errorf("RecordID %d delivered more than once", ev.RecordID)
				default:
					seen[idx] = true
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	for i, ok := range seen {
		if !ok {
			t.Errorf("RecordID %d was never delivered", i+1)
		}
	}
}

// TestReader_ConcurrentReadRaw_MultiChunk exercises ReadRaw across concurrent
// chunk transitions and verifies the returned payload is memory the caller
// owns. Each goroutine snapshots a payload immediately after ReadRaw
// returns, then retains the original slice for the rest of the test — by
// which point many further loadChunk calls (made by other goroutines) have
// run. If ReadRaw ever handed back a slice aliasing the Reader's shared
// chunk buffer, those later loads would overwrite it in place and the
// retained slice would no longer match its snapshot.
func TestReader_ConcurrentReadRaw_MultiChunk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	records := recordCountForChunks(t, 3)
	for i := 0; i < records; i++ {
		if err := w.WriteRecord(4663, testFields()); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	type held struct {
		payload  []byte // slice returned by ReadRaw, retained for the whole test
		snapshot []byte // independent copy taken immediately after the call
	}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		holds []held
	)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				payload, err := r.ReadRaw()
				if errors.Is(err, ErrNoMoreRecords) {
					return
				}
				if err != nil {
					t.Errorf("ReadRaw: %v", err)
					return
				}
				if len(payload) == 0 {
					t.Error("ReadRaw returned empty payload")
					return
				}
				snapshot := append([]byte(nil), payload...)
				mu.Lock()
				holds = append(holds, held{payload: payload, snapshot: snapshot})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(holds) != records {
		t.Fatalf("ReadRaw delivered %d payloads, want %d", len(holds), records)
	}
	// wg.Wait has returned, so every chunk load triggered by any goroutine has
	// already happened. Compare each retained payload against its own
	// snapshot: a mismatch means the slice was mutated after ReadRaw returned
	// it, i.e. it was not the caller's own copy.
	for i, h := range holds {
		if !bytes.Equal(h.payload, h.snapshot) {
			t.Fatalf("payload %d changed after ReadRaw returned: got %x, want %x", i, h.payload, h.snapshot)
		}
	}
}
