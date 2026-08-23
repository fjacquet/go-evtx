// batch_test.go — the WriteRecords batch API (v0.11.0).
//
// No build tag: tests run on all platforms.
// White-box: package evtx.
// stdlib only: no testify, no external libraries.
package evtx

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func batchFields(object string) map[string]string {
	return map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   object,
		"TimeCreated":  "2026-08-22T12:00:00.000000000Z",
	}
}

// TestWriteRecords_EquivalentToIndividualWrites is the contract that makes the
// batch API safe to adopt: the same records through either entry point produce
// the same file, byte for byte.
func TestWriteRecords_EquivalentToIndividualWrites(t *testing.T) {
	const n = 200

	batchPath := filepath.Join(t.TempDir(), "batch.evtx")
	wb, err := New(batchPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New batch: %v", err)
	}
	defer wb.Close() //nolint:errcheck
	recs := make([]RecordInput, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, RecordInput{EventID: 4663, Fields: batchFields("/nas/f.txt")})
	}
	if err := wb.WriteRecords(recs); err != nil {
		t.Fatalf("WriteRecords: %v", err)
	}
	if err := wb.Close(); err != nil {
		t.Fatalf("batch Close: %v", err)
	}

	onePath := filepath.Join(t.TempDir(), "one.evtx")
	wo, err := New(onePath, RotationConfig{})
	if err != nil {
		t.Fatalf("New single: %v", err)
	}
	defer wo.Close() //nolint:errcheck
	for i := 0; i < n; i++ {
		if err := wo.WriteRecord(4663, batchFields("/nas/f.txt")); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := wo.Close(); err != nil {
		t.Fatalf("single Close: %v", err)
	}

	a, err := os.ReadFile(batchPath)
	if err != nil {
		t.Fatalf("ReadFile batch: %v", err)
	}
	b, err := os.ReadFile(onePath)
	if err != nil {
		t.Fatalf("ReadFile single: %v", err)
	}
	if !bytes.Equal(a, b) {
		if len(a) != len(b) {
			t.Fatalf("sizes differ: batch %d, single %d", len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("files differ at offset %d (0x%x): batch %#02x, single %#02x",
					i, i, a[i], b[i])
			}
		}
	}
}

// TestWriteRecords_EmptySliceIsNoOp verifies an empty batch changes nothing.
func TestWriteRecords_EmptySliceIsNoOp(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "empty.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	w.mu.Lock()
	beforeID, beforeLen := w.recordID, len(w.records)
	w.mu.Unlock()

	if err := w.WriteRecords(nil); err != nil {
		t.Fatalf("WriteRecords(nil): %v", err)
	}
	if err := w.WriteRecords([]RecordInput{}); err != nil {
		t.Fatalf("WriteRecords(empty): %v", err)
	}

	w.mu.Lock()
	afterID, afterLen := w.recordID, len(w.records)
	w.mu.Unlock()
	if beforeID != afterID || beforeLen != afterLen {
		t.Fatalf("empty batch mutated state: recordID %d->%d, records %d->%d bytes",
			beforeID, afterID, beforeLen, afterLen)
	}
}

// TestWriteRecords_InvalidRecordWritesNothing is the all-or-nothing contract.
// A bad record anywhere in the slice must leave the writer untouched, and the
// error must name its index.
func TestWriteRecords_InvalidRecordWritesNothing(t *testing.T) {
	cases := []struct {
		name    string
		bad     RecordInput
		wantErr error
	}{
		{
			name:    "missing provider",
			bad:     RecordInput{EventID: 4663, Fields: map[string]string{"Computer": "h"}},
			wantErr: ErrMissingProviderName,
		},
		{
			name: "unparseable Level",
			bad: RecordInput{EventID: 4663, Fields: map[string]string{
				"ProviderName": "P", "Level": "not-a-number",
			}},
			wantErr: ErrInvalidFieldValue,
		},
		{
			name: "oversized record",
			bad: RecordInput{EventID: 4663, Fields: map[string]string{
				"ProviderName": "P", "ObjectName": strings.Repeat("x", 40000),
			}},
			wantErr: ErrRecordTooLarge,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(filepath.Join(t.TempDir(), "bad.evtx"), RotationConfig{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer w.Close() //nolint:errcheck

			w.mu.Lock()
			beforeID, beforeLen := w.recordID, len(w.records)
			w.mu.Unlock()

			recs := []RecordInput{
				{EventID: 4663, Fields: batchFields("/a.txt")},
				{EventID: 4663, Fields: batchFields("/b.txt")},
				tc.bad,
				{EventID: 4663, Fields: batchFields("/c.txt")},
			}
			err = w.WriteRecords(recs)
			if err == nil {
				t.Fatal("WriteRecords accepted a batch containing an invalid record")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want one wrapping %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "record 2") {
				t.Fatalf("error %q does not name the offending index (record 2)", err)
			}

			w.mu.Lock()
			afterID, afterLen := w.recordID, len(w.records)
			w.mu.Unlock()
			if beforeID != afterID || beforeLen != afterLen {
				t.Fatalf("rejected batch still mutated state: recordID %d->%d, records %d->%d bytes",
					beforeID, afterID, beforeLen, afterLen)
			}
		})
	}
}

// TestWriteRecords_SpansChunks verifies a batch larger than one chunk seals
// chunks mid-batch and every record reads back.
func TestWriteRecords_SpansChunks(t *testing.T) {
	p := filepath.Join(t.TempDir(), "span.evtx")
	w, err := New(p, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	const n = 300 // ~83 records per chunk, so several chunks
	recs := make([]RecordInput, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, RecordInput{EventID: 4663, Fields: batchFields("/nas/f.txt")})
	}
	if err := w.WriteRecords(recs); err != nil {
		t.Fatalf("WriteRecords: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close() //nolint:errcheck
	var count int
	for {
		_, err := r.ReadEvent()
		if err == ErrNoMoreRecords {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent after %d: %v", count, err)
		}
		count++
	}
	if count != n {
		t.Fatalf("read %d records, wrote %d", count, n)
	}
}

// TestWriteRecords_ConcurrentWithWriteRecord verifies the batch entry point
// takes the same lock as the single-record one. Run with -race, which is how
// the whole suite runs; a missing or mis-scoped lock shows up here.
func TestWriteRecords_ConcurrentWithWriteRecord(t *testing.T) {
	p := filepath.Join(t.TempDir(), "concurrent.evtx")
	w, err := New(p, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const (
		batchers      = 4
		singles       = 4
		batchSize     = 10
		roundsPerGoro = 20
	)

	var wg sync.WaitGroup
	wg.Add(batchers + singles)

	for i := 0; i < batchers; i++ {
		go func(n int) {
			defer wg.Done()
			recs := make([]RecordInput, batchSize)
			for j := range recs {
				recs[j] = RecordInput{EventID: 4663, Fields: batchFields("/nas/batch.txt")}
			}
			for r := 0; r < roundsPerGoro; r++ {
				if err := w.WriteRecords(recs); err != nil {
					t.Errorf("batcher %d round %d: %v", n, r, err)
					return
				}
			}
		}(i)
	}
	for i := 0; i < singles; i++ {
		go func(n int) {
			defer wg.Done()
			for r := 0; r < roundsPerGoro*batchSize; r++ {
				if err := w.WriteRecord(4663, batchFields("/nas/single.txt")); err != nil {
					t.Errorf("single %d round %d: %v", n, r, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every record must be readable and the IDs must be a gapless sequence —
	// a lost update under concurrency shows up as a short count.
	want := batchers*roundsPerGoro*batchSize + singles*roundsPerGoro*batchSize
	r, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close() //nolint:errcheck
	var count int
	for {
		_, err := r.ReadEvent()
		if err == ErrNoMoreRecords {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent after %d: %v", count, err)
		}
		count++
	}
	if count != want {
		t.Fatalf("read %d records, wrote %d", count, want)
	}
}
