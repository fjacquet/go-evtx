// alloc_test.go — allocation ceilings and buffer-reuse safety (v0.11.0).
//
// No build tag: tests run on all platforms.
// White-box: package evtx.
// stdlib only: no testify, no external libraries.
package evtx

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func allocFields(object string) map[string]string {
	return map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   object,
		"TimeCreated":  "2026-08-22T12:00:00.000000000Z",
	}
}

// TestChunkScratch_NoStaleBytesInPadding is the guard for the reuse hazard.
// flushChunkLocked writes all 65 536 bytes of a chunk, padding included. A
// reused buffer still holds the previous chunk's records, so without clearing
// they would be written into this chunk's padding — leaking data into the file
// and breaking byte-identity with v0.10.0.
//
// The first chunk is filled with a distinctive marker; the second chunk's
// padding must not contain it.
func TestChunkScratch_NoStaleBytesInPadding(t *testing.T) {
	p := filepath.Join(t.TempDir(), "stale.evtx")
	w, err := New(p, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	const marker = "STALEMARKERSTALEMARKER"

	// Fill chunk 0 with marked records.
	w.mu.Lock()
	for w.chunkCount == 0 {
		w.mu.Unlock()
		if err := w.WriteRecord(4663, allocFields("/nas/"+marker+".txt")); err != nil {
			t.Fatalf("WriteRecord (marked): %v", err)
		}
		w.mu.Lock()
	}
	w.mu.Unlock()

	// Write a couple of unmarked records into chunk 1 and seal it.
	for i := 0; i < 3; i++ {
		if err := w.WriteRecord(4663, allocFields("/nas/plain.txt")); err != nil {
			t.Fatalf("WriteRecord (plain): %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Chunk 1's padding runs from its FreeSpaceOffset to the end of the chunk.
	const chunk1Start = evtxFileHeaderSize + evtxChunkSize
	if len(raw) < chunk1Start+evtxChunkSize {
		t.Fatalf("file is %d bytes; expected at least two whole chunks", len(raw))
	}
	chunk1 := raw[chunk1Start : chunk1Start+evtxChunkSize]
	free := int(le32(chunk1[48:]))
	if free < int(evtxRecordsStart) || free > evtxChunkSize {
		t.Fatalf("chunk 1 FreeSpaceOffset = %d, out of range", free)
	}
	padding := chunk1[free:]

	if bytes.Contains(padding, []byte(marker)) {
		t.Fatal("chunk 1's padding contains chunk 0's data — the reused scratch " +
			"buffer was not cleared")
	}
	for i, b := range padding {
		if b != 0 {
			t.Fatalf("chunk 1's padding is non-zero at offset %d (value %#02x); "+
				"padding must be zero", free+i, b)
		}
	}
}

// TestBuildBinXML_PayloadSurvivesNextEncode guards the aliasing hazard. If the
// encoder returns a slice into a reused buffer, the previous record's payload
// is silently rewritten by the next encode.
func TestBuildBinXML_PayloadSurvivesNextEncode(t *testing.T) {
	first := buildBinXML(4663, 1, allocFields("/nas/first-record.txt"), 4096, 512)
	kept := first.payload
	snapshot := append([]byte(nil), kept...)

	// Encode a different record; if payload aliases a shared buffer this
	// overwrites it.
	_ = buildBinXML(4625, 2, allocFields("/nas/second-record-much-longer.txt"), 4096, 512)

	if !bytes.Equal(kept, snapshot) {
		t.Fatal("the first payload changed after a second encode — buildBinXML's " +
			"result aliases a reused buffer and the caller must copy")
	}
}

// TestWriteRecord_AllocationCeiling fails the build when per-record allocation
// regresses, rather than only moving a benchmark number.
func TestWriteRecord_AllocationCeiling(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "alloc.evtx"), RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	fields := allocFields("/nas/f.txt")
	// Warm up so the first record's inline-template encode and the initial
	// scratch allocation are not counted.
	for i := 0; i < 50; i++ {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}

	const ceiling = 12
	got := testing.AllocsPerRun(200, func() {
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord: %v", err)
		}
	})
	if got > ceiling {
		t.Fatalf("WriteRecord allocates %.1f objects per call, ceiling is %d", got, ceiling)
	}
	t.Logf("WriteRecord: %.1f allocs/op", got)
}
