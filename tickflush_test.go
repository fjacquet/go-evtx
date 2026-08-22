// tickflush_test.go — incremental background-tick flush (v0.10.0).
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported writer state).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func tickTestFields() map[string]string {
	return map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"ObjectName":   "/nas/share/file.txt",
		"TimeCreated":  "2026-08-22T12:00:00.000000000Z",
	}
}

// TestWrittenFile_EventRecordsCRCMatchesRecords is the records-checksum
// ordering guard, the pair to TestWrittenFile_ChunkHeaderCRCCoversTables in
// hashtable_integration_test.go: that one guards chunk[124:128] over
// chunk[128:512], this one guards chunk[52:56] over the records region.
//
// The regression it exists for: v0.10.0 briefly replaced the full rescan with
// a CRC maintained incrementally over w.records. fillHashTables patches chain
// offsets INSIDE the records region, so the bytes on disk are not the bytes in
// w.records and every chunk shipped a wrong checksum. TestTickFlush_
// ByteIdenticalToNoTick could not see it — it compares two HEAD writers
// against each other, and the defect was identical on both paths — so this
// asserts the property against the file directly.
func TestWrittenFile_EventRecordsCRCMatchesRecords(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records int
	}{
		{"single", 1},
		{"multi_record", 30},
		{"multi_chunk", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recordscrc.evtx")
			w, err := New(path, RotationConfig{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer w.Close() //nolint:errcheck
			for i := 0; i < tc.records; i++ {
				if err := w.WriteRecord(4663, tickTestFields()); err != nil {
					t.Fatalf("WriteRecord %d: %v", i, err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			nChunks := (len(raw) - evtxFileHeaderSize) / evtxChunkSize
			if nChunks < 1 {
				t.Fatalf("file holds %d chunks", nChunks)
			}
			if tc.name == "multi_chunk" && nChunks < 2 {
				t.Fatalf("wanted a multi-chunk file, got %d chunk(s)", nChunks)
			}
			for c := 0; c < nChunks; c++ {
				off := evtxFileHeaderSize + c*evtxChunkSize
				chunk := raw[off : off+evtxChunkSize]
				// FreeSpaceOffset is at chunk header offset 48; offset 44 is
				// LastEventRecordDataOffset.
				freeSpaceOffset := binary.LittleEndian.Uint32(chunk[48:])
				if freeSpaceOffset < evtxRecordsStart || int(freeSpaceOffset) > evtxChunkSize {
					t.Fatalf("chunk %d: FreeSpaceOffset %d out of range", c, freeSpaceOffset)
				}
				stored := binary.LittleEndian.Uint32(chunk[52:])
				want := crc32.Checksum(chunk[evtxRecordsStart:freeSpaceOffset], crc32.IEEETable)
				if stored != want {
					t.Errorf("chunk %d: EventRecords CRC = 0x%08x, records region "+
						"checksums to 0x%08x — the stored value does not cover the "+
						"bytes on disk", c, stored, want)
				}
			}
		})
	}
}

// TestTickFlush_IdleWritesNothing verifies the background tick performs no
// write and no fsync when no records were appended since the previous tick.
// Before v0.10.0 this rewrote the full 64 KiB chunk on every interval.
func TestTickFlush_IdleWritesNothing(t *testing.T) {
	dir := t.TempDir()
	var syncs int64
	w, err := New(filepath.Join(dir, "idle.evtx"), RotationConfig{
		FlushIntervalSec: 1,
		OnFsync:          func(time.Time) { atomic.AddInt64(&syncs, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	if err := w.WriteRecord(4663, tickTestFields()); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	// Span at least three tick intervals. Only the first has new records.
	time.Sleep(3500 * time.Millisecond)

	if got := atomic.LoadInt64(&syncs); got != 1 {
		t.Fatalf("fsync count = %d after 3 ticks with 1 record, want 1", got)
	}
}

// TestTickFlush_FileChunkAligned verifies the file length stays a whole
// number of chunks after a background tick. A file ending mid-chunk is
// unreadable: loadChunk reads a full evtxChunkSize and hits EOF, and so does
// Windows. This is the regression guard for the partial-range tick write.
func TestTickFlush_FileChunkAligned(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "aligned.evtx")
	var syncs int64
	w, err := New(outPath, RotationConfig{
		FlushIntervalSec: 1,
		OnFsync:          func(time.Time) { atomic.AddInt64(&syncs, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	for i := 0; i < 5; i++ {
		if err := w.WriteRecord(4663, tickTestFields()); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if atomic.LoadInt64(&syncs) == 0 {
		t.Fatal("tick never fired; test cannot measure alignment")
	}

	fi, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	w.mu.Lock()
	chunks := int64(w.chunkCount)
	w.mu.Unlock()

	want := int64(evtxFileHeaderSize) + (chunks+1)*int64(evtxChunkSize)
	if fi.Size() != want {
		t.Fatalf("file size = %d after tick, want %d (header + %d whole chunks)",
			fi.Size(), want, chunks+1)
	}
}

// TestTickFlush_IncrementalRoundTrip verifies records written across several
// background ticks all read back, in order, after Close. This is what proves
// the tick's used-prefix write — the full chunk buffer, patched, with only
// the records region and the 512-byte header written to disk — assembles the
// same chunk the full-chunk write used to produce.
func TestTickFlush_IncrementalRoundTrip(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "incremental.evtx")
	var syncs int64
	w, err := New(outPath, RotationConfig{
		FlushIntervalSec: 1,
		OnFsync:          func(time.Time) { atomic.AddInt64(&syncs, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const batches = 3
	const perBatch = 4
	for b := 0; b < batches; b++ {
		for i := 0; i < perBatch; i++ {
			if err := w.WriteRecord(4663, tickTestFields()); err != nil {
				t.Fatalf("WriteRecord batch %d rec %d: %v", b, i, err)
			}
		}
		time.Sleep(1200 * time.Millisecond) // let a tick land between batches
	}
	if got := atomic.LoadInt64(&syncs); got == 0 {
		t.Fatal("no background tick fired across 3 batches; test cannot verify the incremental round trip")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close() //nolint:errcheck

	var n int
	for {
		_, err := r.ReadEvent()
		if err == ErrNoMoreRecords || err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent after %d records: %v", n, err)
		}
		n++
	}
	if n != batches*perBatch {
		t.Fatalf("read %d records, wrote %d", n, batches*perBatch)
	}
}

// TestTickFlush_CrashSnapshot verifies that a copy of the file taken mid-session
// — that is, whatever a crash would leave behind — parses and yields the records
// written before the last tick. This is the closest available coverage for the
// header-after-records write ordering, which has no injection seam.
func TestTickFlush_CrashSnapshot(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "snapshot.evtx")
	var syncs int64
	w, err := New(outPath, RotationConfig{
		FlushIntervalSec: 1,
		OnFsync:          func(time.Time) { atomic.AddInt64(&syncs, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	const written = 6
	for i := 0; i < written; i++ {
		if err := w.WriteRecord(4663, tickTestFields()); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if atomic.LoadInt64(&syncs) == 0 {
		t.Fatal("tick never fired; nothing to snapshot")
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	snap := filepath.Join(dir, "snapshot-copy.evtx")
	if err := os.WriteFile(snap, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r, err := Open(snap)
	if err != nil {
		t.Fatalf("Open snapshot: %v", err)
	}
	defer r.Close() //nolint:errcheck

	var n int
	for {
		_, err := r.ReadEvent()
		if err == ErrNoMoreRecords || err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent on snapshot after %d records: %v", n, err)
		}
		n++
	}
	if n != written {
		t.Fatalf("snapshot yielded %d records, want %d", n, written)
	}
}

// TestTickFlush_SnapshotHashTablesPopulated verifies a mid-session tick
// actually populates the chunk's hash-table region, chunk[128:512] — the 64
// common-string buckets and 32 template buckets, plus their chain patches.
//
// fillOneTable (chunkhash.go) writes not only the bucket-head arrays inside
// [128:512], but also a 4-byte chain-terminator at chunk[ref.offset:] and a
// 4-byte chain patch at chunk[prev:] for a colliding key — both chunk-
// absolute offsets that point at nodes already copied into the *records*
// region, i.e. at or beyond evtxRecordsStart+evtxRecordHeaderSize (>= 536).
// A header buffer smaller than the full chunk cannot receive those writes:
// every ref fails fillOneTable's bounds check (int(ref.offset)+4 >
// len(chunk)) and is silently skipped, leaving the hash tables entirely
// zero with no error and a CRC computed over the zeros. This test is the
// regression guard for exactly that failure mode.
func TestTickFlush_SnapshotHashTablesPopulated(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "hashsnap.evtx")
	var syncs int64
	w, err := New(outPath, RotationConfig{
		FlushIntervalSec: 1,
		OnFsync:          func(time.Time) { atomic.AddInt64(&syncs, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close() //nolint:errcheck

	const firstBatch = 3
	for i := 0; i < firstBatch; i++ {
		if err := w.WriteRecord(4663, tickTestFields()); err != nil {
			t.Fatalf("WriteRecord batch1 %d: %v", i, err)
		}
	}
	time.Sleep(1200 * time.Millisecond) // let a tick land

	const secondBatch = 3
	for i := 0; i < secondBatch; i++ {
		if err := w.WriteRecord(4663, tickTestFields()); err != nil {
			t.Fatalf("WriteRecord batch2 %d: %v", i, err)
		}
	}
	time.Sleep(1200 * time.Millisecond) // let a second tick land

	if got := atomic.LoadInt64(&syncs); got < 2 {
		t.Fatalf("only %d tick syncs fired, need at least 2", got)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	snap := filepath.Join(dir, "hashsnap-copy.evtx")
	if err := os.WriteFile(snap, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	chunkStart := evtxFileHeaderSize
	tables := raw[chunkStart+128 : chunkStart+512]
	allZero := true
	for _, b := range tables {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("chunk[128:512] is all zero after a mid-session tick; hash tables were not populated")
	}

	r, err := Open(snap)
	if err != nil {
		t.Fatalf("Open snapshot: %v", err)
	}
	defer r.Close() //nolint:errcheck

	var n int
	for {
		_, err := r.ReadEvent()
		if err == ErrNoMoreRecords || err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent on snapshot after %d records: %v", n, err)
		}
		n++
	}
	if n != firstBatch+secondBatch {
		t.Fatalf("snapshot yielded %d records, want %d", n, firstBatch+secondBatch)
	}
}

// TestTickFlush_ByteIdenticalToNoTick is the release invariant for v0.10.0:
// the finished file must be byte-for-byte what a writer with no background
// tick produces. The incremental tick may change how bytes reach the disk; it
// must not change which bytes end up there.
//
// TimeCreated is pinned so record FILETIMEs are deterministic; nothing else in
// the sealed format carries wall-clock data.
func TestTickFlush_ByteIdenticalToNoTick(t *testing.T) {
	const records = 30

	// wantTick is asserted independently of cfg.FlushIntervalSec so that a
	// miswired call — e.g. the "ticked" case accidentally configured with no
	// interval — fails loudly here rather than silently degrading into a
	// second no-tick run that still passes the byte-comparison below.
	write := func(name string, cfg RotationConfig, wantTick bool) []byte {
		t.Helper()
		var syncs int64
		cfg.OnFsync = func(time.Time) { atomic.AddInt64(&syncs, 1) }
		outPath := filepath.Join(t.TempDir(), name)
		w, err := New(outPath, cfg)
		if err != nil {
			t.Fatalf("%s New: %v", name, err)
		}
		// A t.Fatalf below would otherwise leak the tick goroutine and the
		// file handle. Close is idempotent, so the explicit Close still wins.
		defer w.Close() //nolint:errcheck
		for i := 0; i < records; i++ {
			if err := w.WriteRecord(4663, tickTestFields()); err != nil {
				t.Fatalf("%s WriteRecord %d: %v", name, i, err)
			}
			if cfg.FlushIntervalSec > 0 && i == records/2 {
				// Force at least one tick to land mid-chunk, so the file is
				// assembled by the incremental path rather than by Close alone.
				time.Sleep(1200 * time.Millisecond)
			}
		}
		// Check before Close: Close's own final flush fires OnFsync too, which
		// would make this pass even if no background tick ever ran.
		switch preClose := atomic.LoadInt64(&syncs); {
		case wantTick && preClose == 0:
			t.Fatalf("%s: no background tick fired before Close; test cannot verify the incremental path", name)
		case !wantTick && preClose != 0:
			t.Fatalf("%s: fired %d sync(s) before Close, want 0 — no background tick should run", name, preClose)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("%s Close: %v", name, err)
		}
		raw, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("%s ReadFile: %v", name, err)
		}
		return raw
	}

	ticked := write("ticked.evtx", RotationConfig{FlushIntervalSec: 1}, true)
	plain := write("plain.evtx", RotationConfig{}, false)

	if len(ticked) != len(plain) {
		t.Fatalf("file sizes differ: ticked %d, no-tick %d", len(ticked), len(plain))
	}
	if !bytes.Equal(ticked, plain) {
		for i := range ticked {
			if ticked[i] != plain[i] {
				t.Fatalf("files differ at offset %d (0x%x): ticked %#02x, no-tick %#02x",
					i, i, ticked[i], plain[i])
			}
		}
	}
}
