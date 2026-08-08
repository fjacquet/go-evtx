// Package evtx provides a Writer for creating Windows Event Log (.evtx) binary files.
//
// The Writer encodes events as template-based BinXML, which is parseable by
// forensics tools such as python-evtx and the Windows Event Viewer.
//
// Basic usage:
//
//	w, err := evtx.New("/var/log/audit.evtx", evtx.RotationConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer w.Close()
//
//	fields := map[string]string{
//	    "ProviderName": "Microsoft-Windows-Security-Auditing",
//	    "Computer":     "myhost",
//	    "TimeCreated":  time.Now().Format(time.RFC3339Nano),
//	    "ObjectName":   "/mnt/share/file.txt",
//	    "AccessMask":   "0x2",
//	}
//	if err := w.WriteRecord(4663, fields); err != nil {
//	    log.Fatal(err)
//	}
package evtx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// RotationConfig holds periodic flush and rotation configuration for the Writer.
//
// FlushIntervalSec is the interval between checkpoint writes in seconds.
// 0 disables the flush ticker; must be >= 0 (negative values are rejected by New).
//
// MaxFileSizeMB triggers size-based rotation: when the current file reaches this
// size (in mebibytes), rotate() is called automatically. 0 = disabled.
//
// MaxFileCount limits the number of archive files kept on disk. When a new archive
// is created and the count exceeds MaxFileCount, the oldest archives are deleted.
// 0 = unlimited.
//
// RotationIntervalH triggers time-based rotation via a background ticker. After each
// interval (in hours), rotate() is called. 0 = disabled.
type RotationConfig struct {
	FlushIntervalSec  int // 0 = disabled; must be >= 0
	MaxFileSizeMB     int // 0 = disabled; rotate when file >= N MiB
	MaxFileCount      int // 0 = unlimited; keep only N newest archives
	RotationIntervalH int // 0 = disabled; rotate every N hours

	// OnFsync is called after each successful f.Sync() with the time of the
	// sync. nil = no callback. Useful for exposing the fsync timestamp to a
	// Prometheus gauge.
	//
	// It fires on every sync — from WriteRecord's chunk flush, from rotate,
	// from Close, and from the background flush tick — not only when
	// FlushIntervalSec > 0.
	//
	// The callback is invoked after the writer lock is released, so it may
	// safely call any Writer method without deadlocking.
	//
	// That safety does not bound recursion: a callback that itself triggers a
	// new flush — directly, or through a chain of Writer calls — recurses on
	// the callback's own call stack, because the nested call's drain runs
	// before control returns to the outer one. Avoid callbacks whose side
	// effects can generate unbounded further fsyncs.
	OnFsync func(time.Time)
}

// Writer writes Windows .evtx binary format files.
// All exported methods are safe for concurrent use.
type Writer struct {
	mu         sync.Mutex
	path       string   // output file path
	records    []byte   // accumulated event record bytes for current chunk
	recordID   uint64   // monotonically incrementing record ID, starts at 1
	firstID    uint64   // first record ID in current chunk
	f          *os.File // open file handle; created in New(), closed in Close()
	chunkCount uint16   // number of COMPLETE chunks written to disk so far
	// Phase 9 additions:
	cfg  RotationConfig
	done chan struct{}
	wg   sync.WaitGroup
	// Phase 11 additions:
	currentSize int64 // approximate file size in bytes, tracked for size-based rotation
	// v0.6.0 durability state:
	closed       bool        // set by Close; further writes return ErrClosed
	closeErr     error       // result of the first Close, returned by later calls
	closeOnce    sync.Once   // ensures the shutdown/finalize sequence runs exactly once
	err          error       // sticky: durability permanently lost, all calls fail
	fileClosed   bool        // w.f has already been closed (by rotate or by Close)
	pendingFsync []time.Time // OnFsync timestamps to fire after w.mu is released
}

// checkStateLocked reports whether the writer can still accept work.
//
// Error precedence is deliberate and part of the API contract: the sticky
// durability error wins over ErrClosed. A Close that itself failed sets both
// states, and the caller needs to know that data was lost — which ErrClosed
// alone would not tell them. Callers testing specifically for shutdown should
// use errors.Is(err, ErrClosed) rather than equality, and must treat any other
// error as "data may not have been persisted".
//
// CALLER MUST HOLD w.mu.
func (w *Writer) checkStateLocked() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return ErrClosed
	}
	return nil
}

// drainFsyncCallbacks invokes any OnFsync callbacks queued while w.mu was held.
//
// CALLER MUST NOT HOLD w.mu. Invoking the callback under the lock would
// deadlock any callback that re-enters the Writer.
func (w *Writer) drainFsyncCallbacks() {
	w.mu.Lock()
	pending := w.pendingFsync
	w.pendingFsync = nil
	cb := w.cfg.OnFsync
	w.mu.Unlock()

	if cb == nil {
		return
	}
	for _, t := range pending {
		cb(t)
	}
}

// New creates a Writer that will write to the given path.
//
// path must be non-empty. The parent directory is created if it does not exist.
// The file is created immediately in New() and held open until Close().
// A 4096-byte placeholder file header (ChunkCount=0) is written at offset 0.
func New(path string, cfg RotationConfig) (*Writer, error) {
	if path == "" {
		return nil, fmt.Errorf("go_evtx: path must be non-empty")
	}
	if cfg.FlushIntervalSec < 0 {
		return nil, fmt.Errorf("go_evtx: FlushIntervalSec must be >= 0 (got %d)", cfg.FlushIntervalSec)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("go_evtx: create parent directory: %w", err)
	}

	// Open the file immediately (open-handle model).
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("go_evtx: open file: %w", err)
	}

	// Write placeholder file header (ChunkCount=0, NextRecordID=1).
	// This is patched on each flushChunkLocked() call.
	if _, err := f.Write(buildFileHeader(0, 1)); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("go_evtx: write placeholder header: %w", err)
	}

	w := &Writer{
		path:        path,
		recordID:    1,
		firstID:     1,
		f:           f,
		cfg:         cfg,
		done:        make(chan struct{}),
		currentSize: evtxFileHeaderSize, // placeholder header already written
	}
	if cfg.FlushIntervalSec > 0 || cfg.RotationIntervalH > 0 {
		w.wg.Add(1)
		go w.backgroundLoop()
	}
	return w, nil
}

// backgroundLoop runs as a goroutine when FlushIntervalSec > 0 or RotationIntervalH > 0.
// It calls tickFlushLocked() on each flush tick and rotate() on each rotation tick.
// It exits when w.done is closed.
func (w *Writer) backgroundLoop() {
	defer w.wg.Done()

	// Flush ticker: non-nil only when FlushIntervalSec > 0.
	var flushC <-chan time.Time
	if w.cfg.FlushIntervalSec > 0 {
		ft := time.NewTicker(time.Duration(w.cfg.FlushIntervalSec) * time.Second)
		defer ft.Stop()
		flushC = ft.C
	}

	// Rotation ticker: non-nil only when RotationIntervalH > 0.
	// Receiving on a nil channel blocks forever, so the case never fires when disabled.
	var rotC <-chan time.Time
	if w.cfg.RotationIntervalH > 0 {
		rt := time.NewTicker(time.Duration(w.cfg.RotationIntervalH) * time.Hour)
		defer rt.Stop()
		rotC = rt.C
	}

	for {
		select {
		case <-flushC:
			w.mu.Lock()
			if len(w.records) > 0 {
				if err := w.tickFlushLocked(); err != nil {
					// The only persistence path with no caller to return to.
					// Poison the writer rather than let the next WriteRecord
					// report success for data that never reached disk.
					w.err = fmt.Errorf("go_evtx: background flush: %w", err)
					slog.Error("go_evtx_background_flush_failed", "path", w.path, "err", err)
				}
			}
			w.mu.Unlock()
			w.drainFsyncCallbacks()
		case <-rotC:
			w.mu.Lock()
			err := w.rotate()
			w.mu.Unlock()
			w.drainFsyncCallbacks()
			if err != nil {
				slog.Error("go_evtx_scheduled_rotate_failed", "path", w.path, "err", err)
			}
		case <-w.done:
			return
		}
	}
}

// WriteRaw appends a pre-encoded BinXML payload to the writer.
//
// The payload is wrapped with an event record header using the current record ID
// and the current time as the timestamp. Use either WriteRaw or WriteRecord
// in a single session; mixing both is not recommended.
func (w *Writer) WriteRaw(payload []byte) error {
	w.mu.Lock()
	defer w.drainFsyncCallbacks()
	defer w.mu.Unlock()

	if err := w.checkStateLocked(); err != nil {
		return err
	}

	// Size-based rotation check: rotate before adding more data.
	if w.cfg.MaxFileSizeMB > 0 && w.currentSize >= int64(w.cfg.MaxFileSizeMB)*1024*1024 {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	if len(payload) > maxRecordPayload {
		return fmt.Errorf("%w: payload %d bytes exceeds maximum %d",
			ErrRecordTooLarge, len(payload), maxRecordPayload)
	}

	ts := toFILETIME(time.Now())
	rec := wrapEventRecord(w.recordID, ts, payload)

	// If adding this record would exceed chunk capacity, flush first.
	if len(w.records)+len(rec) > maxChunkPayload {
		if err := w.flushChunkLocked(); err != nil {
			return err
		}
	}

	w.records = append(w.records, rec...)
	w.recordID++
	return nil
}

// WriteRecord encodes the event and appends it to the writer.
//
// eventID is the Windows Event ID (e.g. 4663 for file access).
// fields is a map of field names to values.
//
// Reserved field keys:
//   - "ProviderName"  — event provider (STRING); defaults to empty
//   - "Computer"      — computer name (STRING); defaults to empty
//   - "TimeCreated"   — RFC3339Nano timestamp; defaults to time.Now()
//
// Data field keys (12 fields, in order):
//   - SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId
//   - ObjectServer, ObjectType, ObjectName, HandleId
//   - AccessList, AccessMask, ProcessId, ProcessName
func (w *Writer) WriteRecord(eventID int, fields map[string]string) error {
	w.mu.Lock()
	defer w.drainFsyncCallbacks()
	defer w.mu.Unlock()

	if err := w.checkStateLocked(); err != nil {
		return err
	}

	// Size-based rotation check: rotate before adding more data.
	if w.cfg.MaxFileSizeMB > 0 && w.currentSize >= int64(w.cfg.MaxFileSizeMB)*1024*1024 {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	binXMLChunkOffset := evtxRecordsStart + uint32(len(w.records)) + evtxRecordHeaderSize
	payload := buildBinXML(eventID, fields, binXMLChunkOffset)

	// A record larger than a chunk can never be written. Splitting one logical
	// event across chunks is not valid EVTX, so reject it and write nothing.
	// Truncating instead would be checksum-invisible: the CRCs would be
	// computed over the corrupt bytes and verify.
	if len(payload) > maxRecordPayload {
		return fmt.Errorf("%w: payload %d bytes exceeds maximum %d",
			ErrRecordTooLarge, len(payload), maxRecordPayload)
	}

	ts := toFILETIME(parseTimeCreated(fields))
	rec := wrapEventRecord(w.recordID, ts, payload)

	// If adding this record would exceed chunk capacity, flush first.
	if len(w.records)+len(rec) > maxChunkPayload {
		if err := w.flushChunkLocked(); err != nil {
			return err
		}
		// Recompute binXMLChunkOffset for the new (empty) chunk.
		binXMLChunkOffset = evtxRecordsStart + evtxRecordHeaderSize
		payload = buildBinXML(eventID, fields, binXMLChunkOffset)
		rec = wrapEventRecord(w.recordID, ts, payload)
	}

	w.records = append(w.records, rec...)
	w.recordID++
	return nil
}

// archivePathFor returns the archive path for the given active file path.
//
// The archive name is base-YYYY-MM-DDTHH-MM-SS.nnnnnnnnn.ext, a UTC timestamp
// with hyphens for colons. Nanosecond resolution is required: at one-second
// resolution a burst of rotations produced colliding names and os.Rename
// destroyed the earlier archives without an error.
func archivePathFor(activePath string) string {
	ext := filepath.Ext(activePath)
	base := activePath[:len(activePath)-len(ext)]
	ts := time.Now().UTC().Format("2006-01-02T15-04-05.000000000")
	return base + "-" + ts + ext
}

// rotate finalizes the current EVTX file, renames it to a timestamped archive,
// opens a fresh file at the same path, and resets writer state.
//
// CALLER MUST HOLD w.mu when calling rotate().
// rotate() does NOT acquire w.mu itself.
func (w *Writer) rotate() error {
	// Step 1: Flush any pending records to disk as a complete chunk.
	// A failure here is not sticky — the file handle is still valid.
	if len(w.records) > 0 {
		if err := w.flushChunkLocked(); err != nil {
			return fmt.Errorf("go_evtx: rotate flush: %w", err)
		}
	}

	// Step 2: If no data has been written, skip the rename (nothing to archive).
	if w.chunkCount == 0 {
		return nil
	}

	// Step 3: Sync and close the current file.
	// From here until the replacement handle is installed, any failure leaves
	// the writer unable to guarantee durability. Record it permanently rather
	// than accepting events we cannot persist.
	archive := archivePathFor(w.path)
	if err := w.f.Sync(); err != nil {
		w.err = fmt.Errorf("go_evtx: rotate sync: %w", err)
		return w.err
	}
	if err := w.closeFileLocked(); err != nil {
		w.err = fmt.Errorf("go_evtx: rotate close: %w", err)
		return w.err
	}

	// Step 4: Commit the archive with link-then-unlink rather than rename.
	//
	// os.Rename REPLACES an existing non-directory destination on Unix, so a
	// name collision would destroy a committed archive silently. Checking with
	// os.Stat first does not help: it is a time-of-check/time-of-use race, and
	// an O_EXCL probe creates the destination without reserving it for the
	// later rename.
	//
	// os.Link fails if the destination exists, atomically and without a race,
	// using only the standard library. The active path is unlinked afterwards.
	// The window between the two calls leaves both names pointing at the same
	// inode, which is harmless — a reader sees a complete file either way.
	//
	// Not every filesystem supports hard links (FAT32, some SMB and container
	// overlay mounts). Where Link is unsupported, fall back to Stat+Rename and
	// log that the collision guard is now best-effort, rather than failing a
	// rotation that used to work.
	if err := os.Link(w.path, archive); err != nil {
		if !errors.Is(err, errors.ErrUnsupported) && !errors.Is(err, syscall.EPERM) {
			w.err = fmt.Errorf("go_evtx: rotate link archive %s: %w", archive, err)
			return w.err
		}
		slog.Warn("go_evtx_rotate_link_unsupported",
			"path", w.path, "err", err,
			"note", "falling back to rename; archive collision guard is best-effort")
		if _, serr := os.Stat(archive); serr == nil {
			w.err = fmt.Errorf("go_evtx: rotate: archive %s already exists", archive)
			return w.err
		}
		if rerr := os.Rename(w.path, archive); rerr != nil {
			w.err = fmt.Errorf("go_evtx: rotate rename: %w", rerr)
			return w.err
		}
	} else if err := os.Remove(w.path); err != nil {
		w.err = fmt.Errorf("go_evtx: rotate unlink active file: %w", err)
		return w.err
	}

	// Step 5: Open a fresh file at the same path and make its header durable.
	// Without this Sync the placeholder header lives only in the page cache
	// until the first chunk flush, so a crash immediately after rotation
	// leaves a zero-length or partial file where a valid empty one should be.
	f, err := os.OpenFile(w.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		w.err = fmt.Errorf("go_evtx: rotate open new file: %w", err)
		return w.err
	}
	if _, err := f.Write(buildFileHeader(0, 1)); err != nil {
		_ = f.Close()
		w.err = fmt.Errorf("go_evtx: rotate write header: %w", err)
		return w.err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		w.err = fmt.Errorf("go_evtx: rotate sync new header: %w", err)
		return w.err
	}
	w.f = f
	w.fileClosed = false

	// Step 6: Sync the containing directory so both the archive link and the
	// replacement file are durable (best-effort on Unix; no-op on Windows).
	if err := syncDir(filepath.Dir(w.path)); err != nil {
		slog.Warn("go_evtx_rotate_syncdir_warn", "path", w.path, "err", err)
	}

	// Step 7: Reset writer state for the new file.
	w.chunkCount = 0
	w.recordID = 1
	w.firstID = 1
	w.records = w.records[:0]
	w.currentSize = evtxFileHeaderSize

	slog.Info("go_evtx_rotated", "archive", archive, "active", w.path)

	// Step 8: Enforce MaxFileCount by deleting oldest archives.
	if w.cfg.MaxFileCount > 0 {
		if err := w.cleanOldFiles(); err != nil {
			slog.Warn("go_evtx_cleanoldfiles_warn", "path", w.path, "err", err)
		}
	}

	return nil
}

// Rotate finalizes the current EVTX file, renames it to a timestamped archive,
// opens a fresh file at the same path, and resets writer state.
//
// Rotate() is safe to call concurrently with WriteRecord() and WriteRaw().
func (w *Writer) Rotate() error {
	w.mu.Lock()
	defer w.drainFsyncCallbacks()
	defer w.mu.Unlock()
	if err := w.checkStateLocked(); err != nil {
		return err
	}
	return w.rotate()
}

// cleanOldFiles removes the oldest archive files when the count exceeds MaxFileCount.
// The glob pattern "base-*.evtx" deliberately uses a hyphen separator so that the
// active file "base.evtx" is never matched.
//
// CALLER MUST HOLD w.mu when calling cleanOldFiles().
func (w *Writer) cleanOldFiles() error {
	ext := filepath.Ext(w.path)
	base := w.path[:len(w.path)-len(ext)]
	pattern := base + "-*" + ext

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	if len(matches) <= w.cfg.MaxFileCount {
		return nil
	}

	// Sort by modification time (oldest first) and delete the excess.
	type fileInfo struct {
		path  string
		mtime int64
	}
	infos := make([]fileInfo, 0, len(matches))
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil {
			continue
		}
		infos = append(infos, fileInfo{path: m, mtime: st.ModTime().UnixNano()})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].mtime < infos[j].mtime })

	toDelete := len(infos) - w.cfg.MaxFileCount
	for i := 0; i < toDelete; i++ {
		if err := os.Remove(infos[i].path); err != nil {
			slog.Warn("go_evtx_delete_old_archive_warn", "path", infos[i].path, "err", err)
		}
	}
	return nil
}

// chunkCapacityLocked reports whether the pending buffer still fits in a chunk.
//
// The entry guards in WriteRecord and WriteRaw make an overflow unreachable.
// If it ever fires, a code change has reintroduced silent truncation — fail
// permanently rather than write a corrupt chunk whose CRCs verify.
//
// CALLER MUST HOLD w.mu.
func (w *Writer) chunkCapacityLocked() error {
	if len(w.records) > maxChunkPayload {
		w.err = fmt.Errorf("go_evtx: internal: chunk buffer %d bytes exceeds capacity %d",
			len(w.records), maxChunkPayload)
		return w.err
	}
	return nil
}

// queueFsyncLocked records an fsync timestamp for later delivery to OnFsync.
//
// The callback must not run under w.mu — a callback that re-enters the Writer
// would deadlock — so the timestamp is queued here and fired by
// drainFsyncCallbacks once the lock is released.
//
// CALLER MUST HOLD w.mu.
func (w *Writer) queueFsyncLocked() {
	if w.cfg.OnFsync != nil {
		w.pendingFsync = append(w.pendingFsync, time.Now())
	}
}

// flushChunkLocked writes the current in-progress chunk to disk as a complete,
// padded 65536-byte EVTX chunk. It increments w.chunkCount, patches the file
// header at offset 0, calls f.Sync(), and resets w.records and w.firstID.
//
// Must be called with w.mu held. Does nothing if len(w.records) == 0.
func (w *Writer) flushChunkLocked() error {
	if len(w.records) == 0 {
		return nil
	}

	if err := w.chunkCapacityLocked(); err != nil {
		return err
	}
	records := w.records

	recordsStart := int(evtxRecordsStart)
	freeSpaceOffset := uint32(recordsStart + len(records))
	chunkHeader := buildChunkHeader(w.firstID, w.recordID-1, freeSpaceOffset)

	chunkBytes := make([]byte, evtxChunkSize)
	copy(chunkBytes[0:], chunkHeader)
	copy(chunkBytes[recordsStart:], records)

	patchEventRecordsCRC(chunkBytes, recordsStart, recordsStart+len(records))
	patchChunkCRC(chunkBytes)

	// Write chunk at the correct file offset.
	chunkOffset := int64(evtxFileHeaderSize) + int64(w.chunkCount)*int64(evtxChunkSize)
	if _, err := w.f.WriteAt(chunkBytes, chunkOffset); err != nil {
		return fmt.Errorf("go_evtx: write chunk %d: %w", w.chunkCount, err)
	}

	// Track file size: each committed chunk adds evtxChunkSize bytes.
	w.currentSize += int64(evtxChunkSize)

	// Increment chunk count and patch the file header.
	w.chunkCount++
	if _, err := w.f.WriteAt(buildFileHeader(w.chunkCount, w.recordID), 0); err != nil {
		return fmt.Errorf("go_evtx: patch file header: %w", err)
	}

	// Sync to disk.
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("go_evtx: sync: %w", err)
	}
	w.queueFsyncLocked()

	// Reset current chunk buffer.
	w.records = w.records[:0]
	w.firstID = w.recordID

	slog.Info("go_evtx_chunk_flushed",
		"path", w.path,
		"chunk", w.chunkCount-1,
		"total_chunks", w.chunkCount,
	)
	return nil
}

// tickFlushLocked performs a flush-without-reset for the background goroutine tick.
// It writes the current partial chunk to disk at slot w.chunkCount WITHOUT
// incrementing w.chunkCount or resetting w.records (Option A: flush-without-reset).
// The file header is patched with chunkCount+1 to account for the in-progress chunk.
//
// Must be called with w.mu held. Does nothing if len(w.records) == 0.
func (w *Writer) tickFlushLocked() error {
	if len(w.records) == 0 {
		return nil
	}

	// Build the in-progress chunk (same layout as flushChunkLocked, but don't commit).
	if err := w.chunkCapacityLocked(); err != nil {
		return err
	}
	records := w.records

	recordsStart := int(evtxRecordsStart)
	freeSpaceOffset := uint32(recordsStart + len(records))
	chunkHeader := buildChunkHeader(w.firstID, w.recordID-1, freeSpaceOffset)

	chunkBytes := make([]byte, evtxChunkSize)
	copy(chunkBytes[0:], chunkHeader)
	copy(chunkBytes[recordsStart:], records)

	patchEventRecordsCRC(chunkBytes, recordsStart, recordsStart+len(records))
	patchChunkCRC(chunkBytes)

	// Write at the current (in-progress) chunk slot — same slot as next flushChunkLocked.
	chunkOffset := int64(evtxFileHeaderSize) + int64(w.chunkCount)*int64(evtxChunkSize)
	if _, err := w.f.WriteAt(chunkBytes, chunkOffset); err != nil {
		return fmt.Errorf("go_evtx: tick write chunk %d: %w", w.chunkCount, err)
	}

	// Patch file header with chunkCount+1 to reflect in-progress chunk visibility.
	if _, err := w.f.WriteAt(buildFileHeader(w.chunkCount+1, w.recordID), 0); err != nil {
		return fmt.Errorf("go_evtx: tick patch file header: %w", err)
	}

	// Sync to disk.
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("go_evtx: tick sync: %w", err)
	}
	w.queueFsyncLocked()

	return nil
}

// Close stops the background goroutine (if running), waits for it to exit,
// then performs a final flush of any remaining buffered events.
//
// If no events were written and no chunks were committed, Close removes the
// file from disk (an empty session leaves no file) and returns nil.
//
// Close is idempotent: the second and later calls return the first call's
// result and do no work.
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		w.mu.Unlock()

		close(w.done) // signal the background goroutine
		w.wg.Wait()   // wait WITHOUT holding the lock

		w.mu.Lock()
		w.closeErr = w.finalizeLocked()
		w.mu.Unlock()
	})
	defer w.drainFsyncCallbacks()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeErr
}

// finalizeLocked flushes any pending chunk and closes the file handle.
//
// CALLER MUST HOLD w.mu.
func (w *Writer) finalizeLocked() error {
	// Durability was already lost, so do not try to flush — but the file
	// handle may still be open (a rotate that failed at the Sync step never
	// reached its Close), and leaking it on every failed rotation would
	// exhaust the daemon's descriptors.
	if w.err != nil {
		if cerr := w.closeFileLocked(); cerr != nil {
			slog.Warn("go_evtx_close_file_failed", "path", w.path, "err", cerr)
		}
		return w.err
	}

	var err error
	switch {
	case len(w.records) == 0 && w.chunkCount == 0:
		// Empty session: remove the placeholder file.
		_ = os.Remove(w.path)
	case len(w.records) > 0:
		err = w.flushChunkLocked()
	}

	if cerr := w.closeFileLocked(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

// closeFileLocked closes w.f exactly once. rotate() closes the handle
// mid-sequence, so this tracks whether that already happened rather than
// calling Close twice and reporting "file already closed".
//
// CALLER MUST HOLD w.mu.
func (w *Writer) closeFileLocked() error {
	if w.fileClosed || w.f == nil {
		return nil
	}
	w.fileClosed = true
	return w.f.Close()
}

// buildChunkHeader constructs the 512-byte EVTX chunk header.
func buildChunkHeader(firstRecordID, lastRecordID uint64, freeSpaceOffset uint32) []byte {
	buf := make([]byte, evtxChunkHeaderSize)
	copy(buf[0:8], evtxChunkMagic)
	binary.LittleEndian.PutUint64(buf[8:], firstRecordID)    // FirstEventRecordNumber
	binary.LittleEndian.PutUint64(buf[16:], lastRecordID)    // LastEventRecordNumber
	binary.LittleEndian.PutUint64(buf[24:], firstRecordID)   // FirstEventRecordIdentifier
	binary.LittleEndian.PutUint64(buf[32:], lastRecordID)    // LastEventRecordIdentifier
	binary.LittleEndian.PutUint32(buf[40:], 128)             // HeaderSize
	binary.LittleEndian.PutUint32(buf[44:], freeSpaceOffset) // LastEventRecordDataOffset
	binary.LittleEndian.PutUint32(buf[48:], freeSpaceOffset) // FreeSpaceOffset
	return buf
}

// patchEventRecordsCRC computes CRC32 over the event records region and writes it at chunk[52:56].
func patchEventRecordsCRC(chunk []byte, recordsStart, recordsEnd int) {
	c := crc32.Checksum(chunk[recordsStart:recordsEnd], crc32.IEEETable)
	binary.LittleEndian.PutUint32(chunk[52:], c)
}

// parseTimeCreated parses the "TimeCreated" field as RFC3339Nano, falling back to time.Now().
func parseTimeCreated(fields map[string]string) time.Time {
	if s, ok := fields["TimeCreated"]; ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t
		}
	}
	return time.Now()
}
