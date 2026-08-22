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
	// safely call most Writer methods without deadlocking — with one
	// exception: do not call Close from a callback fired by the background
	// goroutine's own fsync drain. Close waits for that goroutine to exit,
	// but the goroutine is currently blocked inside the callback and can
	// never reach its shutdown case, so the call deadlocks.
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
	mu      sync.Mutex
	path    string // output file path
	records []byte // accumulated event record bytes for current chunk
	// chunkNames and chunkTemplates accumulate the hashable nodes emitted into
	// the pending chunk, in emission order. flushChunkLocked turns them into
	// the chunk's two hash tables and then resets them alongside w.records.
	//
	// WriteRaw contributes nothing here: the caller's BinXML is opaque, so its
	// NameNodes cannot be registered. A chunk written via WriteRaw therefore
	// keeps empty tables, exactly as before v0.7.0.
	chunkNames     []chunkRef
	chunkTemplates []chunkRef
	// chunkTemplateOffset is the chunk-relative offset of the template
	// definition already written into the pending chunk, or 0 when the chunk
	// holds none yet. The next record points its instance at it instead of
	// writing a second copy (F19), which is what real Windows does: 545
	// definitions across the derivation corpus against 36 819 backward
	// references. Reset alongside w.records — the offset is chunk-relative and
	// means nothing in the next chunk.
	chunkTemplateOffset uint32
	// lastRecordOffset is the chunk-relative offset where the most recent
	// record in the pending chunk begins. Committed and reset alongside
	// w.records; zero when the chunk is empty.
	lastRecordOffset uint32
	// recordsCRC is the running CRC32 (IEEE) of w.records, maintained
	// incrementally on every append rather than rescanned per flush.
	// crc32.Update over the appended bytes yields the checksum of the
	// concatenation, so this is bit-identical to a full rescan — verified by
	// TestRecordsCRC_MatchesFullScan. Committed and reset alongside
	// w.records; zero when the chunk is empty.
	recordsCRC uint32
	// tickWrittenLen is how many bytes of w.records the background tick has
	// already persisted into the current chunk slot. The tick writes only
	// w.records[tickWrittenLen:] and skips entirely when the two are equal —
	// records are append-only, so bytes already in the slot never change.
	// Committed and reset alongside w.records.
	tickWrittenLen int
	// slotExtended reports whether the current chunk slot has been extended
	// to its full evtxChunkSize on disk. The tick writes only the header and
	// the appended delta, so without this the file would end mid-chunk and
	// loadChunk — which reads a whole evtxChunkSize — would hit EOF. The
	// sparse tail reads back as zeros, which is what the sealing write puts
	// there anyway. Reset alongside w.records.
	slotExtended bool
	recordID     uint64   // monotonically incrementing record ID, starts at 1
	firstID      uint64   // first record ID in current chunk
	f            *os.File // open file handle; created in New(), closed in Close()
	chunkCount   uint16   // number of COMPLETE chunks written to disk so far
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

	// Write placeholder file header (ChunkCount=0, NextRecordID=1). The dirty
	// flag is set from the moment the file is opened for writing, not only
	// once the first chunk happens to flush — a crash before any chunk lands
	// must still read back as dirty, not as the placeholder's zero flags.
	// This is patched on each flushChunkLocked() call.
	if _, err := f.Write(buildFileHeader(0, 1, evtxFlagDirty)); err != nil {
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
			var err error
			if err = w.checkStateLocked(); err == nil {
				err = w.rotate()
			}
			w.mu.Unlock()
			w.drainFsyncCallbacks()
			// A bare ErrClosed here just means Close() won the race with this
			// tick — normal shutdown, not a rotation failure. Anything else
			// (including a sticky error already set by an earlier failure)
			// is worth an operator's attention.
			if err != nil && !errors.Is(err, ErrClosed) {
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

	w.lastRecordOffset = evtxRecordsStart + uint32(len(w.records))
	w.records = append(w.records, rec...)
	w.recordsCRC = crc32.Update(w.recordsCRC, crc32.IEEETable, rec)
	w.recordID++
	return nil
}

// WriteRecord encodes the event and appends it to the writer.
//
// eventID is the Windows Event ID (e.g. 4663 for file access).
// fields is a map of field names to values.
//
// Reserved field keys:
//   - "ProviderName"  — event provider (STRING); must not be empty
//   - "ProviderGuid"  — provider GUID (STRING); defaults to empty
//   - "Computer"      — computer name (STRING); defaults to empty
//   - "Channel"       — channel name (STRING); defaults to empty
//   - "TimeCreated"   — RFC3339Nano timestamp; defaults to time.Now()
//
// Numeric <System> keys. Each is parsed as an unsigned integer of the width
// shown, in decimal or with an 0x prefix, and defaults to 0. A value that does
// not fit returns ErrInvalidFieldValue and writes nothing:
//   - "Level"    — uint8;  4 is what Windows renders as "Information"
//   - "Version"  — uint8
//   - "Task"     — uint16; its display name needs a provider manifest on the
//     reading host, which no value written here can supply
//   - "Opcode"   — uint8
//   - "Keywords" — uint64; 0x80000000000000 renders as "Classic"
//
// Data field keys (13 fields, in order):
//   - SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId
//   - ObjectServer, ObjectType, ObjectName, HandleId
//   - AccessList, AccessMask, ProcessId, ProcessName
//   - IpAddress
//
// The schema is closed: a key outside the reserved and data-field sets is
// ignored, not written and not reported. IpAddress was added in v0.9.0 for
// callers that have a peer address — Windows Security auditing carries one on
// 4625 and 5145 — and previously had nowhere to put it.
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

	// Rejected before anything is written, and deliberately not defaulted to
	// some invented provider name: a record with no provider produces a file
	// Get-WinEvent cannot read, and inventing a value would put a name in a
	// forensic artefact that no caller chose. See ErrMissingProviderName.
	//
	// Checked here rather than beside checkStateLocked so it cannot mask a
	// sticky durability error: a caller must learn that data was lost before
	// it learns its field map is wrong.
	if fields["ProviderName"] == "" {
		return ErrMissingProviderName
	}

	// Level, Version, Task, Opcode and Keywords are encoded as fixed-width
	// unsigned integers. A value that will not fit is rejected here, before
	// anything is written, so the caller learns at the point of the mistake
	// rather than from a blank column in Event Viewer. See
	// ErrInvalidFieldValue and issue #13.
	if err := validateSystemFields(fields); err != nil {
		return err
	}

	binXMLChunkOffset := evtxRecordsStart + uint32(len(w.records)) + evtxRecordHeaderSize
	res := buildBinXML(eventID, w.recordID, fields, binXMLChunkOffset, w.chunkTemplateOffset)

	// A record larger than a chunk can never be written. Splitting one logical
	// event across chunks is not valid EVTX, so reject it and write nothing.
	// Truncating instead would be checksum-invisible: the CRCs would be
	// computed over the corrupt bytes and verify.
	if len(res.payload) > maxRecordPayload {
		return fmt.Errorf("%w: payload %d bytes exceeds maximum %d",
			ErrRecordTooLarge, len(res.payload), maxRecordPayload)
	}

	ts := toFILETIME(parseTimeCreated(fields))
	rec := wrapEventRecord(w.recordID, ts, res.payload)

	// If adding this record would exceed chunk capacity, flush first.
	if len(w.records)+len(rec) > maxChunkPayload {
		if err := w.flushChunkLocked(); err != nil {
			return err
		}
		// The flush reset the collectors; rebuild this record for the new,
		// empty chunk so its node offsets are relative to the right chunk.
		// The new chunk holds no template definition yet, so this record must
		// declare one inline — passing the old chunk's offset here would point
		// the instance at bytes belonging to a chunk that is already on disk.
		binXMLChunkOffset = evtxRecordsStart + evtxRecordHeaderSize
		res = buildBinXML(eventID, w.recordID, fields, binXMLChunkOffset, 0)

		// The rebuilt payload must be re-checked, and this is not belt and
		// braces: before F19 both builds were byte-identical in length, so the
		// check above covered them both. Now the first build may REFERENCE the
		// pending chunk's template definition while the rebuild must INLINE
		// it, which is roughly 2 KB larger. A record that fitted as a
		// reference can therefore exceed the limit as an inline copy, and
		// without this it would be appended anyway — a record larger than a
		// chunk can hold, with CRCs computed over it so the damage verifies.
		if len(res.payload) > maxRecordPayload {
			return fmt.Errorf("%w: payload %d bytes exceeds maximum %d once the template "+
				"is inlined into a fresh chunk", ErrRecordTooLarge, len(res.payload), maxRecordPayload)
		}
		rec = wrapEventRecord(w.recordID, ts, res.payload)
	}

	// The append must happen after the possible flush-and-rebuild above, or
	// the discarded first attempt's offsets would leak into the new chunk.
	w.chunkNames = append(w.chunkNames, res.names...)
	w.chunkTemplates = append(w.chunkTemplates, res.templates...)
	w.chunkTemplateOffset = res.defOffset

	w.lastRecordOffset = evtxRecordsStart + uint32(len(w.records))
	w.records = append(w.records, rec...)
	w.recordsCRC = crc32.Update(w.recordsCRC, crc32.IEEETable, rec)
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
	// A transient I/O failure here is not sticky — the file handle is still
	// valid and the caller can retry. flushChunkLocked can also fail
	// permanently via chunkCapacityLocked's chunk-ceiling guard: at
	// maxChunksPerFile, w.err is set and this is deliberately sticky, because
	// no further chunk can ever be written to this file — there is nothing
	// to retry, unlike a transient error.
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
		if !isLinkUnsupported(err) {
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
	if _, err := f.Write(buildFileHeader(0, 1, evtxFlagDirty)); err != nil {
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
	w.recordsCRC = 0
	w.tickWrittenLen = 0
	w.slotExtended = false
	w.chunkNames = w.chunkNames[:0]
	w.chunkTemplates = w.chunkTemplates[:0]
	w.chunkTemplateOffset = 0
	w.lastRecordOffset = 0
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

// chunkCapacityLocked reports whether the pending buffer still fits in a chunk
// and whether the file has room for another chunk.
//
// The entry guards in WriteRecord and WriteRaw make the payload-size overflow
// unreachable. If it ever fires, a code change has reintroduced silent
// truncation — fail permanently rather than write a corrupt chunk whose CRCs
// verify.
//
// chunkCount is a uint16, so 65535 is the last addressable chunk slot; at
// 65536 the counter would wrap to 0 and chunkOffset would recompute to the
// start of chunk 0, silently overwriting it. That is reachable whenever
// MaxFileSizeMB is 0 (the zero value), since nothing else bounds the file's
// growth. Fail permanently instead of wrapping.
//
// CALLER MUST HOLD w.mu.
func (w *Writer) chunkCapacityLocked() error {
	if w.chunkCount >= maxChunksPerFile {
		w.err = fmt.Errorf("%w: %d chunks", ErrTooManyChunks, w.chunkCount)
		return w.err
	}
	if len(w.records) > maxChunkPayload {
		w.err = fmt.Errorf("go_evtx: internal: chunk buffer %d bytes exceeds capacity %d",
			len(w.records), maxChunkPayload)
		return w.err
	}
	return nil
}

// activeFlagsLocked computes the file header flags to write while the writer
// is open and accepting further data: the dirty bit is always set — the file
// has been written to but not cleanly closed — and the full bit joins it once
// the file has reached the configured size limit.
//
// CALLER MUST HOLD w.mu.
func (w *Writer) activeFlagsLocked() uint32 {
	flags := evtxFlagDirty
	if w.cfg.MaxFileSizeMB > 0 && w.currentSize >= int64(w.cfg.MaxFileSizeMB)*1024*1024 {
		flags |= evtxFlagFull
	}
	return flags
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
// padded 65536-byte EVTX chunk, patches the file header at offset 0, and calls
// f.Sync(). Only once the chunk is durable does it commit w.chunkCount,
// w.currentSize, w.records, and w.firstID together — if any I/O step fails,
// none of that in-memory state has moved, so the call is genuinely retriable
// and a retry cannot write the same records into a second chunk slot.
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
	chunkHeader := buildChunkHeader(w.firstID, w.recordID-1, w.lastRecordOffset, freeSpaceOffset)

	chunkBytes := make([]byte, evtxChunkSize)
	copy(chunkBytes[0:], chunkHeader)
	copy(chunkBytes[recordsStart:], records)

	// Populate the two per-chunk hash tables from the nodes this chunk's
	// records emitted. MUST precede patchChunkCRC — the chunk header checksum
	// covers chunk[128:512], which is exactly the region written here.
	fillHashTables(chunkBytes, w.chunkNames, w.chunkTemplates)

	binary.LittleEndian.PutUint32(chunkBytes[52:], w.recordsCRC)
	patchChunkCRC(chunkBytes)

	// Write chunk at the correct file offset.
	chunkOffset := int64(evtxFileHeaderSize) + int64(w.chunkCount)*int64(evtxChunkSize)
	if _, err := w.f.WriteAt(chunkBytes, chunkOffset); err != nil {
		return fmt.Errorf("go_evtx: write chunk %d: %w", w.chunkCount, err)
	}

	// Patch the file header to acknowledge the new chunk, then make it durable.
	nextChunkCount := w.chunkCount + 1
	if _, err := w.f.WriteAt(buildFileHeader(nextChunkCount, w.recordID, w.activeFlagsLocked()), 0); err != nil {
		return fmt.Errorf("go_evtx: patch file header: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("go_evtx: sync: %w", err)
	}

	// The chunk is durable. Commit every piece of in-memory state together, so
	// a failure above leaves nothing mutated and the operation is genuinely
	// retriable — which is what rotate()'s non-sticky Step 1 already assumes.
	w.chunkCount = nextChunkCount
	w.currentSize += int64(evtxChunkSize)
	w.records = w.records[:0]
	w.recordsCRC = 0
	w.tickWrittenLen = 0
	w.slotExtended = false
	w.chunkNames = w.chunkNames[:0]
	w.chunkTemplates = w.chunkTemplates[:0]
	w.chunkTemplateOffset = 0
	w.lastRecordOffset = 0
	w.firstID = w.recordID
	w.queueFsyncLocked()

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
	// Nothing appended since the last tick wrote this slot. Rewriting the
	// same bytes and fsyncing them again persists nothing new; at idle this
	// is 86 400 fsyncs a day for no data.
	if len(w.records) == w.tickWrittenLen {
		return nil
	}

	// Build the in-progress chunk (same layout as flushChunkLocked, but don't commit).
	if err := w.chunkCapacityLocked(); err != nil {
		return err
	}

	chunkOffset := int64(evtxFileHeaderSize) + int64(w.chunkCount)*int64(evtxChunkSize)
	if !w.slotExtended {
		// The target is always strictly greater than the current file length
		// at this point — the file holds exactly w.chunkCount whole chunks
		// plus the 4096-byte header — so this can never shorten the file.
		if err := w.f.Truncate(chunkOffset + int64(evtxChunkSize)); err != nil {
			return fmt.Errorf("go_evtx: tick extend chunk slot %d: %w", w.chunkCount, err)
		}
		w.slotExtended = true
	}

	records := w.records

	recordsStart := int(evtxRecordsStart)
	freeSpaceOffset := uint32(recordsStart + len(records))
	chunkHeader := buildChunkHeader(w.firstID, w.recordID-1, w.lastRecordOffset, freeSpaceOffset)

	chunkBytes := make([]byte, evtxChunkSize)
	copy(chunkBytes[0:], chunkHeader)
	copy(chunkBytes[recordsStart:], records)

	// Populate the two per-chunk hash tables from the nodes accumulated so
	// far in this (still-open) chunk. MUST precede patchChunkCRC — the chunk
	// header checksum covers chunk[128:512], which is exactly the region
	// written here. Unlike flushChunkLocked, this does NOT reset
	// w.chunkNames/w.chunkTemplates: the chunk is still in progress, exactly
	// as w.records is left intact for further appends.
	fillHashTables(chunkBytes, w.chunkNames, w.chunkTemplates)

	binary.LittleEndian.PutUint32(chunkBytes[52:], w.recordsCRC)
	patchChunkCRC(chunkBytes)
	if _, err := w.f.WriteAt(chunkBytes, chunkOffset); err != nil {
		return fmt.Errorf("go_evtx: tick write chunk %d: %w", w.chunkCount, err)
	}

	// Patch file header with chunkCount+1 to reflect in-progress chunk visibility.
	if _, err := w.f.WriteAt(buildFileHeader(w.chunkCount+1, w.recordID, w.activeFlagsLocked()), 0); err != nil {
		return fmt.Errorf("go_evtx: tick patch file header: %w", err)
	}

	// Sync to disk.
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("go_evtx: tick sync: %w", err)
	}
	w.tickWrittenLen = len(w.records)
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
		if err = w.flushChunkLocked(); err != nil {
			// The final flush is the last chance to persist these records —
			// there is no caller left to retry. Make checkStateLocked's
			// documented precedence (sticky error over ErrClosed) actually
			// true for this path: without this, a Close whose final flush
			// failed would still report only ErrClosed to anyone who asks
			// afterward, hiding that data was lost.
			w.err = err
		}
	}

	// A clean Close clears the dirty flag, so a forensic consumer can tell
	// this file apart from one truncated by a crash. Every prior header write
	// (New, flushChunkLocked, tickFlushLocked) left the dirty bit set; this is
	// the one write that clears it, and only once everything above succeeded
	// and at least one chunk actually exists on disk.
	if err == nil && w.chunkCount > 0 {
		flags := uint32(0)
		if w.cfg.MaxFileSizeMB > 0 && w.currentSize >= int64(w.cfg.MaxFileSizeMB)*1024*1024 {
			flags = evtxFlagFull
		}
		if _, herr := w.f.WriteAt(buildFileHeader(w.chunkCount, w.recordID, flags), 0); herr != nil {
			err = fmt.Errorf("go_evtx: finalize clear dirty flag: %w", herr)
		} else if serr := w.f.Sync(); serr != nil {
			err = fmt.Errorf("go_evtx: finalize sync: %w", serr)
		} else {
			w.queueFsyncLocked()
		}
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
//
// lastRecordOffset is the chunk-relative offset where the LAST record's data
// begins — distinct from freeSpaceOffset, which is where the next record
// would start. A chunk with any records must never write the same value into
// both fields.
func buildChunkHeader(firstRecordID, lastRecordID uint64, lastRecordOffset, freeSpaceOffset uint32) []byte {
	buf := make([]byte, evtxChunkHeaderSize)
	copy(buf[0:8], evtxChunkMagic)
	binary.LittleEndian.PutUint64(buf[8:], firstRecordID)     // FirstEventRecordNumber
	binary.LittleEndian.PutUint64(buf[16:], lastRecordID)     // LastEventRecordNumber
	binary.LittleEndian.PutUint64(buf[24:], firstRecordID)    // FirstEventRecordIdentifier
	binary.LittleEndian.PutUint64(buf[32:], lastRecordID)     // LastEventRecordIdentifier
	binary.LittleEndian.PutUint32(buf[40:], 128)              // HeaderSize
	binary.LittleEndian.PutUint32(buf[44:], lastRecordOffset) // LastEventRecordDataOffset
	binary.LittleEndian.PutUint32(buf[48:], freeSpaceOffset)  // FreeSpaceOffset
	return buf
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
