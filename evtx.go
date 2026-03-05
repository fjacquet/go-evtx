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
	"fmt"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RotationConfig holds periodic flush configuration for the Writer.
// FlushIntervalSec is the interval between checkpoint writes in seconds.
// 0 disables the background goroutine; must be >= 0 (negative values are rejected by New).
type RotationConfig struct {
	FlushIntervalSec int // 0 = disabled; must be >= 0
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
		f.Close()
		return nil, fmt.Errorf("go_evtx: write placeholder header: %w", err)
	}

	w := &Writer{
		path:     path,
		recordID: 1,
		firstID:  1,
		f:        f,
		cfg:      cfg,
		done:     make(chan struct{}),
	}
	if cfg.FlushIntervalSec > 0 {
		w.wg.Add(1)
		go w.backgroundLoop()
	}
	return w, nil
}

// backgroundLoop runs as a goroutine when FlushIntervalSec > 0.
// It calls tickFlushLocked() under w.mu on every ticker interval.
// It exits when w.done is closed.
func (w *Writer) backgroundLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(time.Duration(w.cfg.FlushIntervalSec) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.mu.Lock()
			if len(w.records) > 0 {
				_ = w.tickFlushLocked()
			}
			w.mu.Unlock()
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
	defer w.mu.Unlock()

	ts := toFILETIME(time.Now())
	rec := wrapEventRecord(w.recordID, ts, payload)

	// If adding this record would exceed chunk capacity, flush first.
	maxRecords := int(evtxChunkSize - evtxRecordsStart)
	if len(w.records)+len(rec) > maxRecords {
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
	defer w.mu.Unlock()

	binXMLChunkOffset := evtxRecordsStart + uint32(len(w.records)) + evtxRecordHeaderSize
	payload := buildBinXML(eventID, fields, binXMLChunkOffset)
	ts := toFILETIME(parseTimeCreated(fields))
	rec := wrapEventRecord(w.recordID, ts, payload)

	// If adding this record would exceed chunk capacity, flush first.
	maxRecords := int(evtxChunkSize - evtxRecordsStart)
	if len(w.records)+len(rec) > maxRecords {
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

// flushChunkLocked writes the current in-progress chunk to disk as a complete,
// padded 65536-byte EVTX chunk. It increments w.chunkCount, patches the file
// header at offset 0, calls f.Sync(), and resets w.records and w.firstID.
//
// Must be called with w.mu held. Does nothing if len(w.records) == 0.
func (w *Writer) flushChunkLocked() error {
	if len(w.records) == 0 {
		return nil
	}

	// Clamp records to chunk capacity (defensive guard).
	records := w.records
	maxRecords := int(evtxChunkSize - evtxRecordsStart)
	if len(records) > maxRecords {
		records = records[:maxRecords]
	}

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

	// Increment chunk count and patch the file header.
	w.chunkCount++
	if _, err := w.f.WriteAt(buildFileHeader(w.chunkCount, w.recordID), 0); err != nil {
		return fmt.Errorf("go_evtx: patch file header: %w", err)
	}

	// Sync to disk.
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("go_evtx: sync: %w", err)
	}

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
	records := w.records
	maxRecords := int(evtxChunkSize - evtxRecordsStart)
	if len(records) > maxRecords {
		records = records[:maxRecords]
	}

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

	return nil
}

// Close stops the background goroutine (if running), waits for it to exit,
// then performs a final flush of any remaining buffered events.
// If no events were written and no chunks committed, Close removes the file from
// disk (backward compat: empty session leaves no file) and returns nil.
// Close must be called exactly once.
func (w *Writer) Close() error {
	close(w.done) // 1. signal goroutine
	w.wg.Wait()   // 2. wait — WITHOUT holding any lock
	w.mu.Lock()   // 3. safe to acquire now
	defer w.mu.Unlock()
	defer w.f.Close() // always close the file handle

	// Empty session: no records and no completed chunks.
	if len(w.records) == 0 && w.chunkCount == 0 {
		// Remove the placeholder file (nothing was written).
		_ = os.Remove(w.path)
		return nil
	}

	// Flush remaining partial chunk if any records are pending.
	if len(w.records) > 0 {
		return w.flushChunkLocked()
	}

	// Records were written but last chunk was already flushed by flushChunkLocked.
	// File header was already patched in that call; nothing more to do.
	return nil
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
