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
	mu       sync.Mutex
	path     string // output file path
	records  []byte // accumulated event record bytes for current chunk
	recordID uint64 // monotonically incrementing record ID, starts at 1
	firstID  uint64 // first record ID in current chunk
	// Phase 9 additions:
	cfg  RotationConfig
	done chan struct{}
	wg   sync.WaitGroup
}

// New creates a Writer that will write to the given path.
//
// path must be non-empty. The parent directory is created if it does not
// exist. The file itself is written on Close() and on every ticker interval
// when cfg.FlushIntervalSec > 0.
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
	w := &Writer{
		path:     path,
		recordID: 1,
		firstID:  1,
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
// It calls flushToFile() under w.mu on every ticker interval.
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
				_ = w.flushToFile()
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
	w.records = append(w.records, rec...)
	w.recordID++

	if len(w.records) > chunkFlushThreshold {
		slog.Warn("go_evtx_chunk_boundary_reached",
			"path", w.path,
			"buffered_bytes", len(w.records),
		)
	}
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
	w.records = append(w.records, rec...)
	w.recordID++

	if len(w.records) > chunkFlushThreshold {
		slog.Warn("go_evtx_chunk_boundary_reached",
			"path", w.path,
			"buffered_bytes", len(w.records),
		)
	}
	return nil
}

// Close stops the background goroutine (if running), waits for it to exit,
// then performs a final flush of any remaining buffered events.
// If no events were written, Close returns nil without creating the file.
// Close must be called exactly once.
func (w *Writer) Close() error {
	close(w.done) // 1. signal goroutine
	w.wg.Wait()   // 2. wait — WITHOUT holding any lock
	w.mu.Lock()   // 3. safe to acquire now
	defer w.mu.Unlock()
	if len(w.records) == 0 {
		return nil
	}
	return w.flushToFile() // 4. final flush
}

// flushToFile assembles the complete single-chunk .evtx file and writes it.
func (w *Writer) flushToFile() error {
	maxRecords := evtxChunkSize - int(evtxRecordsStart)
	records := w.records
	if len(records) > maxRecords {
		slog.Warn("go_evtx_records_truncated",
			"path", w.path,
			"total_bytes", len(records),
			"max_bytes", maxRecords,
		)
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

	fileHeader := buildFileHeader(1, w.recordID)
	fileBytes := append(fileHeader, chunkBytes...)
	if err := os.WriteFile(w.path, fileBytes, 0o644); err != nil {
		return fmt.Errorf("go_evtx: write file: %w", err)
	}

	slog.Info("go_evtx_file_written",
		"path", w.path,
		"records", w.recordID-w.firstID,
	)
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
