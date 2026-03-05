// Package evtx — Reader API for Windows Event Log (.evtx) files.
//
// Basic usage:
//
//	r, err := evtx.Open("/var/log/audit.evtx")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer r.Close()
//
//	for {
//	    rec, err := r.ReadRecord()
//	    if errors.Is(err, evtx.ErrNoMoreRecords) {
//	        break
//	    }
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    fmt.Println(rec.EventID, rec.Provider)
//	}
package evtx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrNoMoreRecords is returned by ReadRaw and ReadRecord when all records have been read.
var ErrNoMoreRecords = errors.New("go_evtx: no more records")

// Record holds the decoded fields of a single EVTX event.
type Record struct {
	RecordID    uint64
	Timestamp   time.Time         // from event record header (FILETIME)
	EventID     uint16            // from System/EventID substitution
	Level       uint16            // from System/Level substitution (0 = LogAlways)
	Provider    string            // from System/Provider/@Name
	Computer    string            // from System/Computer
	TimeCreated time.Time         // from System/TimeCreated/@SystemTime
	Fields      map[string]string // EventData Name → value
}

// Reader reads EVTX event records sequentially from a file.
// All exported methods are safe for concurrent use.
type Reader struct {
	f         *os.File
	numChunks int
	chunkIdx  int
	buf       []byte // current chunk (evtxChunkSize bytes)
	recOff    int    // byte offset within buf of the next record to read
	freeOff   int    // byte offset within buf where records end (FreeSpaceOffset)
}

// Open opens an .evtx file for sequential reading.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("go_evtx: open: %w", err)
	}

	hdr := make([]byte, evtxFileHeaderSize)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("go_evtx: read file header: %w", err)
	}
	if string(hdr[0:8]) != evtxFileMagic {
		_ = f.Close()
		return nil, fmt.Errorf("go_evtx: not an evtx file: invalid magic")
	}

	numChunks := int(binary.LittleEndian.Uint16(hdr[42:44]))
	r := &Reader{
		f:         f,
		numChunks: numChunks,
		chunkIdx:  -1,
		buf:       make([]byte, evtxChunkSize),
	}
	if err := r.loadChunk(0); err != nil {
		_ = f.Close()
		return nil, err
	}
	return r, nil
}

// loadChunk reads chunk idx into r.buf and initialises recOff/freeOff.
func (r *Reader) loadChunk(idx int) error {
	if idx >= r.numChunks {
		return ErrNoMoreRecords
	}
	fileOffset := int64(evtxFileHeaderSize) + int64(idx)*int64(evtxChunkSize)
	if _, err := r.f.ReadAt(r.buf, fileOffset); err != nil {
		return fmt.Errorf("go_evtx: read chunk %d: %w", idx, err)
	}
	if string(r.buf[0:8]) != evtxChunkMagic {
		return fmt.Errorf("go_evtx: invalid chunk magic at index %d", idx)
	}
	r.chunkIdx = idx
	r.recOff = int(evtxChunkHeaderSize)                            // records begin after 512-byte chunk header
	r.freeOff = int(binary.LittleEndian.Uint32(r.buf[48:52]))     // FreeSpaceOffset
	return nil
}

// nextRecord advances to and parses the next event record header.
// Returns the raw BinXML payload (without the 24-byte record header or the trailing size copy).
func (r *Reader) nextRecord() (recordID uint64, ts uint64, payload []byte, err error) {
	for {
		if r.recOff >= r.freeOff {
			// Exhausted this chunk; try the next one.
			if loadErr := r.loadChunk(r.chunkIdx + 1); loadErr != nil {
				return 0, 0, nil, ErrNoMoreRecords
			}
			continue
		}

		if r.recOff+24 > len(r.buf) {
			return 0, 0, nil, fmt.Errorf("go_evtx: truncated record at offset %d", r.recOff)
		}
		rec := r.buf[r.recOff:]

		sig := binary.LittleEndian.Uint32(rec[0:4])
		if sig != evtxRecordSignature {
			return 0, 0, nil, fmt.Errorf("go_evtx: invalid record signature 0x%08x at chunk offset %d", sig, r.recOff)
		}

		size := int(binary.LittleEndian.Uint32(rec[4:8]))
		if size < 28 || r.recOff+size > len(r.buf) {
			return 0, 0, nil, fmt.Errorf("go_evtx: invalid record size %d at chunk offset %d", size, r.recOff)
		}

		recordID = binary.LittleEndian.Uint64(rec[8:16])
		ts = binary.LittleEndian.Uint64(rec[16:24])

		// Payload sits between the 24-byte header and the 4-byte trailing size copy.
		raw := make([]byte, size-24-4)
		copy(raw, rec[24:size-4])

		r.recOff += size
		return recordID, ts, raw, nil
	}
}

// ReadRaw returns the raw BinXML payload of the next event record.
// Returns ErrNoMoreRecords when all records have been read.
// The returned bytes can be passed to Writer.WriteRaw to copy records between files.
func (r *Reader) ReadRaw() ([]byte, error) {
	_, _, payload, err := r.nextRecord()
	return payload, err
}

// ReadRecord reads and decodes the next event record.
// Returns ErrNoMoreRecords when all records have been read.
func (r *Reader) ReadRecord() (*Record, error) {
	recordID, ts, payload, err := r.nextRecord()
	if err != nil {
		return nil, err
	}
	rec := &Record{
		RecordID:  recordID,
		Timestamp: fromFILETIME(ts),
	}
	decodeBinXML(payload, rec)
	return rec, nil
}

// Close closes the underlying file.
func (r *Reader) Close() error {
	return r.f.Close()
}
