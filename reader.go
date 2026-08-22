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
//	    ev, err := r.ReadEvent()
//	    if errors.Is(err, evtx.ErrNoMoreRecords) {
//	        break
//	    }
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    fmt.Println(ev.System.EventID, ev.System.Provider.Name)
//	}
package evtx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ErrNoMoreRecords is returned by ReadRaw and ReadEvent when all records have been read.
var ErrNoMoreRecords = errors.New("go_evtx: no more records")

// ErrChunkUnreadable wraps every failure to load a chunk that is not simply the
// end of the file: a short or failing read, or a chunk whose magic is wrong.
//
// It exists because these used to be reported as ErrNoMoreRecords, so a file
// truncated part-way — or one whose fifth chunk of eleven is corrupt — looked
// to every caller like a clean end of stream. Silent truncation of the read is
// the worst class of defect this project has, so the two are now distinct: a
// genuine end of stream is ErrNoMoreRecords, and anything else reaches the
// caller as itself, matching errors.Is(err, ErrChunkUnreadable).
//
// The Reader does not recover from it. The chunk that failed cannot be skipped
// past — its bytes are what would say where the next one begins — so the stream
// ends there: the call that reports it returns the error, and every call after
// it returns ErrNoMoreRecords. A caller looping until ErrNoMoreRecords still
// terminates, and one that inspects each error learns the file was not
// finished.
var ErrChunkUnreadable = errors.New("go_evtx: chunk unreadable")

// FileInfo describes the container, not its contents: the facts carried by
// the 4096-byte file header, which Open reads once. Windows writes format 3.1
// and 3.2; go-evtx writes 3.1.
type FileInfo struct {
	Major, Minor uint16 // format version
	Chunks       int
	Dirty        bool // written to but not cleanly closed
	Full         bool // reached its configured size limit
}

// Reader reads EVTX event records sequentially from a file.
// All exported methods are safe for concurrent use.
type Reader struct {
	mu        sync.Mutex // guards all fields below; Reader is safe for concurrent use
	f         *os.File
	numChunks int
	info      FileInfo // immutable after Open; guarded by mu like every other field
	chunkIdx  int
	buf       []byte // current chunk (evtxChunkSize bytes)
	recOff    int    // byte offset within buf of the next record to read
	freeOff   int    // byte offset within buf where records end (FreeSpaceOffset)

	// templates caches this chunk's template definitions and owns the chunk
	// buffer it was built for (templateCache's own invariant). Offsets in the
	// BinXML stream are chunk-relative, so this MUST be rebuilt whenever a new
	// chunk is loaded — see loadChunk.
	templates *templateCache
}

// Open opens an .evtx file for sequential reading.
//
// Reading a file that a Writer is actively writing is not supported. The
// background tick publishes an in-progress chunk in more than one WriteAt,
// and nothing synchronises a Reader against it. Open a file only after its
// Writer has been closed, or open a copy.
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
	flags := binary.LittleEndian.Uint32(hdr[120:124])
	r := &Reader{
		f:         f,
		numChunks: numChunks,
		chunkIdx:  -1,
		buf:       make([]byte, evtxChunkSize),
		info: FileInfo{
			Minor:  binary.LittleEndian.Uint16(hdr[36:38]),
			Major:  binary.LittleEndian.Uint16(hdr[38:40]),
			Chunks: numChunks,
			Dirty:  flags&evtxFlagDirty != 0,
			Full:   flags&evtxFlagFull != 0,
		},
	}
	if err := r.loadChunk(0); err != nil {
		_ = f.Close()
		return nil, err
	}
	return r, nil
}

// loadChunk reads chunk idx into r.buf and initialises recOff/freeOff.
//
// CALLER MUST HOLD r.mu.
func (r *Reader) loadChunk(idx int) error {
	if idx >= r.numChunks {
		return ErrNoMoreRecords
	}
	fileOffset := int64(evtxFileHeaderSize) + int64(idx)*int64(evtxChunkSize)
	if _, err := r.f.ReadAt(r.buf, fileOffset); err != nil {
		return fmt.Errorf("%w: read chunk %d: %w", ErrChunkUnreadable, idx, err)
	}
	if string(r.buf[0:8]) != evtxChunkMagic {
		return fmt.Errorf("%w: invalid chunk magic at index %d", ErrChunkUnreadable, idx)
	}
	r.chunkIdx = idx
	// r.buf was just refilled in place; any template definitions cached
	// against the previous chunk's bytes now alias the wrong data. Rebuild
	// rather than reset-on-next-use so there is no window where a stale cache
	// could be queried.
	r.templates = newTemplateCache(r.buf)
	r.recOff = int(evtxChunkHeaderSize)                       // records begin after 512-byte chunk header
	r.freeOff = int(binary.LittleEndian.Uint32(r.buf[48:52])) // FreeSpaceOffset
	return nil
}

// abandonChunkLocked gives up on the remainder of the current chunk, so that
// the next call to nextRecord loads the following chunk — or reports the end
// of the stream when there is none.
//
// Every framing field (signature, size) is what tells the reader where the
// *next* record begins. Once one of them is wrong, no offset in the rest of
// the chunk can be trusted, and there is nothing to resynchronise on: the
// only choices are to abandon the chunk or to guess. Returning the error
// without moving is not among them — nextRecord used to do exactly that, and
// every caller looping until ErrNoMoreRecords span forever on the same bytes.
//
// An empty window (both offsets zero) is used rather than recOff = freeOff
// because freeOff is itself read from the chunk header and may be the corrupt
// value in question.
//
// CALLER MUST HOLD r.mu.
func (r *Reader) abandonChunkLocked() {
	r.recOff, r.freeOff = 0, 0
}

// endStreamLocked ends the stream for good: every later call reports
// ErrNoMoreRecords. It is used when a chunk could not be loaded, which is not
// something the Reader can step over — the failed chunk's own bytes are what
// would say where the next record begins, and the chunk after it can only be
// found by trusting the very layout that just proved untrustworthy. Retrying
// the same failing index on the next call would spin, which is the bug
// abandonChunkLocked exists to prevent, so the position is moved past the last
// chunk instead.
//
// CALLER MUST HOLD r.mu.
func (r *Reader) endStreamLocked() {
	r.abandonChunkLocked()
	r.chunkIdx = r.numChunks
}

// nextRecord advances to and parses the next event record header.
// Returns the raw BinXML payload (without the 24-byte record header or the
// trailing size copy) and payloadChunkOffset, the chunk-relative byte offset
// of that same payload within r.buf — ReadEvent needs the offset (to resolve
// template and name references, which are chunk-relative) in addition to the
// copy ReadRaw returns.
//
// CALLER MUST HOLD r.mu.
func (r *Reader) nextRecord() (recordID uint64, ts uint64, payload []byte, payloadChunkOffset int, err error) {
	for {
		if r.recOff >= r.freeOff {
			// Exhausted this chunk; try the next one. Only the absence of a
			// next chunk is the end of the stream — a read failure or a bad
			// chunk magic is a real failure and is returned as itself, because
			// collapsing the two reported a file the reader never finished as
			// a clean finish.
			if loadErr := r.loadChunk(r.chunkIdx + 1); loadErr != nil {
				if errors.Is(loadErr, ErrNoMoreRecords) {
					return 0, 0, nil, 0, ErrNoMoreRecords
				}
				r.endStreamLocked()
				return 0, 0, nil, 0, loadErr
			}
			continue
		}

		if r.recOff+24 > len(r.buf) {
			off := r.recOff
			r.abandonChunkLocked()
			return 0, 0, nil, 0, fmt.Errorf("go_evtx: truncated record at offset %d", off)
		}
		rec := r.buf[r.recOff:]

		sig := binary.LittleEndian.Uint32(rec[0:4])
		if sig != evtxRecordSignature {
			off := r.recOff
			r.abandonChunkLocked()
			return 0, 0, nil, 0, fmt.Errorf("go_evtx: invalid record signature 0x%08x at chunk offset %d", sig, off)
		}

		// The record must fit inside the records region, not merely inside the
		// chunk: freeOff is where the records end and the chunk's padding
		// begins, so a size that stays under 65536 but runs past freeOff would
		// otherwise have padding read as payload and could yield a fabricated
		// event instead of a framing error. Both bounds are checked, not just
		// the tighter one — freeOff is itself read from the chunk header and
		// may be the corrupt value in question.
		size := int(binary.LittleEndian.Uint32(rec[4:8]))
		if size < 28 || r.recOff+size > len(r.buf) || r.recOff+size > r.freeOff {
			off := r.recOff
			r.abandonChunkLocked()
			return 0, 0, nil, 0, fmt.Errorf("go_evtx: invalid record size %d at chunk offset %d", size, off)
		}

		recordID = binary.LittleEndian.Uint64(rec[8:16])
		ts = binary.LittleEndian.Uint64(rec[16:24])

		// Payload sits between the 24-byte header and the 4-byte trailing size copy.
		raw := make([]byte, size-24-4)
		copy(raw, rec[24:size-4])

		payloadOffset := r.recOff + 24
		r.recOff += size
		return recordID, ts, raw, payloadOffset, nil
	}
}

// ReadRaw returns the raw BinXML payload of the next event record.
// Returns ErrNoMoreRecords when all records have been read.
// The returned bytes are the caller's own copy, safe to retain and mutate;
// they can be passed to Writer.WriteRaw to copy records between files. This
// guarantee comes from nextRecord, which copies the payload out of r.buf
// before returning it rather than aliasing the shared chunk buffer — do not
// remove that copy without preserving this guarantee some other way.
// A framing error abandons the remainder of the containing chunk; see
// ReadEvent's doc comment for the full behaviour, which ReadRaw shares.
func (r *Reader) ReadRaw() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _, payload, _, err := r.nextRecord()
	return payload, err
}

// ReadEvent reads and decodes the next event record.
// Returns ErrNoMoreRecords when all records have been read.
//
// Two kinds of failure are returned, and they leave the Reader in different
// places. No partial Event is ever returned by either.
//
// A *decode* failure — the 24-byte record header parsed, but its BinXML
// payload did not — is returned for that record alone. Framing comes from the
// record header independently of the payload, so the Reader stays positioned
// on the next record: the caller chooses whether to stop or to skip, and a
// loop that skips reads every remaining record.
//
// A *framing* failure — a bad signature, an impossible size, a record header
// running past the end of the chunk — is returned once, and the rest of that
// chunk is abandoned, because the fields that say where the next record begins
// are the ones that cannot be trusted. The following call resumes at the next
// chunk, or returns ErrNoMoreRecords when this was the last one. Records after
// the corrupt point in that chunk are therefore not reported; a loop that
// skips still terminates.
//
// A *chunk-load* failure — the next chunk could not be read, or does not carry
// a chunk signature — is returned once, wrapping ErrChunkUnreadable, and ends
// the stream: every later call returns ErrNoMoreRecords. It is distinct from
// ErrNoMoreRecords precisely so that a truncated or damaged file is not
// mistaken for a file that was read to the end.
//
// ReadRaw shares all three behaviours: they belong to record framing, not to
// decoding.
func (r *Reader) ReadEvent() (*Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	recordID, ts, payload, payloadOffset, err := r.nextRecord()
	if err != nil {
		return nil, err
	}
	root, err := decodeRecordBinXML(r.templates, payloadOffset, len(payload))
	if err != nil {
		return nil, fmt.Errorf("go_evtx: chunk %d, record %d: %w", r.chunkIdx, recordID, err)
	}
	ev, err := eventFromNode(root)
	if err != nil {
		return nil, fmt.Errorf("go_evtx: chunk %d, record %d: %w", r.chunkIdx, recordID, err)
	}
	timestamp, err := fromFILETIME(ts)
	if err != nil {
		return nil, fmt.Errorf("go_evtx: chunk %d, record %d: %w", r.chunkIdx, recordID, err)
	}
	ev.RecordID = recordID
	ev.Timestamp = timestamp
	return ev, nil
}

// FileInfo returns the container facts read from the file header at Open.
// Safe for concurrent use, like every other exported Reader method.
func (r *Reader) FileInfo() FileInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.info
}

// Close closes the underlying file.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
