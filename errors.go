// errors.go — sentinel errors and capacity limits for the Writer.
package evtx

import "errors"

// ErrClosed is returned by WriteRecord, WriteRaw and Rotate after Close has
// been called. The writer accepts no further events.
var ErrClosed = errors.New("go_evtx: writer is closed")

// ErrRecordTooLarge is returned when a single event record would not fit in an
// EVTX chunk. Splitting one logical event across chunks is not valid EVTX, so
// the record is rejected and nothing is written.
var ErrRecordTooLarge = errors.New("go_evtx: record exceeds chunk capacity")

// maxChunkPayload is the number of bytes available for event records in a
// single chunk, after the 512-byte chunk header.
const maxChunkPayload = int(evtxChunkSize - evtxRecordsStart) // 65024

// maxRecordPayload is the largest BinXML payload that can fit in one record:
// the chunk payload capacity less the 24-byte record header and the 4-byte
// trailing size copy.
const maxRecordPayload = maxChunkPayload - evtxRecordHeaderSize - 4 // 64996
