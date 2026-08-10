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

// ErrMissingProviderName is returned by WriteRecord when fields has no
// non-empty "ProviderName". Since v0.7.1 an unsupplied value is encoded as a
// NULL substitution, which per the format omits its element — so an empty
// provider name produces <Provider></Provider>, and Get-WinEvent throws a
// NullReferenceException dereferencing a provider that has no name. The file
// is otherwise valid: EventLogReader reads every record and wevtutil exits 0,
// which is what makes the failure so hard to trace back to its cause.
//
// Measured on Windows Server 2025, one variable at a time: an empty
// ProviderName fails, while an empty Computer and an empty Channel both read
// fine. Only this one field is rejected — validating the other two would be
// inventing a rule nothing measured.
//
// Reported downstream as issue #10, where it cost a full investigation before
// the cause was found. An error here is the diagnostic that was missing.
var ErrMissingProviderName = errors.New("go_evtx: ProviderName must not be empty")

// ErrTooManyChunks is returned when a file has reached the maximum number of
// chunks a uint16 chunk counter can address. Continuing would wrap the counter
// and overwrite chunk 0. Rotate, or set MaxFileSizeMB so rotation happens
// first.
var ErrTooManyChunks = errors.New("go_evtx: file has reached the maximum chunk count")

// maxChunkPayload is the number of bytes available for event records in a
// single chunk, after the 512-byte chunk header.
const maxChunkPayload = int(evtxChunkSize - evtxRecordsStart) // 65024

// maxRecordPayload is the largest BinXML payload that can fit in one record:
// the chunk payload capacity less the 24-byte record header and the 4-byte
// trailing size copy.
const maxRecordPayload = maxChunkPayload - evtxRecordHeaderSize - 4 // 64996

// maxChunksPerFile is the largest number of chunks a file may hold. chunkCount
// is a uint16, so 65535 is the last addressable slot; at 65536 the counter
// wraps to 0 and chunkOffset recomputes to the start of chunk 0.
const maxChunksPerFile = 65535
