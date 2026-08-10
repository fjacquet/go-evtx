// binformat.go — pure binary format helpers for .evtx file construction.
//
// No build tag: these helpers are platform-agnostic (pure math, no OS calls).
//
// EVTX binary format references:
//   - https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
//   - Microsoft MS-EVEN6 specification
//
// CRC32 scope:
//   - File header:  crc32(buf[0:120])        written at buf[124:128]
//   - Chunk header: crc32(buf[0:120] + buf[128:512]) written at buf[124:128]
//   - Event records CRC32: crc32(records)    written at chunk[52:56]
package evtx

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
	"time"
	"unicode/utf16"
)

// EVTX format constants.
const (
	evtxFileMagic       = "ElfFile\x00" // 8 bytes: file header signature
	evtxChunkMagic      = "ElfChnk\x00" // 8 bytes: chunk header signature
	evtxRecordSignature = uint32(0x00002A2A)
	evtxFileHeaderSize  = 4096
	evtxChunkSize       = 65536
	evtxChunkHeaderSize = 512
	// filetimeEpochDelta: 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
	filetimeEpochDelta = int64(116444736000000000)
	// filetimeTicksPerSecond: a FILETIME counts 100-nanosecond intervals.
	filetimeTicksPerSecond = int64(10_000_000)
)

// File header flags, written at buf[120:124].
const (
	// evtxFlagDirty marks a log that has been written to but not cleanly
	// closed. A forensic consumer reads it to tell a clean shutdown from a
	// crash-truncated file.
	evtxFlagDirty uint32 = 0x0001
	// evtxFlagFull marks a log that reached its configured size limit.
	evtxFlagFull uint32 = 0x0002
)

// toFILETIME converts a Go time.Time to a Windows FILETIME value.
//
// Seconds and sub-second nanoseconds convert separately on purpose:
// t.UnixNano() is only defined for roughly 1678-2262, while FILETIME starts at
// 1601, so routing the whole value through nanoseconds silently wraps for the
// early range this format actually uses.
func toFILETIME(t time.Time) uint64 {
	u := t.UTC()
	return uint64(u.Unix()*filetimeTicksPerSecond + int64(u.Nanosecond())/100 + filetimeEpochDelta)
}

// fromFILETIME converts a Windows FILETIME value to a Go time.Time.
//
// FILETIME 0 is 1601-01-01T00:00:00Z and Windows writes it for an unset
// timestamp — 180 records across 178 of the 285 files in the local corpus
// carry one. Earlier versions rejected it as corruption, because the
// conversion went through an int64 nanosecond offset, which cannot reach 1601.
// That was a limit of the arithmetic, not of the format. Converting seconds
// and remainder separately covers the whole FILETIME domain, 1601 to roughly
// the year 30828.
//
// A FILETIME above math.MaxInt64 is still rejected: int64(ft) would
// reinterpret as negative, and no such value is a time.
func fromFILETIME(ft uint64) (time.Time, error) {
	if ft > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("go_evtx: FILETIME %d exceeds int64 range", ft)
	}
	delta := int64(ft) - filetimeEpochDelta
	sec := delta / filetimeTicksPerSecond
	nsec := (delta % filetimeTicksPerSecond) * 100
	return time.Unix(sec, nsec).UTC(), nil
}

// encodeUTF16LE encodes a Go string as a length-prefixed, null-terminated UTF-16LE byte slice.
//
// Layout:
//
//	[uint16 char_count][uint16 codeunit_0]...[uint16 codeunit_N][0x0000]
//
// Total byte length: 2 + len(u16)*2 + 2
func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	// 2 bytes for count + 2 bytes per code unit + 2 bytes null terminator
	buf := make([]byte, 2+len(u16)*2+2)
	binary.LittleEndian.PutUint16(buf[0:], uint16(len(u16)))
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(buf[2+i*2:], v)
	}
	// null terminator already zero from make()
	return buf
}

// buildFileHeader constructs the 4096-byte EVTX file header.
//
// Field layout (all little-endian):
//
//	[0:8]    Signature "ElfFile\x00"
//	[8:16]   FirstChunkNumber = 0
//	[16:24]  LastChunkNumber  = chunkCount - 1 (0 when chunkCount == 0)
//	[24:32]  NextRecordIdentifier = nextRecordID
//	[32:36]  HeaderSize = 128
//	[36:38]  MinorVersion = 1
//	[38:40]  MajorVersion = 3
//	[40:42]  BlockSize = 4096
//	[42:44]  ChunkCount = chunkCount
//	[44:120] reserved zeros
//	[120:124] Flags = flags
//	[124:128] CRC32 of buf[0:120]
//	[128:4096] padding zeros
//
// The CRC covers buf[0:120] only, so flags sits outside its range — writing
// it does not invalidate the checksum.
func buildFileHeader(chunkCount uint16, nextRecordID uint64, flags uint32) []byte {
	buf := make([]byte, evtxFileHeaderSize)

	copy(buf[0:8], evtxFileMagic)
	binary.LittleEndian.PutUint64(buf[8:], 0) // FirstChunkNumber
	lastChunk := uint64(0)
	if chunkCount > 0 {
		lastChunk = uint64(chunkCount - 1)
	}
	binary.LittleEndian.PutUint64(buf[16:], lastChunk)    // LastChunkNumber
	binary.LittleEndian.PutUint64(buf[24:], nextRecordID) // NextRecordIdentifier
	binary.LittleEndian.PutUint32(buf[32:], 128)          // HeaderSize
	binary.LittleEndian.PutUint16(buf[36:], 1)            // MinorVersion
	binary.LittleEndian.PutUint16(buf[38:], 3)            // MajorVersion
	binary.LittleEndian.PutUint16(buf[40:], 4096)         // BlockSize
	binary.LittleEndian.PutUint16(buf[42:], chunkCount)   // ChunkCount
	// buf[44:120] — reserved zeros (already zero from make())
	binary.LittleEndian.PutUint32(buf[120:], flags) // Flags
	// buf[124:128] — CRC32 placeholder (must be zero during calculation)

	crc := crc32.Checksum(buf[0:120], crc32.IEEETable)
	binary.LittleEndian.PutUint32(buf[124:], crc)

	// buf[128:4096] — padding zeros (already zero from make())
	return buf
}

// evtxChunkUnknownField120 (B3) is a constant observed at chunk header
// [120:124] in every one of the nine chunks in testdata/system.evtx
// (0x00000001), which go-evtx never wrote. libyal's spec labels the field
// "Unknown", so this is a lower-confidence, parity-only fix: included because
// the real file both carries it and has a verifying header CRC, but a null
// result here would not be surprising the way B1/B2 would be.
const evtxChunkUnknownField120 = uint32(1)

// patchChunkCRC computes and writes the chunk header CRC32, and the
// evtxChunkUnknownField120 constant alongside it.
//
// Per EVTX spec the HeaderCRC32 covers bytes [0:120] and [128:512], skipping
// [120:128] — so [120:124] can be set to any value here without affecting
// the checksum. It must be set HERE, not by an earlier caller: this function
// used to zero the whole [120:128] region before computing, which would
// destroy a value written before the call. Ordering it here instead of at
// each flush call site keeps that trap from being reintroduced.
//
// chunk must be at least 512 bytes.
func patchChunkCRC(chunk []byte) {
	binary.LittleEndian.PutUint32(chunk[120:], evtxChunkUnknownField120) // [120:124]: B3
	binary.LittleEndian.PutUint32(chunk[124:], 0)                        // [124:128]: CRC32 placeholder, zero during calculation
	h := crc32.New(crc32.IEEETable)
	h.Write(chunk[0:120])
	h.Write(chunk[128:512])
	binary.LittleEndian.PutUint32(chunk[124:], h.Sum32())
}

// wrapEventRecord assembles a complete EVTX event record from its constituent parts.
//
// Record layout:
//
//	[0:4]               Signature = 0x00002A2A (little-endian)
//	[4:8]               Size = uint32(24 + len(binXMLPayload) + 4)
//	[8:16]              EventRecordID = recordID
//	[16:24]             TimeCreated = timestamp (FILETIME)
//	[24:24+len(payload)] BinXML payload
//	[end-4:end]         Size copy (same value as offset 4)
func wrapEventRecord(recordID uint64, timestamp uint64, binXMLPayload []byte) []byte {
	size := uint32(24 + len(binXMLPayload) + 4)
	buf := make([]byte, size)

	binary.LittleEndian.PutUint32(buf[0:], evtxRecordSignature) // Signature
	binary.LittleEndian.PutUint32(buf[4:], size)                // Size
	binary.LittleEndian.PutUint64(buf[8:], recordID)            // EventRecordID
	binary.LittleEndian.PutUint64(buf[16:], timestamp)          // TimeCreated (FILETIME)
	copy(buf[24:], binXMLPayload)                               // BinXML payload
	binary.LittleEndian.PutUint32(buf[size-4:], size)           // Size copy at end

	return buf
}
