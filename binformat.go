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
	"hash/crc32"
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
)

// toFILETIME converts a Go time.Time to a Windows FILETIME value.
// FILETIME is expressed as 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
func toFILETIME(t time.Time) uint64 {
	return uint64(t.UTC().UnixNano()/100 + filetimeEpochDelta)
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
//	[16:24]  LastChunkNumber  = chunkCount - 1
//	[24:32]  NextRecordIdentifier = nextRecordID
//	[32:36]  HeaderSize = 128
//	[36:38]  MinorVersion = 1
//	[38:40]  MajorVersion = 3
//	[40:42]  BlockSize = 4096
//	[42:44]  ChunkCount = chunkCount
//	[44:120] reserved zeros
//	[120:124] Flags = 0
//	[124:128] CRC32 of buf[0:120]
//	[128:4096] padding zeros
func buildFileHeader(chunkCount uint16, nextRecordID uint64) []byte {
	buf := make([]byte, evtxFileHeaderSize)

	copy(buf[0:8], evtxFileMagic)
	binary.LittleEndian.PutUint64(buf[8:], 0)                     // FirstChunkNumber
	binary.LittleEndian.PutUint64(buf[16:], uint64(chunkCount-1)) // LastChunkNumber
	binary.LittleEndian.PutUint64(buf[24:], nextRecordID)         // NextRecordIdentifier
	binary.LittleEndian.PutUint32(buf[32:], 128)                  // HeaderSize
	binary.LittleEndian.PutUint16(buf[36:], 1)                    // MinorVersion
	binary.LittleEndian.PutUint16(buf[38:], 3)                    // MajorVersion
	binary.LittleEndian.PutUint16(buf[40:], 4096)                 // BlockSize
	binary.LittleEndian.PutUint16(buf[42:], chunkCount)           // ChunkCount
	// buf[44:120] — reserved zeros (already zero from make())
	// buf[120:124] — Flags = 0 (already zero)
	// buf[124:128] — CRC32 placeholder (must be zero during calculation)

	crc := crc32.Checksum(buf[0:120], crc32.IEEETable)
	binary.LittleEndian.PutUint32(buf[124:], crc)

	// buf[128:4096] — padding zeros (already zero from make())
	return buf
}

// patchChunkCRC computes and writes the chunk header CRC32.
//
// Per EVTX spec the HeaderCRC32 covers bytes [0:120] and [128:512],
// skipping the Flags+CRC32 region [120:128].
//
// chunk must be at least 512 bytes.
func patchChunkCRC(chunk []byte) {
	// Zero out the flags and CRC field before computing.
	for i := 120; i < 128; i++ {
		chunk[i] = 0
	}
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
	binary.LittleEndian.PutUint32(buf[4:], size)                 // Size
	binary.LittleEndian.PutUint64(buf[8:], recordID)             // EventRecordID
	binary.LittleEndian.PutUint64(buf[16:], timestamp)           // TimeCreated (FILETIME)
	copy(buf[24:], binXMLPayload)                                 // BinXML payload
	binary.LittleEndian.PutUint32(buf[size-4:], size)            // Size copy at end

	return buf
}
