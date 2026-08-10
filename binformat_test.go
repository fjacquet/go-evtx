// binformat_test.go — unit tests for EVTX binary format helpers.
//
// No build tag: tests run on all platforms without cross-compilation.
// White-box: package evtx (accesses unexported helpers).
// stdlib only: no testify, no external libraries.
// Table-driven with t.Run.
package evtx

import (
	"encoding/binary"
	"hash/crc32"
	"math"
	"testing"
	"time"
)

// TestToFILETIME verifies the FILETIME conversion formula.
func TestToFILETIME(t *testing.T) {
	cases := []struct {
		name     string
		input    time.Time
		expected uint64
	}{
		{
			name:  "unix_epoch",
			input: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			// 100ns intervals from 1601-01-01 to 1970-01-01
			expected: 116444736000000000,
		},
		{
			name:  "2024-01-01",
			input: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			// Unix seconds for 2024-01-01T00:00:00Z = 1704067200
			// FILETIME = (1704067200 * 10_000_000) + 116444736000000000
			expected: uint64(1704067200)*10_000_000 + 116444736000000000,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toFILETIME(tc.input)
			if got != tc.expected {
				t.Errorf("toFILETIME(%v) = %d, want %d", tc.input, got, tc.expected)
			}
			if got == 0 {
				t.Error("toFILETIME returned 0")
			}
			if got == math.MaxUint64 {
				t.Error("toFILETIME returned MaxUint64")
			}
		})
	}
}

// TestFILETIME_RoundTripAcrossTheRange covers both ends of the format's range,
// not just a modern timestamp. toFILETIME has the same nanosecond-overflow
// defect as fromFILETIME had, so a 1601 case is what proves both halves fixed.
func TestFILETIME_RoundTripAcrossTheRange(t *testing.T) {
	cases := []struct {
		name string
		want time.Time
	}{
		{"filetime epoch", time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"unix epoch", time.Unix(0, 0).UTC()},
		{"one tick after the unix epoch", time.Date(1970, 1, 1, 0, 0, 0, 100, time.UTC)},
		{"present day", time.Date(2026, 8, 10, 6, 2, 35, 412300000, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fromFILETIME(toFILETIME(tc.want))
			if err != nil {
				t.Fatalf("fromFILETIME(toFILETIME(%s)): %v", tc.want.Format(time.RFC3339Nano), err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("round trip = %s, want %s",
					got.Format(time.RFC3339Nano), tc.want.Format(time.RFC3339Nano))
			}
		})
	}
}

// TestFromFILETIME_ZeroIsYear1601 replaces TestFromFILETIME_OutOfRangeIsError,
// which asserted that ft == 0 must be rejected as corruption. It is not
// corruption: FILETIME 0 is 1601-01-01T00:00:00Z, Windows writes it for an
// unset timestamp, and 180 records across 178 of the 285 files in the local
// corpus carry one. The old rejection came from converting through int64
// nanoseconds, which cannot represent 1601 — a limit of our arithmetic, not of
// the format.
func TestFromFILETIME_ZeroIsYear1601(t *testing.T) {
	got, err := fromFILETIME(0)
	if err != nil {
		t.Fatalf("fromFILETIME(0) = error %v, want 1601-01-01T00:00:00Z", err)
	}
	want := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("fromFILETIME(0) = %s, want %s",
			got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

// TestFromFILETIME_AboveInt64RangeIsError verifies the other overflow
// direction: a FILETIME so large that int64(ft) itself would reinterpret as
// negative must also be rejected, not silently misread.
func TestFromFILETIME_AboveInt64RangeIsError(t *testing.T) {
	if _, err := fromFILETIME(math.MaxUint64); err == nil {
		t.Fatal("fromFILETIME(MaxUint64) must report an error")
	}
}

// TestEncodeUTF16LE verifies the length-prefixed null-terminated UTF-16LE encoding.
func TestEncodeUTF16LE(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:  "empty_string",
			input: "",
			// char_count=0 (2 bytes) + null terminator (2 bytes)
			expected: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:  "single_char_A",
			input: "A",
			// char_count=1, 'A'=0x0041, null terminator
			expected: []byte{0x01, 0x00, 0x41, 0x00, 0x00, 0x00},
		},
		{
			name:  "two_chars_AB",
			input: "AB",
			// char_count=2, 'A'=0x0041, 'B'=0x0042, null terminator
			expected: []byte{0x02, 0x00, 0x41, 0x00, 0x42, 0x00, 0x00, 0x00},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := encodeUTF16LE(tc.input)

			// Check exact byte equality
			if len(got) != len(tc.expected) {
				t.Fatalf("encodeUTF16LE(%q) length = %d, want %d", tc.input, len(got), len(tc.expected))
			}
			for i, b := range tc.expected {
				if got[i] != b {
					t.Errorf("encodeUTF16LE(%q)[%d] = 0x%02X, want 0x%02X", tc.input, i, got[i], b)
				}
			}

			// Structural invariants
			runeCount := len([]rune(tc.input))
			wantLen := 2 + runeCount*2 + 2
			if len(got) != wantLen {
				t.Errorf("encodeUTF16LE(%q) len = %d, want %d (2 + %d*2 + 2)", tc.input, len(got), wantLen, runeCount)
			}

			// First 2 bytes must be the character count (little-endian uint16)
			gotCount := binary.LittleEndian.Uint16(got[0:2])
			if int(gotCount) != runeCount {
				t.Errorf("encodeUTF16LE(%q) char_count = %d, want %d", tc.input, gotCount, runeCount)
			}

			// Last 2 bytes must be null terminator
			n := len(got)
			if got[n-2] != 0x00 || got[n-1] != 0x00 {
				t.Errorf("encodeUTF16LE(%q) null terminator = [0x%02X, 0x%02X], want [0x00, 0x00]",
					tc.input, got[n-2], got[n-1])
			}
		})
	}
}

// TestBuildFileHeader verifies the 4096-byte EVTX file header.
func TestBuildFileHeader(t *testing.T) {
	result := buildFileHeader(1, 42, 0)

	if len(result) != 4096 {
		t.Fatalf("buildFileHeader length = %d, want 4096", len(result))
	}

	// Signature
	wantSig := []byte("ElfFile\x00")
	for i, b := range wantSig {
		if result[i] != b {
			t.Errorf("signature[%d] = 0x%02X, want 0x%02X", i, result[i], b)
		}
	}

	// MinorVersion = 1
	if v := binary.LittleEndian.Uint16(result[36:]); v != 1 {
		t.Errorf("MinorVersion = %d, want 1", v)
	}

	// MajorVersion = 3
	if v := binary.LittleEndian.Uint16(result[38:]); v != 3 {
		t.Errorf("MajorVersion = %d, want 3", v)
	}

	// BlockSize = 4096
	if v := binary.LittleEndian.Uint16(result[40:]); v != 4096 {
		t.Errorf("BlockSize = %d, want 4096", v)
	}

	// ChunkCount = 1
	if v := binary.LittleEndian.Uint16(result[42:]); v != 1 {
		t.Errorf("ChunkCount = %d, want 1", v)
	}

	// NextRecordIdentifier = 42
	if v := binary.LittleEndian.Uint64(result[24:]); v != 42 {
		t.Errorf("NextRecordIdentifier = %d, want 42", v)
	}

	// Verify CRC32: zero out [124:128] in a copy and recompute
	crcCopy := make([]byte, 128)
	copy(crcCopy, result[0:128])
	crcCopy[124] = 0
	crcCopy[125] = 0
	crcCopy[126] = 0
	crcCopy[127] = 0
	expectedCRC := crc32.Checksum(crcCopy[0:120], crc32.IEEETable)
	gotCRC := binary.LittleEndian.Uint32(result[124:])
	if gotCRC != expectedCRC {
		t.Errorf("CRC32 = 0x%08X, want 0x%08X", gotCRC, expectedCRC)
	}
}

// TestWrapEventRecord verifies the event record layout.
func TestWrapEventRecord(t *testing.T) {
	payload := []byte{0xAA, 0xBB}
	result := wrapEventRecord(1, 12345678, payload)

	// Signature: 0x00002A2A little-endian → [0x2A, 0x2A, 0x00, 0x00]
	wantSig := []byte{0x2A, 0x2A, 0x00, 0x00}
	for i, b := range wantSig {
		if result[i] != b {
			t.Errorf("signature[%d] = 0x%02X, want 0x%02X", i, result[i], b)
		}
	}

	// Size = 24 + len(payload) + 4 = 30
	wantSize := uint32(24 + len(payload) + 4)
	if wantSize != 30 {
		t.Fatalf("test setup error: expected wantSize=30, got %d", wantSize)
	}

	// Size at offset 4
	if v := binary.LittleEndian.Uint32(result[4:]); v != wantSize {
		t.Errorf("Size at [4:8] = %d, want %d", v, wantSize)
	}

	// Size copy at end (offset 26 for a 30-byte record)
	lastSizeOffset := int(wantSize) - 4
	if v := binary.LittleEndian.Uint32(result[lastSizeOffset:]); v != wantSize {
		t.Errorf("Size copy at [%d:%d] = %d, want %d", lastSizeOffset, lastSizeOffset+4, v, wantSize)
	}

	// EventRecordID = 1
	if v := binary.LittleEndian.Uint64(result[8:]); v != 1 {
		t.Errorf("EventRecordID = %d, want 1", v)
	}

	// TimeCreated = 12345678
	if v := binary.LittleEndian.Uint64(result[16:]); v != 12345678 {
		t.Errorf("TimeCreated = %d, want 12345678", v)
	}

	// Payload at offset 24
	for i, b := range payload {
		if result[24+i] != b {
			t.Errorf("payload[%d] = 0x%02X, want 0x%02X", i, result[24+i], b)
		}
	}
}

// TestPatchChunkCRC verifies that patchChunkCRC writes the correct HeaderCRC32.
func TestPatchChunkCRC(t *testing.T) {
	chunk := make([]byte, 512)

	patchChunkCRC(chunk)

	// CRC field at [124:128] must not be all zeros
	if chunk[124] == 0 && chunk[125] == 0 && chunk[126] == 0 && chunk[127] == 0 {
		t.Error("patchChunkCRC left [124:128] all zeros")
	}

	// B3: [120:124] must carry the constant observed in every real chunk.
	if got := binary.LittleEndian.Uint32(chunk[120:]); got != evtxChunkUnknownField120 {
		t.Errorf("chunk[120:124] = %d, want %d", got, evtxChunkUnknownField120)
	}

	// Recompute independently and compare
	h := crc32.New(crc32.IEEETable)
	// Note: patchChunkCRC writes evtxChunkUnknownField120 into [120:124] and
	// zeroes only the CRC placeholder at [124:128] before computing — neither
	// sub-range is covered by the hash (h.Write below skips [120:128]
	// entirely), so zeroing the whole [120:128] region in this independent
	// copy is just a convenient way to exclude it, not a re-statement of what
	// patchChunkCRC itself zeroes.
	zeroedChunk := make([]byte, 512)
	copy(zeroedChunk, chunk)
	for i := 120; i < 128; i++ {
		zeroedChunk[i] = 0
	}
	h.Write(zeroedChunk[0:120])
	h.Write(zeroedChunk[128:512])
	expectedCRC := h.Sum32()

	gotCRC := binary.LittleEndian.Uint32(chunk[124:])
	if gotCRC != expectedCRC {
		t.Errorf("HeaderCRC32 = 0x%08X, want 0x%08X", gotCRC, expectedCRC)
	}
}
