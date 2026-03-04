// evtx_test.go — integration tests for the go-evtx Writer API.
//
// No build tag: tests run on all platforms.
// White-box: package evtx (accesses unexported helpers for WriteRaw tests).
// stdlib only: no testify, no external libraries.
package evtx

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestWriter_New_EmptyPath verifies that New("") returns a non-nil error.
func TestWriter_New_EmptyPath(t *testing.T) {
	_, err := New("", RotationConfig{})
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

// TestWriter_New_ParentDirCreated verifies that New creates parent directories.
func TestWriter_New_ParentDirCreated(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "nested", "deep", "test.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New with nested path: %v", err)
	}

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
		"TimeCreated":  time.Now().Format(time.RFC3339Nano),
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("output file not found at nested path: %v", err)
	}
}

// TestWriter_WriteRecord_ProducesValidFile verifies the file magic and CRC32.
func TestWriter_WriteRecord_ProducesValidFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "test.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fields := map[string]string{
		"ProviderName":      "Microsoft-Windows-Security-Auditing",
		"Computer":          "testhost",
		"TimeCreated":       time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		"SubjectUserSid":    "S-1-5-21-123",
		"SubjectUserName":   "testuser",
		"SubjectDomainName": "DOMAIN",
		"ObjectName":        "/nas/share/file.txt",
		"AccessMask":        "0x2",
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) < 128 {
		t.Fatalf("file too short: %d bytes", len(data))
	}

	// Magic at [0:8]
	if string(data[0:8]) != "ElfFile\x00" {
		t.Errorf("file magic = %q, want %q", data[0:8], "ElfFile\x00")
	}

	// CRC32 at [124:128]: crc32(buf[0:120])
	stored := binary.LittleEndian.Uint32(data[124:128])
	want := crc32.Checksum(data[0:120], crc32.IEEETable)
	if stored != want {
		t.Errorf("file header CRC32 = 0x%08x, want 0x%08x", stored, want)
	}
}

// TestWriter_WriteRecord_ChunkMagic verifies chunk magic at evtxFileHeaderSize.
func TestWriter_WriteRecord_ChunkMagic(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "chunk.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	minSize := evtxFileHeaderSize + evtxChunkHeaderSize
	if len(data) < minSize {
		t.Fatalf("file too short: %d < %d", len(data), minSize)
	}

	chunkMagic := string(data[evtxFileHeaderSize : evtxFileHeaderSize+8])
	if chunkMagic != "ElfChnk\x00" {
		t.Errorf("chunk magic = %q, want %q", chunkMagic, "ElfChnk\x00")
	}
}

// TestWriter_WriteRaw_ProducesValidFile verifies WriteRaw + Close produces valid file.
func TestWriter_WriteRaw_ProducesValidFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "raw.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Use buildBinXML directly to produce a raw BinXML payload (white-box).
	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "testhost",
	}
	// For WriteRaw, the BinXML chunk offset must be at least evtxRecordsStart + evtxRecordHeaderSize.
	rawPayload := buildBinXML(4663, fields, evtxRecordsStart+evtxRecordHeaderSize)

	if err := w.WriteRaw(rawPayload); err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) < 128 {
		t.Fatalf("file too short: %d bytes", len(data))
	}

	// Magic at [0:8]
	if string(data[0:8]) != "ElfFile\x00" {
		t.Errorf("file magic = %q, want %q", data[0:8], "ElfFile\x00")
	}

	// CRC32 at [124:128]
	stored := binary.LittleEndian.Uint32(data[124:128])
	want := crc32.Checksum(data[0:120], crc32.IEEETable)
	if stored != want {
		t.Errorf("file header CRC32 = 0x%08x, want 0x%08x", stored, want)
	}
}

// TestWriter_EmptyClose verifies that Close with no writes returns nil and does not create a file.
func TestWriter_EmptyClose(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "empty.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close on empty writer: %v", err)
	}

	if _, err := os.Stat(outPath); err == nil {
		t.Error("expected no file on empty close, but file was created")
	}
}

// TestWriter_Concurrent verifies concurrent WriteRecord calls are safe.
func TestWriter_Concurrent(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "concurrent.evtx")

	w, err := New(outPath, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			fields := map[string]string{
				"ProviderName": "Microsoft-Windows-Security-Auditing",
				"Computer":     "testhost",
				"ObjectName":   "/nas/file.txt",
			}
			if err := w.WriteRecord(4663, fields); err != nil {
				t.Errorf("goroutine %d WriteRecord: %v", n, err)
			}
		}(i)
	}

	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("output file missing after concurrent writes: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output file is empty after concurrent writes")
	}
}
