package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	evtx "github.com/fjacquet/go-evtx"
)

// evtx file geometry, repeated here rather than exported from the library:
// these tests damage a file at a byte offset, which is a property of the
// format, not of the library's API.
const (
	fileHeaderSize = 4096
	chunkSize      = 65536
)

// writeMultiChunkFixture writes a file with at least two chunks.
func writeMultiChunkFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "multi.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 600; i++ {
		if err := w.WriteRecord(4663, map[string]string{
			"ProviderName": "Microsoft-Windows-Security-Auditing",
			"Computer":     "TESTHOST",
			"ObjectName":   "C:\\logs\\file.txt",
		}); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r, err := evtx.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	chunks := r.FileInfo().Chunks
	_ = r.Close()
	if chunks < 2 {
		t.Fatalf("fixture has %d chunks, want at least 2", chunks)
	}
	return path
}

// truncatedFixture returns a file cut off part-way through its second chunk.
func truncatedFixture(t *testing.T) string {
	t.Helper()
	path := writeMultiChunkFixture(t)
	if err := os.Truncate(path, fileHeaderSize+chunkSize+1000); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	return path
}

// badMagicFixture returns a file whose second chunk does not carry a chunk
// signature.
func badMagicFixture(t *testing.T) string {
	t.Helper()
	path := writeMultiChunkFixture(t)
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.WriteAt([]byte("NotAChnk"), fileHeaderSize+chunkSize); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// TestRunDump_UnreadableChunkExitsOne pins the contract that a file the dump
// never reached the end of is an unreadable input (1), not a run in which some
// records were skipped (2). Both commands used to see a clean end of stream
// here and exit 0.
func TestRunDump_UnreadableChunkExitsOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture func(*testing.T) string
	}{
		{"truncated mid-chunk", truncatedFixture},
		{"second chunk has bad magic", badMagicFixture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.fixture(t)
			var out, errb bytes.Buffer
			if code := runDump([]string{"--in", path}, &out, &errb); code != 1 {
				t.Errorf("runDump = %d, want 1; stderr: %s", code, errb.String())
			}
			if !strings.Contains(errb.String(), "not read to the end") {
				t.Errorf("stderr = %q, want it to say the file was not finished", errb.String())
			}
			if out.Len() == 0 {
				t.Error("stdout is empty; the records before the failure should still have been written")
			}
		})
	}
}

// TestRunDump_UnreadableChunkNotSuppressedByAllowErrors: --allow-errors means
// "some records were skipped is acceptable", never "the file was not finished
// is acceptable".
func TestRunDump_UnreadableChunkNotSuppressedByAllowErrors(t *testing.T) {
	path := badMagicFixture(t)
	var out, errb bytes.Buffer
	if code := runDump([]string{"--in", path, "--allow-errors"}, &out, &errb); code != 1 {
		t.Errorf("runDump --allow-errors = %d, want 1; stderr: %s", code, errb.String())
	}
}

// TestRunInfo_UnreadableChunkExitsOne: info must not print "0 failures" for a
// file it did not finish reading.
func TestRunInfo_UnreadableChunkExitsOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture func(*testing.T) string
	}{
		{"truncated mid-chunk", truncatedFixture},
		{"second chunk has bad magic", badMagicFixture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.fixture(t)
			var out, errb bytes.Buffer
			if code := runInfo([]string{"--in", path}, &out, &errb); code != 1 {
				t.Errorf("runInfo = %d, want 1; stderr: %s", code, errb.String())
			}
			if !strings.Contains(out.String(), "read       incomplete") {
				t.Errorf("stdout = %q, want it to report the pass as incomplete", out.String())
			}
			if !strings.Contains(errb.String(), "chunk unreadable") {
				t.Errorf("stderr = %q, want it to name the failure", errb.String())
			}
		})
	}
}
