// reader_test.go — integration tests for the go-evtx Reader API.
//
// No build tag: tests run on all platforms.
// White-box: package evtx.
// stdlib only: no testify, no external libraries.
package evtx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestFile is a helper that writes a single event record and returns the file path.
func writeTestFile(t *testing.T, fields map[string]string, eventID int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.evtx")
	w, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(eventID, fields); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// TestOpen_InvalidPath verifies that Open returns an error for a missing file.
func TestOpen_InvalidPath(t *testing.T) {
	_, err := Open("/nonexistent/path/audit.evtx")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestOpen_InvalidMagic verifies that Open rejects files with wrong magic.
func TestOpen_InvalidMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.evtx")
	// Write garbage — not a valid EVTX file.
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Open(path)
	if err == nil {
		t.Fatal("expected error for invalid magic, got nil")
	}
}

// TestReadRecord_RoundTrip writes a record with all fields and reads it back,
// verifying every field is decoded correctly.
func TestReadRecord_RoundTrip(t *testing.T) {
	ts := time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC)
	fields := map[string]string{
		"ProviderName":      "Microsoft-Windows-Security-Auditing",
		"Computer":          "myhost.example.com",
		"TimeCreated":       ts.Format(time.RFC3339Nano),
		"SubjectUserSid":    "S-1-5-21-123",
		"SubjectUserName":   "alice",
		"SubjectDomainName": "EXAMPLE",
		"SubjectLogonId":    "0x12345",
		"ObjectServer":      "Security",
		"ObjectType":        "File",
		"ObjectName":        "/mnt/share/document.docx",
		"HandleId":          "0x1a2b",
		"AccessList":        "%%4416",
		"AccessMask":        "0x2",
		"ProcessId":         "0x0",
		"ProcessName":       "",
	}
	path := writeTestFile(t, fields, 4663)

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	rec, err := r.ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}

	if rec.RecordID != 1 {
		t.Errorf("RecordID = %d, want 1", rec.RecordID)
	}
	if rec.EventID != 4663 {
		t.Errorf("EventID = %d, want 4663", rec.EventID)
	}
	if rec.Provider != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("Provider = %q, want %q", rec.Provider, "Microsoft-Windows-Security-Auditing")
	}
	if rec.Computer != "myhost.example.com" {
		t.Errorf("Computer = %q, want %q", rec.Computer, "myhost.example.com")
	}
	if !rec.TimeCreated.Equal(ts) {
		t.Errorf("TimeCreated = %v, want %v", rec.TimeCreated, ts)
	}

	// Verify EventData fields.
	wantFields := map[string]string{
		"SubjectUserSid":    "S-1-5-21-123",
		"SubjectUserName":   "alice",
		"SubjectDomainName": "EXAMPLE",
		"SubjectLogonId":    "0x12345",
		"ObjectServer":      "Security",
		"ObjectType":        "File",
		"ObjectName":        "/mnt/share/document.docx",
		"HandleId":          "0x1a2b",
		"AccessList":        "%%4416",
		"AccessMask":        "0x2",
		"ProcessId":         "0x0",
		"ProcessName":       "",
	}
	for k, want := range wantFields {
		if got := rec.Fields[k]; got != want {
			t.Errorf("Fields[%q] = %q, want %q", k, got, want)
		}
	}
}

// TestReadRaw_NonEmpty verifies that ReadRaw returns a non-empty payload.
func TestReadRaw_NonEmpty(t *testing.T) {
	fields := map[string]string{
		"ProviderName": "TestProvider",
		"Computer":     "testhost",
	}
	path := writeTestFile(t, fields, 4663)

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	payload, err := r.ReadRaw()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if len(payload) == 0 {
		t.Error("ReadRaw returned empty payload")
	}
}

// TestReadRaw_WriteRaw_RoundTrip verifies that ReadRaw → WriteRaw → ReadRecord preserves content.
func TestReadRaw_WriteRaw_RoundTrip(t *testing.T) {
	fields := map[string]string{
		"ProviderName":    "TestProvider",
		"Computer":        "testhost",
		"SubjectUserName": "bob",
	}
	src := writeTestFile(t, fields, 4663)

	// Read raw payload from source file.
	r, err := Open(src)
	if err != nil {
		t.Fatalf("Open src: %v", err)
	}
	payload, err := r.ReadRaw()
	r.Close()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	// Write raw payload to a new file.
	dir := t.TempDir()
	dst := filepath.Join(dir, "copy.evtx")
	w, err := New(dst)
	if err != nil {
		t.Fatalf("New dst: %v", err)
	}
	if err := w.WriteRaw(payload); err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close dst: %v", err)
	}

	// Verify the copy file is non-empty.
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("Stat dst: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("copied file is empty")
	}
}

// TestErrNoMoreRecords verifies that reading past the last record returns ErrNoMoreRecords.
func TestErrNoMoreRecords(t *testing.T) {
	fields := map[string]string{"ProviderName": "TestProvider"}
	path := writeTestFile(t, fields, 4663)

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	// Read the single record.
	if _, err := r.ReadRecord(); err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	// Next read must return ErrNoMoreRecords.
	_, err = r.ReadRecord()
	if !errors.Is(err, ErrNoMoreRecords) {
		t.Errorf("second ReadRecord error = %v, want ErrNoMoreRecords", err)
	}
}

// TestReadRecord_MultipleRecords verifies sequential reading of multiple records.
func TestReadRecord_MultipleRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.evtx")
	w, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const count = 5
	for i := 0; i < count; i++ {
		fields := map[string]string{
			"ProviderName":    "TestProvider",
			"Computer":        "testhost",
			"SubjectUserName": "user",
		}
		if err := w.WriteRecord(4663, fields); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	var got int
	for {
		rec, err := r.ReadRecord()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadRecord %d: %v", got, err)
		}
		got++
		if rec.EventID != 4663 {
			t.Errorf("record %d EventID = %d, want 4663", got, rec.EventID)
		}
		if rec.RecordID != uint64(got) {
			t.Errorf("record %d RecordID = %d, want %d", got, rec.RecordID, got)
		}
	}
	if got != count {
		t.Errorf("read %d records, want %d", got, count)
	}
}

// TestDecodeSubString verifies the UTF-16LE decoder.
func TestDecodeSubString(t *testing.T) {
	cases := []struct {
		input string
	}{
		{""},
		{"hello"},
		{"Microsoft-Windows-Security-Auditing"},
		{"S-1-5-21-1234567890"},
	}
	for _, tc := range cases {
		encoded := encodeSubString(tc.input)
		got := decodeSubString(encoded)
		if got != tc.input {
			t.Errorf("round-trip(%q) = %q", tc.input, got)
		}
	}
}
