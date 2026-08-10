// reader_test.go — integration tests for the go-evtx Reader API.
//
// No build tag: tests run on all platforms.
// White-box: package evtx.
// stdlib only: no testify, no external libraries.
package evtx

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestFile is a helper that writes a single event record and returns the file path.
func writeTestFile(t *testing.T, fields map[string]string, eventID int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.evtx")
	w, err := New(path, RotationConfig{})
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

// TestReadEvent_AllFields writes a record with all fields and reads it back
// with the generic decoder, verifying every field is decoded correctly.
func TestReadEvent_AllFields(t *testing.T) {
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
	defer func() { _ = r.Close() }()

	ev, err := r.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}

	if ev.RecordID != 1 {
		t.Errorf("RecordID = %d, want 1", ev.RecordID)
	}
	if ev.System.EventID != 4663 {
		t.Errorf("EventID = %d, want 4663", ev.System.EventID)
	}
	if ev.System.Provider.Name != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("Provider.Name = %q, want %q", ev.System.Provider.Name, "Microsoft-Windows-Security-Auditing")
	}
	if ev.System.Computer != "myhost.example.com" {
		t.Errorf("Computer = %q, want %q", ev.System.Computer, "myhost.example.com")
	}
	if !ev.System.TimeCreated.Equal(ts) {
		t.Errorf("TimeCreated = %v, want %v", ev.System.TimeCreated, ts)
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
	got := make(map[string]string, len(ev.EventData))
	for _, d := range ev.EventData {
		got[d.Name] = d.Value.String()
	}
	for k, want := range wantFields {
		if got[k] != want {
			t.Errorf("EventData[%q] = %q, want %q", k, got[k], want)
		}
	}
}

// The writer's own output must survive the generic decoder. This is the
// round-trip that the old decoder made meaningless: it and the writer shared
// the same wrong assumptions, so a green result proved only their mutual
// agreement.
func TestReadEvent_RoundTripsWriterOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rt.evtx")

	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4624, map[string]string{
		"ProviderName": "TestProvider",
		"ObjectName":   "C:\\secret.txt",
	}); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	ev, err := r.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if ev.System.Provider.Name != "TestProvider" {
		t.Errorf("Provider.Name = %q, want %q", ev.System.Provider.Name, "TestProvider")
	}
	if ev.System.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", ev.System.EventID)
	}
	var found bool
	for _, d := range ev.EventData {
		if d.Name == "ObjectName" && d.Value.String() == "C:\\secret.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("ObjectName not found in EventData: %+v", ev.EventData)
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
	defer func() { _ = r.Close() }()

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
	_ = r.Close()
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}

	// Write raw payload to a new file.
	dir := t.TempDir()
	dst := filepath.Join(dir, "copy.evtx")
	w, err := New(dst, RotationConfig{})
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
	defer func() { _ = r.Close() }()

	// Read the single record.
	if _, err := r.ReadEvent(); err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	// Next read must return ErrNoMoreRecords.
	_, err = r.ReadEvent()
	if !errors.Is(err, ErrNoMoreRecords) {
		t.Errorf("second ReadEvent error = %v, want ErrNoMoreRecords", err)
	}
}

// TestReadEvent_MultipleRecords verifies sequential reading of multiple records.
func TestReadEvent_MultipleRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.evtx")
	w, err := New(path, RotationConfig{})
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
	defer func() { _ = r.Close() }()

	var got int
	for {
		ev, err := r.ReadEvent()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			t.Fatalf("ReadEvent %d: %v", got, err)
		}
		got++
		if ev.System.EventID != 4663 {
			t.Errorf("record %d EventID = %d, want 4663", got, ev.System.EventID)
		}
		if ev.RecordID != uint64(got) {
			t.Errorf("record %d RecordID = %d, want %d", got, ev.RecordID, got)
		}
	}
	if got != count {
		t.Errorf("read %d records, want %d", got, count)
	}
}

// TestReadEvent_ZeroTimestampDecodes covers the record shape that made
// ReadEvent fail on 178 of the 285 files in the local corpus: a record-header
// FILETIME of 0, which is 1601-01-01T00:00:00Z and which Windows writes for an
// unset timestamp. Written through the public API rather than by hand-
// assembling bytes, so what is read back is whatever the real encode path
// produces for this timestamp rather than what the test author believed it
// would produce. (Not a CRC argument: the reader verifies no checksum, so
// patched bytes would be accepted just as readily.)
func TestReadEvent_ZeroTimestampDecodes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zero-ts.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "TESTHOST",
		"TimeCreated":  "1601-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	ev, err := r.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	want := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	if !ev.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %s, want %s",
			ev.Timestamp.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

// writeSignatureCorruptFile writes a multi-record fixture and then flips the
// first record's *signature* — the framing field, not the BinXML payload that
// cmd/evtx's writeCorruptFixture deliberately leaves the framing intact for.
// A framing error tells the reader nothing about where the next record starts,
// which is what makes the abandon-the-chunk behaviour necessary.
//
// The on-disk offset is asserted rather than assumed: New always produces a
// single-chunk file here (a 4096-byte file header, then one chunk whose
// 512-byte header precedes its first record), so the first signature sits at
// exactly 4096+512.
func writeSignatureCorruptFile(t *testing.T, records int) string {
	t.Helper()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.evtx")
	w, err := New(good, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < records; i++ {
		if err := w.WriteRecord(4663, map[string]string{
			"ProviderName": "Microsoft-Windows-Security-Auditing",
			"Computer":     "TESTHOST",
		}); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	b, err := os.ReadFile(good) // #nosec G304 — a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	recStart := int(evtxFileHeaderSize) + int(evtxChunkHeaderSize)
	if len(b) < recStart+24 {
		t.Fatalf("fixture is only %d bytes, too small to hold a record at offset %d", len(b), recStart)
	}
	if got := binary.LittleEndian.Uint32(b[recStart : recStart+4]); got != evtxRecordSignature {
		t.Fatalf("no record signature at offset %d, got 0x%08x — the on-disk layout changed", recStart, got)
	}
	b[recStart] ^= 0xff // no longer the record signature

	bad := filepath.Join(dir, "corrupt.evtx")
	if err := os.WriteFile(bad, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return bad
}

// TestReadEvent_FramingErrorTerminates is the regression guard for the spin:
// nextRecord used to return a framing error without advancing recOff, so every
// subsequent call re-read the same bytes and returned the same error forever.
// The iteration guard is deliberate — if the bug returns, this test fails
// instead of hanging CI.
func TestReadEvent_FramingErrorTerminates(t *testing.T) {
	path := writeSignatureCorruptFile(t, 3)

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	const maxIterations = 100 // three records were written; anything near this is a spin
	var framingErrs, decoded, iterations int
	for iterations = 0; iterations < maxIterations; iterations++ {
		_, err := r.ReadEvent()
		if errors.Is(err, ErrNoMoreRecords) {
			break
		}
		if err != nil {
			framingErrs++
			if !strings.Contains(err.Error(), "invalid record signature") {
				t.Fatalf("unexpected error: %v", err)
			}
			continue
		}
		decoded++
	}
	if iterations >= maxIterations {
		t.Fatalf("ReadEvent did not terminate within %d calls — the framing error is not advancing the reader", maxIterations)
	}
	if framingErrs != 1 {
		t.Errorf("framing errors = %d, want exactly 1 (reported once, then the chunk is abandoned)", framingErrs)
	}
	// The chunk is abandoned, so the records after the corrupt one are not
	// recovered: framing is what tells the reader where they start.
	if decoded != 0 {
		t.Errorf("decoded = %d, want 0 — the rest of the chunk is abandoned, not resynchronised", decoded)
	}
}

// TestReadRaw_FramingErrorTerminates pins the same guarantee on the other
// record-level entry point, since both share nextRecord.
func TestReadRaw_FramingErrorTerminates(t *testing.T) {
	path := writeSignatureCorruptFile(t, 3)

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	const maxIterations = 100
	var i int
	for i = 0; i < maxIterations; i++ {
		if _, err := r.ReadRaw(); errors.Is(err, ErrNoMoreRecords) {
			break
		}
	}
	if i >= maxIterations {
		t.Fatalf("ReadRaw did not terminate within %d calls", maxIterations)
	}
}

// TestReader_FileInfo pins the container facts a consumer cannot otherwise
// reach: the format version in particular, which Open reads and used to
// discard. go-evtx writes 3.1; Windows Server 2025 writes 3.2, and telling
// them apart is the first thing anyone asks of an unfamiliar file.
func TestReader_FileInfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "info.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := w.WriteRecord(4663, map[string]string{
			"ProviderName": "Microsoft-Windows-Security-Auditing",
			"Computer":     "TESTHOST",
		}); err != nil {
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
	defer func() { _ = r.Close() }()

	fi := r.FileInfo()
	if fi.Major != 3 || fi.Minor != 1 {
		t.Errorf("format = %d.%d, want 3.1", fi.Major, fi.Minor)
	}
	if fi.Chunks != 1 {
		t.Errorf("Chunks = %d, want 1", fi.Chunks)
	}
	if fi.Dirty {
		t.Error("Dirty = true on a cleanly closed file")
	}
	if fi.Full {
		t.Error("Full = true on a file that never reached a size limit")
	}
}
