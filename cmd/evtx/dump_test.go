package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunDump_EventShapeRoundTrips(t *testing.T) {
	path := writeFixture(t, 4)
	var out, errb bytes.Buffer
	if code := runDump([]string{"--in", path}, &out, &errb); code != 0 {
		t.Fatalf("runDump = %d, want 0; stderr: %s", code, errb.String())
	}

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4", len(lines))
	}
	// Asserted through a generic map, not evtx.Event: the library deliberately
	// has no UnmarshalJSON on Value, since a lossy one would discard the
	// declared type MarshalJSON exists to render (a SID, a FILETIME and a
	// HexInt64 would all come back as undifferentiated strings). This proves
	// the same three facts the event-typed assertion would have without that
	// API.
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		sys, ok := obj["system"].(map[string]any)
		if !ok {
			t.Fatalf("line %d has no system object", i)
		}
		provider, ok := sys["provider"].(map[string]any)
		if !ok {
			t.Fatalf("line %d has no system.provider object", i)
		}
		if provider["name"] != "Microsoft-Windows-Security-Auditing" {
			t.Errorf("line %d: system.provider.name = %v, want the value passed to WriteRecord",
				i, provider["name"])
		}
		if sys["computer"] != "TESTHOST" {
			t.Errorf("line %d: system.computer = %v, want TESTHOST", i, sys["computer"])
		}
	}
}

func TestRunDump_FlatShapeIsOneLevel(t *testing.T) {
	path := writeFixture(t, 2)
	var out, errb bytes.Buffer
	if code := runDump([]string{"--in", path, "--shape", "flat"}, &out, &errb); code != 0 {
		t.Fatalf("runDump = %d, want 0; stderr: %s", code, errb.String())
	}
	for i, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if obj["provider"] != "Microsoft-Windows-Security-Auditing" {
			t.Errorf("line %d: provider = %v, want the flat scalar", i, obj["provider"])
		}
		if _, nested := obj["system"]; nested {
			t.Errorf("line %d: flat output still carries a nested system object", i)
		}
		if _, ok := obj["ObjectName"]; !ok {
			t.Errorf("line %d: ObjectName was not lifted to the root", i)
		}
	}
}

func TestRunDump_WritesToOutFile(t *testing.T) {
	path := writeFixture(t, 2)
	outPath := filepath.Join(t.TempDir(), "out.ndjson")
	var out, errb bytes.Buffer
	if code := runDump([]string{"--in", path, "--out", outPath}, &out, &errb); code != 0 {
		t.Fatalf("runDump = %d, want 0; stderr: %s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty when --out is given, got %q", out.String())
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Errorf("%s has %d lines, want 2", outPath, n)
	}
}

// writeCorruptFixture writes a normal fixture via writeFixture, then flips
// one byte inside the first record's BinXML payload — the template-instance
// token, five bytes past the fragment header, itself four bytes past the
// 24-byte record header — to a value no token table recognises. Record
// framing (signature, size, record ID, timestamp, trailing size copy) is
// untouched: the reader parses that independently of BinXML, so a corrupt
// payload still lets it advance to the next record, which is what keeps
// runDump's loop from spinning rather than reporting one skipped record.
//
// The two on-disk offsets below aren't guesses: writeFixture always produces
// a single-chunk file (a 4096-byte file header, then one chunk whose 512-byte
// chunk header precedes its first record — reader.go's loadChunk and
// nextRecord), so the first record's signature always starts at exactly
// 4096+512. This is asserted below rather than assumed, so a change to
// either constant fails loudly here instead of silently corrupting the wrong
// byte.
func writeCorruptFixture(t *testing.T, records int) string {
	t.Helper()
	good := writeFixture(t, records)
	b, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}

	const (
		fileHeaderSize  = 4096
		chunkHeaderSize = 512
		recordHeaderLen = 24 // signature(4) + size(4) + recordID(8) + timestamp(8)
		fragHeaderLen   = 4  // BinXML fragment header: token, major, minor, flags
	)
	recStart := fileHeaderSize + chunkHeaderSize
	if len(b) < recStart+recordHeaderLen+fragHeaderLen+1 {
		t.Fatalf("fixture is only %d bytes, too small to hold a record at offset %d", len(b), recStart)
	}
	if sig := b[recStart : recStart+4]; sig[0] != 0x2a || sig[1] != 0x2a || sig[2] != 0 || sig[3] != 0 {
		t.Fatalf("no record signature at offset %d, got % x — writeFixture's on-disk layout changed", recStart, sig)
	}
	tokenOff := recStart + recordHeaderLen + fragHeaderLen
	b[tokenOff] = 0xff // not a template-instance token, nor anything else recognised

	bad := filepath.Join(t.TempDir(), "corrupt.evtx")
	if err := os.WriteFile(bad, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return bad
}

func TestRunDump_DecodeFailureExitsTwo(t *testing.T) {
	path := writeCorruptFixture(t, 3)
	var out, errb bytes.Buffer
	code := runDump([]string{"--in", path}, &out, &errb)
	if code != 2 {
		t.Fatalf("runDump = %d, want 2 (a corrupted fixture that fails to decode); stderr: %s", code, errb.String())
	}

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d surviving records on stdout, want 2 (3 written, 1 corrupted)", len(lines))
	}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("surviving line %d is not valid JSON: %v", i, err)
		}
	}

	errOut := errb.String()
	if !strings.Contains(errOut, "chunk 0, record") {
		t.Errorf("stderr = %q, want a per-record failure line naming the record", errOut)
	}
	if !strings.Contains(errOut, "1 of 3 records failed to decode") {
		t.Errorf("stderr = %q, want the summary line '1 of 3 records failed to decode'", errOut)
	}
}

func TestRunDump_AllowErrorsExitsZero(t *testing.T) {
	path := writeCorruptFixture(t, 3)
	var out, errb bytes.Buffer
	code := runDump([]string{"--in", path, "--allow-errors"}, &out, &errb)
	if code != 0 {
		t.Fatalf("runDump --allow-errors = %d, want 0; stderr: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "1 of 3 records failed to decode") {
		t.Errorf("stderr = %q, want the failure summary even with --allow-errors", errb.String())
	}
}

// writeFramingCorruptFixture flips the first record's *signature* rather than
// a payload byte. writeCorruptFixture above deliberately leaves framing
// intact; this one breaks it, which is the case that used to make runDump spin
// forever — nextRecord reported the error without advancing, so the loop
// re-read the same bytes indefinitely.
func writeFramingCorruptFixture(t *testing.T, records int) string {
	t.Helper()
	good := writeFixture(t, records)
	b, err := os.ReadFile(good) // #nosec G304 — a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	const (
		fileHeaderSize  = 4096
		chunkHeaderSize = 512
	)
	recStart := fileHeaderSize + chunkHeaderSize
	if len(b) < recStart+24 {
		t.Fatalf("fixture is only %d bytes, too small to hold a record at offset %d", len(b), recStart)
	}
	if sig := b[recStart : recStart+4]; sig[0] != 0x2a || sig[1] != 0x2a || sig[2] != 0 || sig[3] != 0 {
		t.Fatalf("no record signature at offset %d, got % x — writeFixture's on-disk layout changed", recStart, sig)
	}
	b[recStart] ^= 0xff

	bad := filepath.Join(t.TempDir(), "framing.evtx")
	if err := os.WriteFile(bad, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return bad
}

// TestRunDump_FramingErrorTerminates bounds the run rather than trusting it:
// the bug this guards against produced megabytes of identical stderr lines
// without ever returning, so an unbounded assertion would hang CI instead of
// failing it. errb is capped at syncBufferBudget: if the reader ever regresses
// to spinning on the same framing error again, the buffer stops allocating
// almost immediately instead of growing to the multi-gigabyte size (3.2 GB,
// observed) that made the earlier, unbounded version of this test expensive
// to fail.
func TestRunDump_FramingErrorTerminates(t *testing.T) {
	path := writeFramingCorruptFixture(t, 3)

	// Both buffers are mutex-guarded: runDump writes them from another
	// goroutine, and the timeout branch reads one while it is still running.
	done := make(chan int, 1)
	out, errb := &syncBuffer{}, &syncBuffer{max: syncBufferBudget}
	go func() { done <- runDump([]string{"--in", path}, out, errb) }()

	select {
	case code := <-done:
		if code == 0 {
			t.Fatalf("runDump = 0 on a framing-corrupt file, want non-zero; stderr: %s", errb.String())
		}
		if n := strings.Count(errb.String(), "invalid record signature"); n != 1 {
			t.Errorf("the framing error was reported %d times, want exactly 1; stderr: %q", n, errb.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("runDump did not terminate on a framing-corrupt file (stderr grew to %d bytes, capped at %d)", errb.Len(), syncBufferBudget)
	}
}

// syncBufferBudget is far more than the handful of lines the passing case
// produces, but small enough that a spinning runDump cannot exhaust memory
// before the test's own timeout fires.
const syncBufferBudget = 256 * 1024

// errSyncBufferFull is returned by syncBuffer.Write once its budget is spent.
var errSyncBufferFull = errors.New("syncBuffer: write budget exhausted")

// syncBuffer is a bytes.Buffer usable from two goroutines at once. When max is
// non-zero, writes that would grow the buffer past max are rejected instead
// of allocated, bounding memory for callers (such as a spinning runDump) that
// never stop writing.
type syncBuffer struct {
	mu  sync.Mutex
	b   bytes.Buffer
	max int
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.max > 0 && s.b.Len() >= s.max {
		return 0, errSyncBufferFull
	}
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

func TestRunDump_UnknownShapeExitsOne(t *testing.T) {
	path := writeFixture(t, 1)
	var out, errb bytes.Buffer
	if code := runDump([]string{"--in", path, "--shape", "sideways"}, &out, &errb); code != 1 {
		t.Errorf("runDump with an unknown shape = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "shape") {
		t.Errorf("stderr = %q, want it to name the bad flag", errb.String())
	}
}

// TestRunDump_BadInputLeavesOutFileIntact pins the ordering: os.Create
// truncates, so creating the output before opening the input turned a typo in
// --in into the loss of a previous dump.
func TestRunDump_BadInputLeavesOutFileIntact(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "previous.ndjson")
	const existing = "{\"record_id\":1}\n"
	if err := os.WriteFile(outPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	if code := runDump([]string{"--in", filepath.Join(dir, "absent.evtx"), "--out", outPath}, &out, &errb); code != 1 {
		t.Errorf("runDump on a missing input = %d, want 1", code)
	}
	b, err := os.ReadFile(outPath) // #nosec G304 — a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != existing {
		t.Errorf("--out file = %q, want it untouched (%q) when the input could not be opened", b, existing)
	}
}

func TestRunDump_MissingFileExitsOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runDump([]string{"--in", filepath.Join(t.TempDir(), "absent.evtx")}, &out, &errb); code != 1 {
		t.Errorf("runDump on a missing file = %d, want 1", code)
	}
}

// TestRun_DumpIsDispatched covers the wiring rather than the subcommand: run
// must reach runDump, and usage must name it. Task 3 deliberately left both
// out, since a usage line for a subcommand the switch cannot serve is worse
// than no line at all.
func TestRun_DumpIsDispatched(t *testing.T) {
	path := writeFixture(t, 1)
	var out, errb bytes.Buffer
	if code := run([]string{"dump", "--in", path}, &out, &errb); code != 0 {
		t.Fatalf("run(dump) = %d, want 0; stderr: %s", code, errb.String())
	}
	if out.Len() == 0 {
		t.Error("run(dump) produced no output")
	}

	var usageOut, usageErr bytes.Buffer
	if code := run([]string{"help"}, &usageOut, &usageErr); code != 0 {
		t.Fatalf("run(help) = %d, want 0", code)
	}
	if !strings.Contains(usageOut.String(), "dump") {
		t.Errorf("usage does not mention dump:\n%s", usageOut.String())
	}
}

// TestRunDump_OutIsInputRejected: os.Create truncates, so --out naming the
// input destroyed the file the dump was still reading. The two spellings are
// compared by identity, so a relative path and an absolute one for the same
// file are both caught.
func TestRunDump_OutIsInputRejected(t *testing.T) {
	path := writeFixture(t, 3)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	rel, err := filepath.Rel(filepath.Dir(path), path)
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()

	for _, out := range []string{path, rel, "./" + rel} {
		var stdout, stderr bytes.Buffer
		if code := runDump([]string{"--in", path, "--out", out}, &stdout, &stderr); code != 1 {
			t.Errorf("runDump --out %q = %d, want 1", out, code)
		}
		if !strings.Contains(stderr.String(), "is the input file") {
			t.Errorf("--out %q: stderr = %q, want it to name the problem", out, stderr.String())
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("--out %q: the input file was modified", out)
		}
	}
}
