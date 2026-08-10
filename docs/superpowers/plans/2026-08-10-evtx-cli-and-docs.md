# `evtx` CLI and documentation set — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an `evtx` binary with `dump` and `info`, fix the FILETIME conversion that rejects 1601, and replace a documentation set that has been wrong since March.

**Architecture:** `cmd/evtx/` joins the existing module as `package main`, using only the library's exported API plus the standard library's `flag`. Two library changes support it: `fromFILETIME`/`toFILETIME` gain the full FILETIME range, and `Reader` gains a `FileInfo` accessor for the file-header facts it already reads and discards. The flat JSON projection stays in the CLI so it never becomes a library contract.

**Tech Stack:** Go 1.22+, standard library only. GoReleaser v2 for release artefacts.

Spec: `docs/superpowers/specs/2026-08-10-evtx-cli-and-docs-design.md`.

## Global Constraints

- **Zero external dependencies.** `go.mod` must keep an empty require block. No CLI framework, no colour library. ADR-001.
- **Every test run uses the race detector:** `go test -race ./... -count=1`.
- **`gofmt`, `go vet ./...` and `golangci-lint run` must be clean before every commit.**
- **`GOOS=windows go build ./...` must succeed** — the Windows path is not built on darwin/linux by default.
- **Never add a `.evtx` file to the repository** beyond the two already tracked. Corpus tests skip unless `EVTX_CORPUS` is set.
- **Error strings start with `go_evtx: `** in the library; CLI messages start with `evtx <subcommand>: `.
- **Unexported helpers requiring a held mutex end in `Locked`** and carry a `// CALLER MUST HOLD <mutex>.` comment.
- **Commit messages** use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) and end with:
  ```
  Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
  ```
- **Branch:** all work lands on `feat/evtx-cli`, which already exists and carries the spec commit.

---

### Task 1: FILETIME conversion over the full format range

**Files:**
- Modify: `binformat.go:28-70` (the `filetimeEpochDelta` const block, `toFILETIME`, `fromFILETIME`)
- Test: `binformat_test.go:55-86` (rewrite `TestFromFILETIME_OutOfRangeIsError`, extend the round trip)
- Test: `reader_test.go` (append one reader-level test)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `fromFILETIME(ft uint64) (time.Time, error)` no longer errors for any `ft <= math.MaxInt64`; `toFILETIME(t time.Time) uint64` is exact from year 1601. Later tasks rely on `Reader.ReadEvent` no longer failing on zero record timestamps.

**Background the implementer needs.** A Windows FILETIME counts 100-nanosecond ticks since 1601-01-01. `filetimeEpochDelta = 116444736000000000` is the tick count between 1601 and the Unix epoch. The current code converts by building a nanosecond offset (`time.Unix(0, delta*100)`), and an `int64` of nanoseconds only spans roughly 1678–2262 — so year 1601 overflows and is reported as an error. Windows writes FILETIME 0 for an unset timestamp: 180 records across 178 of the 285 files in the local corpus carry one. The fix converts seconds and sub-second remainder separately.

- [ ] **Step 1: Rewrite the test that asserts the wrong belief**

In `binformat_test.go`, replace `TestFromFILETIME_OutOfRangeIsError` (currently at lines 68-77) entirely with:

```go
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
```

- [ ] **Step 2: Extend the round trip across the range**

Replace `TestFromFILETIME_RoundTrip` (currently at lines 55-66) with:

```go
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
```

Leave `TestFromFILETIME_AboveInt64RangeIsError` (lines 79-86) untouched: that rejection stays.

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test -race -run 'TestFromFILETIME|TestFILETIME' . -v`
Expected: `TestFromFILETIME_ZeroIsYear1601` fails with `fromFILETIME(0) = error go_evtx: FILETIME 0 is out of range for a 100ns Unix offset`, and the `filetime epoch` subtest fails.

- [ ] **Step 4: Add the ticks-per-second constant**

In `binformat.go`, inside the const block that already holds `filetimeEpochDelta` (around line 32), add below it:

```go
	// filetimeTicksPerSecond: a FILETIME counts 100-nanosecond intervals.
	filetimeTicksPerSecond = int64(10_000_000)
```

- [ ] **Step 5: Fix `toFILETIME`**

Replace the whole function (currently `binformat.go:48-50`) with:

```go
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
```

- [ ] **Step 6: Fix `fromFILETIME`**

Replace the whole function including its doc comment (currently `binformat.go:52-70`) with:

```go
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
```

Note for the implementer: Go's integer division truncates toward zero, so for a
negative `delta` both `sec` and `nsec` are negative or zero. `time.Unix`
explicitly accepts an out-of-range `nsec` and normalises it, so this is correct
without a manual carry.

- [ ] **Step 7: Run the unit tests and confirm they pass**

Run: `go test -race -run 'TestFromFILETIME|TestFILETIME' . -v`
Expected: PASS, four subtests in the round trip.

- [ ] **Step 8: Add the reader-level test**

`WriteRecord` takes the record-header timestamp from `fields["TimeCreated"]`
parsed as RFC3339Nano (`evtx.go:370`, `parseTimeCreated` at `evtx.go:913`), so a
zero FILETIME can be produced end to end with no byte patching. Append to
`reader_test.go`:

```go
// TestReadEvent_ZeroTimestampDecodes covers the record shape that made
// ReadEvent fail on 178 of the 285 files in the local corpus: a record-header
// FILETIME of 0, which is 1601-01-01T00:00:00Z and which Windows writes for an
// unset timestamp. Written through the public API rather than by patching
// bytes, so the chunk CRCs stay valid and the test exercises the real path.
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
```

If `reader_test.go` does not already import `path/filepath` or `time`, add them.

- [ ] **Step 9: Run the full suite**

Run: `go test -race ./... -count=1`
Expected: PASS. If any other test asserted that a zero or pre-1678 FILETIME
errors, it encoded the same wrong belief — rewrite it the way Step 1 rewrote
`TestFromFILETIME_OutOfRangeIsError`, with a comment saying what changed.

- [ ] **Step 10: Re-measure against the corpus and record the result**

Run, substituting your own corpus path:

```bash
EVTX_CORPUS=/path/to/corpus go test -run TestCorpusScan . -v 2>&1 | tail -3
```

Then write a short note in the commit body with the new `ReadEvent` failure
count. The expectation from the spec is 206 failures falling to 26. If it does
not, stop and report — the fix is either incomplete or the measurement was
wrong, and both are worth knowing before the CLI is built on top.

- [ ] **Step 11: Commit**

```bash
git add binformat.go binformat_test.go reader_test.go
git commit -F - <<'EOF'
fix: convert FILETIME over the format's whole range, not just 1678-2262

FILETIME 0 is 1601-01-01T00:00:00Z and Windows writes it for an unset
timestamp. Both conversions routed the epoch offset through int64
nanoseconds, which cannot reach 1601, so ReadEvent rejected 180 records
across 178 of the 285 files in the local corpus.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
```

---

### Task 2: `Reader.FileInfo`

**Files:**
- Modify: `reader.go:36-81` (the `Reader` struct and `Open`)
- Test: `reader_test.go` (append)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  ```go
  type FileInfo struct {
      Major, Minor uint16
      Chunks       int
      Dirty, Full  bool
  }
  func (r *Reader) FileInfo() FileInfo
  ```
  Task 3's `runInfo` reads all four fields.

**Background.** `Open` already reads the 4096-byte file header into `hdr` and
pulls the chunk count from `hdr[42:44]`. The format version sits at
`hdr[36:38]` (minor) and `hdr[38:40]` (major) and is currently discarded;
`buildFileHeader` (`binformat.go:123-124`) writes 1 and 3, so a go-evtx file is
3.1 while Windows Server 2025 writes 3.2. The flags word is at `hdr[120:124]`,
with `evtxFlagDirty = 0x0001` and `evtxFlagFull = 0x0002` already declared in
`binformat.go:41-43`.

- [ ] **Step 1: Write the failing test**

Append to `reader_test.go`:

```go
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
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test -race -run TestReader_FileInfo . -v`
Expected: compile failure — `r.FileInfo undefined (type *Reader has no field or method FileInfo)`.

- [ ] **Step 3: Add the type and the field**

In `reader.go`, above the `Reader` struct, add:

```go
// FileInfo describes the container, not its contents: the facts carried by
// the 4096-byte file header, which Open reads once. Windows writes format 3.1
// and 3.2; go-evtx writes 3.1.
type FileInfo struct {
	Major, Minor uint16 // format version
	Chunks       int
	Dirty        bool // written to but not cleanly closed
	Full         bool // reached its configured size limit
}
```

Then add a field to the `Reader` struct, below `numChunks`:

```go
	info      FileInfo // immutable after Open; guarded by mu like every other field
```

- [ ] **Step 4: Populate it in `Open`**

In `reader.go`, replace the `r := &Reader{...}` literal (currently lines 70-75) with:

```go
	flags := binary.LittleEndian.Uint32(hdr[120:124])
	r := &Reader{
		f:         f,
		numChunks: numChunks,
		chunkIdx:  -1,
		buf:       make([]byte, evtxChunkSize),
		info: FileInfo{
			Minor:  binary.LittleEndian.Uint16(hdr[36:38]),
			Major:  binary.LittleEndian.Uint16(hdr[38:40]),
			Chunks: numChunks,
			Dirty:  flags&evtxFlagDirty != 0,
			Full:   flags&evtxFlagFull != 0,
		},
	}
```

- [ ] **Step 5: Add the accessor**

In `reader.go`, immediately before `Close`, add:

```go
// FileInfo returns the container facts read from the file header at Open.
// Safe for concurrent use, like every other exported Reader method.
func (r *Reader) FileInfo() FileInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.info
}
```

- [ ] **Step 6: Run the test**

Run: `go test -race -run TestReader_FileInfo . -v`
Expected: PASS.

- [ ] **Step 7: Run the full suite and vet**

Run: `go test -race ./... -count=1 && go vet ./... && gofmt -l .`
Expected: PASS, no vet output, `gofmt -l` prints nothing.

- [ ] **Step 8: Commit**

```bash
git add reader.go reader_test.go
git commit -F - <<'EOF'
feat(reader): expose the file header facts as Reader.FileInfo

Format version, chunk count and the dirty/full flags. Open already read
all four and kept only the chunk count. Version is what tells a 3.1 file
from a 3.2 one, which is the first question anyone asks of an
unfamiliar .evtx.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
```

---

### Task 3: `cmd/evtx` skeleton and the `info` subcommand

**Files:**
- Create: `cmd/evtx/main.go`
- Create: `cmd/evtx/info.go`
- Create: `cmd/evtx/main_test.go`
- Create: `cmd/evtx/info_test.go`

**Interfaces:**
- Consumes: `evtx.Open`, `evtx.Reader.FileInfo` (Task 2), `evtx.Reader.ReadEvent`, `evtx.ErrNoMoreRecords`.
- Produces:
  ```go
  func run(args []string, stdout, stderr io.Writer) int
  func runInfo(args []string, stdout, stderr io.Writer) int
  func inputPath(in string, rest []string) (string, error)
  func normaliseCause(err error) string
  ```
  Task 4 calls `inputPath` and `normaliseCause`, and adds a `dump` case to `run`.

**Background.** The binary must stay dependency-free, so argument parsing is
`flag` with one `FlagSet` per subcommand. Subcommands are functions returning an
exit code rather than calling `os.Exit`, so tests assert the code directly with
no process spawn. `ReadEvent` documents that a decode failure is returned for
that record alone and the reader stays positioned on the next one, so the loop
continues past an error rather than stopping.

- [ ] **Step 1: Write the failing tests**

Create `cmd/evtx/main_test.go`:

```go
package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestInputPath(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		rest    []string
		want    string
		wantErr bool
	}{
		{"flag only", "a.evtx", nil, "a.evtx", false},
		{"positional only", "", []string{"a.evtx"}, "a.evtx", false},
		{"both is a usage error", "a.evtx", []string{"b.evtx"}, "", true},
		{"neither is a usage error", "", nil, "", true},
		{"two positionals is a usage error", "", []string{"a.evtx", "b.evtx"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inputPath(tc.in, tc.rest)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("inputPath(%q, %v) = %q, want an error", tc.in, tc.rest, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("inputPath(%q, %v): %v", tc.in, tc.rest, err)
			}
			if got != tc.want {
				t.Errorf("inputPath(%q, %v) = %q, want %q", tc.in, tc.rest, got, tc.want)
			}
		})
	}
}

// TestNormaliseCause pins the grouping rule: two failures of the same kind at
// different positions are one cause, not two. Without this an info report
// would print one line per record, which is what makes 206 failures
// unreadable and 2 lines useful.
func TestNormaliseCause(t *testing.T) {
	a := errors.New("go_evtx: chunk 0, record 2: go_evtx: FILETIME 0 is out of range")
	b := errors.New("go_evtx: chunk 314, record 62400: go_evtx: FILETIME 0 is out of range")
	if normaliseCause(a) != normaliseCause(b) {
		t.Errorf("causes differ:\n  %q\n  %q", normaliseCause(a), normaliseCause(b))
	}
	if strings.Contains(normaliseCause(a), "chunk") {
		t.Errorf("cause still carries its position: %q", normaliseCause(a))
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"frobnicate"}, &out, &errb); code != 1 {
		t.Errorf("run(frobnicate) = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "unknown subcommand") {
		t.Errorf("stderr = %q, want it to name the unknown subcommand", errb.String())
	}
}

func TestRun_NoArgs(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 1 {
		t.Errorf("run(nil) = %d, want 1", code)
	}
}
```

Create `cmd/evtx/info_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	evtx "github.com/fjacquet/go-evtx"
)

// writeFixture writes a small valid file and returns its path. Every CLI test
// works from a file this package wrote, so the tests never need a tracked
// .evtx and never depend on a corpus.
func writeFixture(t *testing.T, records int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < records; i++ {
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
	return path
}

func TestRunInfo_ReportsTheContainer(t *testing.T) {
	path := writeFixture(t, 5)
	var out, errb bytes.Buffer
	if code := runInfo([]string{"--in", path}, &out, &errb); code != 0 {
		t.Fatalf("runInfo = %d, want 0; stderr: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{
		"format     3.1",
		"chunks     1",
		"flags      dirty=false full=false",
		"records    5",
		"decode     5/5 records, 0 failures",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("info output missing %q; got:\n%s", want, got)
		}
	}
}

func TestRunInfo_PositionalArgument(t *testing.T) {
	path := writeFixture(t, 1)
	var out, errb bytes.Buffer
	if code := runInfo([]string{path}, &out, &errb); code != 0 {
		t.Fatalf("runInfo = %d, want 0; stderr: %s", code, errb.String())
	}
}

func TestRunInfo_MissingFileExitsOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runInfo([]string{"--in", filepath.Join(t.TempDir(), "absent.evtx")}, &out, &errb); code != 1 {
		t.Errorf("runInfo on a missing file = %d, want 1", code)
	}
}

func TestRunInfo_InvalidMagicExitsOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notevtx.bin")
	if err := os.WriteFile(path, []byte("this is not an evtx file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runInfo([]string{"--in", path}, &out, &errb); code != 1 {
		t.Errorf("runInfo on a non-evtx file = %d, want 1", code)
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test -race ./cmd/evtx/ -v`
Expected: build failure — `no required module provides package`, or once the
directory exists, `undefined: run`, `undefined: runInfo`, `undefined: inputPath`,
`undefined: normaliseCause`.

- [ ] **Step 3: Write `main.go`**

```go
// Command evtx reads Windows Event Log (.evtx) files.
//
// It is a thin shell over the go-evtx library: dump serialises records through
// the library's own Event type and its MarshalJSON, and info reports the file
// header plus a decode pass. Nothing here reimplements the format.
//
// Usage:
//
//	evtx dump [--in FILE] [--out FILE] [--shape=event|flat] [--allow-errors] [FILE]
//	evtx info [--in FILE] [FILE]
package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// version is replaced at release time by GoReleaser's default ldflags,
// which inject -X main.version=<tag>.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a subcommand and returns the process exit code. Keeping this
// separate from main is what lets the tests assert exit codes without
// spawning a process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 1
	}
	switch args[0] {
	case "dump":
		return runDump(args[1:], stdout, stderr)
	case "info":
		return runInfo(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "evtx: unknown subcommand %q\n", args[0])
		usage(stderr)
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `evtx reads Windows Event Log (.evtx) files.

Usage:
  evtx dump [--in FILE] [--out FILE] [--shape=event|flat] [--allow-errors] [FILE]
  evtx info [--in FILE] [FILE]
  evtx version

dump writes one JSON object per record (NDJSON) to stdout or --out.
info reports the file header and the result of a full decode pass.

Exit codes for dump: 0 all records decoded, 2 some were skipped,
1 usage error or unreadable input. info exits 0 unless the input is
unreadable.
`)
}

// inputPath resolves --in against a positional argument. Supplying both is an
// error rather than a silent preference: a typo in one of them would otherwise
// look like it worked.
func inputPath(in string, rest []string) (string, error) {
	switch {
	case in != "" && len(rest) > 0:
		return "", fmt.Errorf("give the input either as --in or as an argument, not both")
	case in != "":
		return in, nil
	case len(rest) == 1:
		return rest[0], nil
	case len(rest) == 0:
		return "", fmt.Errorf("no input file")
	default:
		return "", fmt.Errorf("expected one input file, got %d", len(rest))
	}
}

// digits matches every run of decimal digits in an error message.
var digits = regexp.MustCompile(`[0-9]+`)

// normaliseCause reduces a per-record error to its cause so that failures of
// the same kind group together. ReadEvent wraps each failure with its position
// ("chunk 314, record 62400: ..."), and without this reduction a report would
// print one line per record — which is what makes 206 failures unreadable and
// two lines useful.
func normaliseCause(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, "go_evtx: "); i >= 0 {
		msg = msg[i+len("go_evtx: "):]
	}
	return digits.ReplaceAllString(msg, "N")
}
```

- [ ] **Step 4: Write `info.go`**

```go
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	evtx "github.com/fjacquet/go-evtx"
)

func runInfo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "input .evtx file")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	path, err := inputPath(*in, fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "evtx info: %v\n", err)
		return 1
	}

	r, err := evtx.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "evtx info: %v\n", err)
		return 1
	}
	defer func() { _ = r.Close() }()

	fi := r.FileInfo()

	// A decode failure is reported for that record alone and the reader stays
	// positioned on the next one, so the walk continues rather than stopping
	// at the first surprise — measuring only what already decodes is how this
	// project used to miss its own defects.
	total, failed := 0, 0
	causes := map[string]int{}
	for {
		_, err := r.ReadEvent()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		total++
		if err != nil {
			failed++
			causes[normaliseCause(err)]++
		}
	}

	fmt.Fprintf(stdout, "file       %s\n", filepath.Base(path))
	fmt.Fprintf(stdout, "format     %d.%d\n", fi.Major, fi.Minor)
	fmt.Fprintf(stdout, "chunks     %d\n", fi.Chunks)
	fmt.Fprintf(stdout, "flags      dirty=%t full=%t\n", fi.Dirty, fi.Full)
	fmt.Fprintf(stdout, "records    %d\n", total)
	fmt.Fprintf(stdout, "decode     %d/%d records, %d failures\n", total-failed, total, failed)
	for _, c := range sortedCauses(causes) {
		fmt.Fprintf(stdout, "           %6d  %s\n", causes[c], c)
	}
	return 0
}

// sortedCauses orders causes by descending count, then by text, so that two
// runs over the same file print the same report.
func sortedCauses(causes map[string]int) []string {
	out := make([]string, 0, len(causes))
	for c := range causes {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if causes[out[i]] != causes[out[j]] {
			return causes[out[i]] > causes[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}
```

- [ ] **Step 5: Add a temporary `runDump` so the package compiles**

`run` references `runDump`, which Task 4 writes. Add this to `dump.go` now so
the package builds, and replace it wholesale in Task 4:

```go
package main

import (
	"fmt"
	"io"
)

func runDump(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "evtx dump: not implemented yet")
	return 1
}
```

- [ ] **Step 6: Run the tests**

Run: `go test -race ./cmd/evtx/ -v`
Expected: PASS. `TestRunInfo_ReportsTheContainer` proves `FileInfo` is wired
through: `format     3.1` can only come from the file header.

- [ ] **Step 7: Verify the whole repo still builds, including Windows**

Run: `go build ./... && GOOS=windows go build ./... && go vet ./... && gofmt -l .`
Expected: no output from any of them.

- [ ] **Step 8: Commit**

```bash
git add cmd/evtx/
git commit -F - <<'EOF'
feat(cli): add cmd/evtx with the info subcommand

Subcommands are functions returning an exit code rather than calling
os.Exit, so the tests assert codes without spawning a process. Parsing is
stdlib flag: go.mod keeps its empty require block.

info groups decode failures by normalised cause instead of listing one
line per record — two lines say what 206 lines cannot.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
```

---

### Task 4: `evtx dump --shape=event`

**Files:**
- Modify: `cmd/evtx/dump.go` (replace the placeholder from Task 3 entirely)
- Create: `cmd/evtx/dump_test.go`

**Interfaces:**
- Consumes: `inputPath`, `normaliseCause` (Task 3); `evtx.Open`, `evtx.Reader.ReadEvent`, `evtx.ErrNoMoreRecords`, `evtx.Event`.
- Produces: `runDump(args []string, stdout, stderr io.Writer) int`, and the `--shape` flag whose `flat` value Task 5 implements.

**Background.** `evtx.Event` already carries JSON tags and `evtx.Value` already
has a type-aware `MarshalJSON`, so the event shape is `json.Encoder.Encode(ev)`
and nothing else. `json.Encoder.Encode` appends a newline after each value,
which is exactly NDJSON.

- [ ] **Step 1: Write the failing tests**

Create `cmd/evtx/dump_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	evtx "github.com/fjacquet/go-evtx"
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
	for i, line := range lines {
		var ev evtx.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if ev.System.Provider.Name != "Microsoft-Windows-Security-Auditing" {
			t.Errorf("line %d: provider = %q, want the value passed to WriteRecord",
				i, ev.System.Provider.Name)
		}
		if ev.System.Computer != "TESTHOST" {
			t.Errorf("line %d: computer = %q, want TESTHOST", i, ev.System.Computer)
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

func TestRunDump_MissingFileExitsOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runDump([]string{"--in", filepath.Join(t.TempDir(), "absent.evtx")}, &out, &errb); code != 1 {
		t.Errorf("runDump on a missing file = %d, want 1", code)
	}
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test -race ./cmd/evtx/ -run TestRunDump -v`
Expected: every subtest fails with `evtx dump: not implemented yet` and exit code 1.

- [ ] **Step 3: Replace `dump.go`**

```go
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	evtx "github.com/fjacquet/go-evtx"
)

func runDump(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "input .evtx file")
	out := fs.String("out", "", "output file; stdout when empty")
	shape := fs.String("shape", "event", "output shape: event or flat")
	allowErrors := fs.Bool("allow-errors", false, "exit 0 even when records were skipped")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *shape != "event" && *shape != "flat" {
		fmt.Fprintf(stderr, "evtx dump: unknown --shape %q, want event or flat\n", *shape)
		return 1
	}
	path, err := inputPath(*in, fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "evtx dump: %v\n", err)
		return 1
	}

	w := stdout
	if *out != "" {
		f, err := os.Create(*out) // #nosec G304 — an operator-supplied output path
		if err != nil {
			fmt.Fprintf(stderr, "evtx dump: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	r, err := evtx.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "evtx dump: %v\n", err)
		return 1
	}
	defer func() { _ = r.Close() }()

	enc := json.NewEncoder(w)
	total, skipped, relocated := 0, 0, 0
	for {
		ev, err := r.ReadEvent()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		total++
		if err != nil {
			// One line per skipped record, on stderr, keeping the position
			// ReadEvent already put in the message. The stream on stdout stays
			// pure NDJSON so a pipeline never has to filter it.
			skipped++
			fmt.Fprintf(stderr, "%v\n", err)
			continue
		}
		var payload any = ev
		if *shape == "flat" {
			flat, moved := flatten(ev)
			payload, relocated = flat, relocated+moved
		}
		if err := enc.Encode(payload); err != nil {
			fmt.Fprintf(stderr, "evtx dump: %v\n", err)
			return 1
		}
	}

	if skipped > 0 {
		fmt.Fprintf(stderr, "%d of %d records failed to decode\n", skipped, total)
	}
	if relocated > 0 {
		fmt.Fprintf(stderr, "%d event_data keys were renamed to avoid a collision\n", relocated)
	}
	if skipped > 0 && !*allowErrors {
		return 2
	}
	return 0
}
```

- [ ] **Step 4: Add a stub `flatten` so the package compiles**

Task 5 writes the real one. Create `cmd/evtx/flat.go`:

```go
package main

import evtx "github.com/fjacquet/go-evtx"

func flatten(ev *evtx.Event) (map[string]any, int) {
	return map[string]any{"record_id": ev.RecordID}, 0
}
```

- [ ] **Step 5: Run the dump tests**

Run: `go test -race ./cmd/evtx/ -run TestRunDump -v`
Expected: PASS.

- [ ] **Step 6: Run everything**

Run: `go test -race ./... -count=1 && go vet ./... && gofmt -l .`
Expected: PASS, no output.

- [ ] **Step 7: Commit**

```bash
git add cmd/evtx/dump.go cmd/evtx/dump_test.go cmd/evtx/flat.go
git commit -F - <<'EOF'
feat(cli): add evtx dump with the faithful event shape

The event shape is json.Encoder.Encode on the library's own Event: the
CLI adds no serialisation of its own, so it cannot drift from the API it
demonstrates. Value.MarshalJSON already renders SIDs, FILETIMEs, base64
binary and the 2^53 quoting rule.

Diagnostics go to stderr so stdout stays pure NDJSON.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
```

---

### Task 5: the flat shape and the corpus test

**Files:**
- Modify: `cmd/evtx/flat.go` (replace the Task 4 stub entirely)
- Create: `cmd/evtx/flat_test.go`
- Create: `cmd/evtx/corpus_test.go`

**Interfaces:**
- Consumes: `evtx.Event`, `evtx.System`, `evtx.Data`, `evtx.Value`, `evtx.Node`; `runDump` (Task 4).
- Produces: `flatten(ev *evtx.Event) (map[string]any, int)` — the map is the JSON object, the int counts keys renamed to avoid a collision.

**The rule, from the spec.** An `EventData` entry takes its own name as its
root key when that name is non-empty, collides with no reserved key, and has
not already been used. Otherwise its key is `data_<i>`, where `i` is the
entry's absolute index in `EventData`, followed by `_<Name>` when a name
exists.

**Why the reserved set is derived, not listed.** Several `System` JSON tags
carry `omitempty`, so a key present in one record is absent from the next. If
the reserved set were built from the record in hand, whether a `<Data
Name="task">` collided would depend on whether *that* record had a non-zero
`Task` — the same name would land in two different places in one file. The set
is therefore read once from `evtx.System`'s struct tags via `reflect`.

**Why this is unit-tested and not tested end to end.** go-evtx's writer cannot
produce any of the contentious cases: its twelve `<Data>` names are fixed, all
named, and none collides with a `System` key. An end-to-end test would never
construct a collision and would pass while testing nothing.

- [ ] **Step 1: Write the failing tests**

Create `cmd/evtx/flat_test.go`:

```go
package main

import (
	"testing"

	evtx "github.com/fjacquet/go-evtx"
)

func TestFlatten_PlainNameStaysItself(t *testing.T) {
	ev := &evtx.Event{
		RecordID: 7,
		System:   evtx.System{EventID: 4663, Computer: "TESTHOST"},
		EventData: []evtx.Data{
			{Name: "ObjectName"},
		},
	}
	flat, relocated := flatten(ev)
	if relocated != 0 {
		t.Errorf("relocated = %d, want 0", relocated)
	}
	if _, ok := flat["ObjectName"]; !ok {
		t.Errorf("ObjectName missing; got keys %v", keysOf(flat))
	}
	if flat["computer"] != "TESTHOST" {
		t.Errorf("computer = %v, want TESTHOST", flat["computer"])
	}
	if flat["record_id"] != uint64(7) {
		t.Errorf("record_id = %v, want 7", flat["record_id"])
	}
}

// TestFlatten_CollisionWithSystemIsRenamed is the case the writer cannot
// produce and Windows can: a <Data Name="Computer"> beside System/Computer.
// The System value must survive untouched.
func TestFlatten_CollisionWithSystemIsRenamed(t *testing.T) {
	ev := &evtx.Event{
		System: evtx.System{Computer: "REAL-HOST"},
		EventData: []evtx.Data{
			{Name: "SubjectUserName"},
			{Name: "computer"},
		},
	}
	flat, relocated := flatten(ev)
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1", relocated)
	}
	if flat["computer"] != "REAL-HOST" {
		t.Errorf("System computer was overwritten: %v", flat["computer"])
	}
	if _, ok := flat["data_1_computer"]; !ok {
		t.Errorf("renamed key missing; got keys %v", keysOf(flat))
	}
}

func TestFlatten_UnnamedEntryUsesItsIndex(t *testing.T) {
	ev := &evtx.Event{
		EventData: []evtx.Data{
			{Name: "First"},
			{Name: ""},
			{Name: "Third"},
		},
	}
	flat, relocated := flatten(ev)
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1", relocated)
	}
	if _, ok := flat["data_1"]; !ok {
		t.Errorf("data_1 missing; got keys %v", keysOf(flat))
	}
}

func TestFlatten_RepeatedNameKeepsBoth(t *testing.T) {
	ev := &evtx.Event{
		EventData: []evtx.Data{
			{Name: "Param"},
			{Name: "Param"},
		},
	}
	flat, relocated := flatten(ev)
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1", relocated)
	}
	if _, ok := flat["Param"]; !ok {
		t.Errorf("first Param missing; got keys %v", keysOf(flat))
	}
	if _, ok := flat["data_1_Param"]; !ok {
		t.Errorf("second Param missing; got keys %v", keysOf(flat))
	}
}

// TestFlatten_ReservedSetIgnoresOmitempty guards the rule that makes the
// projection deterministic across records: a System key must be reserved even
// when this particular record leaves it at its zero value and omitempty drops
// it from the output. Without this, the same Data name would land in two
// different places in one file.
func TestFlatten_ReservedSetIgnoresOmitempty(t *testing.T) {
	ev := &evtx.Event{
		System:    evtx.System{}, // task is zero, so omitempty drops it
		EventData: []evtx.Data{{Name: "task"}},
	}
	flat, relocated := flatten(ev)
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1 — 'task' is a System key whether or not this record carries one", relocated)
	}
	if _, ok := flat["data_0_task"]; !ok {
		t.Errorf("renamed key missing; got keys %v", keysOf(flat))
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
```

- [ ] **Step 2: Run and confirm failure**

Run: `go test -race ./cmd/evtx/ -run TestFlatten -v`
Expected: all five fail — the stub returns only `record_id`.

- [ ] **Step 3: Replace `flat.go`**

```go
package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	evtx "github.com/fjacquet/go-evtx"
)

// reservedKeys are the root keys the flat shape will not let an EventData
// entry take. They are read from evtx.System's struct tags rather than listed
// by hand, for two reasons: adding a System field cannot silently open a
// collision, and several tags carry omitempty, so a set derived from the
// record in hand would reserve different keys for different records of the
// same file.
var reservedKeys = buildReservedKeys()

func buildReservedKeys() map[string]bool {
	keys := map[string]bool{
		"record_id": true,
		"timestamp": true,
		"binary":    true,
		"user_data": true,
		// Provider is one nested object in the faithful shape and three scalar
		// keys here; none of the three appears in System's own tags.
		"provider":                   true,
		"provider_guid":              true,
		"provider_event_source_name": true,
	}
	t := reflect.TypeOf(evtx.System{})
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}

// flatten projects an Event onto a single JSON level and reports how many
// EventData keys had to be renamed.
//
// The rule: an EventData entry takes its own name as its root key when that
// name is non-empty, collides with no reserved key, and has not already been
// used. Otherwise its key is data_<i>, where i is the entry's absolute index,
// followed by _<Name> when a name exists.
//
// user_data stays nested even here: it is an arbitrary XML tree, and
// flattening it would mean inventing a path convention. "Flat" describes
// EventData, not the whole record.
func flatten(ev *evtx.Event) (map[string]any, int) {
	root := map[string]any{
		"record_id": ev.RecordID,
		"timestamp": ev.Timestamp,
	}

	// System is lifted through its own JSON tags rather than field by field,
	// so it cannot fall out of step with the faithful shape.
	var sys map[string]any
	if b, err := json.Marshal(ev.System); err == nil {
		_ = json.Unmarshal(b, &sys)
	}
	delete(sys, "provider")
	for k, v := range sys {
		root[k] = v
	}

	if ev.System.Provider.Name != "" {
		root["provider"] = ev.System.Provider.Name
	}
	if ev.System.Provider.GUID != "" {
		root["provider_guid"] = ev.System.Provider.GUID
	}
	if ev.System.Provider.EventSourceName != "" {
		root["provider_event_source_name"] = ev.System.Provider.EventSourceName
	}
	if !ev.Binary.IsAbsent() {
		root["binary"] = ev.Binary
	}
	if ev.UserData != nil {
		root["user_data"] = ev.UserData
	}

	used := make(map[string]bool, len(ev.EventData))
	relocated := 0
	for i, d := range ev.EventData {
		key := d.Name
		if key == "" || reservedKeys[key] || used[key] {
			relocated++
			key = fmt.Sprintf("data_%d", i)
			if d.Name != "" {
				key += "_" + d.Name
			}
		}
		used[key] = true
		root[key] = d.Value
	}
	return root, relocated
}
```

- [ ] **Step 4: Run the flatten tests**

Run: `go test -race ./cmd/evtx/ -run TestFlatten -v`
Expected: PASS, five tests.

- [ ] **Step 5: Add an end-to-end flat test and the corpus test**

Append to `cmd/evtx/dump_test.go`:

```go
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
```

Create `cmd/evtx/corpus_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCorpusDump runs dump over a local corpus of real Windows files. It
// skips unless EVTX_CORPUS is set, exactly like the library's own corpus
// tests, and asserts nothing about counts: the corpus is a developer's local
// directory and will differ from machine to machine, so an assertion on "26
// failures" would be false for everyone else.
//
// What it does assert is that every emitted line is valid JSON and every
// reported failure carries a cause — a dump that silently emitted a truncated
// line, or an error line with an empty reason, would otherwise look like
// success.
func TestCorpusDump(t *testing.T) {
	root := os.Getenv("EVTX_CORPUS")
	if root == "" {
		t.Skip("set EVTX_CORPUS to a directory of real .evtx files")
	}
	files := 0
	for _, r := range filepath.SplitList(root) {
		err := filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".evtx") {
				return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
			}
			files++
			var out, errb bytes.Buffer
			code := runDump([]string{"--in", p}, &out, &errb)
			if code != 0 && code != 2 {
				t.Errorf("%s: runDump = %d, want 0 or 2; stderr: %s",
					filepath.Base(p), code, errb.String())
				return nil
			}
			for i, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
				if line == "" {
					continue
				}
				var obj map[string]any
				if err := json.Unmarshal([]byte(line), &obj); err != nil {
					t.Errorf("%s line %d: not valid JSON: %v", filepath.Base(p), i, err)
					return nil
				}
			}
			for _, line := range strings.Split(strings.TrimSpace(errb.String()), "\n") {
				if line == "" || strings.Contains(line, "failed to decode") ||
					strings.Contains(line, "were renamed") {
					continue
				}
				if !strings.Contains(line, ": ") {
					t.Errorf("%s: failure line carries no cause: %q", filepath.Base(p), line)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", r, err)
		}
	}
	if files == 0 {
		t.Fatalf("no .evtx files found under %q", root)
	}
	t.Logf("dumped %d files", files)
}
```

- [ ] **Step 6: Run the CLI tests, then the corpus test**

Run: `go test -race ./cmd/evtx/ -v`
Expected: PASS, with `TestCorpusDump` skipped.

Run, substituting your corpus path:
`EVTX_CORPUS=/path/to/corpus go test -race ./cmd/evtx/ -run TestCorpusDump -v`
Expected: PASS, logging the file count.

- [ ] **Step 7: Run everything**

Run: `go test -race ./... -count=1 && go vet ./... && gofmt -l . && GOOS=windows go build ./...`
Expected: PASS, no output.

- [ ] **Step 8: Commit**

```bash
git add cmd/evtx/flat.go cmd/evtx/flat_test.go cmd/evtx/dump_test.go cmd/evtx/corpus_test.go
git commit -F - <<'EOF'
feat(cli): add the flat dump shape with an explicit collision rule

An EventData entry keeps its own name unless that name is empty, is a
reserved key, or was already used; otherwise it becomes data_<i>_<Name>.
Deterministic, traceable to the originating index, and lossless.

The reserved set is read from evtx.System's struct tags, not listed by
hand: several tags carry omitempty, so a set derived from the record in
hand would reserve different keys for different records of one file.

Unit-tested rather than end to end on purpose — the writer cannot produce
a single one of the contentious cases, so an end-to-end test would pass
while testing nothing.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
```

---

### Task 6: ship the binary — GoReleaser and ADR-005

**Files:**
- Modify: `.goreleaser.yaml`
- Create: `docs/adr/ADR-005-ship-cli-binaries.md`
- Modify: `cmd/evtx/main.go` (extend the version variables)

**Interfaces:**
- Consumes: `cmd/evtx` from Tasks 3-5.
- Produces: release artefacts named `go-evtx_<version>_<os>_<arch>` plus `checksums.txt`.

**Verified against the GoReleaser v2 documentation:** `archives.builds` was
renamed to `archives.ids`; the default `ldflags` already inject
`-s -w -X main.version={{.Version}} -X main.commit={{.Commit}} -X main.date={{.Date}} -X main.builtBy=goreleaser`,
so no custom `ldflags` entry is needed — declaring the matching variables is
enough. A `-X` against a symbol that does not exist is ignored by the linker.

- [ ] **Step 1: Declare the version variables GoReleaser injects**

In `cmd/evtx/main.go`, replace the single `version` declaration with:

```go
// Injected at release time by GoReleaser's default ldflags. They keep their
// placeholder values in a `go install` or `go build` binary, which is correct:
// such a build has no release identity to report.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)
```

And replace the `version` case in `run` with:

```go
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "evtx %s (commit %s, built %s)\n", version, commit, date)
		return 0
```

- [ ] **Step 2: Add a test for it**

Append to `cmd/evtx/main_test.go`:

```go
func TestRun_Version(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("run(version) = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "evtx ") {
		t.Errorf("stdout = %q, want it to name the binary and its version", out.String())
	}
}
```

- [ ] **Step 3: Run it**

Run: `go test -race ./cmd/evtx/ -run TestRun_Version -v`
Expected: PASS.

- [ ] **Step 4: Replace the `builds` block in `.goreleaser.yaml`**

Replace:

```yaml
builds:
  # go-evtx is a library — no binary to build.
  # GoReleaser creates the GitHub release with changelog; consumers use go get.
  - skip: true
```

with:

```yaml
builds:
  # The library itself ships through the module proxy, not as an artefact.
  # cmd/evtx is the one binary: naming its main package explicitly is also what
  # keeps the two fixture generators in cmd/ out of the release.
  - id: evtx
    main: ./cmd/evtx
    binary: evtx
    env:
      - CGO_ENABLED=0
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]

archives:
  - id: evtx
    ids: [evtx]
    name_template: '{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}'

checksum:
  name_template: 'checksums.txt'
```

Leave the existing `before`, `changelog` and `release` blocks unchanged.

- [ ] **Step 5: Validate the configuration**

Run: `goreleaser check`
Expected: `configuration is valid`. If `goreleaser` is not installed, run
`go tool` equivalents are not available — install it or run
`docker run --rm -v $PWD:/src -w /src goreleaser/goreleaser check`.

Then build a snapshot without publishing:

Run: `goreleaser build --snapshot --clean --single-target`
Expected: a binary under `dist/`. Run `./dist/evtx_*/evtx version` and confirm
it prints a version line.

- [ ] **Step 6: Write ADR-005**

Create `docs/adr/ADR-005-ship-cli-binaries.md`, following the format of the
four existing ADRs (read `docs/adr/ADR-004-open-handle-incremental-flush.md`
first for its heading structure):

```markdown
# ADR-005 — Ship CLI binaries

**Status:** Accepted
**Date:** 2026-08-10

## Context

go-evtx has been a library since v0.1.0. `.goreleaser.yaml` sets
`builds: [{skip: true}]`, and a release with zero attached assets is the
correct outcome under that decision: consumers reach the code through
`go get` and the module proxy.

Two subcommands now exist that are useful outside a Go program — `evtx dump`
and `evtx info` — and the library has no executable demonstration of itself.
Someone evaluating go-evtx has the README, the godoc, and no way to point the
thing at a file.

## Decision

Ship one binary, `evtx`, built from `cmd/evtx` in this module, for
linux/darwin/windows on amd64 and arm64, with a checksums file.

`cmd/evtx` stays inside the existing module rather than taking its own
`go.mod` or its own repository. `go install github.com/fjacquet/go-evtx/cmd/evtx@latest`
then works with no extra setup, and the binary's version is the library's
version — `evtx version` reporting v0.8.0 means something.

## Consequences

- **The CLI surface becomes a compatibility promise.** Flag names, the shape
  of the NDJSON, and the exit codes are now things consumers script against.
  Breaking any of them needs a major or minor bump and a CHANGELOG entry, the
  same as an exported Go symbol.
- **Zero release assets stops being the expected state.** A release that
  attaches nothing is now a failed build, not a correct library release. Anyone
  reading an old release page should know assets were absent by design until
  v0.8.0.
- **A library consumer also fetches the `cmd/` sources.** With no dependencies
  these are inert Go files; the empty require block in `go.mod` is unaffected.
- **The two fixture generators stay unshipped.** `builds[].main` names
  `./cmd/evtx` explicitly, so `gen-fixture-system` and `gen-fixture-minimal`
  remain CI-only tools.

## Alternatives considered

**A separate module under `cmd/evtx/go.mod`.** Would isolate CLI dependencies
if the CLI ever wanted cobra or coloured output. Rejected: it costs `replace`
directives during development, two tags per release and a doubled CI matrix,
paid today for a freedom two subcommands do not need.

**A separate `go-evtx-cli` repository.** Total isolation, no discoverability,
and two release processes for one binary with one upstream consumer. Rejected.
```

- [ ] **Step 7: Run everything**

Run: `go test -race ./... -count=1 && go vet ./... && gofmt -l .`
Expected: PASS, no output.

- [ ] **Step 8: Commit**

```bash
git add .goreleaser.yaml docs/adr/ADR-005-ship-cli-binaries.md cmd/evtx/main.go cmd/evtx/main_test.go
git commit -F - <<'EOF'
build: ship the evtx binary, and record the posture change as ADR-005

builds[].main names ./cmd/evtx explicitly, so the two fixture generators
stay unshipped. GoReleaser's default ldflags already inject main.version;
the binary declares the matching variables.

Zero release assets was the correct outcome for a library and stops being
so here — that is what the ADR exists to record.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
```

---

### Task 7: the documentation set

**Files:**
- Create: `docs/adr/ADR-006-corpus-derived-format-method.md`
- Rewrite: `docs/PRD.md`
- Create: `docs/user-guide.md`
- Modify: `docs/index.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the CLI surface from Tasks 3-5, `Reader.FileInfo` from Task 2, ADR-005 from Task 6.
- Produces: no code.

**The measured figures every document must use, and must not round differently:**

| Fact | Value |
|---|---|
| Corpus files | 285 (`system.evtx` excluded) |
| Corpus records | 333 100 |
| `ReadEvent` succeeds | 332 894 — 99.938% before the FILETIME fix |
| Remaining failures after Task 1 | 26, all `AnsiString`, across 4 files |
| Records with an empty `Provider` | 1 |
| Writer conformance evidence | `ToXml` renders, both `Get-WinEvent` orderings enumerate, `EventLogReader` reads all 403, python-evtx agrees — all merge gates |

Re-run the measurement from Task 1 Step 10 before writing, and use the numbers
you actually obtained rather than these if they differ.

- [ ] **Step 1: Write ADR-006**

Create `docs/adr/ADR-006-corpus-derived-format-method.md`:

```markdown
# ADR-006 — Derive format rules from a corpus, not from one sample

**Status:** Accepted
**Date:** 2026-08-10

## Context

This format was implemented against another parser's behaviour before it was
implemented against its specification, and then validated against the single
file it had been derived from. Seventeen tasks went by with
`EventLogRecord.ToXml()` rejecting every file go-evtx wrote.

Two failure modes caused that, and neither is visible from inside the loop that
produces them:

- **Deriving a rule from one sample and asserting against that same sample.**
  The assertion cannot fail when the derivation is wrong.
- **A one-bit oracle.** "Does Windows accept this file?" cannot distinguish a
  wrong hypothesis from a right hypothesis aimed at the wrong field. F14 spent
  a whole task on that and concluded "unresolved"; F16 repeated it.

## Decision

Format rules are derived from a corpus of hundreds of real files, named
against a normative specification, confirmed on a Windows VM, and recorded by
CI. In that order.

- **The corpus derives.** `corpus_scan_test.go` and `corpus_shape_test.go`
  emit structural facts — counts, offsets, types, never string values — over
  every record, including the ones the decoder rejects. A rule is a claim about
  a distribution, quoted with its count.
- **The specification names.** [MS-EVEN6] and libyal/libevtx give the field its
  real name and meaning. `docs/evtx-format-notes.md` marks every claim as
  measured or read-from-source and keeps that distinction.
- **The VM confirms.** A Windows runner is the arbiter of acceptance, never of
  derivation.
- **CI records.** `docs/format-baseline.md` is append-only; a run is selected
  by `head_sha`, never by recency.

`isExcludedFixture` enforces the first rule mechanically: the corpus scan
refuses any file named `system.evtx`, the sample this project originally
derived everything from.

## Consequences

- **Rules carry their evidence.** "An `OptionalSubstitution` declares its
  field's own type while its array entry declares NULL" is backed by 27 million
  shape observations across 320 398 records, against zero occurrences of the
  shape go-evtx used to write. That is what F15 was, and it is what finally
  made `ToXml` render.
- **A permissive parser passing proves nothing.** python-evtx's own source
  says `TODO: use this size() field` for a field Windows enforces. An encoding
  choice is never justified by what a reader tolerates.
- **Facts are recorded for records the decoder rejects.** Measuring only what
  already decodes is the round-trip blindness that hid every v0.6.0 defect.
- **No string values leave the corpus.** Real logs carry account names, SIDs,
  machine names and IP addresses, and this output gets quoted in `docs/`.
- **A corpus is a developer's local directory.** These tests skip unless
  `EVTX_CORPUS` is set, so CI never runs them and no `.evtx` beyond the two
  tracked fixtures enters the repository.

## Alternatives considered

**Keep iterating against the Windows VM alone.** It is the fastest loop to set
up and the one that produced seventeen failed tasks. Rejected on that record.

**Trust the project's own written specification.** It claimed templates bucket
by `template_id % 32`. Measured against two real Windows files that scored 10
of 386 entries; the correct rule scores 386 of 386. Nobody had checked before
writing it down.
```

- [ ] **Step 2: Rewrite `docs/PRD.md`**

Replace the file entirely. Keep the existing section numbering and table style
(read the current file first), and make these changes:

- Header: `**Version:** 0.8.0`, `**Last updated:** 2026-08-10`.
- Section 3: replace the per-version delivered tables with one **Delivered**
  table covering the writer (W-01…W-13), the reader (R-01…R-08) and the CLI
  (C-01…C-05). Add rows for what shipped since 0.2.0: rotation
  (`RotationConfig`, `MaxFileSizeMB`, `MaxFileCount`, `RotationIntervalH`,
  `OnFsync`), the sticky error, `ErrMissingProviderName`, the generic decoder,
  `Reader.FileInfo`, and the two subcommands with their exit codes.
- Section 5, **Known limitations** — replace every row. The current table is
  wrong in both directions. The new rows:

  | Limitation | Impact | Status |
  |---|---|---|
  | The writer emits one event shape: one template, twelve fixed `<Data>` names, `Level`/`Task`/`Opcode`/`Keywords` pinned to 0, no `UserData`, no `Binary`, no typed values | Cannot represent an arbitrary Windows event. What it writes is accepted by Windows; what it can write is a fraction of what Windows writes | Largest open item; needs its own design |
  | `AnsiString` (type 0x02) is not decoded | 26 records across 4 of 285 corpus files fail to decode | Deliberate: the format carries no codepage, so any decoding would be a guess |
  | The 3.2 template bucket rule is unknown | None. go-evtx writes 3.1, and the reader resolves templates by offset, never by bucket | Documented gap |
  | `WriteRecord` and `WriteRaw` must not be mixed in one session | Caller contract, not enforced at runtime | Open |

- Section 4, **Non-functional requirements**: keep NF-01…NF-05, and update
  NF-04 to name the actual gates — `EventLogReader`, `EventLogRecord.ToXml()`,
  `Get-WinEvent` in both orderings, `wevtutil`, and python-evtx 0.8.1.
- Section 6: add ADR-005 and ADR-006 to the list.

- [ ] **Step 3: Write `docs/user-guide.md`**

Create it with these sections, each carrying runnable content:

1. **Install** — `go get github.com/fjacquet/go-evtx` for the library;
   `go install github.com/fjacquet/go-evtx/cmd/evtx@latest` or a release
   archive for the CLI.
2. **Read a file** — a complete `main` using `Open`, `ReadEvent`, the
   `ErrNoMoreRecords` loop, and `FileInfo`. Show reading `ev.System.EventID`,
   `ev.System.Provider.Name` and iterating `ev.EventData`.
3. **Write records** — a complete `main` using `New`, `WriteRecord` with the
   reserved keys (`ProviderName`, `Computer`, `Channel`, `TimeCreated`,
   `ProviderGuid`) and `Close`. State that `ProviderName` is mandatory.
4. **Rotation** — the `RotationConfig` table from `CLAUDE.md`, the archive name
   format `base-2006-01-02T15-04-05.000000000.evtx`, and the note that
   `OnFsync` must not call `Close`.
5. **The CLI** — `evtx dump` and `evtx info` with their flags, a sample of each
   output shape, the exit-code table, and a `jq` one-liner over the NDJSON.
6. **What this library cannot do** — the same four rows as the PRD's
   limitations table, in prose.
7. **Errors you will actually meet** — `ErrMissingProviderName` (what triggers
   it and why it is an error rather than a silent empty `<Provider>`),
   `ErrRecordTooLarge` (records are rejected, never truncated, because
   truncation would be checksum-invisible), and the sticky error (no automatic
   recovery; a half-rotated directory needs an operator and a new `Writer`).

Every Go snippet must compile. Verify by pasting each into a scratch file under
`/tmp` and running `go vet` on it before committing.

- [ ] **Step 4: Update `docs/index.md` and `README.md`**

In `docs/index.md`, add ADR-005 and ADR-006 to the decisions list, and add
links to the user guide and to the CLI section.

In `README.md`, add a `## Command line` section after the existing intro:
install line, the two subcommands with one example each, and a pointer to the
user guide. Keep the existing badges and the Windows-verification paragraph.

- [ ] **Step 5: Check every link resolves**

Run:

```bash
grep -oE '\]\([^)#][^)]*\)' README.md docs/index.md docs/PRD.md docs/user-guide.md \
  | sed -E 's/.*\((.*)\)/\1/' | grep -v '^http' | sort -u \
  | while read -r p; do [ -e "$p" ] || [ -e "docs/$p" ] || echo "MISSING: $p"; done
```

Expected: no `MISSING:` lines.

- [ ] **Step 6: Commit**

```bash
git add docs/ README.md
git commit -F - <<'EOF'
docs: rewrite the PRD, add ADR-006 and a user guide

The PRD said 0.2.0 and March, and its known-limitations table was wrong in
both directions: it listed gaps closed in v0.3-v0.7 and omitted the one
that bites, the writer's single event shape.

ADR-006 traces the method that ended the seventeen-task hunt — the corpus
derives, the specification names, the VM confirms, CI records. It lived
only in CLAUDE.md, which is agent instructions, not a decision record.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
```

---

### Task 8: godoc examples, CHANGELOG, release

**Files:**
- Modify: `example_test.go`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: everything from Tasks 1-7.
- Produces: the v0.8.0 release.

- [ ] **Step 1: Read the existing examples**

Run: `cat example_test.go`

Match their style exactly: each `Example…` function ends with an `// Output:`
comment whose text `go test` verifies. An example with no `// Output:` compiles
but never runs, which is the rot this task exists to avoid.

- [ ] **Step 2: Add two examples**

Append to `example_test.go`:

```go
// ExampleReader_FileInfo shows how to tell a go-evtx file from a
// Windows-written one: the format version is in the file header, and Windows
// Server 2025 writes 3.2 where this library writes 3.1.
func ExampleReader_FileInfo() {
	dir, err := os.MkdirTemp("", "evtx-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "example.evtx")

	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		log.Fatal(err)
	}
	if err := w.WriteRecord(4663, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "EXAMPLE-HOST",
	}); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	r, err := evtx.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	fi := r.FileInfo()
	fmt.Printf("format %d.%d, %d chunk(s), dirty=%t\n", fi.Major, fi.Minor, fi.Chunks, fi.Dirty)
	// Output: format 3.1, 1 chunk(s), dirty=false
}

// ExampleReader_ReadEvent_json shows the library's own JSON rendering, which
// is exactly what `evtx dump` emits: Event carries the tags and Value renders
// each type, so a consumer never has to reimplement either.
func ExampleReader_ReadEvent_json() {
	dir, err := os.MkdirTemp("", "evtx-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "example.evtx")

	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		log.Fatal(err)
	}
	if err := w.WriteRecord(4663, map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "EXAMPLE-HOST",
		"TimeCreated":  "2026-08-10T06:02:35Z",
	}); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	r, err := evtx.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	ev, err := r.ReadEvent()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d %s %s\n", ev.System.EventID, ev.System.Computer,
		ev.System.TimeCreated.UTC().Format(time.RFC3339))
	// Output: 4663 EXAMPLE-HOST 2026-08-10T06:02:35Z
}
```

Adjust the import block of `example_test.go` for `os`, `log`, `fmt`,
`path/filepath` and `time` if any are missing.

- [ ] **Step 3: Run the examples**

Run: `go test -race -run Example . -v`
Expected: PASS. If an `// Output:` line does not match, fix the *comment* to
the real output — never loosen the example to avoid the mismatch.

- [ ] **Step 4: Add the CHANGELOG entry**

In `CHANGELOG.md`, replace the empty `## [Unreleased]` section with a
`## [0.8.0] - 2026-08-10` section holding:

**Added**
- `evtx` command line binary with `dump` and `info`, shipped as a release
  artefact for linux/darwin/windows on amd64 and arm64. Install with
  `go install github.com/fjacquet/go-evtx/cmd/evtx@latest`. `dump` writes
  NDJSON in a faithful shape (the library's own `Event`) or a flat shape;
  exit code 2 when records were skipped, `--allow-errors` to suppress it.
  `info` reports the file header and a full decode pass with failures grouped
  by cause.
- `Reader.FileInfo` returning the format version, chunk count and the
  dirty/full flags.

**Fixed**
- FILETIME conversion covers the format's whole range. FILETIME 0 is
  1601-01-01T00:00:00Z and Windows writes it for an unset timestamp; both
  conversions routed the epoch offset through `int64` nanoseconds, which spans
  only 1678–2262, so `ReadEvent` rejected 180 records across 178 of the 285
  files in the local corpus. Records that previously failed to decode now
  decode.

Then add the compare links at the bottom of the file:

```
[Unreleased]: https://github.com/fjacquet/go-evtx/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/fjacquet/go-evtx/compare/v0.7.3...v0.8.0
```

and change the existing `[Unreleased]` line to point from `v0.8.0`.

- [ ] **Step 5: Full verification**

Run:

```bash
go test -race ./... -count=1 && \
go vet ./... && \
gofmt -l . && \
GOOS=windows go build ./... && \
golangci-lint run && \
goreleaser check
```

Expected: all pass, `gofmt -l` silent.

- [ ] **Step 6: Commit and open the pull request**

```bash
git add CHANGELOG.md example_test.go
git commit -F - <<'EOF'
docs: promote Unreleased to 0.8.0, add two runnable examples

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
git push -u origin feat/evtx-cli
gh pr create --title "feat: the evtx CLI, a rewritten doc set, and FILETIME over the whole range" --body-file - <<'EOF'
Two read-side subcommands, `Reader.FileInfo`, and the FILETIME fix that
measuring the CLI's exit-code policy uncovered.

## The fix that was not planned

`fromFILETIME` and `toFILETIME` both routed the epoch offset through int64
nanoseconds, which spans 1678-2262. FILETIME 0 is 1601, so `ReadEvent`
rejected it — 180 records across **178 of the 285** files in the local
corpus. Windows writes a zero FILETIME for an unset timestamp; the
rejection was our arithmetic, not the format.

## The CLI

`evtx dump` writes NDJSON, faithful shape by default (literally
`json.Marshal` on the library's `Event`) or flat behind `--shape=flat`.
`evtx info` reports the header and a decode pass with failures grouped by
cause.

Exit codes: 0 clean, 2 records skipped, 1 usage or unreadable input.

## Docs

ADR-005 records the posture change from library-only to shipping a
binary. ADR-006 traces the corpus-derived method. The PRD said 0.2.0 and
March; its known-limitations table was wrong in both directions.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01V4aa2erUpGicpwi3pPi6Ds
EOF
```

- [ ] **Step 7: Merge and release once CI is green**

Wait for `CI` and `Format Verify` to pass, confirming the run's `head_sha`
matches the commit under test rather than picking the most recent run:

```bash
gh pr checks --watch
gh pr merge --merge
git checkout main && git pull --ff-only
gh run list -c "$(git rev-parse HEAD)" --json name,conclusion,headSha \
  --jq '.[] | .name + " " + .conclusion + " " + .headSha[0:7]'
```

Then tag and warm the module proxy:

```bash
git tag -a v0.8.0 -m "v0.8.0"
git push origin v0.8.0
# Wait a minute before the first warm: a request that arrives before the proxy
# has seen the tag caches a negative entry, and @v/<version>.info then serves
# 404 for several minutes even while @latest and @v/list already know it.
sleep 60
GOPROXY=https://proxy.golang.org go list -m github.com/fjacquet/go-evtx@v0.8.0
```

Expected: `github.com/fjacquet/go-evtx v0.8.0`. A version appearing in
`@v/list` is **not** evidence it is consumable — `go get` reads `.info`.

---

## Self-review

**Spec coverage.** Every section of the spec maps to a task: the FILETIME fix
to Task 1, `Reader.FileInfo` to Task 2, the architecture and `info` to Task 3,
`dump --shape=event` and the exit codes to Task 4, the flat shape rules and the
corpus test to Task 5, the release posture and ADR-005 to Task 6, the remaining
documents to Task 7, the godoc examples and CHANGELOG to Task 8.

One spec item was dropped during planning and the spec was corrected to match:
`info` no longer prints a distinct-template count, which is unreachable from an
external package without exporting chunk internals.

One item was added: `toFILETIME` needs the same fix as `fromFILETIME`, because
`UnixNano` is equally undefined before 1678 — without it the 1601 round trip
the fix exists to enable would fail on the encode side.

**Type consistency.** `flatten(ev *evtx.Event) (map[string]any, int)` is used
with that signature in Task 4's `dump.go`, stubbed with it in Task 4 Step 4 and
implemented with it in Task 5. `runDump`, `runInfo` and `run` all take
`(args []string, stdout, stderr io.Writer) int`. `inputPath(in string, rest
[]string) (string, error)` and `normaliseCause(err error) string` are defined in
Task 3 and consumed in Task 4. `FileInfo`'s four fields are defined in Task 2
and read in Task 3's `runInfo`.
