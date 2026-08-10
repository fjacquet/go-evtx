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
