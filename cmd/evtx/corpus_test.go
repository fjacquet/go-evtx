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
