// Command gen-hybrid-preamble-real builds Task 9b's Hybrid 2 from the v0.7.0
// format-correctness release
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9b-report.md):
// the exact record cmd/gen-fixture-minimal writes (go-evtx's own encoder, own
// body, own substitution array -- currently failing Get-WinEvent/ToXml), with
// ONLY its outer preamble's identity fields (template_id and the TemplateNode
// GUID) replaced by testdata/system.evtx chunk 0 record 0's real values.
// Everything else stays exactly what go-evtx's own encoder produces.
//
// This is Hybrid 1's mirror image: Hybrid 1 asks "does using go-evtx's own
// trivial template_id/GUID matter, holding the rest at real bytes"; this asks
// "does using the real file's own template_id/GUID matter, holding the rest
// at go-evtx's own (currently failing) bytes." Symmetric, and just as
// offset-safe with no rewriting -- see gen-hybrid-preamble-ours's doc comment
// for why: these two fields are pure identity/cache metadata, referenced by
// nothing else in either payload.
//
// Does NOT touch cmd/gen-fixture/main.go, cmd/gen-fixture-minimal/main.go, or
// testdata/system.evtx.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	evtx "github.com/fjacquet/go-evtx"
)

func buildOurs(tmpDir string) ([]byte, error) {
	path := filepath.Join(tmpDir, "ours-source.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		return nil, err
	}
	fields := map[string]string{
		"ProviderName":    "Microsoft-Windows-Security-Auditing",
		"Computer":        "TESTHOST",
		"TimeCreated":     "2026-01-01T00:00:00Z",
		"SubjectUserName": "tester",
		"ObjectName":      `C:\test\file.txt`,
		"ObjectType":      "File",
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	r, err := evtx.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return r.ReadRaw()
}

func main() {
	out := flag.String("out", ".", "output directory")
	src := flag.String("src", "testdata/system.evtx", "source .evtx file to take the real template_id/GUID from")
	flag.Parse()

	tmpDir, err := os.MkdirTemp("", "gen-hybrid-preamble-real-")
	if err != nil {
		fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	ours, err := buildOurs(tmpDir)
	if err != nil {
		fatal(fmt.Errorf("build ours: %w", err))
	}

	r, err := evtx.Open(*src)
	if err != nil {
		fatal(fmt.Errorf("open source %s: %w", *src, err))
	}
	real, err := r.ReadRaw()
	_ = r.Close()
	if err != nil {
		fatal(fmt.Errorf("read %s record 0: %w", *src, err))
	}
	if len(ours) < 38 || len(real) < 38 {
		fatal(fmt.Errorf("payload too short: ours=%d real=%d", len(ours), len(real)))
	}

	hybrid := make([]byte, len(ours))
	copy(hybrid, ours)

	// TemplateInstanceNode.template_id: bytes [6:10]. Copy real's own value.
	copy(hybrid[6:10], real[6:10])
	// TemplateNode header GUID: bytes [18:34]. Copy real's own 16 bytes.
	copy(hybrid[18:34], real[18:34])

	// data_length [34:38] and everything from 38 onward (body + substitution
	// array) is untouched -- still go-evtx's own bytes.
	if binary.LittleEndian.Uint32(hybrid[34:38]) != binary.LittleEndian.Uint32(ours[34:38]) {
		fatal(fmt.Errorf("internal error: data_length must stay unchanged"))
	}

	path := filepath.Join(*out, "hybrid-preamble-real.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}
	if err := w.WriteRaw(hybrid); err != nil {
		fatal(fmt.Errorf("write hybrid via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 hybrid record, %d bytes: go-evtx's own minimal-fixture BinXML with template_id/GUID replaced by real %s chunk 0 record 0's values, body+subs untouched)\n",
		path, len(hybrid), *src)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-hybrid-preamble-real:", err)
	os.Exit(1)
}
