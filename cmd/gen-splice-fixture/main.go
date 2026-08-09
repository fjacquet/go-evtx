// Command gen-splice-fixture builds Experiment B from the v0.7.0
// format-correctness release
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9a-report.md):
// does Windows accept a REAL record's BinXML, extracted from
// testdata/system.evtx, written into one of go-evtx's own chunks via
// WriteRaw? Seventeen record-level format fixes landed this release without
// moving Get-WinEvent/ToXml; this settles whether go-evtx's file/chunk
// *container* is sound independently of its own BinXML *generation* --
// nothing measured before this task distinguishes those two.
//
// # Which record, and why no offset rewriting was needed
//
// A real record's BinXML contains chunk-relative offsets (name_offset,
// template_offset) that are only valid at the position they were written.
// Naively splicing an arbitrary record would place those offsets next to
// data they no longer point at, and a resulting Windows failure would prove
// nothing.
//
// This command always takes chunk 0's record 0 -- the first record
// Open+ReadRaw returns -- deliberately, not arbitrarily: it is the first
// record ever written into that chunk, so by construction every name and
// template it references must be introduced inline, within its own payload
// bytes. Nothing precedes it in the chunk's data area for it to reference
// instead. This was verified, not assumed: a structural walk of its BinXML
// (every OpenStartElementTag/Attribute name_offset and the
// TemplateInstanceNode's template_offset, following the exact token layout
// this project already confirmed against the same file -- see binxml.go's
// F9-F15 notes) found 27 name_offset references and 1 template_offset,
// every one resolving inside the record's own byte range. Full trace in
// task-9a-report.md.
//
// Writer.WriteRaw's own first call on a fresh file places its record at the
// identical chunk-relative offset a real file's chunk 0 record 0 occupies:
// 512 (chunk header) + 24 (record header) = 536. So the extracted bytes
// need no rewriting at all -- copied verbatim, every internal reference
// lands exactly where it pointed in the source file. This is option 1 from
// the experiment's own preference order (find a self-relative record) over
// option 2 (rewrite offsets) or option 3 (decline the experiment).
//
// Does NOT touch cmd/gen-fixture/main.go, its output, or testdata/system.evtx.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	evtx "github.com/fjacquet/go-evtx"
)

func main() {
	out := flag.String("out", ".", "output directory")
	src := flag.String("src", "testdata/system.evtx", "source .evtx file to splice a record from")
	flag.Parse()

	payload, err := extractFirstRecord(*src)
	if err != nil {
		fatal(err)
	}

	path := filepath.Join(*out, "spliced.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}
	if err := w.WriteRaw(payload); err != nil {
		fatal(fmt.Errorf("splice record via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 spliced record, %d bytes of real BinXML from %s chunk 0 record 0)\n",
		path, len(payload), *src)
}

// extractFirstRecord returns chunk 0's record 0 raw BinXML payload from a
// source .evtx file -- the first record Open+ReadRaw returns, and the record
// this command's own doc comment establishes is self-contained.
func extractFirstRecord(src string) ([]byte, error) {
	r, err := evtx.Open(src)
	if err != nil {
		return nil, fmt.Errorf("open source %s: %w", src, err)
	}
	defer func() { _ = r.Close() }()

	payload, err := r.ReadRaw()
	if err != nil {
		return nil, fmt.Errorf("read %s record 0: %w", src, err)
	}
	return payload, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-splice-fixture:", err)
	os.Exit(1)
}
