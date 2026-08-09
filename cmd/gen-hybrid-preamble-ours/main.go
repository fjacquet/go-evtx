// Command gen-hybrid-preamble-ours builds Task 9b's Hybrid 1 from the v0.7.0
// format-correctness release
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9b-report.md):
// Experiment B's real record (testdata/system.evtx chunk 0 record 0,
// self-contained -- see cmd/gen-splice-fixture), with ONLY its outer
// preamble's identity fields (template_id and the TemplateNode GUID)
// replaced by go-evtx's own trivial values (template_id=1, GUID = 01 00 00
// 00 followed by 12 zero bytes -- exactly what binxml.go's buildBinXML
// writes). Everything else -- the entire template body and substitution
// array -- is byte-identical to the real record that Experiment B already
// proved Windows accepts.
//
// # Why this is offset-safe with no rewriting
//
// template_id and the TemplateNode GUID are pure identity/cache metadata:
// nothing in the template body or substitution array references them by
// value (only name_offset and template_offset reference chunk POSITIONS, and
// this command changes no position, no length -- only two field VALUES, in
// place). The chunk's hash tables are irrelevant here too: WriteRaw never
// populates them (see cmd/gen-splice-fixture's own doc comment), so nothing
// downstream depends on template_id/GUID matching any hash bucket. This
// isolates one narrow question cut point 1 (the brief's "fixed preamble")
// asks: does USING go-evtx's own (trivial, low-entropy) template_id/GUID
// values, as opposed to a real file's own values, matter to Windows on its
// own -- holding literally everything else at the real, already-passing
// bytes?
//
// Does NOT touch cmd/gen-fixture/main.go, cmd/gen-splice-fixture/main.go, or
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

func main() {
	out := flag.String("out", ".", "output directory")
	src := flag.String("src", "testdata/system.evtx", "source .evtx file to take the real preamble+body+subs from")
	flag.Parse()

	r, err := evtx.Open(*src)
	if err != nil {
		fatal(fmt.Errorf("open source %s: %w", *src, err))
	}
	payload, err := r.ReadRaw()
	_ = r.Close()
	if err != nil {
		fatal(fmt.Errorf("read %s record 0: %w", *src, err))
	}
	if len(payload) < 38 {
		fatal(fmt.Errorf("record 0 payload too short (%d bytes)", len(payload)))
	}

	hybrid := make([]byte, len(payload))
	copy(hybrid, payload)

	// TemplateInstanceNode.template_id: bytes [6:10] (token(1)@4 + unknown0(1)@5 + template_id(4)@6..10).
	binary.LittleEndian.PutUint32(hybrid[6:10], 1)
	// TemplateNode header GUID: bytes [18:34] (next_offset(4)@14..18 + GUID(16)@18..34).
	// buildBinXML: guid := make([]byte, 16); binary.LittleEndian.PutUint32(guid, 1) -- first 4 bytes = template_id, rest zero.
	for i := 18; i < 34; i++ {
		hybrid[i] = 0
	}
	binary.LittleEndian.PutUint32(hybrid[18:22], 1)

	// data_length [34:38] and everything from 38 onward (body + substitution
	// array) is untouched -- still the real record's own bytes.

	if binary.LittleEndian.Uint32(hybrid[34:38]) != binary.LittleEndian.Uint32(payload[34:38]) {
		fatal(fmt.Errorf("internal error: data_length must stay unchanged"))
	}

	path := filepath.Join(*out, "hybrid-preamble-ours.evtx")
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

	fmt.Printf("wrote %s (1 hybrid record, %d bytes: real %s chunk 0 record 0 BinXML with template_id/GUID replaced by go-evtx's own trivial values, body+subs untouched)\n",
		path, len(hybrid), *src)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-hybrid-preamble-ours:", err)
	os.Exit(1)
}
