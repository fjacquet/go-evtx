// Command gen-ladder-system-only builds ladder rung 1 of the v0.7.0
// format-correctness release's task 9c
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9c-report.md):
// "shrink our own record until it renders" — emit progressively smaller
// variants THROUGH go-evtx's own encoder (no grafting) and find the largest
// one Get-WinEvent accepts.
//
// This rung is the smallest: <Event><System>...</System></Event> with no
// <EventData> element at all, and only the 18 substitutions <System>
// itself needs (evtx.VariantSystemOnly, binxml_variants.go). <System>'s own
// content is byte-for-byte the same shape task 9b already confirmed matches
// testdata/system.evtx exactly (14 children, same order, same types) — this
// rung tests only "does removing EventData entirely let Windows render the
// record," holding everything else fixed.
//
// Uses evtx.BuildVariantBinXML (exported for exactly this purpose — see its
// own doc comment) plus the existing, unmodified Writer.WriteRaw, the same
// pattern cmd/gen-splice-fixture and cmd/gen-hybrid-* already established.
// Does NOT touch cmd/gen-fixture/main.go, its output, or binxml.go's own
// buildBinXML/buildTemplateBody.
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
	flag.Parse()

	path := filepath.Join(*out, "ladder-system-only.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	const eventID = 4663
	const recordID = 1 // first record of a fresh Writer (Writer.recordID starts at 1)

	fields := map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "TESTHOST",
		"TimeCreated":  "2026-01-01T00:00:00Z", // fixed, not time.Now() -- a stable, reproducible probe
		"Channel":      "Security",
		"ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
	}

	// binXMLChunkOffset: the first record of a fresh chunk sits at
	// 512 (chunk header) + 24 (record header) = 536 -- the same value
	// WriteRaw's own first call places a record at on an empty Writer, per
	// cmd/gen-splice-fixture's own doc comment.
	const binXMLChunkOffset = 512 + 24
	payload := evtx.BuildVariantBinXML(evtx.VariantSystemOnly, eventID, recordID, fields, binXMLChunkOffset)

	if err := w.WriteRaw(payload); err != nil {
		fatal(fmt.Errorf("write system-only record via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 record, System-only, no EventData, %d bytes BinXML)\n", path, len(payload))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-ladder-system-only:", err)
	os.Exit(1)
}
