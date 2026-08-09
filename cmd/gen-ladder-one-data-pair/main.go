// Command gen-ladder-one-data-pair builds ladder rung 2 of the v0.7.0
// format-correctness release's task 9c
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9c-report.md):
// "shrink our own record until it renders."
//
// This rung is <System> (identical shape to rung 1, cmd/gen-ladder-system-only)
// plus <EventData> containing exactly ONE <Data Name="%N">%N+1</Data> pair —
// both Name and Value as NormalSubstitution, the same per-pair convention
// production's own 12-pair loop uses (evtx.VariantEventDataOnePair,
// binxml_variants.go). Isolates "does EventData's presence at all break
// rendering" from "does its full 12-pair size" by sitting strictly between
// rung 1 (no EventData) and rung 3 (the existing minimal fixture's full
// 12-pair EventData, cmd/gen-fixture-minimal / the generate-minimal +
// get-winevent-minimal jobs already in this workflow).
//
// Uses evtx.BuildVariantBinXML plus the existing, unmodified Writer.WriteRaw
// — same pattern as cmd/gen-ladder-system-only. Does NOT touch
// cmd/gen-fixture/main.go, its output, or binxml.go's own
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

	path := filepath.Join(*out, "ladder-one-data-pair.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	const eventID = 4663
	const recordID = 1 // first record of a fresh Writer (Writer.recordID starts at 1)

	fields := map[string]string{
		"ProviderName":   "Microsoft-Windows-Security-Auditing",
		"Computer":       "TESTHOST",
		"TimeCreated":    "2026-01-01T00:00:00Z", // fixed, not time.Now() -- a stable, reproducible probe
		"Channel":        "Security",
		"ProviderGuid":   "{54849625-5478-4994-A5BA-3E3B0328C30D}",
		"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-512", // dataFieldNames[0] -- the one pair this rung writes
	}

	// binXMLChunkOffset: see cmd/gen-ladder-system-only's own doc comment.
	const binXMLChunkOffset = 512 + 24
	payload := evtx.BuildVariantBinXML(evtx.VariantEventDataOnePair, eventID, recordID, fields, binXMLChunkOffset)

	if err := w.WriteRaw(payload); err != nil {
		fatal(fmt.Errorf("write one-data-pair record via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 record, System + EventData with 1 Data pair, %d bytes BinXML)\n", path, len(payload))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-ladder-one-data-pair:", err)
	os.Exit(1)
}
