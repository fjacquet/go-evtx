// Command gen-ladder-literal-dataname builds ladder rung 4 of the v0.7.0
// format-correctness release's task 9c
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9c-report.md):
// "shrink our own record until it renders."
//
// This rung is NOT smaller than the control (rung 3, cmd/gen-fixture-minimal
// through production's real WriteRecord, already in this workflow as the
// generate-minimal / get-winevent-minimal jobs) — it is the SAME scale
// (<System> plus <EventData> with all 12 Data pairs) with exactly one
// variable changed: each <Data>'s Name attribute is written as a literal
// ValueText (the same convention F8's xmlns attribute already uses) instead
// of a NormalSubstitution. Only each pair's Value is still substituted
// (evtx.VariantEventDataLiteralNames, binxml_variants.go).
//
// This is a specific, named hypothesis, not a hex-dump guess: a BinXML
// template is meant to be the fixed shape, with only VALUES varying between
// instances. go-evtx currently puts the 12 Data element NAMES into
// substitution slots too. MS-EVEN6 does permit substitutions in attribute
// values, so this is a hypothesis worth testing as one ladder rung next to
// its own control, not a standalone fix.
//
// Uses evtx.BuildVariantBinXML plus the existing, unmodified Writer.WriteRaw
// — same pattern as cmd/gen-ladder-system-only/cmd/gen-ladder-one-data-pair.
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

	path := filepath.Join(*out, "ladder-literal-dataname.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	const eventID = 4663
	const recordID = 1 // first record of a fresh Writer (Writer.recordID starts at 1)

	// All 12 data fields populated, like the control (cmd/gen-fixture-minimal
	// leaves most empty; this rung fills every one so a real value backs
	// every literal-named Data element).
	fields := map[string]string{
		"ProviderName":      "Microsoft-Windows-Security-Auditing",
		"Computer":          "TESTHOST",
		"TimeCreated":       "2026-01-01T00:00:00Z", // fixed, not time.Now() -- a stable, reproducible probe
		"Channel":           "Security",
		"ProviderGuid":      "{54849625-5478-4994-A5BA-3E3B0328C30D}",
		"SubjectUserSid":    "S-1-5-21-1004336348-1177238915-682003330-512",
		"SubjectUserName":   "tester",
		"SubjectDomainName": "TESTHOST",
		"SubjectLogonId":    "0x3e7",
		"ObjectServer":      "Security",
		"ObjectType":        "File",
		"ObjectName":        `C:\test\file.txt`,
		"HandleId":          "0x1234",
		"AccessList":        "%%1537",
		"AccessMask":        "0x10000",
		"ProcessId":         "0x4d8",
		"ProcessName":       `C:\Windows\explorer.exe`,
	}

	// binXMLChunkOffset: see cmd/gen-ladder-system-only's own doc comment.
	const binXMLChunkOffset = 512 + 24
	payload := evtx.BuildVariantBinXML(evtx.VariantEventDataLiteralNames, eventID, recordID, fields, binXMLChunkOffset)

	if err := w.WriteRaw(payload); err != nil {
		fatal(fmt.Errorf("write literal-dataname record via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 record, System + EventData with 12 Data pairs, literal Names, %d bytes BinXML)\n", path, len(payload))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-ladder-literal-dataname:", err)
	os.Exit(1)
}
