// Command gen-ladder-no-xmlns builds task 9d's secondary rung 2
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9d-report.md):
// an xmlns-free variant.
//
// This fixture is the control's own shape (<System> plus <EventData> with
// all 12 substituted-name Data pairs, production's own <System> convention
// unchanged — same scale as cmd/gen-ladder-all-normal-sub, differing only
// in this one variable) with <Event>'s xmlns attribute (F8, task 8) removed
// entirely: <Event> becomes a plain no-attributes element (token 0x01, no
// attribute list at all), not merely an attribute list with an empty/absent
// xmlns entry (evtx.VariantNoXmlns, binxml_variants.go).
//
// F8 (xmlns) was established necessary for python-evtx (task 8: fixed
// ObjectName extraction from 0/403 to green) but a prior hybrid (task 9b
// H1, real body+subs + go-evtx's own preamble) only arguably cleared the
// preamble as a factor — xmlns itself has never been independently varied.
// This fixture is EXPECTED to break python-evtx, which queries with a
// namespaced XPath (scripts/verify_python_evtx.py) — deliberately given its
// own fixture and its own CI jobs, so that expected Linux failure does not
// gate or obscure this fixture's independent Windows (Get-WinEvent/ToXml)
// result.
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

	path := filepath.Join(*out, "ladder-no-xmlns.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	const eventID = 4663
	const recordID = 1 // first record of a fresh Writer (Writer.recordID starts at 1)

	// Same field set as cmd/gen-ladder-all-normal-sub, so the two secondary
	// rungs differ in exactly the one variable each is named for.
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
	payload := evtx.BuildVariantBinXML(evtx.VariantNoXmlns, eventID, recordID, fields, binXMLChunkOffset)

	if err := w.WriteRaw(payload); err != nil {
		fatal(fmt.Errorf("write no-xmlns record via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 record, System + EventData with 12 Data pairs, no xmlns attribute on Event, %d bytes BinXML)\n", path, len(payload))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-ladder-no-xmlns:", err)
	os.Exit(1)
}
