// Command gen-ladder-all-normal-sub builds task 9d's secondary rung 1
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9d-report.md):
// "all OptionalSubstitution (0x0E) replaced by NormalSubstitution (0x0D),
// dependency identifiers set to the 'not set' sentinel."
//
// This fixture is the control's own shape (<System> plus <EventData> with
// all 12 substituted-name Data pairs — production's own convention,
// identical scale to cmd/gen-fixture-minimal's real WriteRecord output)
// with every OptionalSubstitution token binxml.go's <System> block uses
// (task 8b/F12c, task 8c/F13a) reverted to NormalSubstitution, and every
// element/attribute dependency_id that used to tie to a real substitution
// index reset to depIDNotSet (0xffff) instead (evtx.VariantAllNormalSubstitution,
// binxml_variants.go).
//
// 0x0E was adopted from reading the real file (testdata/system.evtx) but
// has never itself been isolated as the one variable under test — every
// measurement since task 8b changed 0x0E alongside something else (a type
// width, a Qualifiers attribute, a Provider/@Guid). This fixture changes
// nothing else.
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

	path := filepath.Join(*out, "ladder-all-normal-sub.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	const eventID = 4663
	const recordID = 1 // first record of a fresh Writer (Writer.recordID starts at 1)

	// All 12 data fields populated, matching cmd/gen-ladder-literal-dataname's
	// own control-scale field set (rung 4) so this fixture is comparable to
	// it, not just to the smaller rungs.
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
	payload := evtx.BuildVariantBinXML(evtx.VariantAllNormalSubstitution, eventID, recordID, fields, binXMLChunkOffset)

	if err := w.WriteRaw(payload); err != nil {
		fatal(fmt.Errorf("write all-normal-sub record via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 record, System + EventData with 12 Data pairs, all OptionalSubstitution reverted to NormalSubstitution, %d bytes BinXML)\n", path, len(payload))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-ladder-all-normal-sub:", err)
	os.Exit(1)
}
