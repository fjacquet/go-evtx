// Command gen-ladder-all-string builds task 9e's decisive experiment
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9e-report.md):
// every one of the control's 42 substitutions declared as StringType
// (0x01), the value formatted the way it would render in XML.
//
// Task 9d found no size boundary anywhere in go-evtx's own template
// (task 9c's ladder, every rung from <System> alone up to the full control
// fails identically) and could not build its own decisive all-literal
// experiment at all — MS-EVEN6's own grammar has no ValueText production
// for a non-string type, so every typed scalar go-evtx or real Windows has
// ever written MUST be a substitution (verified against
// testdata/system.evtx: 35/35 real substitutions there are typed, 15/15
// real literals are all StringType, zero exceptions). What remained
// unisolated, across every measurement this release has made, is the
// declared VALUE TYPE of each substitution.
//
// This fixture is the control's own shape (<System> plus <EventData> with
// all 12 substituted-name Data pairs, xmlns present, production's own
// OptionalSubstitution/dependency_id convention unchanged — that axis was
// already isolated as a null result by task 9d's VariantAllNormalSubstitution)
// with every substitution's declared type forced to StringType — the most
// permissive type, already proven renderable by task 9a's splice
// experiment (Windows rendered string content from go-evtx's own container
// without complaint) — and its value reformatted to text (decimal digits
// for an integer, hex for Keywords, ISO-8601 for the FILETIME, empty
// string for a field with no source). See evtx.VariantAllString
// (binxml_variants.go) for the exact per-field rendering rules.
//
// If this renders, the defect is a type mismatch on one specific
// substitution — a very small target for the next task's bisect. If it
// still fails, value types are exonerated as a category and what remains
// is the template body's own element/token encoding.
//
// Uses evtx.BuildVariantBinXML plus the existing, unmodified Writer.WriteRaw
// — same pattern as cmd/gen-ladder-no-xmlns. Does NOT touch
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

	path := filepath.Join(*out, "ladder-all-string.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	const eventID = 4663
	const recordID = 1 // first record of a fresh Writer (Writer.recordID starts at 1)

	// Same field set as cmd/gen-ladder-all-normal-sub and
	// cmd/gen-ladder-no-xmlns, so all of task 9d/9e's control-scale rungs
	// differ from each other in exactly the one variable each is named for.
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
	payload := evtx.BuildVariantBinXML(evtx.VariantAllString, eventID, recordID, fields, binXMLChunkOffset)

	if err := w.WriteRaw(payload); err != nil {
		fatal(fmt.Errorf("write all-string record via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 record, System + EventData with 12 Data pairs, every substitution declared StringType, %d bytes BinXML)\n", path, len(payload))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-ladder-all-string:", err)
	os.Exit(1)
}
