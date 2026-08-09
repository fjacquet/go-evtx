// Command gen-ladder-four-string builds task 9e's secondary rung
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9e-report.md),
// batched into the same CI run as cmd/gen-ladder-all-string: production's
// own declared types unchanged, EXCEPT for the four substitutions whose
// types were never independently verified as strings —
// Security/@UserID, Execution/@ProcessID, Execution/@ThreadID, Keywords —
// each forced to StringType (0x01) the same way cmd/gen-ladder-all-string
// forces all 42.
//
// These four carry the least evidence of any declared type in the whole
// template: task-8b-report.md's own Step 1 type table was later shown
// wrong at exactly these positions (F14, task 8e's correction note — a
// byte-for-byte re-parse of the real record the table cites found these
// indices declared type 0x00/NULL in the real file, not the table's
// claimed GUID/SID/UNSIGNED_WORD types; go-evtx's own production encoding
// for three of the four is binXMLTypeNull, matching the real file, while
// Keywords is HEXINT64 with an always-zero value). If cmd/gen-ladder-all-string
// renders and this narrower variant does too, the search narrows further
// for free in the same run; if the all-string variant fails and this one
// passes, the defect is isolated to one of these four fields without a
// further bisect task.
//
// Uses evtx.BuildVariantBinXML plus the existing, unmodified Writer.WriteRaw
// — same pattern as cmd/gen-ladder-all-string. Does NOT touch
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

	path := filepath.Join(*out, "ladder-four-string.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	const eventID = 4663
	const recordID = 1 // first record of a fresh Writer (Writer.recordID starts at 1)

	// Same field set as cmd/gen-ladder-all-string, so the two rungs differ
	// in exactly the one variable each is named for.
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
	payload := evtx.BuildVariantBinXML(evtx.VariantFourFieldsString, eventID, recordID, fields, binXMLChunkOffset)

	if err := w.WriteRaw(payload); err != nil {
		fatal(fmt.Errorf("write four-string record via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 record, System + EventData with 12 Data pairs, UserID/ProcessID/ThreadID/Keywords declared StringType, %d bytes BinXML)\n", path, len(payload))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-ladder-four-string:", err)
	os.Exit(1)
}
