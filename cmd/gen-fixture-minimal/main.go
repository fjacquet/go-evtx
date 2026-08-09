// Command gen-fixture-minimal writes the smallest .evtx fixture the public
// API can produce: one record, one chunk, pure ASCII field values, and a
// fixed timestamp. No oversized or boundary-case records, no non-BMP
// strings, no multi-chunk rotation.
//
// This is Experiment A from the v0.7.0 format-correctness release
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9a-report.md):
// every prior Windows measurement used the 403-record, 21+-chunk fixture
// cmd/gen-fixture produces, which carries a lot of surface for a bisect. This
// command is a second, deliberately minimal fixture, run through the same
// Windows probes (see .github/workflows/format-verify.yml's
// get-winevent-minimal job) so a render failure can be localised to
// "something only the big fixture exercises" or "the simplest record this
// library can produce," which are very different next steps.
//
// Does NOT touch cmd/gen-fixture/main.go or its output -- that fixture must
// stay byte-identical so the release's existing measurement table keeps
// comparing. This is an addition alongside it, not a replacement.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	evtx "github.com/fjacquet/go-evtx"
)

// expected is what a correct parser must find in minimal.evtx.
type expected struct {
	RecordCount int    `json:"record_count"`
	EventID     int    `json:"event_id"`
	ObjectName  string `json:"object_name"`
}

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()

	path := filepath.Join(*out, "minimal.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	const eventID = 4663
	const objectName = `C:\test\file.txt`

	// Every value below is plain ASCII, unlike cmd/gen-fixture's fixture,
	// which deliberately includes BMP and non-BMP (surrogate-pair) strings.
	fields := map[string]string{
		"ProviderName":    "Microsoft-Windows-Security-Auditing",
		"Computer":        "TESTHOST",
		"TimeCreated":     "2026-01-01T00:00:00Z", // fixed, not time.Now() -- a stable, reproducible probe
		"SubjectUserName": "tester",
		"ObjectName":      objectName,
		"ObjectType":      "File",
	}
	if err := w.WriteRecord(eventID, fields); err != nil {
		fatal(fmt.Errorf("write record: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	exp := expected{RecordCount: 1, EventID: eventID, ObjectName: objectName}
	blob, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "minimal-expected.json"), blob, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (1 record, 1 chunk, ASCII)\n", path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-fixture-minimal:", err)
	os.Exit(1)
}
