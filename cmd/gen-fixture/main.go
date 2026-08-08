// Command gen-fixture writes a .evtx file and a JSON description of what a
// correct parser must find in it. Both CI verification jobs consume the pair,
// so the expectations cannot drift from the fixture.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	evtx "github.com/fjacquet/go-evtx"
)

type expected struct {
	RecordCount int      `json:"record_count"`
	EventIDs    []int    `json:"event_ids"`
	ObjectNames []string `json:"object_names"`
}

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()

	path := filepath.Join(*out, "generated.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	var exp expected
	// Enough records to span several chunks, with content a parser can check.
	for i := 0; i < 400; i++ {
		objectName := fmt.Sprintf(`C:\logs\file-%03d.txt`, i)
		switch i % 4 {
		case 1:
			objectName = `C:\journaux\fichier-é-à-ü.txt` // non-ASCII, BMP
		case 2:
			objectName = `C:\logs\emoji-🔥-` + fmt.Sprint(i) // non-BMP, surrogate pair
		case 3:
			objectName = `C:\logs\` + strings.Repeat("w", 2000) // long, but well under the limit
		}
		fields := map[string]string{
			"SubjectUserName": "verifier",
			"ObjectName":      objectName,
			"ObjectType":      "File",
			"TimeCreated":     "2026-08-08T12:00:00Z",
		}
		if err := w.WriteRecord(4663, fields); err != nil {
			fatal(fmt.Errorf("record %d: %w", i, err))
		}
		exp.RecordCount++
		exp.EventIDs = append(exp.EventIDs, 4663)
		exp.ObjectNames = append(exp.ObjectNames, objectName)
	}

	if err := w.Close(); err != nil {
		fatal(err)
	}

	blob, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "expected.json"), blob, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (%d records)\n", path, exp.RecordCount)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-fixture:", err)
	os.Exit(1)
}
