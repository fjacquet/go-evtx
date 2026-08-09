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
	// MaxObjectNameLen is the rune count of the near-maximum ObjectName
	// actually written (see largestAccepted below), so the baseline this
	// fixture produces can state the size range it covers.
	MaxObjectNameLen int `json:"max_object_name_len"`
}

// probeCeiling bounds the search in largestAccepted. It is deliberately far
// past any plausible maxRecordPayload so that hitting it means the search
// never found a real ceiling, not that the ceiling is unusually large.
const probeCeiling = 40000

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()

	// Probe the real ceiling before writing the fixture that depends on it.
	// Hardcoding a length would silently stop being a boundary case the
	// moment maxRecordPayload changes -- which Task 6 of this release does
	// (8-byte alignment shrinks it by 7 bytes).
	maxLen := largestAccepted()
	if maxLen == probeCeiling {
		fatal(fmt.Errorf("largestAccepted: no rejection found up to %d runes; "+
			"the search range no longer brackets maxRecordPayload", probeCeiling))
	}

	path := filepath.Join(*out, "generated.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}

	var exp expected
	exp.MaxObjectNameLen = maxLen

	write := func(objectName string) {
		fields := map[string]string{
			"SubjectUserName": "verifier",
			"ObjectName":      objectName,
			"ObjectType":      "File",
			"TimeCreated":     "2026-08-08T12:00:00Z",
		}
		if err := w.WriteRecord(4663, fields); err != nil {
			fatal(fmt.Errorf("record %d: %w", exp.RecordCount, err))
		}
		exp.RecordCount++
		exp.EventIDs = append(exp.EventIDs, 4663)
		exp.ObjectNames = append(exp.ObjectNames, objectName)
	}

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
		write(objectName)
	}

	// Boundary cases. The evtx package exports no size constants (New,
	// WriteRecord and Close are the whole surface this command consumes),
	// so both records below are sized from maxLen, the empirically probed
	// ceiling, rather than from hardcoded byte counts.

	// Near-maximum record: exactly the longest ObjectName largestAccepted
	// found acceptable. No path prefix, unlike the loop above -- adding one
	// would make this record's ObjectName longer than what was probed, and
	// the whole point is that this field is exactly at the accepted edge.
	write(strings.Repeat("w", maxLen))

	// Chunk-fill boundary: two records each sized to comfortably more than
	// half of a chunk's payload capacity. maxRecordPayload and
	// maxChunkPayload differ only by the fixed 28-byte record header/trailer,
	// so halving the probed record ceiling is effectively halving the chunk
	// ceiling too. 55% rather than a literal 50% leaves margin so two of
	// these can never both fit in one chunk regardless of small overhead
	// changes elsewhere in the record -- writing the second is guaranteed to
	// flush the chunk holding the first and start a new one, exercising the
	// flush-then-recompute-offset path in WriteRecord. Do not merge these
	// into the main loop or "simplify" them to a single record: their sizing
	// relative to each other, not their content, is the point.
	halfLen := maxLen * 11 / 20
	write(strings.Repeat("h", halfLen))
	write(strings.Repeat("h", halfLen))

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
	fmt.Printf("wrote %s (%d records, max ObjectName %d runes)\n", path, exp.RecordCount, maxLen)
}

// largestAccepted binary-searches the longest ObjectName the writer will take.
// Hardcoding a length would silently stop being a boundary case the moment
// maxRecordPayload changes -- which Task 6 of this release does.
func largestAccepted() int {
	// This is a find-last-true bisection: it assumes lo=1 is accepted and
	// only searches for where acceptance stops. That assumption is never
	// checked by the loop below -- if the writer rejected even a 1-rune
	// ObjectName, the loop would still return lo=1 unchanged, main's
	// probeCeiling guard would pass (1 != probeCeiling), and the generator
	// would report success while writing a fixture with no boundary coverage
	// at all. Probe it explicitly and fail loudly rather than silently
	// trusting the assumption.
	const lo0 = 1
	if !acceptsObjectName(lo0) {
		fatal(fmt.Errorf("largestAccepted: writer rejected a %d-rune ObjectName; "+
			"the binary search's lower-bound assumption does not hold", lo0))
	}

	lo, hi := lo0, probeCeiling // hi is deliberately past any plausible limit
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if acceptsObjectName(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// acceptsObjectName reports whether the writer accepts a single WriteRecord
// call carrying an ObjectName of n runes. It writes to a throwaway file in
// its own temp directory, used only for this probe and removed before
// returning.
func acceptsObjectName(n int) bool {
	dir, err := os.MkdirTemp("", "gen-fixture-probe")
	if err != nil {
		fatal(fmt.Errorf("probe temp dir: %w", err))
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			fatal(fmt.Errorf("probe cleanup: %w", err))
		}
	}()

	w, err := evtx.New(filepath.Join(dir, "probe.evtx"), evtx.RotationConfig{})
	if err != nil {
		fatal(fmt.Errorf("probe writer: %w", err))
	}
	// The probe's own signal is WriteRecord's error, not Close's; a close
	// failure on a throwaway file is not this probe's concern to report.
	defer func() { _ = w.Close() }()

	fields := map[string]string{
		"SubjectUserName": "verifier",
		"ObjectName":      strings.Repeat("w", n),
		"ObjectType":      "File",
		"TimeCreated":     "2026-08-08T12:00:00Z",
	}
	return w.WriteRecord(4663, fields) == nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-fixture:", err)
	os.Exit(1)
}
