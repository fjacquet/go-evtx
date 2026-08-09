package evtx

// corpus_shape_test.go — the shape census.
//
// What it does: walk a corpus of real .evtx files through the decoder's shape
// hook (see shapeEvent in binxml_decode.go), count how often each distinct
// structural shape occurs, and write the totals as a derived, non-identifying
// JSON file.
//
// What it is for: go-evtx's encoder was built by imitating one sample file.
// A census over hundreds of thousands of real records re-derives every rule
// that sample supplied, and — the point — makes "go-evtx emits a shape no real
// record emits" a mechanical query rather than an intuition.
//
// testdata/system.evtx is never read: isExcludedFixture skips it, and the
// reason is in that function's comment.
//
// Usage:
//
//	EVTX_CORPUS=/dir/one:/dir/two go test -run TestCorpusShapeCensus -v .
//
// Writes to $EVTX_SHAPE_OUT, default testdata/shape-census.json.

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// censusRow is one shape and how often the corpus contains it. Flattened from
// shapeEvent so the JSON reads as a table, and ordered deterministically by
// censusRows so the committed file only changes when the measurement does.
type censusRow struct {
	Kind        string `json:"kind"`
	Token       string `json:"token"`
	DepSet      bool   `json:"dep_set,omitempty"`
	DataSizeNil bool   `json:"data_size_zero,omitempty"`
	EmptyClose  bool   `json:"empty_close,omitempty"`
	HasValue    bool   `json:"has_value,omitempty"`
	HasChildren bool   `json:"has_children,omitempty"`
	AttrPos     string `json:"attr_pos,omitempty"`
	Declared    string `json:"declared_type,omitempty"`
	Actual      string `json:"array_type,omitempty"`
	Count       int    `json:"count"`
}

func toCensusRow(e shapeEvent, count int) censusRow {
	r := censusRow{
		Kind:        e.Kind,
		Token:       fmt.Sprintf("%#02x", e.Token),
		DepSet:      e.DepSet,
		DataSizeNil: e.DataSizeNil,
		EmptyClose:  e.EmptyClose,
		HasValue:    e.HasValue,
		HasChildren: e.HasChildren,
		AttrPos:     e.AttrPos,
		Count:       count,
	}
	switch e.Kind {
	case shapeKindSubstitution, shapeKindLiteral, shapeKindAttribute:
		r.Actual = e.Actual.String()
	}
	if e.Kind == shapeKindSubstitution || e.Kind == shapeKindLiteral {
		r.Declared = e.Declared.String()
	}
	return r
}

// censusRows flattens and sorts a tally. The sort is total and content-based,
// never map order, so re-running on the same corpus rewrites an identical file.
func censusRows(tally map[shapeEvent]int) []censusRow {
	rows := make([]censusRow, 0, len(tally))
	for e, n := range tally {
		rows = append(rows, toCensusRow(e, n))
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch {
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		case a.Token != b.Token:
			return a.Token < b.Token
		case a.Declared != b.Declared:
			return a.Declared < b.Declared
		case a.Actual != b.Actual:
			return a.Actual < b.Actual
		case a.AttrPos != b.AttrPos:
			return a.AttrPos < b.AttrPos
		case a.DepSet != b.DepSet:
			return b.DepSet
		case a.DataSizeNil != b.DataSizeNil:
			return b.DataSizeNil
		case a.EmptyClose != b.EmptyClose:
			return b.EmptyClose
		case a.HasValue != b.HasValue:
			return b.HasValue
		default:
			return b.HasChildren
		}
	})
	return rows
}

// censusCorpus walks every .evtx file under each root and tallies the shapes
// its records produce. Records the decoder rejects still contribute every
// shape emitted before the rejection: a census that only counted clean records
// would be blind exactly where the format is unusual.
func censusCorpus(t *testing.T, roots []string) (tally map[shapeEvent]int, files int) {
	t.Helper()
	tally = map[shapeEvent]int{}
	onShape := func(e shapeEvent) { tally[e]++ }

	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".evtx") {
				return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
			}
			if isExcludedFixture(p) {
				t.Logf("skip %s: excluded as evidence", filepath.Base(p))
				return nil
			}
			files++
			if scanErr := scanEVTX(p, files, func(any) {}, onShape); scanErr != nil {
				t.Logf("skip %s: %v", filepath.Base(p), scanErr)
				files--
				return nil
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return tally, files
}

func TestCorpusShapeCensus(t *testing.T) {
	roots := os.Getenv("EVTX_CORPUS")
	if roots == "" {
		t.Skip("set EVTX_CORPUS to one or more colon-separated directories of real .evtx files")
	}
	tally, files := censusCorpus(t, filepath.SplitList(roots))
	if len(tally) == 0 {
		t.Fatal("no shapes counted: the corpus produced no decodable records at all")
	}

	rows := censusRows(tally)
	total := 0
	for _, r := range rows {
		total += r.Count
	}

	outPath := os.Getenv("EVTX_SHAPE_OUT")
	if outPath == "" {
		outPath = filepath.Join("testdata", "shape-census.json")
	}
	out, err := os.Create(outPath) // #nosec G304 — a developer-supplied output path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rows); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d files, %d distinct shapes, %d observations -> %s", files, len(rows), total, outPath)
}

// TestShapeDiffTarget profiles one file through the same hook and reports
// every shape it emits that the committed census never saw. That list is the
// point of this whole apparatus: a shape absent from 27 million observations
// of real Windows output, present in ours, is a candidate defect rather than
// an opinion.
//
//	EVTX_SHAPE_TARGET=/path/to/generated.evtx go test -run TestShapeDiffTarget -v .
func TestShapeDiffTarget(t *testing.T) {
	target := os.Getenv("EVTX_SHAPE_TARGET")
	if target == "" {
		t.Skip("set EVTX_SHAPE_TARGET to the .evtx file to compare against the census")
	}
	censusPath := os.Getenv("EVTX_SHAPE_CENSUS")
	if censusPath == "" {
		censusPath = filepath.Join("testdata", "shape-census.json")
	}
	raw, err := os.ReadFile(censusPath) // #nosec G304 — a developer-supplied path
	if err != nil {
		t.Fatalf("read census: %v", err)
	}
	var rows []censusRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("parse census: %v", err)
	}
	known := make(map[censusRow]int, len(rows))
	for _, r := range rows {
		c := r.Count
		r.Count = 0
		known[r] = c
	}

	tally := map[shapeEvent]int{}
	if err := scanEVTX(target, 0, func(any) {}, func(e shapeEvent) {
		tally[e]++
	}); err != nil {
		t.Fatalf("scan %s: %v", target, err)
	}

	var unseen, rare []string
	for _, r := range censusRows(tally) {
		mine := r.Count
		r.Count = 0
		switch n, ok := known[r]; {
		case !ok:
			unseen = append(unseen, fmt.Sprintf("  NEVER SEEN  x%-7d %+v", mine, r))
		case n < 1000:
			rare = append(rare, fmt.Sprintf("  rare (%d in corpus)  x%-7d %+v", n, mine, r))
		}
	}
	t.Logf("%s: %d distinct shapes", filepath.Base(target), len(tally))
	if len(unseen) == 0 {
		t.Logf("no shape in %s is absent from the census", filepath.Base(target))
	}
	for _, s := range unseen {
		t.Log(s)
	}
	for _, s := range rare {
		t.Log(s)
	}
}
