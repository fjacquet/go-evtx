package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	evtx "github.com/fjacquet/go-evtx"
)

func runInfo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "input .evtx file")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	path, err := inputPath(*in, fs.Args())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evtx info: %v\n", err)
		return 1
	}

	r, err := evtx.Open(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evtx info: %v\n", err)
		return 1
	}
	defer func() { _ = r.Close() }()

	fi := r.FileInfo()

	// A decode failure is reported for that record alone and the reader stays
	// positioned on the next one, so the walk continues rather than stopping
	// at the first surprise — measuring only what already decodes is how this
	// project used to miss its own defects.
	total, failed := 0, 0
	causes := map[string]int{}
	var fatal error
	for {
		_, err := r.ReadEvent()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		// A chunk that cannot be loaded is not a decode failure to be tallied:
		// it means the pass never reached the end of the file, so "N failures"
		// would be a count over records that were never read. Reported as
		// itself, and the command exits non-zero — the input could not be
		// read.
		if errors.Is(err, evtx.ErrChunkUnreadable) {
			fatal = err
			break
		}
		total++
		if err != nil {
			failed++
			causes[normaliseCause(err)]++
		}
	}

	_, _ = fmt.Fprintf(stdout, "file       %s\n", filepath.Base(path))
	_, _ = fmt.Fprintf(stdout, "format     %d.%d\n", fi.Major, fi.Minor)
	_, _ = fmt.Fprintf(stdout, "chunks     %d\n", fi.Chunks)
	_, _ = fmt.Fprintf(stdout, "flags      dirty=%t full=%t\n", fi.Dirty, fi.Full)
	_, _ = fmt.Fprintf(stdout, "records    %d\n", total)
	_, _ = fmt.Fprintf(stdout, "decode     %d/%d records, %d failures\n", total-failed, total, failed)
	for _, c := range sortedCauses(causes) {
		_, _ = fmt.Fprintf(stdout, "           %6d  %s\n", causes[c], c)
	}
	if fatal != nil {
		// Printed after the report rather than instead of it: the header facts
		// and the records that did decode are still true and still useful, and
		// the line below is what stops them being read as the whole file.
		_, _ = fmt.Fprintf(stdout, "read       incomplete after %d records\n", total)
		_, _ = fmt.Fprintf(stderr, "evtx info: %v\n", fatal)
		return 1
	}
	return 0
}

// sortedCauses orders causes by descending count, then by text, so that two
// runs over the same file print the same report.
func sortedCauses(causes map[string]int) []string {
	out := make([]string, 0, len(causes))
	for c := range causes {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if causes[out[i]] != causes[out[j]] {
			return causes[out[i]] > causes[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}
