package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	evtx "github.com/fjacquet/go-evtx"
)

func runDump(args []string, stdout, stderr io.Writer) (code int) {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "input .evtx file")
	out := fs.String("out", "", "output file; stdout when empty")
	shape := fs.String("shape", "event", "output shape: event or flat")
	allowErrors := fs.Bool("allow-errors", false, "exit 0 even when records were skipped")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *shape != "event" && *shape != "flat" {
		_, _ = fmt.Fprintf(stderr, "evtx dump: unknown --shape %q, want event or flat\n", *shape)
		return 1
	}
	path, err := inputPath(*in, fs.Args())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evtx dump: %v\n", err)
		return 1
	}

	w := stdout
	if *out != "" {
		f, err := os.Create(*out) // #nosec G304 — an operator-supplied output path
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "evtx dump: %v\n", err)
			return 1
		}
		// Close is checked, not discarded: a write failure that only surfaces
		// at close — a flush failure, a quota, an NFS write-back error — must
		// not leave the process exiting 0 over a short or corrupt --out file.
		// This overrides whatever exit code the rest of the function computed:
		// a close failure means the artefact on disk cannot be trusted no
		// matter how many records decoded cleanly before it.
		defer func() {
			if cerr := f.Close(); cerr != nil {
				_, _ = fmt.Fprintf(stderr, "evtx dump: %v\n", cerr)
				code = 1
			}
		}()
		w = f
	}

	r, err := evtx.Open(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evtx dump: %v\n", err)
		return 1
	}
	defer func() { _ = r.Close() }()

	enc := json.NewEncoder(w)
	total, skipped, relocated := 0, 0, 0
	for {
		ev, err := r.ReadEvent()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		total++
		if err != nil {
			// One line per skipped record, on stderr, keeping the position
			// ReadEvent already put in the message. The stream on stdout stays
			// pure NDJSON so a pipeline never has to filter it.
			skipped++
			_, _ = fmt.Fprintf(stderr, "%v\n", err)
			continue
		}
		var payload any = ev
		if *shape == "flat" {
			flat, moved := flatten(ev)
			payload, relocated = flat, relocated+moved
		}
		if err := enc.Encode(payload); err != nil {
			_, _ = fmt.Fprintf(stderr, "evtx dump: %v\n", err)
			return 1
		}
	}

	if skipped > 0 {
		_, _ = fmt.Fprintf(stderr, "%d of %d records failed to decode\n", skipped, total)
	}
	if relocated > 0 {
		_, _ = fmt.Fprintf(stderr, "%d event_data keys were renamed to avoid a collision\n", relocated)
	}
	if skipped > 0 && !*allowErrors {
		return 2
	}
	return 0
}
