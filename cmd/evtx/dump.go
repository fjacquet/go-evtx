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

	// The input is opened before the output is created. os.Create truncates,
	// so the other order destroys an existing --out file and then exits 1 when
	// the input turns out not to be readable — a typo in --in costing the
	// previous dump.
	r, err := evtx.Open(path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "evtx dump: %v\n", err)
		return 1
	}
	defer func() { _ = r.Close() }()

	w := stdout
	if *out != "" {
		// os.Create truncates, so --out naming the input destroys the file
		// being read. Checked after the input opens, and by identity rather
		// than by string: ./f.evtx and /abs/f.evtx, or a symlink and its
		// target, are the same file spelled two ways.
		if same, err := sameFile(path, *out); err != nil {
			_, _ = fmt.Fprintf(stderr, "evtx dump: %v\n", err)
			return 1
		} else if same {
			_, _ = fmt.Fprintf(stderr, "evtx dump: --out %s is the input file; it would be truncated before it is read\n", *out)
			return 1
		}
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

	enc := json.NewEncoder(w)
	total, skipped, relocated := 0, 0, 0
	for {
		ev, err := r.ReadEvent()
		if errors.Is(err, evtx.ErrNoMoreRecords) {
			break
		}
		// A chunk that cannot be loaded ends the stream early: the records
		// after it are not skipped, they are unread, and the file has not been
		// dumped. That is an unreadable input (exit 1), not a record-level
		// skip (exit 2), and --allow-errors does not cover it — it suppresses
		// "some records were skipped", never "the file was not finished".
		if errors.Is(err, evtx.ErrChunkUnreadable) {
			_, _ = fmt.Fprintf(stderr, "evtx dump: %v\n", err)
			_, _ = fmt.Fprintf(stderr, "evtx dump: stopped after %d records; the file was not read to the end\n", total)
			return 1
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
			flat, moved, ferr := flatten(ev)
			if ferr != nil {
				// Handled exactly like a decode failure on one record: a line
				// on stderr keeping the record's identity, that record left
				// out of the stream, and the exit code that says records were
				// skipped. Emitting a partial projection instead would be the
				// silent loss this shape exists not to do.
				skipped++
				_, _ = fmt.Fprintf(stderr, "go_evtx: record %d: %v\n", ev.RecordID, ferr)
				continue
			}
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
