// Command evtx reads Windows Event Log (.evtx) files.
//
// It is a thin shell over the go-evtx library: dump serialises records through
// the library's own Event type and its MarshalJSON, and info reports the file
// header plus a decode pass. Nothing here reimplements the format.
//
// Usage:
//
//	evtx dump [--in FILE] [--out FILE] [--shape=event|flat] [--allow-errors] [FILE]
//	evtx info [--in FILE] [FILE]
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Injected at release time by GoReleaser's default ldflags. They keep their
// placeholder values in a `go install` or `go build` binary, which is correct:
// such a build has no release identity to report.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a subcommand and returns the process exit code. Keeping this
// separate from main is what lets the tests assert exit codes without
// spawning a process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 1
	}
	switch args[0] {
	case "dump":
		return runDump(args[1:], stdout, stderr)
	case "info":
		return runInfo(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		_, _ = fmt.Fprintf(stdout, "evtx %s (commit %s, built %s)\n", version, commit, date)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "evtx: unknown subcommand %q\n", args[0])
		usage(stderr)
		return 1
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `evtx reads Windows Event Log (.evtx) files.

Usage:
  evtx dump [--in FILE] [--out FILE] [--shape=event|flat] [--allow-errors] [FILE]
  evtx info [--in FILE] [FILE]
  evtx version

dump writes one JSON object per record (NDJSON) to stdout or --out.
info reports the file header and the result of a full decode pass.

Exit codes for dump: 0 all records decoded, 2 some were skipped,
1 usage error or unreadable input. info exits 0 unless the input is
unreadable.
`)
}

// inputPath resolves --in against a positional argument. Supplying both is an
// error rather than a silent preference: a typo in one of them would otherwise
// look like it worked.
func inputPath(in string, rest []string) (string, error) {
	switch {
	case in != "" && len(rest) > 0:
		return "", fmt.Errorf("give the input either as --in or as an argument, not both")
	case in != "":
		return in, nil
	case len(rest) == 1:
		return rest[0], nil
	case len(rest) == 0:
		return "", fmt.Errorf("no input file")
	default:
		return "", fmt.Errorf("expected one input file, got %d", len(rest))
	}
}

// sameFile reports whether two paths name the same file on disk.
//
// os.SameFile is the authority when both paths exist: it compares the device
// and inode, so a symlink, a hard link and a relative spelling all resolve to
// the same answer. When the second path does not exist yet — the ordinary case
// for an output file — there is nothing to stat, and cleaned absolute paths are
// compared instead, which still catches the relative-versus-absolute spelling
// of one file.
func sameFile(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err == nil {
		return os.SameFile(ai, bi), nil
	}
	if !os.IsNotExist(err) {
		return false, err
	}
	absA, err := filepath.Abs(a)
	if err != nil {
		return false, err
	}
	absB, err := filepath.Abs(b)
	if err != nil {
		return false, err
	}
	return filepath.Clean(absA) == filepath.Clean(absB), nil
}

// positions matches the position fields the library attaches to an error: the
// "chunk N, record N" prefix ReadEvent wraps every per-record failure with, and
// the "at [chunk ]offset N" a framing error carries. Only these are erased.
//
// Every run of digits used to be replaced, which merged causes that are
// genuinely different — two unsupported value types, say — into one line of the
// tally, hiding one of them behind the other's count. A number that is part of
// what went wrong is part of the cause.
var positions = regexp.MustCompile(`\b(chunk|record|offset) [0-9]+`)

// normaliseCause reduces a per-record error to its cause so that failures of
// the same kind group together. ReadEvent wraps each failure with its position
// ("chunk 314, record 62400: ..."), and without this reduction a report would
// print one line per record — which is what makes 206 failures unreadable and
// two lines useful.
func normaliseCause(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, "go_evtx: "); i >= 0 {
		msg = msg[i+len("go_evtx: "):]
	}
	return positions.ReplaceAllString(msg, "$1 N")
}
