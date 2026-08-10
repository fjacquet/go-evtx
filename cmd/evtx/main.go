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
	"regexp"
	"strings"
)

// version is replaced at release time by GoReleaser's default ldflags,
// which inject -X main.version=<tag>.
var version = "dev"

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
	// The dump case arrives with dump.go; usage below documents only what
	// this switch can actually serve.
	case "info":
		return runInfo(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		_, _ = fmt.Fprintln(stdout, version)
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
  evtx info [--in FILE] [FILE]
  evtx version

info reports the file header and the result of a full decode pass.
It exits 0 unless the input is unreadable.
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

// digits matches every run of decimal digits in an error message.
var digits = regexp.MustCompile(`[0-9]+`)

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
	return digits.ReplaceAllString(msg, "N")
}
