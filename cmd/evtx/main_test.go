package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestInputPath(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		rest    []string
		want    string
		wantErr bool
	}{
		{"flag only", "a.evtx", nil, "a.evtx", false},
		{"positional only", "", []string{"a.evtx"}, "a.evtx", false},
		{"both is a usage error", "a.evtx", []string{"b.evtx"}, "", true},
		{"neither is a usage error", "", nil, "", true},
		{"two positionals is a usage error", "", []string{"a.evtx", "b.evtx"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inputPath(tc.in, tc.rest)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("inputPath(%q, %v) = %q, want an error", tc.in, tc.rest, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("inputPath(%q, %v): %v", tc.in, tc.rest, err)
			}
			if got != tc.want {
				t.Errorf("inputPath(%q, %v) = %q, want %q", tc.in, tc.rest, got, tc.want)
			}
		})
	}
}

// TestNormaliseCause pins the grouping rule: two failures of the same kind at
// different positions are one cause, not two. Without this an info report
// would print one line per record, which is what makes 206 failures
// unreadable and 2 lines useful.
func TestNormaliseCause(t *testing.T) {
	a := errors.New("go_evtx: chunk 0, record 2: go_evtx: FILETIME 0 is out of range")
	b := errors.New("go_evtx: chunk 314, record 62400: go_evtx: FILETIME 0 is out of range")
	if normaliseCause(a) != normaliseCause(b) {
		t.Errorf("causes differ:\n  %q\n  %q", normaliseCause(a), normaliseCause(b))
	}
	if strings.Contains(normaliseCause(a), "chunk") {
		t.Errorf("cause still carries its position: %q", normaliseCause(a))
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"frobnicate"}, &out, &errb); code != 1 {
		t.Errorf("run(frobnicate) = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "unknown subcommand") {
		t.Errorf("stderr = %q, want it to name the unknown subcommand", errb.String())
	}
}

func TestRun_NoArgs(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 1 {
		t.Errorf("run(nil) = %d, want 1", code)
	}
}

func TestRun_Version(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("run(version) = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "evtx ") {
		t.Errorf("stdout = %q, want it to name the binary and its version", out.String())
	}
}
