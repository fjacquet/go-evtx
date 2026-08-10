package evtx

// systemfields_test.go — the numeric <System> children a caller supplies
// through the fields map: Level, Version, Task, Opcode and Keywords.
//
// Until v0.7.4 all five were literal zeros and their fields-map keys were
// dropped without a word, so a caller passing Level=4 got a file whose Event
// Viewer Level column was blank and nothing anywhere said why (issue #13).
// These tests pin both halves of the fix: the values reach the file, and a
// value that cannot be encoded is an error rather than a quiet zero.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// systemFieldsBase is the minimum a record needs to be written at all.
func systemFieldsBase() map[string]string {
	return map[string]string{
		"ProviderName": "Microsoft-Windows-Security-Auditing",
		"Computer":     "TESTHOST",
		"Channel":      "Security",
	}
}

// writeOneRecord writes a single record and returns the file path.
func writeOneRecord(t *testing.T, fields map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "system-fields.evtx")
	w, err := New(path, RotationConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// TestWriteRecord_NumericSystemFieldsRoundTrip is the issue #13 case. The
// values are the ones Win32 ReportEvent produces for
// EVENTLOG_INFORMATION_TYPE, which is what the reporter compared against:
// Level 4 renders as "Information" and Keywords 0x80000000000000 as "Classic"
// through mappings built into Windows, with no provider manifest needed.
func TestWriteRecord_NumericSystemFieldsRoundTrip(t *testing.T) {
	fields := systemFieldsBase()
	fields["Level"] = "4"
	fields["Version"] = "1"
	fields["Task"] = "12800"
	fields["Opcode"] = "2"
	fields["Keywords"] = "0x80000000000000"

	r, err := Open(writeOneRecord(t, fields))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	ev, err := r.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if ev.System.Level != 4 {
		t.Errorf("Level = %d, want 4", ev.System.Level)
	}
	if ev.System.Version != 1 {
		t.Errorf("Version = %d, want 1", ev.System.Version)
	}
	if ev.System.Task != 12800 {
		t.Errorf("Task = %d, want 12800", ev.System.Task)
	}
	if ev.System.Opcode != 2 {
		t.Errorf("Opcode = %d, want 2", ev.System.Opcode)
	}
	if ev.System.Keywords != 0x80000000000000 {
		t.Errorf("Keywords = %#x, want 0x80000000000000", ev.System.Keywords)
	}
}

// TestWriteRecord_NumericSystemFieldsDefaultToZero keeps the pre-v0.7.4
// behaviour for a caller that supplies none of them: zero is a legitimate
// value for all five, and Version 0 is what the sampled real Windows record
// carries.
func TestWriteRecord_NumericSystemFieldsDefaultToZero(t *testing.T) {
	r, err := Open(writeOneRecord(t, systemFieldsBase()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	ev, err := r.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if ev.System.Level != 0 || ev.System.Version != 0 || ev.System.Task != 0 ||
		ev.System.Opcode != 0 || ev.System.Keywords != 0 {
		t.Errorf("unsupplied fields did not default to zero: level=%d version=%d task=%d opcode=%d keywords=%#x",
			ev.System.Level, ev.System.Version, ev.System.Task, ev.System.Opcode, ev.System.Keywords)
	}
}

// TestWriteRecord_KeywordsAcceptsDecimal covers the other spelling. Windows
// displays Keywords in hex, so that is the form a caller copies, but a decimal
// value must work too rather than being silently misread.
func TestWriteRecord_KeywordsAcceptsDecimal(t *testing.T) {
	fields := systemFieldsBase()
	fields["Keywords"] = "36028797018963968" // 0x80000000000000

	r, err := Open(writeOneRecord(t, fields))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	ev, err := r.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if ev.System.Keywords != 0x80000000000000 {
		t.Errorf("Keywords = %#x, want 0x80000000000000", ev.System.Keywords)
	}
}

// TestWriteRecord_InvalidNumericFieldIsRejected is the half of issue #13 that
// matters most: silence was the defect. A value that cannot be encoded must
// reach the caller as an error at the point of the mistake, the same stance
// ErrMissingProviderName takes, rather than becoming a quiet zero.
func TestWriteRecord_InvalidNumericFieldIsRejected(t *testing.T) {
	cases := []struct {
		key   string
		value string
		why   string
	}{
		{"Level", "quatre", "not a number at all"},
		{"Level", "256", "exceeds a uint8"},
		{"Level", "-1", "negative"},
		{"Task", "65536", "exceeds a uint16"},
		{"Opcode", "300", "exceeds a uint8"},
		{"Version", "1.0", "not an integer"},
		{"Keywords", "0xZZ", "not valid hex"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			fields := systemFieldsBase()
			fields[tc.key] = tc.value

			path := filepath.Join(t.TempDir(), "rejected.evtx")
			w, err := New(path, RotationConfig{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = w.WriteRecord(4663, fields)
			if !errors.Is(err, ErrInvalidFieldValue) {
				t.Fatalf("WriteRecord with %s=%q (%s) = %v, want ErrInvalidFieldValue",
					tc.key, tc.value, tc.why, err)
			}
			// Nothing may have been written: a rejected record must leave the
			// writer exactly as it was, the same contract ErrRecordTooLarge has.
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if _, statErr := os.Stat(path); statErr == nil {
				t.Error("a file was created for a session whose only record was rejected")
			}
		})
	}
}

// TestParseSystemUint covers the helper directly, including the empty and
// absent cases that must not be errors.
func TestParseSystemUint(t *testing.T) {
	cases := []struct {
		name    string
		fields  map[string]string
		key     string
		bits    int
		want    uint64
		wantErr bool
	}{
		{"absent key is zero", map[string]string{}, "Level", 8, 0, false},
		{"empty value is zero", map[string]string{"Level": ""}, "Level", 8, 0, false},
		{"decimal", map[string]string{"Level": "4"}, "Level", 8, 4, false},
		{"hex", map[string]string{"Keywords": "0x8000000000000000"}, "Keywords", 64, 0x8000000000000000, false},
		{"uint8 upper bound", map[string]string{"Level": "255"}, "Level", 8, 255, false},
		{"uint8 overflow", map[string]string{"Level": "256"}, "Level", 8, 0, true},
		{"not a number", map[string]string{"Task": "soon"}, "Task", 16, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSystemUint(tc.fields, tc.key, tc.bits)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidFieldValue) {
					t.Fatalf("parseSystemUint = (%d, %v), want ErrInvalidFieldValue", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSystemUint: %v", err)
			}
			if got != tc.want {
				t.Errorf("parseSystemUint = %d, want %d", got, tc.want)
			}
		})
	}
}
