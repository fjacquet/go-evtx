package main

import (
	"encoding/json"
	"strings"
	"testing"

	evtx "github.com/fjacquet/go-evtx"
)

func TestFlatten_PlainNameStaysItself(t *testing.T) {
	ev := &evtx.Event{
		RecordID: 7,
		System:   evtx.System{EventID: 4663, Computer: "TESTHOST"},
		EventData: []evtx.Data{
			{Name: "ObjectName"},
		},
	}
	flat, relocated, err := flatten(ev)
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	if relocated != 0 {
		t.Errorf("relocated = %d, want 0", relocated)
	}
	if _, ok := flat["ObjectName"]; !ok {
		t.Errorf("ObjectName missing; got keys %v", keysOf(flat))
	}
	if flat["computer"] != "TESTHOST" {
		t.Errorf("computer = %v, want TESTHOST", flat["computer"])
	}
	if flat["record_id"] != uint64(7) {
		t.Errorf("record_id = %v, want 7", flat["record_id"])
	}
}

// TestFlatten_CollisionWithSystemIsRenamed is the case the writer cannot
// produce and Windows can: a <Data Name="Computer"> beside System/Computer.
// The System value must survive untouched.
func TestFlatten_CollisionWithSystemIsRenamed(t *testing.T) {
	ev := &evtx.Event{
		System: evtx.System{Computer: "REAL-HOST"},
		EventData: []evtx.Data{
			{Name: "SubjectUserName"},
			{Name: "computer"},
		},
	}
	flat, relocated, err := flatten(ev)
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1", relocated)
	}
	if flat["computer"] != "REAL-HOST" {
		t.Errorf("System computer was overwritten: %v", flat["computer"])
	}
	if _, ok := flat["data_1_computer"]; !ok {
		t.Errorf("renamed key missing; got keys %v", keysOf(flat))
	}
}

func TestFlatten_UnnamedEntryUsesItsIndex(t *testing.T) {
	ev := &evtx.Event{
		EventData: []evtx.Data{
			{Name: "First"},
			{Name: ""},
			{Name: "Third"},
		},
	}
	flat, relocated, err := flatten(ev)
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1", relocated)
	}
	if _, ok := flat["data_1"]; !ok {
		t.Errorf("data_1 missing; got keys %v", keysOf(flat))
	}
}

func TestFlatten_RepeatedNameKeepsBoth(t *testing.T) {
	ev := &evtx.Event{
		EventData: []evtx.Data{
			{Name: "Param"},
			{Name: "Param"},
		},
	}
	flat, relocated, err := flatten(ev)
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1", relocated)
	}
	if _, ok := flat["Param"]; !ok {
		t.Errorf("first Param missing; got keys %v", keysOf(flat))
	}
	if _, ok := flat["data_1_Param"]; !ok {
		t.Errorf("second Param missing; got keys %v", keysOf(flat))
	}
}

// TestFlatten_ReservedSetIgnoresOmitempty guards the rule that makes the
// projection deterministic across records: a System key must be reserved even
// when this particular record leaves it at its zero value and omitempty drops
// it from the output. Without this, the same Data name would land in two
// different places in one file.
func TestFlatten_ReservedSetIgnoresOmitempty(t *testing.T) {
	ev := &evtx.Event{
		System:    evtx.System{}, // task is zero, so omitempty drops it
		EventData: []evtx.Data{{Name: "task"}},
	}
	flat, relocated, err := flatten(ev)
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1 — 'task' is a System key whether or not this record carries one", relocated)
	}
	if _, ok := flat["data_0_task"]; !ok {
		t.Errorf("renamed key missing; got keys %v", keysOf(flat))
	}
}

// TestFlatten_GeneratedKeyDoesNotOverwrite covers the case the rule used to
// lose silently: a Data entry literally named data_3 at index 0, and an
// unnamed entry at index 3 whose generated key is also data_3. Writing the
// generated key unconditionally made the second overwrite the first while
// relocated counted it as a successful rename.
//
// Value carries no exported constructor, so the two entries are told apart by
// the keys they land under rather than by their values: what is at stake is
// that four entries produce four keys, not three.
func TestFlatten_GeneratedKeyDoesNotOverwrite(t *testing.T) {
	ev := &evtx.Event{
		EventData: []evtx.Data{
			{Name: "data_3"}, // index 0, owns the name a later entry will generate
			{Name: "B"},
			{Name: "C"},
			{Name: ""}, // index 3, generates data_3
		},
	}
	flat, relocated, err := flatten(ev)
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1 (only the unnamed entry is renamed)", relocated)
	}
	for _, k := range []string{"data_3", "B", "C", "data_3_2"} {
		if _, ok := flat[k]; !ok {
			t.Errorf("%s missing — an entry was silently overwritten; got keys %v", k, keysOf(flat))
		}
	}
}

// The reserved set is checked for the generated key too, not just for the
// entry's own name: data_0_timestamp would otherwise land on the root
// timestamp the projection puts there.
func TestFlatten_GeneratedKeyAvoidsReserved(t *testing.T) {
	ev := &evtx.Event{
		EventData: []evtx.Data{{Name: "record_id"}},
	}
	// Pin the premise: if this key ever stops being reserved the test below
	// stops testing anything.
	if !reservedKeys["data_0_record_id"] {
		reservedKeys["data_0_record_id"] = true
		defer delete(reservedKeys, "data_0_record_id")
	}
	flat, relocated, err := flatten(ev)
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1", relocated)
	}
	if _, ok := flat["data_0_record_id_2"]; !ok {
		t.Errorf("generated key collided with a reserved key; got keys %v", keysOf(flat))
	}
}

// TestFlatten_LargeKeywordsKeepsEveryDigit pins the precision of a uint64 that
// exceeds float64's 53-bit mantissa. It asserts on the marshalled bytes rather
// than on a re-parsed value, because parsing the output back through the same
// lossy path would hide the very defect this guards.
//
// 0x8000000000000000 is not a contrived value: the top Keywords bit is set on
// nearly every real Windows event. Before the fix, flatten decoded System into
// a map[string]any, which turns each JSON number into a float64, and the mask
// came back out as 9223372036854776000 — a silently wrong value in the shape
// meant for ingestion. No test caught it because every fixture this package
// writes carries Keywords 0.
func TestFlatten_LargeKeywordsKeepsEveryDigit(t *testing.T) {
	const (
		keywords = uint64(0x8000000000000000)
		exact    = "9223372036854775808"
	)
	ev := &evtx.Event{System: evtx.System{Keywords: keywords}}

	flat, _, err := flatten(ev)
	if err != nil {
		t.Fatalf("flatten: %v", err)
	}
	b, err := json.Marshal(flat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `"keywords":` + exact; !strings.Contains(string(b), want) {
		t.Errorf("flat output does not carry %s exactly.\ngot: %s", want, b)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
