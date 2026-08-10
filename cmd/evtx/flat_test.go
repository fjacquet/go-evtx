package main

import (
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
	flat, relocated := flatten(ev)
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
	flat, relocated := flatten(ev)
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
	flat, relocated := flatten(ev)
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
	flat, relocated := flatten(ev)
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
	flat, relocated := flatten(ev)
	if relocated != 1 {
		t.Errorf("relocated = %d, want 1 — 'task' is a System key whether or not this record carries one", relocated)
	}
	if _, ok := flat["data_0_task"]; !ok {
		t.Errorf("renamed key missing; got keys %v", keysOf(flat))
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
