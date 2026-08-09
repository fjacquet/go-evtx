package evtx

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustVal(t *testing.T, typ ValueType, data []byte) Value {
	t.Helper()
	v, err := decodeValue(typ, data)
	if err != nil {
		t.Fatalf("decodeValue: %v", err)
	}
	return v
}

func TestEventFromNode(t *testing.T) {
	root := &Node{Name: "Event", Children: []Node{
		{Name: "System", Children: []Node{
			{Name: "Provider", Attributes: []Attr{
				{Name: "Name", Value: mustVal(t, ValString, utf16le("Microsoft-Windows-Security-Auditing"))},
			}},
			{Name: "EventID", Value: ptrVal(mustVal(t, ValUInt16, []byte{0x10, 0x12}))},
			{Name: "Level", Value: ptrVal(mustVal(t, ValUInt8, []byte{0x04}))},
			{Name: "Computer", Value: ptrVal(mustVal(t, ValString, utf16le("WIN-TEST")))},
		}},
		{Name: "EventData", Children: []Node{
			{Name: "Data",
				Attributes: []Attr{{Name: "Name", Value: mustVal(t, ValString, utf16le("TargetUserName"))}},
				Value:      ptrVal(mustVal(t, ValString, utf16le("alice")))},
			// A positional <Data> with no Name attribute — a map cannot hold this.
			{Name: "Data", Value: ptrVal(mustVal(t, ValString, utf16le("positional")))},
		}},
	}}

	ev, err := eventFromNode(root)
	if err != nil {
		t.Fatalf("eventFromNode: %v", err)
	}
	if ev.System.Provider.Name != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("Provider.Name = %q", ev.System.Provider.Name)
	}
	if ev.System.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", ev.System.EventID)
	}
	if ev.System.Level != 4 {
		t.Errorf("Level = %d, want 4", ev.System.Level)
	}
	if ev.System.Computer != "WIN-TEST" {
		t.Errorf("Computer = %q", ev.System.Computer)
	}
	if len(ev.EventData) != 2 {
		t.Fatalf("EventData has %d entries, want 2", len(ev.EventData))
	}
	if ev.EventData[0].Name != "TargetUserName" || ev.EventData[0].Value.String() != "alice" {
		t.Errorf("EventData[0] = %+v", ev.EventData[0])
	}
	if ev.EventData[1].Name != "" {
		t.Errorf("EventData[1].Name = %q, want empty for a positional Data", ev.EventData[1].Name)
	}
	if ev.EventData[1].Value.String() != "positional" {
		t.Errorf("EventData[1].Value = %q", ev.EventData[1].Value.String())
	}
}

func TestEventFromNode_WrongRootIsError(t *testing.T) {
	if _, err := eventFromNode(&Node{Name: "NotAnEvent"}); err == nil {
		t.Fatal("expected an error for a root element that is not <Event>")
	}
}

// EventData marshals as an array, not an object: names are optional and may
// repeat, and an object would silently drop both cases.
func TestEvent_EventDataMarshalsAsArray(t *testing.T) {
	ev := &Event{EventData: []Data{
		{Name: "a", Value: mustVal(t, ValString, utf16le("1"))},
		{Name: "", Value: mustVal(t, ValString, utf16le("2"))},
	}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out struct {
		EventData []struct {
			Name  string `json:"name"`
			Value any    `json:"value"`
		} `json:"event_data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v (payload %s)", err, b)
	}
	if len(out.EventData) != 2 {
		t.Errorf("event_data has %d entries, want 2 — a JSON object would have collapsed them", len(out.EventData))
	}
}

// The two tests below are grounded in testdata/win2025-system-expected.xml:
// Windows' own EventLogRecord.ToXml() rendering of the first four records of
// testdata/win2025-system.evtx, captured on the machine that produced the
// file. They assert against Windows' rendering, never against this library's
// own decode of the same bytes — a decoder checked against itself agrees with
// itself.
//
// They read through the public Reader and iterate to the record they need
// rather than walking chunk offsets by hand. The previous versions walked
// offsets into whatever file readFixtureChunk returned and asserted values
// belonging to one specific log; when that log was deleted they skipped
// silently for a whole release, then failed the moment a different fixture
// appeared. Iterating makes the record they mean explicit.

// nthEvent returns the n-th event (1-based) of the tracked fixture.
func nthEvent(t *testing.T, n int) *Event {
	t.Helper()
	r, err := Open(fixturePath(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = r.Close() }()
	for i := 1; ; i++ {
		ev, err := r.ReadEvent()
		if err != nil {
			t.Fatalf("reading event %d: %v", i, err)
		}
		if i == n {
			return ev
		}
	}
}

// TestEventFromNode_RealFixtureUserData checks record 1, whose <UserData> is a
// literal child of <Event> but whose CONTENT is a nested BinXml-typed
// substitution wrapping <LogFileCleared> — not literal children. An earlier
// eventFromNode set Event.UserData to the empty <UserData> wrapper (Value set,
// no Children of its own) instead of following it through; this test is what
// catches that.
//
// Every System field is checked against the golden file's own value rather
// than merely for being non-zero, so a transposed ProcessID/ThreadID or a
// Guid/GUID attribute-name typo fails here instead of passing quietly.
func TestEventFromNode_RealFixtureUserData(t *testing.T) {
	ev := nthEvent(t, 1)
	sys := ev.System

	if sys.Provider.Name != "Microsoft-Windows-Eventlog" {
		t.Errorf("Provider.Name = %q", sys.Provider.Name)
	}
	if sys.Provider.GUID != "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" {
		t.Errorf("Provider.GUID = %q", sys.Provider.GUID)
	}
	if sys.Provider.EventSourceName != "" {
		t.Errorf("Provider.EventSourceName = %q, want empty — record 1 declares none", sys.Provider.EventSourceName)
	}
	if sys.EventID != 104 {
		t.Errorf("EventID = %d, want 104", sys.EventID)
	}
	if sys.Version != 1 {
		t.Errorf("Version = %d, want 1", sys.Version)
	}
	if sys.Level != 4 {
		t.Errorf("Level = %d, want 4", sys.Level)
	}
	if sys.Task != 104 {
		t.Errorf("Task = %d, want 104", sys.Task)
	}
	if sys.Opcode != 0 {
		t.Errorf("Opcode = %d, want 0", sys.Opcode)
	}
	const wantKeywords = uint64(0x8000000000000000)
	if sys.Keywords != wantKeywords {
		t.Errorf("Keywords = %#x, want %#x", sys.Keywords, wantKeywords)
	}
	wantTime, err := time.Parse(time.RFC3339Nano, "2026-07-16T01:38:33.7110047Z")
	if err != nil {
		t.Fatalf("parsing want time: %v", err)
	}
	if !sys.TimeCreated.Equal(wantTime) {
		t.Errorf("TimeCreated = %v, want %v", sys.TimeCreated, wantTime)
	}
	if sys.EventRecordID != 29910 {
		t.Errorf("EventRecordID = %d, want 29910", sys.EventRecordID)
	}
	if sys.ActivityID != "" {
		t.Errorf("ActivityID = %q, want empty — record 1's <Correlation/> is empty", sys.ActivityID)
	}
	if sys.ProcessID != 1328 {
		t.Errorf("ProcessID = %d, want 1328", sys.ProcessID)
	}
	if sys.ThreadID != 4516 {
		t.Errorf("ThreadID = %d, want 4516", sys.ThreadID)
	}
	if sys.Channel != "System" {
		t.Errorf("Channel = %q, want %q", sys.Channel, "System")
	}
	if sys.Computer != "EC2AMAZ-ETN574G" {
		t.Errorf("Computer = %q", sys.Computer)
	}
	if sys.UserID != "S-1-5-21-875595685-4085717449-396137586-500" {
		t.Errorf("UserID = %q", sys.UserID)
	}

	if len(ev.EventData) != 0 {
		t.Errorf("EventData has %d entries, want 0 — record 1 uses UserData", len(ev.EventData))
	}
	if ev.UserData == nil {
		t.Fatal("UserData is nil, want the <LogFileCleared> element")
	}
	// The wrapper must have been followed through to its real content.
	if ev.UserData.Name != "LogFileCleared" {
		t.Fatalf("UserData.Name = %q, want %q — the <UserData> wrapper was not followed to its content",
			ev.UserData.Name, "LogFileCleared")
	}
	want := []struct{ name, value string }{
		{"SubjectUserName", "Administrator"},
		{"SubjectDomainName", "EC2AMAZ-ETN574G"},
		{"Channel", "System"},
		{"BackupPath", ""},
		{"ClientProcessId", "4040"},
		{"ClientProcessStartKey", "26177172834092454"},
	}
	if len(ev.UserData.Children) != len(want) {
		t.Fatalf("UserData has %d children, want %d", len(ev.UserData.Children), len(want))
	}
	for i, w := range want {
		got := ev.UserData.Children[i]
		if got.Name != w.name {
			t.Errorf("UserData child %d name = %q, want %q", i, got.Name, w.name)
		}
		if got.Value == nil {
			if w.value != "" {
				t.Errorf("UserData child %d (%s) has no value, want %q", i, w.name, w.value)
			}
			continue
		}
		if got.Value.String() != w.value {
			t.Errorf("UserData child %d (%s) = %q, want %q", i, w.name, got.Value.String(), w.value)
		}
	}
}

// TestEventFromNode_RealFixtureEventData checks record 4, whose <EventData> is
// not a child element of <Event> at all — it IS <Event>'s own bare
// substitution value, so root.child("EventData") finds nothing and
// eventFromNode must resolve it through Event's own Value instead. The record
// also carries a trailing <Binary> that is not a <Data>, and a
// <Provider EventSourceName='...'> attribute; both have their own field on
// Event rather than being dropped.
func TestEventFromNode_RealFixtureEventData(t *testing.T) {
	ev := nthEvent(t, 4)
	sys := ev.System

	if sys.Provider.Name != "Service Control Manager" {
		t.Errorf("Provider.Name = %q", sys.Provider.Name)
	}
	if sys.Provider.GUID != "{555908d1-a6d7-4695-8e1e-26931d2012f4}" {
		t.Errorf("Provider.GUID = %q", sys.Provider.GUID)
	}
	if sys.Provider.EventSourceName != "Service Control Manager" {
		t.Errorf("Provider.EventSourceName = %q, want %q", sys.Provider.EventSourceName, "Service Control Manager")
	}
	if sys.EventID != 7036 {
		t.Errorf("EventID = %d, want 7036", sys.EventID)
	}
	if sys.Qualifiers != 16384 {
		t.Errorf("Qualifiers = %d, want 16384", sys.Qualifiers)
	}
	if sys.Version != 0 {
		t.Errorf("Version = %d, want 0", sys.Version)
	}
	if sys.Level != 4 {
		t.Errorf("Level = %d, want 4", sys.Level)
	}
	if sys.Task != 0 {
		t.Errorf("Task = %d, want 0", sys.Task)
	}
	if sys.Opcode != 0 {
		t.Errorf("Opcode = %d, want 0", sys.Opcode)
	}
	const wantKeywords = uint64(0x8080000000000000)
	if sys.Keywords != wantKeywords {
		t.Errorf("Keywords = %#x, want %#x", sys.Keywords, wantKeywords)
	}
	wantTime, err := time.Parse(time.RFC3339Nano, "2026-07-16T01:38:33.0418309Z")
	if err != nil {
		t.Fatalf("parsing want time: %v", err)
	}
	if !sys.TimeCreated.Equal(wantTime) {
		t.Errorf("TimeCreated = %v, want %v", sys.TimeCreated, wantTime)
	}
	if sys.EventRecordID != 29913 {
		t.Errorf("EventRecordID = %d, want 29913", sys.EventRecordID)
	}
	if sys.ActivityID != "" {
		t.Errorf("ActivityID = %q, want empty — record 4's <Correlation/> is empty", sys.ActivityID)
	}
	if sys.ProcessID != 708 {
		t.Errorf("ProcessID = %d, want 708", sys.ProcessID)
	}
	if sys.ThreadID != 4968 {
		t.Errorf("ThreadID = %d, want 4968", sys.ThreadID)
	}
	if sys.Channel != "System" {
		t.Errorf("Channel = %q, want %q", sys.Channel, "System")
	}
	if sys.Computer != "EC2AMAZ-ETN574G" {
		t.Errorf("Computer = %q", sys.Computer)
	}
	if sys.UserID != "" {
		t.Errorf("UserID = %q, want empty — record 4 has no <Security UserID>", sys.UserID)
	}
	if ev.UserData != nil {
		t.Errorf("UserData = %+v, want nil — record 4 uses EventData", ev.UserData)
	}

	if len(ev.EventData) != 2 {
		t.Fatalf("EventData has %d entries, want 2 (the trailing <Binary> is not a <Data>): %+v",
			len(ev.EventData), ev.EventData)
	}
	if ev.EventData[0].Name != "param1" || ev.EventData[0].Value.String() != "AppX Deployment Service (AppXSVC)" {
		t.Errorf("EventData[0] = %+v", ev.EventData[0])
	}
	if ev.EventData[1].Name != "param2" || ev.EventData[1].Value.String() != "running" {
		t.Errorf("EventData[1] = %+v", ev.EventData[1])
	}
	if ev.Binary.IsAbsent() {
		t.Fatal("Binary is absent, want the trailing <Binary> element's value")
	}
	// "AppXSvc/4" as UTF-16LE with a terminator. ToXml() renders Binary as
	// uppercase hex, this library's String() as lowercase — same bytes.
	const wantBinaryHex = "41007000700058005300760063002f0034000000"
	if got := strings.ToLower(ev.Binary.String()); got != wantBinaryHex {
		t.Errorf("Binary = %s, want %s", got, wantBinaryHex)
	}
}

func utf16le(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func ptrVal(v Value) *Value { return &v }
