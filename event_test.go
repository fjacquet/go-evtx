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

// TestEventFromNode_RealFixtureUserData decodes testdata/system.evtx's first
// record (ground-truthed by testdata/system-expected-windows.xml's RECORD 1,
// EventRecordID 12049) and checks the assembled Event against it, field by
// field against the golden file's own values — not merely "non-zero" — so a
// transposed ProcessID/ThreadID or a "Guid"/"GUID" attribute-name typo would
// fail here rather than pass silently (fix round 1, Finding 3).
//
// This record's <UserData> is a literal child of <Event>, but ITS content is
// a nested BinXml-typed substitution wrapping <AutoBackup> — not literal
// children (see TestDecodeRecordBinXML_RealFixture in binxml_decode_test.go,
// and contentNode's doc comment in event.go). The task-6-brief.md version of
// eventFromNode set Event.UserData to that empty <UserData> wrapper node
// (Value set, no Children of its own) instead of following it to
// <AutoBackup> — this test is what catches that and pins the fix.
func TestEventFromNode_RealFixtureUserData(t *testing.T) {
	chunk := readFixtureChunk(t, 0)
	recOff := evtxChunkHeaderSize
	size := int(le32(chunk[recOff+4 : recOff+8]))
	payloadOff := recOff + 24
	payloadLen := size - 24 - 4

	cache := newTemplateCache(chunk)
	root, err := decodeRecordBinXML(cache, payloadOff, payloadLen)
	if err != nil {
		t.Fatalf("decodeRecordBinXML: %v", err)
	}
	ev, err := eventFromNode(root)
	if err != nil {
		t.Fatalf("eventFromNode: %v", err)
	}

	sys := ev.System
	if sys.Provider.Name != "Microsoft-Windows-Eventlog" {
		t.Errorf("Provider.Name = %q", sys.Provider.Name)
	}
	if sys.Provider.GUID != "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" {
		t.Errorf("Provider.GUID = %q", sys.Provider.GUID)
	}
	if sys.Provider.EventSourceName != "" {
		t.Errorf("Provider.EventSourceName = %q, want empty — record 1's <Provider> carries no EventSourceName", sys.Provider.EventSourceName)
	}
	if sys.EventID != 105 {
		t.Errorf("EventID = %d, want 105", sys.EventID)
	}
	if sys.Qualifiers != 0 {
		t.Errorf("Qualifiers = %d, want 0 (record 1's <EventID> carries no Qualifiers attribute)", sys.Qualifiers)
	}
	if sys.Version != 0 {
		t.Errorf("Version = %d, want 0", sys.Version)
	}
	if sys.Level != 4 {
		t.Errorf("Level = %d, want 4", sys.Level)
	}
	if sys.Task != 105 {
		t.Errorf("Task = %d, want 105", sys.Task)
	}
	if sys.Opcode != 0 {
		t.Errorf("Opcode = %d, want 0", sys.Opcode)
	}
	const wantKeywords = uint64(0x8000000000000000)
	if sys.Keywords != wantKeywords {
		t.Errorf("Keywords = %#x, want %#x", sys.Keywords, wantKeywords)
	}
	wantTime, err := time.Parse(time.RFC3339Nano, "2012-03-14T04:17:43.3545627Z")
	if err != nil {
		t.Fatalf("parsing want time: %v", err)
	}
	if !sys.TimeCreated.Equal(wantTime) {
		t.Errorf("TimeCreated = %v, want %v", sys.TimeCreated, wantTime)
	}
	if sys.EventRecordID != 12049 {
		t.Errorf("EventRecordID = %d, want 12049", sys.EventRecordID)
	}
	if sys.ActivityID != "" {
		t.Errorf("ActivityID = %q, want empty — record 1's <Correlation/> is empty", sys.ActivityID)
	}
	if sys.ProcessID != 820 {
		t.Errorf("ProcessID = %d, want 820", sys.ProcessID)
	}
	if sys.ThreadID != 2868 {
		t.Errorf("ThreadID = %d, want 2868", sys.ThreadID)
	}
	if sys.Channel != "System" {
		t.Errorf("Channel = %q, want %q", sys.Channel, "System")
	}
	if sys.Computer != "WKS-WIN764BITB.shieldbase.local" {
		t.Errorf("Computer = %q", sys.Computer)
	}
	if sys.UserID != "" {
		t.Errorf("UserID = %q, want empty — record 1's <Security/> is empty", sys.UserID)
	}
	if len(ev.EventData) != 0 {
		t.Errorf("EventData = %+v, want none — record 1 uses UserData, not EventData", ev.EventData)
	}
	if !ev.Binary.IsAbsent() {
		t.Errorf("Binary = %+v, want absent — record 1 has no <Binary>", ev.Binary)
	}
	if ev.UserData == nil {
		t.Fatal("UserData is nil")
	}
	if ev.UserData.Name != "AutoBackup" {
		t.Fatalf("UserData.Name = %q, want %q — the <UserData> wrapper itself must be unwrapped", ev.UserData.Name, "AutoBackup")
	}
	var channel, backupPath string
	for _, c := range ev.UserData.Children {
		switch c.Name {
		case "Channel":
			if c.Value != nil {
				channel = c.Value.String()
			}
		case "BackupPath":
			if c.Value != nil {
				backupPath = c.Value.String()
			}
		}
	}
	if channel != "System" {
		t.Errorf("AutoBackup/Channel = %q, want %q", channel, "System")
	}
	const wantBackupPath = `C:\Windows\System32\Winevt\Logs\Archive-System-2012-03-14-04-17-39-932.evtx`
	if backupPath != wantBackupPath {
		t.Errorf("AutoBackup/BackupPath = %q, want %q", backupPath, wantBackupPath)
	}
}

// TestEventFromNode_RealFixtureEventData decodes testdata/system.evtx's
// second record (ground-truthed by RECORD 2 in
// testdata/system-expected-windows.xml, EventRecordID 12050), and — like
// TestEventFromNode_RealFixtureUserData — checks every System field against
// the golden file's own values (fix round 1, Finding 3).
//
// This record's <EventData> is not a child element of <Event> at all — it IS
// <Event>'s own bare substitution value (see setElementValue's doc comment in
// binxml_decode.go), so root.child("EventData") finds nothing and
// eventFromNode's fallback must resolve it through Event's own Value instead.
// It also carries a trailing <Binary> element that is not a <Data>; fix round
// 1's Finding 2 gives that its own field on Event rather than dropping it —
// this test pins the fix and the <Provider EventSourceName='...'> Finding 1
// added.
func TestEventFromNode_RealFixtureEventData(t *testing.T) {
	chunk := readFixtureChunk(t, 0)
	recOff := evtxChunkHeaderSize
	size := int(le32(chunk[recOff+4 : recOff+8]))
	recOff += size // skip record 1

	size = int(le32(chunk[recOff+4 : recOff+8]))
	payloadOff := recOff + 24
	payloadLen := size - 24 - 4

	cache := newTemplateCache(chunk)
	root, err := decodeRecordBinXML(cache, payloadOff, payloadLen)
	if err != nil {
		t.Fatalf("decodeRecordBinXML: %v", err)
	}
	ev, err := eventFromNode(root)
	if err != nil {
		t.Fatalf("eventFromNode: %v", err)
	}

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
	wantTime, err := time.Parse(time.RFC3339Nano, "2012-03-14T04:17:38.2763402Z")
	if err != nil {
		t.Fatalf("parsing want time: %v", err)
	}
	if !sys.TimeCreated.Equal(wantTime) {
		t.Errorf("TimeCreated = %v, want %v", sys.TimeCreated, wantTime)
	}
	if sys.EventRecordID != 12050 {
		t.Errorf("EventRecordID = %d, want 12050", sys.EventRecordID)
	}
	if sys.ActivityID != "" {
		t.Errorf("ActivityID = %q, want empty — record 2's <Correlation/> is empty", sys.ActivityID)
	}
	if sys.ProcessID != 548 {
		t.Errorf("ProcessID = %d, want 548", sys.ProcessID)
	}
	if sys.ThreadID != 1340 {
		t.Errorf("ThreadID = %d, want 1340", sys.ThreadID)
	}
	if sys.Channel != "System" {
		t.Errorf("Channel = %q, want %q", sys.Channel, "System")
	}
	if sys.Computer != "WKS-WIN764BITB.shieldbase.local" {
		t.Errorf("Computer = %q", sys.Computer)
	}
	if sys.UserID != "" {
		t.Errorf("UserID = %q, want empty — record 2's <Security/> is empty", sys.UserID)
	}
	if ev.UserData != nil {
		t.Errorf("UserData = %+v, want nil — record 2 uses EventData, not UserData", ev.UserData)
	}
	if len(ev.EventData) != 2 {
		t.Fatalf("EventData has %d entries, want 2 (the trailing <Binary> is not a <Data>): %+v", len(ev.EventData), ev.EventData)
	}
	if ev.EventData[0].Name != "param1" || ev.EventData[0].Value.String() != "Windows Modules Installer" {
		t.Errorf("EventData[0] = %+v", ev.EventData[0])
	}
	if ev.EventData[1].Name != "param2" || ev.EventData[1].Value.String() != "stopped" {
		t.Errorf("EventData[1] = %+v", ev.EventData[1])
	}
	if ev.Binary.IsAbsent() {
		t.Fatal("Binary is absent, want the trailing <Binary> element's value")
	}
	const wantBinaryHex = "540072007500730074006500640049006e007300740061006c006c00650072002f0031000000"
	if got := strings.ToLower(ev.Binary.String()); got != wantBinaryHex {
		t.Errorf("Binary = %s, want %s (case-insensitive; ToXml() renders Binary as uppercase hex, "+
			"our own String() renders lowercase — same bytes)", got, wantBinaryHex)
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
