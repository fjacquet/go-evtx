// system_test.go — Task 8b (F12a/F12b): Level's declared value type must be
// UInt8, and every <System> child testdata/system.evtx has but go-evtx
// didn't must be present in the encoded template body.
//
// Per the task's Step 2, these were written and run against the pre-fix
// encoder first: Level's value type was binXMLTypeUint16 (0x06), and none of
// the fourteen names below appeared anywhere in the payload — go-evtx wrote
// only Provider/EventID/Level/TimeCreated/Computer, 5 of the real file's 14
// <System> children. Both assertions failed as expected before F12a/F12b
// landed.
package evtx

import (
	"bytes"
	"testing"
	"unicode/utf16"
)

// TestCollectSubstitutions_LevelIsUint8 confirms F12a directly against the
// substitution array collectSubstitutionsFromFields builds: Level (index 2)
// must declare value type UInt8 (0x04), matching testdata/system.evtx's own
// record 0 (OptionalSubstitution index 0, value_type UNSIGNED_BYTE, decoded
// in Task 8b's Step 1) — not UInt16 (0x06), which every prior go-evtx
// release wrote.
func TestCollectSubstitutions_LevelIsUint8(t *testing.T) {
	subs := collectSubstitutionsFromFields(4663, 1, goldenFields())
	if len(subs) <= 2 {
		t.Fatalf("collectSubstitutionsFromFields returned %d entries, want > 2", len(subs))
	}
	if subs[2].typ != binXMLTypeUint8 {
		t.Errorf("Level (substitution 2) value type = 0x%02x, want 0x%02x (UINT8)", subs[2].typ, binXMLTypeUint8)
	}
	if len(subs[2].data) != 1 {
		t.Errorf("Level (substitution 2) value data length = %d, want 1 (a UINT8)", len(subs[2].data))
	}
}

// TestBuildTemplateBody_NewSystemChildrenPresent asserts every F12b-added
// <System> element/attribute name is present in the encoded template body,
// by searching for its UTF-16LE encoding — the same technique
// namespace_test.go (F8) uses. Presence alone does not prove correct
// placement, type or dependency_id: attrlist_test.go, dependency_test.go,
// datasize_test.go and the hash-table integration test cover that
// structural detail. This test's job is only to fail loudly if an element
// F12b promised is silently dropped.
func TestBuildTemplateBody_NewSystemChildrenPresent(t *testing.T) {
	res := buildBinXML(4663, 1, goldenFields(), uint32(evtxRecordsStart+evtxRecordHeaderSize))

	want := []string{
		"Version", "Task", "Opcode", "Keywords", "EventRecordID",
		"Correlation", "ActivityID", "RelatedActivityID",
		"Execution", "ProcessID", "ThreadID",
		"Channel",
		"Security", "UserID",
	}
	for _, name := range want {
		u16 := utf16.Encode([]rune(name))
		encoded := make([]byte, len(u16)*2)
		for i, c := range u16 {
			encoded[i*2] = byte(c)
			encoded[i*2+1] = byte(c >> 8)
		}
		if !bytes.Contains(res.payload, encoded) {
			t.Errorf("encoded payload does not contain the element/attribute name %q", name)
		}
	}
}
