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
//
// Task 8c (F13a/F13b/F13c) adds three more tests below, closing the named
// list task-8b-report.md's "Concerns" section left open: EventID/Level must
// use OptionalSubstitution (0x0E) with a real dependency_id, Provider must
// carry a second attribute (Guid) using the 0x46/0x06 "more attributes
// follow" pattern, and EventID must carry a Qualifiers attribute whose value
// is NULL. All three were confirmed failing against the pre-F13 encoder
// before implementation: EventID/Level's OpenStartElementTag carried
// depIDNotSet (0xffff) and their content used binXMLNormalSubstitution
// (0x0D); Provider had one attribute; "Guid" and "Qualifiers" appeared
// nowhere in the payload.
//
// F14 (Task 8e) tried correcting Qualifiers' declared type from UNSIGNED_WORD
// (0x06) to a generic NULL (0x00), on the strength of a byte-for-byte
// re-parse of testdata/system.evtx's own record finding the attribute
// declared type 0x00 there, contradicting task-8b-report.md's Step 1 table
// (which F13c built from). That change made Get-WinEvent's STAGE2 READ
// regress from reading all 403 records to failing on record 0 — reverted
// back to UNSIGNED_WORD on that stronger, directly measured signal. See the
// F14 doc comment in binxml.go, by the type constants, for the full,
// unresolved story. TestBuildTemplateBody_EventIDQualifiersIsNullOptional
// below asserts UNSIGNED_WORD again, matching F13c's original.
package evtx

import (
	"bytes"
	"encoding/binary"
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

// utf16Bytes returns the UTF-16LE encoding of s with no null terminator —
// how a NameNode's own character run is stored, matching writeNameNode.
func utf16Bytes(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	buf := make([]byte, len(u16)*2)
	for i, c := range u16 {
		buf[i*2] = byte(c)
		buf[i*2+1] = byte(c >> 8)
	}
	return buf
}

// TestBuildTemplateBody_EventIDAndLevelUseOptionalSubstitution (F13a):
// testdata/system.evtx ties EventID's and Level's own OpenStartElementTag
// dependency_id to their own content substitution's index (3 and 0 in the
// real file's numbering; task-8b-report.md's Step 1 table), the same
// convention F12b/F12c already established for Version/Task/Opcode/Keywords/
// EventRecordID. go-evtx's own indices for EventID/Level are 1 and 2
// (unchanged — see the sub* constants), so their dependency_id must now be
// 1 and 2 respectively, not depIDNotSet, and their content token must be
// OptionalSubstitution (0x0E), not NormalSubstitution (0x0D).
func TestBuildTemplateBody_EventIDAndLevelUseOptionalSubstitution(t *testing.T) {
	const base = uint32(evtxRecordsStart + evtxRecordHeaderSize)
	res := buildBinXML(4663, 1, goldenFields(), base)
	payload := res.payload

	cases := []struct {
		name    string
		subIdx  uint16
		subType byte
	}{
		{"EventID", subEventID, binXMLTypeUint16},
		{"Level", subLevel, binXMLTypeUint8},
	}

	for _, c := range cases {
		encoded := utf16Bytes(c.name)
		nn := bytes.Index(payload, encoded)
		if nn < 8 {
			t.Fatalf("%s: NameNode characters not found in payload (or too close to start)", c.name)
		}
		// NameNode layout: next_offset(4) + hash(2) + char_count(2) + chars + null(2).
		// The characters start 8 bytes into the NameNode.
		nameNodeStart := nn - 8
		// writeOpenElement's fixed header: token(1) + dep_id(2) + data_size(4) + name_offset(4) = 11.
		tokenPos := nameNodeStart - 11
		if tokenPos < 0 {
			t.Fatalf("%s: computed OpenStartElement token position %d is negative", c.name, tokenPos)
		}
		tok := payload[tokenPos]
		if tok != binXMLOpenElement && tok != binXMLOpenElementAttrs {
			t.Fatalf("%s: byte 0x%02x at computed token position %d is not an OpenStartElement token", c.name, tok, tokenPos)
		}
		depID := binary.LittleEndian.Uint16(payload[tokenPos+1:])
		if depID != c.subIdx {
			t.Errorf("%s: OpenStartElementTag dependency_id = 0x%04x, want 0x%04x (own content substitution index)", c.name, depID, c.subIdx)
		}

		// The content substitution token follows shortly after the NameNode's
		// null terminator (immediately for Level, after an attribute list for
		// EventID) — search a bounded window rather than compute the exact
		// offset, since EventID's Qualifiers attribute varies the gap.
		nameNodeEnd := nn + len(encoded) + 2 // + null terminator
		end := nameNodeEnd + 200
		if end > len(payload) {
			end = len(payload)
		}
		window := payload[nameNodeEnd:end]
		wantTok := []byte{binXMLOptionalSubstitution, byte(c.subIdx), byte(c.subIdx >> 8), c.subType}
		if !bytes.Contains(window, wantTok) {
			t.Errorf("%s: OptionalSubstitution token %x not found shortly after its NameNode", c.name, wantTok)
		}
		unwantTok := []byte{binXMLNormalSubstitution, byte(c.subIdx), byte(c.subIdx >> 8), c.subType}
		if bytes.Contains(window, unwantTok) {
			t.Errorf("%s: still emits NormalSubstitution token %x (0x0D) instead of OptionalSubstitution", c.name, unwantTok)
		}
	}
}

// TestBuildTemplateBody_ProviderTwoAttributes (F13b): Provider must carry a
// second attribute, Guid, and — per a previous task's confirmation that the
// real file writes 0x46 ("more attributes follow") for a non-final attribute
// and 0x06 for the last — Name's own attribute token must become 0x46 now
// that it is no longer the only attribute, while Guid's is 0x06.
//
// Located via res.names (the offsets buildBinXML itself reports) rather than
// raw byte search: "Name" is not unique in the payload (every one of the 12
// <Data> elements also has a "Name" attribute), but names are appended in
// emission order and Provider's own Name/Guid are emitted first.
func TestBuildTemplateBody_ProviderTwoAttributes(t *testing.T) {
	const base = uint32(evtxRecordsStart + evtxRecordHeaderSize)
	res := buildBinXML(4663, 1, goldenFields(), base)
	payload := res.payload

	wantNameHash := sdbmHash("Name")
	wantGuidHash := sdbmHash("Guid")
	var nameOff, guidOff uint32
	foundName, foundGuid := false, false
	for _, ref := range res.names {
		if !foundName && ref.key == wantNameHash {
			nameOff = ref.offset
			foundName = true
		}
		if !foundGuid && ref.key == wantGuidHash {
			guidOff = ref.offset
			foundGuid = true
		}
	}
	if !foundName {
		t.Fatal("no NameNode for \"Name\" reported by buildBinXML")
	}
	if !foundGuid {
		t.Fatal("no NameNode for \"Guid\" reported by buildBinXML — Provider/@Guid is missing")
	}

	// writeAttributeSub's layout: [token:1][name_offset:4][NameNode...] — the
	// attribute token sits 5 bytes before the NameNode itself.
	nameTokPos := int(nameOff) - int(base) - 5
	guidTokPos := int(guidOff) - int(base) - 5
	if nameTokPos < 0 || guidTokPos < 0 {
		t.Fatalf("computed attribute token positions out of range: name=%d guid=%d", nameTokPos, guidTokPos)
	}
	if got := payload[nameTokPos]; got != binXMLAttributeMore {
		t.Errorf("Provider's Name attribute token = 0x%02x, want 0x%02x (more attributes follow — Guid comes after it)", got, binXMLAttributeMore)
	}
	if got := payload[guidTokPos]; got != binXMLAttribute {
		t.Errorf("Provider's Guid attribute token = 0x%02x, want 0x%02x (last attribute in the list)", got, binXMLAttribute)
	}
}

// TestCollectSubstitutions_ProviderGuidIsString (F13b): the Guid substitution
// slot must round-trip an arbitrary caller-supplied value, confirming it is
// wired as a real substitution (STRING-typed, per Provider/@Name's existing
// precedent) rather than hardcoded or dropped.
func TestCollectSubstitutions_ProviderGuidIsString(t *testing.T) {
	fields := goldenFields()
	const want = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
	fields["ProviderGuid"] = want

	subs := collectSubstitutionsFromFields(4663, 1, fields)
	if len(subs) <= subProviderGuid {
		t.Fatalf("collectSubstitutionsFromFields returned %d entries, want > %d", len(subs), subProviderGuid)
	}
	got := subs[subProviderGuid]
	if got.typ != binXMLTypeString {
		t.Errorf("Provider/@Guid (substitution %d) value type = 0x%02x, want 0x%02x (STRING)", subProviderGuid, got.typ, binXMLTypeString)
	}
	if decoded := decodeSubString(got.data); decoded != want {
		t.Errorf("Provider/@Guid round-trip = %q, want %q", decoded, want)
	}
}

// TestBuildTemplateBody_EventIDQualifiersIsNullOptional (F13c; F14
// re-confirmed this after a false start): EventID must carry a Qualifiers
// attribute, and — since go-evtx has no caller-supplied source for it — its
// substitution entry must be NULL: value-spec type UNSIGNED_WORD (0x06,
// Qualifiers' own declared type per task-8b-report.md's Step 1 table), size
// 0. F14 (Task 8e) tried asserting binXMLTypeNull (0x00) here instead,
// following a byte-for-byte re-parse of testdata/system.evtx's own record
// that contradicted this table — but that change made Get-WinEvent's
// STAGE2 READ regress from all 403 records to failing on record 0, an
// unambiguous signal stronger than the byte-level re-parse. Reverted back
// to UNSIGNED_WORD on that evidence; see the doc comment in binxml.go by
// the type constants for the full, unresolved story.
func TestBuildTemplateBody_EventIDQualifiersIsNullOptional(t *testing.T) {
	res := buildBinXML(4663, 1, goldenFields(), uint32(evtxRecordsStart+evtxRecordHeaderSize))

	encoded := utf16Bytes("Qualifiers")
	if !bytes.Contains(res.payload, encoded) {
		t.Fatal("encoded payload does not contain the attribute name \"Qualifiers\"")
	}

	subs := collectSubstitutionsFromFields(4663, 1, goldenFields())
	if len(subs) <= subEventIDQualifiers {
		t.Fatalf("collectSubstitutionsFromFields returned %d entries, want > %d", len(subs), subEventIDQualifiers)
	}
	got := subs[subEventIDQualifiers]
	if got.typ != binXMLTypeUint16 {
		t.Errorf("EventID/@Qualifiers (substitution %d) value type = 0x%02x, want 0x%02x (UNSIGNED_WORD, matching the real file's NULL encoding)", subEventIDQualifiers, got.typ, binXMLTypeUint16)
	}
	if len(got.data) != 0 {
		t.Errorf("EventID/@Qualifiers (substitution %d) value data length = %d, want 0 (NULL)", subEventIDQualifiers, len(got.data))
	}
}
