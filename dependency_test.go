// dependency_test.go — every OpenStartElement must carry dependency_id 0xffff,
// the sentinel libyal's EVTX documentation defines as "not set". Zero is a
// valid identifier pointing at template value 0, which is a claim go-evtx has
// no business making on every element it writes.
package evtx

import (
	"encoding/binary"
	"testing"
)

func TestWriteOpenElement_DependencyIDIsUnset(t *testing.T) {
	res := buildBinXML(4663, goldenFields(), uint32(evtxRecordsStart+evtxRecordHeaderSize))

	// Walk the payload for OpenStartElement tokens and check each one's
	// dependency identifier. Tokens: 0x01 without attributes, 0x41 with.
	//
	// The scan starts at preambleSize, not 0: the fixed 38-byte preamble
	// (outer FragmentHeader + TemplateInstanceNode + TemplateNode header)
	// contains structural bytes that are not element tokens but coincidentally
	// pass the "plausible header" guard below — the outer fragment header's
	// minor-version byte (0x01) followed by flags(0x00)+TemplateInstance
	// token(0x0C) reads as a small, in-range "size", and likewise the low
	// byte of the TemplateNode GUID (== template_id == 1). Real
	// OpenStartElement tokens only ever occur in the template body, which
	// starts at preambleSize.
	found := 0
	for i := preambleSize; i+3 < len(res.payload); i++ {
		tok := res.payload[i]
		if tok != binXMLOpenElement && tok != binXMLOpenElementAttrs {
			continue
		}
		dep := binary.LittleEndian.Uint16(res.payload[i+1:])
		if dep == 0xffff {
			found++
			continue
		}
		// A 0x01/0x41 byte can occur inside string data, so only flag a
		// mismatch when the following bytes look like a plausible header.
		size := binary.LittleEndian.Uint32(res.payload[i+3:])
		if size < uint32(len(res.payload)) {
			t.Errorf("offset %d: OpenStartElement dependency_id = 0x%04x, want 0xffff", i, dep)
		}
	}
	if found == 0 {
		t.Fatal("no OpenStartElement tokens with dependency_id 0xffff found — " +
			"the scan is wrong or nothing was emitted")
	}
	t.Logf("%d OpenStartElement tokens carry the 0xffff sentinel", found)
}
