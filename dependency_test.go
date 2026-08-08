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
			// Task 7e gave data_size a real, content-derived value. That
			// value's own bytes (payload[i+3:i+7]) can coincidentally equal
			// 0x01/0x41 partway through — e.g. data_size 0x0133 stores 0x01
			// at i+4 — which this loop would otherwise revisit on the very
			// next iterations and misread as a second, bogus element header
			// nested inside this element's own fixed header fields. Skip
			// past this element's own header (token+dep_id+data_size+
			// name_offset[+attr_list_size]) so only bytes that could
			// plausibly start another token are considered; the NameNode,
			// attributes, and any real nested children that follow are
			// still scanned normally.
			headerSize := 11 // token(1) + dep_id(2) + data_size(4) + name_offset(4)
			if tok == binXMLOpenElementAttrs {
				headerSize = 15 // + attr_list_size(4)
			}
			i += headerSize - 1 // loop's own i++ accounts for the last byte
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
