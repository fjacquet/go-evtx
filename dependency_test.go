// dependency_test.go — every OpenStartElement must carry dependency_id
// depIDNotSet (0xffff), the sentinel libyal's EVTX documentation defines as
// "not set" — UNLESS it is one of the five F12c elements (Task 8b) whose sole
// content is the OptionalSubstitution of that same index, matching
// testdata/system.evtx. 0 is otherwise a valid identifier pointing at
// template value 0, which is a claim go-evtx has no business making on any
// other element it writes.
package evtx

import (
	"encoding/binary"
	"testing"
)

// knownOptionalDependencyIDs are the F12c substitution indices legitimate
// OpenStartElementTags may carry as their own dependency_id instead of the
// depIDNotSet sentinel — Version, Task, Opcode, Keywords, EventRecordID,
// each an unattributed element whose own text content is the
// OptionalSubstitution of that same index (see binxml.go's sub* constants).
// Shared with datasize_test.go.
var knownOptionalDependencyIDs = map[uint16]bool{
	subVersion:       true,
	subTask:          true,
	subOpcode:        true,
	subKeywords:      true,
	subEventRecordID: true,
}

// isRecognisedDependencyID reports whether dep is either the "always
// present" sentinel or one of the five known F12c optional indices above.
func isRecognisedDependencyID(dep uint16) bool {
	return dep == depIDNotSet || knownOptionalDependencyIDs[dep]
}

func TestWriteOpenElement_DependencyIDIsUnset(t *testing.T) {
	const base = uint32(evtxRecordsStart + evtxRecordHeaderSize)
	res := buildBinXML(4663, 1, goldenFields(), base)
	payload := res.payload

	// Bound the scan to the template body: preambleSize (38) through
	// preambleSize+data_length, the same region decodeBinXML locates data
	// from payload[34:38] (binxml_reader.go). OpenStartElementTag tokens
	// only ever occur there — the substitution array and value data that
	// follow are a different structure entirely, and (Task 8b) now contain
	// enough varied bytes (a NULL entry's absence of data, EventRecordID's
	// small uint64) that scanning past the template body risks a genuine
	// coincidental token-header match, not just the reasoned "plausible
	// header" collisions this test already guards against below.
	bodyEnd := preambleSize + int(binary.LittleEndian.Uint32(payload[34:38]))
	if bodyEnd > len(payload) {
		bodyEnd = len(payload)
	}

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
	foundOptional := 0
	for i := preambleSize; i+3 < bodyEnd; i++ {
		tok := payload[i]

		// F8/F12b knock-on: an Attribute token (0x06, or 0x46 "more
		// attributes follow" — F12b's Correlation/Execution carry one of
		// each) carries its own 4-byte name_offset immediately followed by
		// an inline NameNode. That name_offset is an absolute chunk offset,
		// not a small count, so its low byte is effectively arbitrary — it
		// can coincidentally equal 0x01/0x41, and the NameNode's own
		// next_offset field (always written as 0 by writeNameNode) is
		// guaranteed to look like a "plausible" zero-sized element span
		// immediately after. Before F8 (Task 8) added a 135-byte literal
		// attribute to <Event>, no name_offset in the payload happened to
		// collide this way; shifting every later offset by that amount made
		// the <Provider> element's own "Name" attribute collide (payload
		// offset 997 = the low byte of name_offset 0x0601).
		//
		// 0x06 itself is far too common a byte (it turns up throughout
		// ordinary UTF-16LE text and substitution value data — an unguarded
		// probe found 26 "matches" in this payload, most of them nonsense
		// like a decoded char_count of 17152) to treat every occurrence as a
		// real Attribute token the way 0x01/0x41 are. Instead, require the
		// name_offset field to hold the exact absolute address writeNameNode
		// would place its NameNode at, base+i+attrHeaderSize — a coincidence
		// that random bytes essentially never produce — before trusting the
		// decoded char_count to compute a skip; otherwise treat the byte as
		// ordinary and only advance by one, same as before this branch
		// existed.
		if tok == binXMLAttribute || tok == binXMLAttributeMore {
			const attrHeaderSize = 5 // token(1) + name_offset(4)
			if i+attrHeaderSize <= len(payload) {
				nameOffset := binary.LittleEndian.Uint32(payload[i+1:])
				nn := i + attrHeaderSize
				if nameOffset == base+uint32(nn) && nn+8 <= len(payload) {
					charCount := int(binary.LittleEndian.Uint16(payload[nn+6:]))
					nameNodeSize := 8 + charCount*2 + 2
					if end := nn + nameNodeSize; end <= len(payload) {
						i = end - 1 // loop's own i++ lands exactly on end
					}
				}
			}
			continue
		}

		if tok != binXMLOpenElement && tok != binXMLOpenElementAttrs {
			continue
		}
		dep := binary.LittleEndian.Uint16(payload[i+1:])
		if isRecognisedDependencyID(dep) {
			if dep == depIDNotSet {
				found++
			} else {
				foundOptional++
			}
			// Task 7e gave data_size a real, content-derived value. That
			// value's own bytes (payload[i+3:i+7]) can coincidentally equal
			// 0x01/0x41 partway through — e.g. data_size 0x0133 stores 0x01
			// at i+4 — which this loop would otherwise revisit on the very
			// next iterations and misread as a second, bogus element header
			// nested inside this element's own fixed header fields. Skip past
			// this element's own fixed header (token+dep_id+data_size+
			// name_offset) so only bytes that could plausibly start another
			// token are considered; the NameNode, attr_list_size (Task 7f
			// moved it after the NameNode; it too now carries a real,
			// content-derived value instead of the 0 it used to be),
			// attributes, and any real nested children that follow are still
			// scanned normally.
			//
			// headerSize is 11 for BOTH the with- and without-attributes forms
			// (Task 7f/F11): real Windows places the NameNode at the same
			// fixed offset either way, and go-evtx now matches — see
			// writeOpenElement's doc comment in binxml.go.
			const headerSize = 11 // token(1) + dep_id(2) + data_size(4) + name_offset(4)
			i += headerSize - 1   // loop's own i++ accounts for the last byte
			continue
		}
		// A 0x01/0x41 byte can occur inside string data, so only flag a
		// mismatch when the following bytes look like a plausible header.
		size := binary.LittleEndian.Uint32(payload[i+3:])
		if size < uint32(len(payload)) {
			t.Errorf("offset %d: OpenStartElement dependency_id = 0x%04x, want 0xffff or a known F12c optional index", i, dep)
		}
	}
	if found == 0 {
		t.Fatal("no OpenStartElement tokens with dependency_id 0xffff found — " +
			"the scan is wrong or nothing was emitted")
	}
	if foundOptional != len(knownOptionalDependencyIDs) {
		t.Errorf("found %d OpenStartElement tokens with a known F12c optional dependency_id, want exactly %d (one per scalar element)",
			foundOptional, len(knownOptionalDependencyIDs))
	}
	t.Logf("%d OpenStartElement tokens carry the 0xffff sentinel, %d carry a known F12c optional dependency_id", found, foundOptional)
}
