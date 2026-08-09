// dependency_test.go — every OpenStartElement must carry dependency_id
// depIDNotSet (0xffff), the sentinel libyal's EVTX documentation defines as
// "not set" — UNLESS it is one of the seven F12c/F13a elements (Tasks 8b/8c)
// whose own dependency_id ties to their own content substitution's index,
// matching testdata/system.evtx. 0 is otherwise a valid identifier pointing
// at template value 0, which is a claim go-evtx has no business making on
// any other element it writes.
package evtx

import (
	"encoding/binary"
	"testing"
)

// knownOptionalDependencyIDs are the F12c/F13a substitution indices
// legitimate OpenStartElementTags may carry as their own dependency_id
// instead of the depIDNotSet sentinel: Version, Task, Opcode, Keywords,
// EventRecordID (F12c) are each an unattributed element whose own text
// content is the OptionalSubstitution of that same index; EventID and Level
// (F13a) are the same shape but pre-existing, and now attributed in
// EventID's case — their dependency_id still ties to their own CONTENT
// index, not any attribute's (see binxml.go's sub* constants and
// subEventID/subLevel's doc comment). Shared with datasize_test.go.
// F18 adds Channel, Computer and the twelve <Data> values. Those carry a
// caller-supplied string that may legitimately be empty, and the census says
// an absent value is only ever referenced by an OptionalSubstitution: a
// NormalSubstitution paired with a NULL array entry occurs 0 times in 27
// million observations of real output, against 1 152 729 for the optional
// form. Each of these elements' dependency_id therefore names its own content
// substitution, exactly like the seven above.
var knownOptionalDependencyIDs = map[uint16]bool{
	subVersion:       true,
	subTask:          true,
	subOpcode:        true,
	subKeywords:      true,
	subEventRecordID: true,
	subEventID:       true,
	subLevel:         true,
	subChannel:       true,
	subComputer:      true,
}

func init() {
	// The twelve <Data> value slots, 6, 8, ... 28.
	for i := 0; i < 12; i++ {
		knownOptionalDependencyIDs[uint16(6+i*2)] = true
	}
}

// isRecognisedDependencyID reports whether dep is either the "always
// present" sentinel or one of the seven known F12c/F13a optional indices above.
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
	// The scan starts at preambleSize+fragHeaderSize, not preambleSize: the
	// fixed 38-byte preamble (outer FragmentHeader + TemplateInstanceNode +
	// TemplateNode header) contains structural bytes that are not element
	// tokens but coincidentally pass the "plausible header" guard below — the
	// outer fragment header's minor-version byte (0x01) followed by
	// flags(0x00)+TemplateInstance token(0x0C) reads as a small, in-range
	// "size", and likewise the low byte of the TemplateNode GUID (==
	// template_id == 1). The template body's OWN nested FragmentHeader (B2,
	// Task 7 Part B: "every real template body opens with its own nested
	// fragment header, before the first element token") occupies the first 4
	// bytes of the body itself and has the exact same problem: byte 1 of that
	// header is 0x01 (major version), immediately followed by 0x01 0x00 (minor
	// version + flags) — which reads as token 0x01 with dependency_id 0x0001.
	// Harmless before F13a (Task 8c), when no OpenStartElementTag legitimately
	// carried dependency_id 1; F13a's EventID now does, so this coincidence
	// stopped being filtered out by the "not recognised" branch and instead
	// got miscounted as a real match, then advanced the scan by a false
	// 11-byte header, desynchronising it. Real OpenStartElement tokens only
	// ever occur after both nested fragment headers, i.e. at
	// preambleSize+fragHeaderSize.
	found := 0
	foundOptional := 0
	for i := preambleSize + fragHeaderSize; i+3 < bodyEnd; i++ {
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

		// headerSize is 11 for BOTH the with- and without-attributes forms
		// (Task 7f/F11): real Windows places the NameNode at the same fixed
		// offset either way, and go-evtx now matches — see writeOpenElement's
		// doc comment in binxml.go.
		const headerSize = 11 // token(1) + dep_id(2) + data_size(4) + name_offset(4)

		// Verify this candidate is a genuine element header BEFORE trusting
		// its dependency_id: name_offset (the 4 bytes at i+7) must equal the
		// exact absolute address writeOpenElement would place the inline
		// NameNode at, base+i+headerSize — the same verification already used
		// for Attribute tokens above and for OpenElementAttrs in
		// attrlist_test.go.
		//
		// Needed since F13a (Task 8c): a 0x01/0x41 byte can occur inside
		// string data or other token bytes (already true before this task —
		// hence the old "plausible size" guard below), but F13a introduced a
		// NEW, more specific coincidence a size-only guard cannot catch:
		// Provider's Name attribute is now a NormalSubstitution whose own
		// type byte is 0x01 (STRING) — the same value as binXMLOpenElement —
		// and it sits directly before Guid's own attribute token (0x06).
		// Together, those two unrelated bytes decode as tok=0x01,
		// dependency_id=0x5806, and 0x5806 happens to pair with a small
		// "size" that used to slip past the old guard. name_offset doesn't:
		// a real header's name_offset is always base+i+11, and this
		// coincidence decodes to something else entirely.
		if i+headerSize > len(payload) {
			continue
		}
		nameOffset := binary.LittleEndian.Uint32(payload[i+7:])
		if nameOffset != base+uint32(i)+headerSize {
			continue // not a genuine element header — ordinary byte, advance by one
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
			i += headerSize - 1 // loop's own i++ accounts for the last byte
			continue
		}
		t.Errorf("offset %d: OpenStartElement dependency_id = 0x%04x, want 0xffff or a known F12c/F13a optional index", i, dep)
	}
	if found == 0 {
		t.Fatal("no OpenStartElement tokens with dependency_id 0xffff found — " +
			"the scan is wrong or nothing was emitted")
	}
	if foundOptional != len(knownOptionalDependencyIDs) {
		t.Errorf("found %d OpenStartElement tokens with a known F12c/F13a optional dependency_id, want exactly %d (one per scalar element)",
			foundOptional, len(knownOptionalDependencyIDs))
	}
	t.Logf("%d OpenStartElement tokens carry the 0xffff sentinel, %d carry a known F12c/F13a optional dependency_id", found, foundOptional)
}
