// attrlist_test.go — attr_list_size must sit AFTER the inline NameNode, not
// before it, and must carry the byte count of the attribute list rather than
// 0 (F11).
//
// Measured, not assumed: Task 7f's Step 1 probe walked three 0x41 elements in
// testdata/system.evtx chunk 0 — <Event> at chunk-relative offset 578,
// <Provider> at 783, <TimeCreated> at 1286 — and found, in every case:
//
//   - name_offset == token_pos + 11 (the NameNode sits immediately after the
//     fixed 11-byte header: token(1) + dep_id(2) + data_size(4) + name_offset(4),
//     the SAME size the without-attributes form already used — real Windows
//     does not grow the fixed header for the with-attributes case; it moves
//     attr_list_size instead)
//   - a NameNode decodes there
//   - the four bytes immediately after the NameNode's end are a non-zero
//     attr_list_size
//   - attr_list_size counts exactly the bytes from there up to (but not
//     including) the Close(Start|Empty)ElementTag that follows: for all three
//     measured elements, attr_region_start + attr_list_size landed exactly on
//     a close-tag byte (0x02 for <Event>, which has children; 0x03 for
//     <Provider> and <TimeCreated>, which are self-closing).
//
// See task-7f-report.md for the full measurement table.
package evtx

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// TestWriteOpenElement_AttrListSizeAfterNameNode walks every OpenElementAttrs
// (0x41) token buildBinXML emits and checks: name_offset points 11 bytes past
// the token; a NameNode decodes there whose stored hash matches its own name;
// and attr_list_size, sitting immediately after that NameNode ends, is
// non-zero and lands exactly on the CloseStartElementTag (0x02) that follows
// — go-evtx never emits the self-closing CloseEmptyElementTag (0x03; every
// element it writes closes via 0x02 and a later, separate EndElementTag).
func TestWriteOpenElement_AttrListSizeAfterNameNode(t *testing.T) {
	const base = uint32(evtxRecordsStart + evtxRecordHeaderSize)
	res := buildBinXML(4663, 1, goldenFields(), base)
	payload := res.payload

	checked := 0
	for i := preambleSize; i+7 < len(payload); i++ {
		if payload[i] != binXMLOpenElementAttrs {
			continue
		}
		if dep := binary.LittleEndian.Uint16(payload[i+1:]); !isRecognisedDependencyID(dep) {
			// F13a: EventID is now a 0x41 (attribute-bearing) element whose
			// dependency_id is subEventID (1), not depIDNotSet — recognise it
			// via the same helper dependency_test.go defines, rather than
			// silently skipping EventID's own Qualifiers attribute list.
			continue // not a genuine element header
		}

		nameOffset := int(binary.LittleEndian.Uint32(payload[i+7:])) - int(base)
		if want := i + 11; nameOffset != want {
			t.Errorf("offset %d: name_offset (payload-relative) = %d, want %d (token+11)", i, nameOffset, want)
			continue
		}

		// Decode the NameNode at name_offset.
		nn := nameOffset
		if nn+8 > len(payload) {
			t.Errorf("offset %d: NameNode at %d runs past payload", i, nn)
			continue
		}
		n := int(binary.LittleEndian.Uint16(payload[nn+6:]))
		if nn+8+2*n+2 > len(payload) {
			t.Errorf("offset %d: NameNode at %d has char data running past payload", i, nn)
			continue
		}
		u16 := make([]uint16, n)
		for j := 0; j < n; j++ {
			u16[j] = binary.LittleEndian.Uint16(payload[nn+8+2*j:])
		}
		name := string(utf16.Decode(u16))
		if storedHash := binary.LittleEndian.Uint16(payload[nn+4:]); uint16(sdbmHash(name)) != storedHash {
			t.Errorf("offset %d: NameNode at %d decodes to %q, whose hash 0x%04x doesn't match sdbmHash 0x%04x",
				i, nn, name, storedHash, uint16(sdbmHash(name)))
			continue
		}
		nameNodeEnd := nn + 8 + 2*n + 2

		// attr_list_size: the 4 bytes immediately after the NameNode — NOT
		// between name_offset and the NameNode, which is where go-evtx wrote
		// it (as 0, unconditionally) before this task.
		if nameNodeEnd+4 > len(payload) {
			t.Errorf("offset %d (%q): attr_list_size field at %d runs past payload", i, name, nameNodeEnd)
			continue
		}
		attrListSize := binary.LittleEndian.Uint32(payload[nameNodeEnd:])
		if attrListSize == 0 {
			t.Errorf("offset %d (%q): attr_list_size is 0", i, name)
			continue
		}
		attrRegionStart := nameNodeEnd + 4
		closeAt := attrRegionStart + int(attrListSize)
		if closeAt >= len(payload) {
			t.Errorf("offset %d (%q): attr_list_size %d runs the attribute list past the payload (closeAt %d >= %d)",
				i, name, attrListSize, closeAt, len(payload))
			continue
		}
		if got := payload[closeAt]; got != binXMLCloseElement {
			t.Errorf("offset %d (%q): attr_list_size %d does not land on CloseStartElementTag — byte at %d is 0x%02x, want 0x%02x",
				i, name, attrListSize, closeAt, got, binXMLCloseElement)
			continue
		}

		checked++
		// Resume scanning from the close tag: everything between here and
		// there (this element's own header, NameNode, attr_list_size, and
		// attribute list) has already been validated as a unit, and
		// re-scanning it byte-by-byte risks misreading its interior bytes as
		// a bogus nested header — the same class of false positive Task 7e
		// hit in dependency_test.go.
		i = closeAt - 1 // loop's own i++ lands exactly on closeAt
	}
	if checked == 0 {
		t.Fatal("no OpenElementAttrs (0x41) tokens examined — the scan is wrong")
	}
	t.Logf("%d attribute-bearing elements carry a correctly-placed, non-zero attr_list_size", checked)
}
