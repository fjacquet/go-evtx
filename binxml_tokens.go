// binxml_tokens.go — the low-level BinXML token writers and the little-endian
// helpers they use. Split out of binxml.go, which had grown to 1174 lines
// carrying three separable things: the record assembly, the template body, and
// these primitives.
//
// Nothing here knows what a <System> block is. Each function writes one token
// exactly as the format defines it; deciding which token an element needs is
// buildTemplateBody's job, in binxml_template.go.
package evtx

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// ---------------------------------------------------------------------------
// BinXML token writers (used by buildTemplateBody)
// ---------------------------------------------------------------------------

// writeOpenElement writes an OpenStartElement token with inline NameNode, and
// returns the token byte's position within b (i.e. b.Len() as it stood
// before this call — a local offset into the template-body buffer, NOT
// adjusted by binXMLBase), so a caller building a stack of open elements
// (buildTemplateBody, via pushOpenElement/pushOpenElementAttrs) can later
// back-patch this token's data_size field once its EndElementTag is known:
// the patch is applied to the finished template-body byte slice at the exact
// field offset, so pos must stay in that slice's own coordinate space.
// data_size is written as 0 here — a placeholder patched in by
// writeEndElement/buildTemplateBody's final patch pass, never left as 0 in
// the returned payload.
//
// For an element with attributes, attrListPos is the buffer position of
// attr_list_size's own 4 bytes (also written as a 0 placeholder here, patched
// by closeAttrList once the attribute list is known); for an element without
// attributes attrListPos is meaningless and always 0 — hasAttrs tells the
// caller which applies.
//
// Layout without attrs (0x01):
//
//	[token: 1B] [dep_id: 2B] [data_size: 4B] [name_offset: 4B] [NameNode]
//
// Layout with attrs (0x41):
//
//	[token: 1B] [dep_id: 2B] [data_size: 4B] [name_offset: 4B] [NameNode] [attr_list_size: 4B] [attributes…]
//
// F11 (Task 7f): real Windows places the inline NameNode immediately after
// name_offset in BOTH forms and puts attr_list_size after it, right before
// the attribute list. go-evtx used to write attr_list_size first (still
// always 0) and the NameNode after — a parser reading go-evtx's stream took
// the NameNode's next_offset (always 0) as attr_list_size, concluded the
// element had no attributes, and desynchronised immediately. Measured against
// testdata/system.evtx chunk 0 (Task 7f's Step 1 probe, task-7f-report.md):
// three 0x41 elements (<Event> at 578, <Provider> at 783, <TimeCreated> at
// 1286) all have name_offset == token_pos + 11, a NameNode decoding there,
// and a non-zero attr_list_size sitting immediately after that NameNode ends.
// Because the NameNode now always sits at the same fixed offset regardless of
// hasAttrs, headerSize is 11 for both branches — it no longer varies.
//
// depID is written verbatim as dependency_id: depIDNotSet (0xffff, libyal
// EVTX docs: "-1 (0xffff) => not set") for the elements confirmed against
// testdata/system.evtx to always render, or one of the sub* constants
// (Task 8b/F12c, Task 8c/F13a) for the seven elements whose own
// OptionalSubstitution content wraps that same index — real Windows ties
// dependency_id to exactly that substitution for every element of this shape
// it emits. EventID and Level are two of the seven: F12b left them at
// depIDNotSet as an explicit, permitted scope decision ("elements that are
// genuinely always present may legitimately stay 0x0D"); F13a (Task 8c)
// closes that out to match the real file exactly, since the measured table
// shows real Windows uses 0x0E for them too, dependency_id tied to their own
// content index (not, for EventID, its Qualifiers attribute's index).
func writeOpenElement(b *bytes.Buffer, name string, hasAttrs bool, depID uint16, binXMLBase uint32, refs *[]chunkRef) (tokenPos, attrListPos uint32) {
	tokenPos = uint32(b.Len())
	if hasAttrs {
		b.WriteByte(binXMLOpenElementAttrs) // 0x41
	} else {
		b.WriteByte(binXMLOpenElement) // 0x01
	}
	writeUint16LE(b, depID)
	writeUint32LE(b, 0) // data_size: placeholder, back-patched by writeEndElement

	const headerSize = 11 // token(1) + dep_id(2) + data_size(4) + name_offset(4) — NameNode always sits here now, for both branches
	nameNodeOffset := binXMLBase + tokenPos + headerSize
	writeUint32LE(b, nameNodeOffset)

	writeNameNode(b, name, binXMLBase, refs)

	if hasAttrs {
		attrListPos = uint32(b.Len())
		writeUint32LE(b, 0) // attr_list_size: placeholder, back-patched by closeAttrList once the attribute list is written
	}

	return tokenPos, attrListPos
}

// writeAttributeSub writes an Attribute token with inline NameNode, followed by
// a NormalSubstitution token as the attribute's value.
//
// moreAttrs selects token 0x46 ("more attributes follow") instead of the
// last-attribute form 0x06 (F12b) — needed whenever this attribute is not
// the last one in its element's list, e.g. Provider's own Name/Guid pair in
// the real file, or this task's new Correlation/Execution attribute pairs
// (which go through writeAttributeOptional instead, sharing the same flag).
//
// Layout: [token: 1B] [name_offset: 4B] [NameNode] [0x0D subIdx subType]
func writeAttributeSub(b *bytes.Buffer, name string, subIndex uint16, subType byte, moreAttrs bool, binXMLBase uint32, refs *[]chunkRef) {
	tokenPos := uint32(b.Len())
	if moreAttrs {
		b.WriteByte(binXMLAttributeMore)
	} else {
		b.WriteByte(binXMLAttribute)
	}
	nameNodeOffset := binXMLBase + tokenPos + 5 // 5 = token(1) + offset(4)
	writeUint32LE(b, nameNodeOffset)
	writeNameNode(b, name, binXMLBase, refs)
	writeSubstitution(b, subIndex, subType)
}

// writeAttributeOptional is writeAttributeSub for an attribute value go-evtx
// has no source for: Correlation's ActivityID/RelatedActivityID, Execution's
// ProcessID/ThreadID, and Security's UserID (F12b/F12c) pass binXMLTypeNull,
// matching how testdata/system.evtx itself encodes these exact fields when
// an event doesn't populate them (value_spec size 0, type 0x00) —
// reproducing the real file's own answer to "we don't have this," not
// inventing one. EventID's Qualifiers (F13c) is the one exception: it passes
// binXMLTypeUint16 instead, which F14 found is empirically required for
// Get-WinEvent to read the record at all, even though it does not match
// this same reasoning — see the F14 doc comment by the type constants for
// the full, unresolved story. In every case the value token is
// OptionalSubstitution (0x0E) rather than NormalSubstitution (0x0D).
//
// Layout: [token: 1B] [name_offset: 4B] [NameNode] [0x0E subIdx subType]
func writeAttributeOptional(b *bytes.Buffer, name string, subIndex uint16, subType byte, moreAttrs bool, binXMLBase uint32, refs *[]chunkRef) {
	tokenPos := uint32(b.Len())
	if moreAttrs {
		b.WriteByte(binXMLAttributeMore)
	} else {
		b.WriteByte(binXMLAttribute)
	}
	nameNodeOffset := binXMLBase + tokenPos + 5 // 5 = token(1) + offset(4)
	writeUint32LE(b, nameNodeOffset)
	writeNameNode(b, name, binXMLBase, refs)
	writeOptionalSubstitution(b, subIndex, subType)
}

// writeAttributeLiteral writes an Attribute token with inline NameNode,
// followed by a literal ValueText token as the attribute's value — for
// attributes whose value is fixed in every record (F8's xmlns), as opposed to
// writeAttributeSub's substitution-array reference.
//
// Layout: [token: 1B] [name_offset: 4B] [NameNode] [ValueText]
//
// Measured directly against testdata/system.evtx (chunk 0, the <Event>
// element's xmlns attribute at chunk-relative offset 4709 absolute /
// name_offset 589 chunk-relative): AttributeToken 0x06, a 4-byte name_offset,
// an inline NameNode for "xmlns" (20 bytes: next_offset(4)+hash(2)+
// char_count(2)+10 UTF-16LE chars+null(2)), then a ValueText token whose
// layout writeValueText below reproduces byte for byte — token 0x05, type
// 0x01 (String), a 2-byte char_count of 53 (NOT including a null terminator),
// and 106 bytes of UTF-16LE characters with no terminator at all. Summed
// (1+4+20+1+1+2+106 = 135) that exactly equals the attr_list_size the real
// file stores for this element (135, landing precisely on the byte after —
// CloseStartElementTag 0x02), confirming both the token layout and that
// ValueText carries no null terminator, unlike NameNode strings and
// substitution string values which do.
func writeAttributeLiteral(b *bytes.Buffer, name, value string, binXMLBase uint32, refs *[]chunkRef) {
	tokenPos := uint32(b.Len())
	b.WriteByte(binXMLAttribute)
	nameNodeOffset := binXMLBase + tokenPos + 5 // 5 = token(1) + offset(4)
	writeUint32LE(b, nameNodeOffset)
	writeNameNode(b, name, binXMLBase, refs)
	writeValueText(b, value)
}

// writeValueText writes a literal (non-substituted) string value token.
//
// Layout: [token: 0x05] [type: 0x01] [char_count: 2B LE] [UTF-16LE chars, NO
// null terminator] — confirmed against testdata/system.evtx; see
// writeAttributeLiteral's doc comment for the byte-for-byte measurement.
func writeValueText(b *bytes.Buffer, value string) {
	b.WriteByte(binXMLValueText)
	b.WriteByte(binXMLTypeString)
	u16 := utf16.Encode([]rune(value))
	writeUint16LE(b, uint16(len(u16)))
	for _, c := range u16 {
		writeUint16LE(b, c)
	}
}

// writeSubstitution writes a NormalSubstitution token (4 bytes).
//
// Layout: [token: 0x0D] [index: 2B LE] [type: 1B]
func writeSubstitution(b *bytes.Buffer, index uint16, valueType byte) {
	b.WriteByte(binXMLNormalSubstitution)
	writeUint16LE(b, index)
	b.WriteByte(valueType)
}

// writeOptionalSubstitution writes an OptionalSubstitution token (4 bytes) —
// F12c, token 0x0E rather than 0x0D. Per MS-EVEN6, ties to NULL-conditional
// omission: an element whose dependency_id names this same index is dropped
// from the rendered XML if the substitution array entry at that index is
// NULL-typed at render time. Measured throughout testdata/system.evtx's
// <System> block, which uses this token — never 0x0D — for every scalar
// child and every attribute value sampled.
//
// Layout: [token: 0x0E] [index: 2B LE] [type: 1B]
func writeOptionalSubstitution(b *bytes.Buffer, index uint16, valueType byte) {
	b.WriteByte(binXMLOptionalSubstitution)
	writeUint16LE(b, index)
	b.WriteByte(valueType)
}

// writeNameNode writes a NameNode inline in the BinXML stream and records its
// chunk-relative offset in refs.
//
// Layout: [next_offset: 4B = 0] [hash: 2B] [char_count: 2B] [UTF-16LE chars] [null: 2B]
//
// next_offset is written as 0 here. fillHashTables patches it later for the
// nodes it chains into a bucket; nodes it does not chain keep the 0.
func writeNameNode(b *bytes.Buffer, name string, binXMLBase uint32, refs *[]chunkRef) {
	h := sdbmHash(name)
	*refs = append(*refs, chunkRef{key: h, offset: binXMLBase + uint32(b.Len())})

	u16 := utf16.Encode([]rune(name))
	writeUint32LE(b, 0)                // next_offset, patched by fillHashTables
	writeUint16LE(b, uint16(h))        // SDBM hash
	writeUint16LE(b, uint16(len(u16))) // string_length
	for _, c := range u16 {
		writeUint16LE(b, c)
	}
	writeUint16LE(b, 0) // null terminator
}

// encodeSubString encodes a string as raw UTF-16LE for use in the
// substitution value data, WITHOUT a null terminator.
//
// F15 (Task 8f): real Windows never null-terminates a String-typed
// substitution-array VALUE — confirmed independently against
// testdata/system.evtx by parsing 45 records that use a "full" (inline,
// non-cached) template instance and decoding their substitution arrays
// directly (count + size/type/pad specs + concatenated value_data, no
// decoding library involved): all 28 non-empty String-typed entries found
// had a declared size of exactly char_count*2, none had a trailing
// UTF-16 null pair. Two examples: "Microsoft-Windows-WindowsUpdateClient"
// (37 chars, declared size 74) and "System" (6 chars, declared size 12).
// This independently reproduces task-8e-report.md's own Part 4 finding
// (28/28 samples, same two examples).
//
// This is NOT true of NameNode strings, which real Windows DOES
// null-terminate — confirmed directly against the same file: the "Event"
// NameNode occurs as bytes `00 00 00 00 ba 0c 05 00 45 00 76 00 65 00 6e
// 00 74 00 00 00` (next_offset=0, hash=0x0cba, char_count=5, "Event",
// then a 2-byte null terminator), matching CLAUDE.md's documented pattern
// exactly. writeNameNode's own terminator is therefore untouched by this
// change — only this function, which feeds substitution-array value data,
// changes.
func encodeSubString(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	buf := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], v)
	}
	return buf
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

func writeUint16LE(b *bytes.Buffer, v uint16) {
	_ = b.WriteByte(byte(v))
	_ = b.WriteByte(byte(v >> 8))
}

func writeUint32LE(b *bytes.Buffer, v uint32) {
	_ = b.WriteByte(byte(v))
	_ = b.WriteByte(byte(v >> 8))
	_ = b.WriteByte(byte(v >> 16))
	_ = b.WriteByte(byte(v >> 24))
}

func uint16LEBytes(v uint16) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, v)
	return buf
}

func uint64LEBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	return buf
}
