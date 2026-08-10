// binxml_template.go — the <Event> template body: which element gets which
// token, in which order, with which substitution index. Split out of
// binxml.go, which carried it alongside the record assembly and the token
// primitives.
//
// This is the file that changes when the encoded shape of an event changes.
// Every F-numbered format fix in docs/evtx-format-notes.md that touched the
// element tree touched this function.
package evtx

import (
	"bytes"
	"encoding/binary"
)

// buildTemplateBody constructs the BinXML template body. Most substitutions
// are NormalSubstitution (0x0D); F12c's five scalar System children
// (Version/Task/Opcode/Keywords/EventRecordID), F13a's EventID/Level, and
// four attribute-only elements' attribute values
// (Correlation/Execution/Security/EventID's own Qualifiers) use
// OptionalSubstitution (0x0E) instead, matching testdata/system.evtx.
//
// Substitution indices — see the comment above the sub* constants for how
// indices 29-41 were chosen; <System> element order below matches the real
// file's order exactly (Task 8b Step 1): Provider, EventID, Version, Level,
// Task, Opcode, Keywords, TimeCreated, EventRecordID, Correlation,
// Execution, Channel, Computer, Security.
//
//	0:  ProviderName  (STRING)
//	1:  EventID       (UINT16)                        — F13a: now OptionalSubstitution, dependency_id = own index
//	2:  Level         (UINT8)                         — F12a: was UINT16; F13a: now OptionalSubstitution, dependency_id = own index
//	3:  SystemTime    (FILETIME)
//	4:  Computer      (STRING)
//	5+2i:  Data[i] Name attr  (STRING)   — 12 data fields
//	6+2i:  Data[i] value      (STRING)
//	29: Version                    (UINT8)    — F12b, no source: always 0
//	30: Task                       (UINT16)   — F12b, no source: always 0
//	31: Opcode                     (UINT8)    — F12b, no source: always 0
//	32: Keywords                   (HEXINT64) — F12b, no source: always 0
//	33: EventRecordID              (UINT64)   — F12b, the writer's record ID
//	34: Correlation/@ActivityID        (NULL) — F12b, no source
//	35: Correlation/@RelatedActivityID (NULL) — F12b, no source
//	36: Execution/@ProcessID           (NULL) — F12b, no source
//	37: Execution/@ThreadID            (NULL) — F12b, no source
//	38: Channel                    (STRING)   — F12b, from fields["Channel"]
//	39: Security/@UserID               (NULL) — F12b, no source
//	40: Provider/@Guid             (STRING)   — F13b, from fields["ProviderGuid"]
//	41: EventID/@Qualifiers            (NULL, type UNSIGNED_WORD) — F13c, no source; F14 tried NULL-type here and it broke STAGE2 READ — see the F14 doc comment by the type constants
//
// Total: 29 + 13 = 42 substitutions.
//
// names accumulates the chunk-relative offset and hash of every NameNode
// emitted along the way, in emission order.
func buildTemplateBody(baseOffset uint32, names *[]chunkRef) []byte {
	b := &bytes.Buffer{}

	// dataSizeStack tracks the chunk-relative token position of every
	// OpenStartElementTag whose EndElementTag has not yet been written, in
	// nesting order (innermost last) — pushed by writeOpenElement, popped by
	// writeEndElement. patches accumulates one (pos, size) back-patch per
	// completed field — one per popped OpenStartElementTag (data_size) plus
	// one per closed attribute list (attr_list_size, Task 7f/F11) — where pos
	// is the exact buffer offset of the 4-byte field itself. bytes.Buffer
	// offers no in-place mutation of bytes already written, so the patches
	// are applied to the finished []byte once, just before this function
	// returns, rather than as each field becomes known.
	var dataSizeStack []uint32
	var patches []fieldPatch

	// B2: every real template body opens with its own nested fragment header,
	// before the first element token — verified against testdata/system.evtx
	// (the template at chunk offset 24508 has data_length 52 and its body at
	// 24532 starts "0f 01 01 00 01 ff"). This shifts every offset inside the
	// body by 4 bytes; writeOpenElement/writeAttributeSub/writeNameNode below
	// compute offsets as baseOffset + b.Len(), so they follow automatically
	// (confirmed by TestFixture_TemplateTableBucketRule and the hash-table
	// integration test, which walk the real and written tables respectively).
	b.WriteByte(binXMLFragmentHeader)
	b.WriteByte(0x01) // major version
	b.WriteByte(0x01) // minor version
	b.WriteByte(0x00) // flags

	var attrListPos uint32

	// <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
	//
	// F8: xmlns is a literal-valued attribute, not a substitution — its value
	// is fixed in every record, so it is written inline as a ValueText token
	// rather than occupying one of the 29 substitution slots (which would
	// shift the index map documented in CLAUDE.md and every index in
	// binxml_reader.go). This promotes <Event> from token 0x01 (no attrs) to
	// 0x41 (has attrs), so it now goes through pushOpenElementAttrs and
	// closeAttrList exactly like <Provider>/<TimeCreated>/<Data> below —
	// reusing the back-patch mechanism Task 7f built, not a second one.
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Event", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeLiteral(b, "xmlns", eventNamespaceURI, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)

	//   <System>
	dataSizeStack = pushOpenElement(b, "System", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)

	//     <Provider Name="%0" Guid="%40"/>                              (F13b)
	//
	// Provider's first attribute (Name) is no longer the list's only one, so
	// its own token must switch from binXMLAttribute (0x06) to
	// binXMLAttributeMore (0x46) — a previous task confirmed real Windows
	// writes 0x46 for every non-final attribute and 0x06 only for the last;
	// go-evtx had only ever emitted 0x06 because every element it wrote had
	// exactly one attribute until now. Guid's value is a substitution (like
	// Name's), not a literal, even though the real file happens to write
	// Provider's Guid as a literal ValueText — a provider GUID varies per
	// caller, so it needs the same per-record flexibility Name already has.
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Provider", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "Name", subProviderName, binXMLTypeString, true, baseOffset, names)
	writeAttributeOptional(b, "Guid", subProviderGuid, binXMLTypeString, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <EventID Qualifiers="%41">%1</EventID>                        (F13a/F13c)
	//
	// F13c declares Qualifiers UNSIGNED_WORD (0x06) at size 0.
	// docs/reports/task-8b-report.md's Step 1 table cites this as the real file's own
	// encoding; F14 (Task 8e) partly disputed that (a byte-for-byte re-parse
	// of the real record the table cites found index 4 declared type 0x00,
	// not 0x06) and briefly changed this to binXMLTypeNull to match — but
	// that change made Windows' EventLogReader.ReadEvent() regress from
	// reading all 403 records to failing on record 0 (STAGE2 READ), an
	// unambiguous, directly-measured CI signal stronger than the byte-level
	// re-parse it contradicts. Reverted back to UNSIGNED_WORD on that
	// evidence. The two findings are not reconciled: either this task's
	// index-to-field identification of "Qualifiers = substitution index 4 in
	// the real file's own numbering" doesn't actually hold (the Step 1
	// table's index assignments, not just its types, may themselves be
	// unreliable — this task did not re-derive them independently, only
	// re-checked the types at the indices the table already named), or some
	// other mechanism ties Windows' acceptance to this declared type in a
	// way not yet understood. See docs/reports/task-8e-report.md's "Concerns" for the
	// open question this leaves. F13a: the element's own dependency_id
	// becomes subEventID (its own content index), and the content
	// substitution switches to OptionalSubstitution.
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "EventID", subEventID, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "Qualifiers", subEventIDQualifiers, binXMLTypeUint16, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subEventID, binXMLTypeUint16)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Version>%29</Version>                                        (F12b/F12c)
	dataSizeStack = pushOpenElement(b, "Version", false, subVersion, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subVersion, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Level>%2</Level>                                             (F12a: UINT8, was UINT16; F13a: OptionalSubstitution)
	dataSizeStack = pushOpenElement(b, "Level", false, subLevel, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subLevel, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Task>%30</Task>                                              (F12b/F12c)
	dataSizeStack = pushOpenElement(b, "Task", false, subTask, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subTask, binXMLTypeUint16)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Opcode>%31</Opcode>                                          (F12b/F12c)
	dataSizeStack = pushOpenElement(b, "Opcode", false, subOpcode, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subOpcode, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Keywords>%32</Keywords>                                      (F12b/F12c)
	dataSizeStack = pushOpenElement(b, "Keywords", false, subKeywords, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subKeywords, binXMLTypeHexInt64)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <TimeCreated SystemTime="%3"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "TimeCreated", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeSub(b, "SystemTime", 3, binXMLTypeFiletime, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <EventRecordID>%33</EventRecordID>                            (F12b/F12c)
	dataSizeStack = pushOpenElement(b, "EventRecordID", false, subEventRecordID, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subEventRecordID, binXMLTypeUint64)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Correlation ActivityID="%34" RelatedActivityID="%35"/>       (F12b/F12c)
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Correlation", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "ActivityID", subActivityID, binXMLTypeGuid, true, baseOffset, names)
	writeAttributeOptional(b, "RelatedActivityID", subRelatedActivityID, binXMLTypeGuid, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Execution ProcessID="%36" ThreadID="%37"/>                   (F12b/F12c)
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Execution", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "ProcessID", subProcessID, binXMLTypeUint32, true, baseOffset, names)
	writeAttributeOptional(b, "ThreadID", subThreadID, binXMLTypeUint32, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Channel>%38</Channel>                                        (F12b, F18)
	dataSizeStack = pushOpenElement(b, "Channel", false, subChannel, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subChannel, binXMLTypeString)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Computer>%4</Computer>                                       (F18)
	dataSizeStack = pushOpenElement(b, "Computer", false, subComputer, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, subComputer, binXMLTypeString)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Security UserID="%39"/>                                      (F12b/F12c)
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Security", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "UserID", subSecurityUserID, binXMLTypeSid, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//   </System>
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//   <EventData>
	dataSizeStack = pushOpenElement(b, "EventData", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)

	//     12 Data elements: <Data Name="%N">%N+1</Data>
	for i := 0; i < 12; i++ {
		nameIdx := uint16(5 + i*2)
		valueIdx := uint16(6 + i*2)
		// F18: the value may be absent, so it is an OptionalSubstitution and
		// <Data>'s own dependency_id names it. The NAME never is — it comes
		// from dataFieldNames — so it stays a NormalSubstitution.
		dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Data", valueIdx, baseOffset, names, dataSizeStack)
		writeAttributeSub(b, "Name", nameIdx, binXMLTypeString, false, baseOffset, names)
		patches = closeAttrList(b, attrListPos, patches)
		b.WriteByte(binXMLCloseElement)
		writeOptionalSubstitution(b, valueIdx, binXMLTypeString)
		dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)
	}

	//   </EventData>
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	// </Event>
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	// EndOfStream (terminates template body's _children loop).
	b.WriteByte(0x00)

	if len(dataSizeStack) != 0 {
		// Every writeOpenElement call above is paired with exactly one
		// writeEndElement call, so the stack must be empty here. A future
		// edit that adds an element without closing it (or vice versa) would
		// otherwise leave an OpenStartElementTag's data_size silently
		// unpatched (still 0) instead of failing loudly.
		panic("buildTemplateBody: unbalanced writeOpenElement/writeEndElement calls")
	}

	buf := b.Bytes()
	for _, p := range patches {
		binary.LittleEndian.PutUint32(buf[p.pos:], p.size)
	}
	return buf
}

// fieldPatch records where to write a back-patched 4-byte little-endian field
// once the template body is complete: buf[pos:pos+4] = size. Used for both
// data_size (written by writeEndElement once an OpenStartElementTag's
// EndElementTag is known) and attr_list_size (written by closeAttrList once
// an element's attribute list is known to be complete) — both are only
// knowable after content that comes later in the stream has been written, so
// both go through the same accumulate-then-apply mechanism rather than two
// separate ones.
type fieldPatch struct {
	pos  uint32 // exact buffer offset of the 4-byte field to patch
	size uint32 // computed value
}

// pushOpenElement calls writeOpenElement and pushes the token position it
// reports onto stack, returning the updated stack. A thin wrapper rather than
// inlining `stack = append(stack, writeOpenElement(...))` at every call site,
// so buildTemplateBody's element list reads the same as it did before this
// task (one line per open, one line per close). For an element with
// attributes, use pushOpenElementAttrs instead — it also surfaces the
// attr_list_size back-patch position that this wrapper discards.
//
// depID is the element's own dependency_id: depIDNotSet for the (still
// overwhelming majority of) unconditional elements, or one of the sub*
// constants for the five F12c scalar elements whose OptionalSubstitution
// content shares their own index.
func pushOpenElement(b *bytes.Buffer, name string, hasAttrs bool, depID uint16, binXMLBase uint32, refs *[]chunkRef, stack []uint32) []uint32 {
	pos, _ := writeOpenElement(b, name, hasAttrs, depID, binXMLBase, refs)
	return append(stack, pos)
}

// pushOpenElementAttrs is pushOpenElement for an element that has attributes:
// it additionally returns the buffer position of attr_list_size's own 4
// bytes, so the caller can write the attribute list and then pass that
// position to closeAttrList once it knows where the list ends.
func pushOpenElementAttrs(b *bytes.Buffer, name string, depID uint16, binXMLBase uint32, refs *[]chunkRef, stack []uint32) (newStack []uint32, attrListPos uint32) {
	tokenPos, attrListPos := writeOpenElement(b, name, true, depID, binXMLBase, refs)
	return append(stack, tokenPos), attrListPos
}

// closeAttrList records a back-patch for attr_list_size — the byte count of
// the attribute list that was just written — once the caller has finished
// writing that element's attributes (writeAttributeSub calls) but BEFORE
// writing the Close(Start|Empty)ElementTag that follows.
//
// Measured, not assumed (Task 7f's Step 1 probe, testdata/system.evtx chunk
// 0): for the three 0x41 elements checked — <Event> at 578 (closes via 0x02,
// since it has children), <Provider> at 783 and <TimeCreated> at 1286 (both
// close via 0x03, self-closing) — attr_region_start + attr_list_size landed
// exactly on that closing-tag byte in every case, with attr_region_start
// being the offset immediately after attr_list_size's own 4 bytes. So
// attr_list_size counts only the attribute list itself: not the
// Close(Start|Empty)ElementTag, and not any children or the element's own
// EndElementTag — those are already accounted for by data_size, which spans
// the element's entire content.
func closeAttrList(b *bytes.Buffer, attrListPos uint32, patches []fieldPatch) []fieldPatch {
	size := uint32(b.Len()) - (attrListPos + 4)
	return append(patches, fieldPatch{pos: attrListPos, size: size})
}

// writeEndElement writes an EndElementTag (0x04) and pops the position of the
// OpenStartElementTag it closes off stack, recording a data_size patch for
// it. The formula — data_size = (offset immediately after this closing tag)
// − (element_start + 7) — was measured directly against testdata/system.evtx
// (Task 7e's Step 1 probe): a data_size-blind structural parse of two real
// records (33 elements total, 3 nesting depths, both inline and
// back-referenced element names) found this formula's result equal to the
// independently-derived structural end in every case, with no exceptions.
// "+7" is token(1) + dependency_id(2) + data_size(4) — the fixed bytes common
// to both the with- and without-attributes OpenStartElementTag forms, after
// which data_size's own count begins.
//
// Precondition: stack's top must be the OpenStartElementTag this
// EndElementTag closes — i.e. every writeOpenElement/pushOpenElement call
// must be matched by exactly one writeEndElement call, in strict LIFO order.
// buildTemplateBody's structure (every element closes via EndElementTag
// before its parent does) guarantees this.
func writeEndElement(b *bytes.Buffer, stack []uint32, patches []fieldPatch) ([]uint32, []fieldPatch) {
	b.WriteByte(binXMLEndElement)
	n := len(stack)
	pos := stack[n-1]
	stack = stack[:n-1]
	size := uint32(b.Len()) - (pos + 7)
	patches = append(patches, fieldPatch{pos: pos + 3, size: size}) // pos+3 = data_size field's own offset (past token+dep_id)
	return stack, patches
}
