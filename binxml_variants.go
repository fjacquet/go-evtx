// binxml_variants.go — investigative BinXML variant builders for the v0.7.0
// format-correctness release's task 9c "shrink our own record" ladder
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9c-report.md).
//
// Task 9b localised go-evtx's Get-WinEvent/ToXml render failure to
// buildTemplateBody's own <EventData> structure or the substitution array
// (binxml.go) — everything else (the outer preamble, <System>'s own
// content) was eliminated by construction. Grafting a real record's
// <EventData>/<UserData> was not possible: task-9b-report.md found
// testdata/system.evtx record 0 uses a different, 20-substitution template
// (<UserData>), so a byte graft against go-evtx's own 42-substitution
// scheme fails on an index/count mismatch, not a format defect.
//
// This file instead SHRINKS go-evtx's own template through its own
// encoder — no grafting, no reimplementation of the BinXML format — by
// calling the exact same low-level token writers buildTemplateBody itself
// calls (the pushOpenElement family, writeAttributeSub/Optional/Literal,
// writeSubstitution/writeOptionalSubstitution, writeNameNode,
// closeAttrList, writeEndElement, encodeSubString, writeSubstitutionArray),
// just assembling them into smaller or altered shapes. A variant's Windows
// verdict is therefore a genuine measurement of go-evtx's own encoder, not
// of a parallel reimplementation that could carry its own, unrelated
// defect.
//
// buildBinXML and buildTemplateBody themselves are NOT called and NOT
// modified by this file — WriteRecord's production output is therefore
// unaffected by construction (a disjoint call graph from this file's own
// entry point), not merely unaffected in practice. binxml_variants_test.go
// additionally confirms buildBinXML's own golden-file regression test
// (TestBuildBinXML_PayloadUnchangedByCollection, nodecollect_test.go) keeps
// passing unmodified.
//
// Exported ONLY so the cmd/gen-ladder-* generator commands (a separate Go
// package — unexported identifiers are not reachable across a package
// boundary) can build these payloads and hand them to the existing, public
// Writer.WriteRaw. Not part of the writer's stable API, and not referenced
// by any exported Writer/Reader method.
package evtx

import (
	"bytes"
	"encoding/binary"
)

// Variant selects one rung of the task 9c ladder.
type Variant int

const (
	// VariantSystemOnly emits <Event><System>...</System></Event> — no
	// <EventData> element at all, and only the 18 substitutions <System>
	// needs (see the v* index constants below). Ladder rung 1.
	VariantSystemOnly Variant = iota
	// VariantEventDataOnePair adds <EventData> containing exactly one
	// <Data Name="%N">%N+1</Data> pair, both Name and Value as
	// NormalSubstitution — matching production's own per-pair encoding
	// (buildTemplateBody's Data loop), just one pair instead of twelve.
	// Ladder rung 2.
	VariantEventDataOnePair
	// VariantEventDataLiteralNames emits <System> plus <EventData> with all
	// 12 Data pairs — matching the control's (rung 3, cmd/gen-fixture-minimal
	// through production's real WriteRecord) scale exactly — but each
	// Data/@Name is a literal ValueText (writeAttributeLiteral, F8's xmlns
	// convention) instead of a NormalSubstitution. Only Value is
	// substituted. Tests the brief's hypothesis: a template's element/
	// attribute NAMES are the template's own fixed shape; only values vary.
	// Ladder rung 4.
	VariantEventDataLiteralNames
)

// Substitution indices <System> alone needs, when it is not sharing index
// space with production's interleaved Data fields (0-28, see binxml.go's
// sub* constants). Assigned in the same element order as buildTemplateBody's
// own <System> (Task 8b Step 1): Provider, EventID, Version, Level, Task,
// Opcode, Keywords, TimeCreated, EventRecordID, Correlation, Execution,
// Channel, Computer, Security.
const (
	vProviderName      = 0
	vEventID           = 1
	vLevel             = 2
	vSystemTime        = 3
	vComputer          = 4
	vVersion           = 5
	vTask              = 6
	vOpcode            = 7
	vKeywords          = 8
	vEventRecordID     = 9
	vActivityID        = 10
	vRelatedActivityID = 11
	vProcessID         = 12
	vThreadID          = 13
	vChannel           = 14
	vSecurityUserID    = 15
	vProviderGuid      = 16
	vEventIDQualifiers = 17

	// vSystemSubCount is the total number of substitutions <System> alone
	// needs — also the first free substitution index any <EventData>
	// variant's own Data pairs start from.
	vSystemSubCount = 18
)

// BuildVariantBinXML builds one of the task-9c ladder's BinXML payloads —
// the same shape WriteRaw expects (fragment header + TemplateInstanceNode +
// TemplateNode header + template body + substitution array) — for the
// given event. binXMLChunkOffset must be the chunk-relative offset the
// record will be written at; for the first record of a fresh Writer that is
// 536 (512-byte chunk header + 24-byte record header), the same value
// cmd/gen-splice-fixture's own doc comment establishes for WriteRaw's first
// call on an empty file.
//
// See Variant's own doc comments for what each rung emits. Reuses the exact
// preamble buildBinXML itself writes (template_id=1, GUID = 01 00 00 00 +
// 12 zero bytes — task 9b eliminated this preamble as a factor in both
// directions, so it is held fixed here rather than re-tested) — duplicated
// rather than shared via a refactor of buildBinXML, so that function's own
// bytes are provably untouched by this file (see this file's own top
// comment).
func BuildVariantBinXML(variant Variant, eventID int, recordID uint64, fields map[string]string, binXMLChunkOffset uint32) []byte {
	templateBodyBase := binXMLChunkOffset + preambleSize

	var names []chunkRef
	tbody := buildVariantTemplateBody(templateBodyBase, &names, variant)
	subs := variantSubstitutions(variant, eventID, recordID, fields)

	out := &bytes.Buffer{}

	// 1. Fragment header (4 bytes) — identical to buildBinXML's own.
	out.WriteByte(binXMLFragmentHeader)
	out.WriteByte(0x01)
	out.WriteByte(0x01)
	out.WriteByte(0x00)

	// 2. TemplateInstanceNode (10 bytes) — identical to buildBinXML's own.
	out.WriteByte(binXMLTemplateInstance)
	out.WriteByte(0x01)
	writeUint32LE(out, 1)
	templateOffset := binXMLChunkOffset + fragHeaderSize + templInstSize
	writeUint32LE(out, templateOffset)

	// 3. TemplateNode header (24 bytes) — identical to buildBinXML's own.
	guid := make([]byte, 16)
	binary.LittleEndian.PutUint32(guid, 1)
	writeUint32LE(out, 0)
	out.Write(guid)
	writeUint32LE(out, uint32(len(tbody)))

	// 4. Template body.
	out.Write(tbody)

	// 5. Substitution array.
	writeSubstitutionArray(out, subs)

	return out.Bytes()
}

// buildVariantTemplateBody assembles the shared outer shape every rung
// uses (nested fragment header, <Event xmlns=...>, <System>...</System>),
// then adds whatever <EventData> shape (or none) variant needs. Mirrors
// buildTemplateBody's own EndOfStream/back-patch-application tail exactly
// (binxml.go) — this function's own control flow is new code, not shared
// via refactor with buildTemplateBody, so that production function's bytes
// stay provably untouched (see this file's own top comment); every
// byte-emitting call it makes goes through the identical low-level
// primitives buildTemplateBody itself uses.
func buildVariantTemplateBody(baseOffset uint32, names *[]chunkRef, variant Variant) []byte {
	b := &bytes.Buffer{}
	var dataSizeStack []uint32
	var patches []fieldPatch

	// Nested fragment header (B2) — identical to buildTemplateBody's own.
	b.WriteByte(binXMLFragmentHeader)
	b.WriteByte(0x01)
	b.WriteByte(0x01)
	b.WriteByte(0x00)

	// <Event xmlns="...">
	var attrListPos uint32
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Event", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeLiteral(b, "xmlns", eventNamespaceURI, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)

	dataSizeStack, patches = writeVariantSystemBlock(b, baseOffset, names, dataSizeStack, patches)

	switch variant {
	case VariantSystemOnly:
		// Rung 1: no <EventData> at all.
	case VariantEventDataOnePair:
		dataSizeStack, patches = writeVariantEventData(b, baseOffset, names, dataSizeStack, patches, 1, true)
	case VariantEventDataLiteralNames:
		dataSizeStack, patches = writeVariantEventData(b, baseOffset, names, dataSizeStack, patches, 12, false)
	}

	// </Event>
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	// EndOfStream.
	b.WriteByte(0x00)

	if len(dataSizeStack) != 0 {
		panic("buildVariantTemplateBody: unbalanced writeOpenElement/writeEndElement calls")
	}

	buf := b.Bytes()
	for _, p := range patches {
		binary.LittleEndian.PutUint32(buf[p.pos:], p.size)
	}
	return buf
}

// writeVariantSystemBlock writes <System>...</System> with the SAME 14
// children, in the SAME order, using the SAME element shapes (which are
// plain, which carry attributes, which are OptionalSubstitution vs.
// NormalSubstitution, which dependency_id ties to their own content) as
// buildTemplateBody's own <System> (binxml.go) — only the substitution
// indices differ (the v* constants above, 0-17, instead of the sub*
// constants interleaved with Data at 5-28). Every call below goes through
// the same low-level token writers buildTemplateBody itself uses.
func writeVariantSystemBlock(b *bytes.Buffer, baseOffset uint32, names *[]chunkRef, dataSizeStack []uint32, patches []fieldPatch) ([]uint32, []fieldPatch) {
	var attrListPos uint32

	//   <System>
	dataSizeStack = pushOpenElement(b, "System", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)

	//     <Provider Name="%0" Guid="%16"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Provider", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeSub(b, "Name", vProviderName, binXMLTypeString, true, baseOffset, names)
	writeAttributeSub(b, "Guid", vProviderGuid, binXMLTypeString, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <EventID Qualifiers="%17">%1</EventID>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "EventID", vEventID, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "Qualifiers", vEventIDQualifiers, binXMLTypeUint16, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vEventID, binXMLTypeUint16)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Version>%5</Version>
	dataSizeStack = pushOpenElement(b, "Version", false, vVersion, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vVersion, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Level>%2</Level>
	dataSizeStack = pushOpenElement(b, "Level", false, vLevel, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vLevel, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Task>%6</Task>
	dataSizeStack = pushOpenElement(b, "Task", false, vTask, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vTask, binXMLTypeUint16)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Opcode>%7</Opcode>
	dataSizeStack = pushOpenElement(b, "Opcode", false, vOpcode, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vOpcode, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Keywords>%8</Keywords>
	dataSizeStack = pushOpenElement(b, "Keywords", false, vKeywords, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vKeywords, binXMLTypeHexInt64)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <TimeCreated SystemTime="%3"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "TimeCreated", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeSub(b, "SystemTime", vSystemTime, binXMLTypeFiletime, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <EventRecordID>%9</EventRecordID>
	dataSizeStack = pushOpenElement(b, "EventRecordID", false, vEventRecordID, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vEventRecordID, binXMLTypeUint64)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Correlation ActivityID="%10" RelatedActivityID="%11"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Correlation", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "ActivityID", vActivityID, binXMLTypeNull, true, baseOffset, names)
	writeAttributeOptional(b, "RelatedActivityID", vRelatedActivityID, binXMLTypeNull, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Execution ProcessID="%12" ThreadID="%13"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Execution", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "ProcessID", vProcessID, binXMLTypeNull, true, baseOffset, names)
	writeAttributeOptional(b, "ThreadID", vThreadID, binXMLTypeNull, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Channel>%14</Channel>
	dataSizeStack = pushOpenElement(b, "Channel", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, vChannel, binXMLTypeString)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Computer>%4</Computer>
	dataSizeStack = pushOpenElement(b, "Computer", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, vComputer, binXMLTypeString)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Security UserID="%15"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Security", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "UserID", vSecurityUserID, binXMLTypeNull, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//   </System>
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	return dataSizeStack, patches
}

// writeVariantEventData writes <EventData> with n Data pairs. When
// substitutedNames is true, each pair's Name AND Value are
// NormalSubstitution — the same convention production's own Data loop
// uses (buildTemplateBody), just contiguous indices starting at
// vSystemSubCount instead of interleaved with <System> at 5-28. When false
// (VariantEventDataLiteralNames, rung 4), each pair's Name is a literal
// ValueText (writeAttributeLiteral, F8's xmlns convention) and only Value
// occupies a substitution slot — one index per pair instead of two.
func writeVariantEventData(b *bytes.Buffer, baseOffset uint32, names *[]chunkRef, dataSizeStack []uint32, patches []fieldPatch, n int, substitutedNames bool) ([]uint32, []fieldPatch) {
	dataSizeStack = pushOpenElement(b, "EventData", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)

	for i := 0; i < n; i++ {
		var attrListPos uint32
		var valueIdx uint16

		if substitutedNames {
			nameIdx := uint16(vSystemSubCount + i*2)
			valueIdx = uint16(vSystemSubCount + i*2 + 1)
			dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Data", depIDNotSet, baseOffset, names, dataSizeStack)
			writeAttributeSub(b, "Name", nameIdx, binXMLTypeString, false, baseOffset, names)
		} else {
			valueIdx = uint16(vSystemSubCount + i)
			dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Data", depIDNotSet, baseOffset, names, dataSizeStack)
			writeAttributeLiteral(b, "Name", dataFieldNames[i], baseOffset, names)
		}
		patches = closeAttrList(b, attrListPos, patches)
		b.WriteByte(binXMLCloseElement)
		writeSubstitution(b, valueIdx, binXMLTypeString)
		dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)
	}

	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)
	return dataSizeStack, patches
}

// variantSubstitutions builds the substitution array entries for variant —
// <System>'s own 18 entries (v* indices, always present) plus whatever
// <EventData> needs.
func variantSubstitutions(variant Variant, eventID int, recordID uint64, fields map[string]string) []substitutionEntry {
	subs := systemSubstitutions(eventID, recordID, fields)

	switch variant {
	case VariantSystemOnly:
		// No Data pairs.
	case VariantEventDataOnePair:
		subs = append(subs, dataPairSubstitutions(fields, 1, true)...)
	case VariantEventDataLiteralNames:
		subs = append(subs, dataPairSubstitutions(fields, 12, false)...)
	}
	return subs
}

// systemSubstitutions builds the 18 substitution entries <System> alone
// needs (v* indices), matching production's own values field-for-field
// (collectSubstitutionsFromFields in binxml.go) — same fallback logic
// (parseTimeCreated), same typed-zero placeholders for fields go-evtx has
// no source for.
func systemSubstitutions(eventID int, recordID uint64, fields map[string]string) []substitutionEntry {
	systemTime := parseTimeCreated(fields)

	subs := make([]substitutionEntry, 0, vSystemSubCount)
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["ProviderName"])}) // 0 ProviderName
	subs = append(subs, substitutionEntry{binXMLTypeUint16, uint16LEBytes(uint16(eventID))})          // 1 EventID
	subs = append(subs, substitutionEntry{binXMLTypeUint8, []byte{0}})                                // 2 Level
	subs = append(subs, substitutionEntry{binXMLTypeFiletime, uint64LEBytes(toFILETIME(systemTime))}) // 3 SystemTime
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["Computer"])})     // 4 Computer
	subs = append(subs, substitutionEntry{binXMLTypeUint8, []byte{0}})                                // 5 Version
	subs = append(subs, substitutionEntry{binXMLTypeUint16, uint16LEBytes(0)})                        // 6 Task
	subs = append(subs, substitutionEntry{binXMLTypeUint8, []byte{0}})                                // 7 Opcode
	subs = append(subs, substitutionEntry{binXMLTypeHexInt64, uint64LEBytes(0)})                      // 8 Keywords
	subs = append(subs, substitutionEntry{binXMLTypeUint64, uint64LEBytes(recordID)})                 // 9 EventRecordID
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                       // 10 Correlation/@ActivityID
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                       // 11 Correlation/@RelatedActivityID
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                       // 12 Execution/@ProcessID
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                       // 13 Execution/@ThreadID
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["Channel"])})      // 14 Channel
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                       // 15 Security/@UserID
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["ProviderGuid"])}) // 16 Provider/@Guid
	subs = append(subs, substitutionEntry{binXMLTypeUint16, nil})                                     // 17 EventID/@Qualifiers
	return subs
}

// dataPairSubstitutions builds n Data pairs' substitution entries.
// includeNames controls whether each pair contributes a Name entry (true,
// matching production's per-pair convention) or only a Value entry (false,
// VariantEventDataLiteralNames — the Name is embedded as a literal in the
// template body instead, see writeVariantEventData).
func dataPairSubstitutions(fields map[string]string, n int, includeNames bool) []substitutionEntry {
	subs := make([]substitutionEntry, 0, n*2)
	for i := 0; i < n; i++ {
		name := dataFieldNames[i]
		if includeNames {
			subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(name)})
		}
		subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields[name])})
	}
	return subs
}
