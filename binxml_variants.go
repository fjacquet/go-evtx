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
//
// Task 9e (task-9e-report.md) adds VariantAllString and
// VariantFourFieldsString. Task 9d's own ladder found no size boundary
// (task 9c) and could not build its decisive all-literal experiment at all
// — MS-EVEN6's own grammar has no ValueText production for a non-string
// type, so every typed scalar MUST be a substitution (verified against
// testdata/system.evtx: 35/35 real substitutions there are typed, 15/15
// real literals are all StringType). What was never isolated, across every
// measurement this release has made, is the declared VALUE TYPE of each
// substitution — UINT16 for EventID, HEXINT64 for Keywords, and so on.
// VariantAllString reverts every one of the 42 control-scale substitutions
// (the whole <System> block plus <EventData>'s 12 Data pairs) to StringType
// (0x01), formatting each value the way it would render in XML (decimal
// digits for an integer, hex for Keywords, ISO-8601 for the FILETIME, an
// empty string for a field with no source) — the most permissive type,
// already proven renderable by task 9a's splice experiment. It reuses
// production's own OptionalSubstitution/dependency_id convention exactly
// (VariantAllNormalSubstitution already isolated that axis as a null
// result in task 9d) and changes ONLY the type byte, in both the template
// body's substitution tokens and the substitution array's value-spec
// descriptors, so the two always agree. VariantFourFieldsString is the
// same mechanism applied to only the four values a prior task's own type
// table was later shown wrong about (task-8b/8e's F14 correction):
// Security/@UserID, Execution/@ProcessID, Execution/@ThreadID, Keywords —
// everything else stays at production's own declared type.
package evtx

import (
	"bytes"
	"encoding/binary"
	"strconv"
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

	// VariantAllNormalSubstitution (task 9d, secondary rung 1) is the
	// control's own shape (System + EventData with all 12 substituted-name
	// Data pairs — identical to VariantEventDataLiteralNames's sibling with
	// substituted names, i.e. production's own convention) with every
	// OptionalSubstitution (0x0E) token binxml.go's <System> block uses
	// replaced by NormalSubstitution (0x0D), and every element/attribute
	// dependency_id that named a real substitution index (F12c/F13a) reset
	// to depIDNotSet (0xffff) instead. 0x0E was adopted from reading the
	// real file (task 8b/8c) but has never itself been isolated as the
	// variable under test — every measurement since has changed 0x0E
	// alongside something else. This is the pre-F12c/F13a shape.
	VariantAllNormalSubstitution

	// VariantNoXmlns (task 9d, secondary rung 2) is the control's own shape
	// (same as VariantAllNormalSubstitution's EventData/System scale, but
	// <System> keeps production's own OptionalSubstitution convention
	// unchanged) with <Event>'s xmlns attribute (F8) removed entirely —
	// <Event> becomes a plain no-attributes element (token 0x01, no
	// attribute list at all), not merely an empty one. F8 (xmlns) was
	// established necessary for python-evtx (task 8) but a prior hybrid
	// (task 9b H1, real body+subs + our preamble) only arguably cleared the
	// preamble; xmlns itself has never been independently varied. Expected
	// to break python-evtx's own namespaced XPath query — this variant gets
	// its own fixture/jobs specifically so that expected Linux failure does
	// not gate or obscure its independent Windows result.
	VariantNoXmlns

	// VariantAllString (task 9e, decisive experiment) is the control's own
	// shape (System + EventData, all 12 substituted-name Data pairs,
	// xmlns present, production's own OptionalSubstitution/dependency_id
	// convention unchanged) with every one of the 42 substitutions' declared
	// VALUE TYPE forced to StringType (0x01) — both in the template body's
	// own substitution tokens (writeSubstitution/writeOptionalSubstitution's
	// valueType argument) and in the substitution array's value-spec
	// descriptors (substitutionEntry.typ), so the two never disagree. Each
	// value's DATA is reformatted to match: decimal digits for an integer
	// (EventID, Level, Version, Task, Opcode, EventRecordID), a hex string
	// for Keywords (Windows' own rendering convention for that field), an
	// ISO-8601 string for SystemTime, and an empty string for a field
	// go-evtx has no source for (ActivityID, RelatedActivityID, ProcessID,
	// ThreadID, UserID, EventID/@Qualifiers) — every field that is already
	// StringType in production (ProviderName, Computer, Channel,
	// Provider/@Guid, every Data name/value) is unaffected by construction.
	// If this renders, the defect is a type mismatch on one specific
	// substitution and the next step is a per-element bisect; if it still
	// fails, value types are exonerated as a category and what remains is
	// the template body's own element/token encoding.
	VariantAllString

	// VariantFourFieldsString (task 9e, secondary rung, batched into the
	// same CI run as VariantAllString) applies VariantAllString's exact
	// mechanism to ONLY the four substitutions whose types were never
	// independently verified as strings — Security/@UserID,
	// Execution/@ProcessID, Execution/@ThreadID, Keywords — the four
	// positions task-8b-report.md's own Step 1 type table was later shown
	// wrong about (F14, task 8e), so they carry the least evidence of any
	// declared type in the whole template. Every other substitution keeps
	// its production declared type unchanged. If VariantAllString renders
	// and this narrower variant does too, the search narrows further for
	// free in the same run; if VariantAllString fails and this one passes,
	// the defect is isolated to one of these four fields without a further
	// bisect task.
	VariantFourFieldsString
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

	// <Event xmlns="...">, or (VariantNoXmlns) plain <Event> with no
	// attribute list at all — not merely an xmlns-less attribute list, since
	// <Event> has no other attribute to keep the list non-empty.
	var attrListPos uint32
	if variant == VariantNoXmlns {
		dataSizeStack = pushOpenElement(b, "Event", false, depIDNotSet, baseOffset, names, dataSizeStack)
		b.WriteByte(binXMLCloseElement)
	} else {
		dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Event", depIDNotSet, baseOffset, names, dataSizeStack)
		writeAttributeLiteral(b, "xmlns", eventNamespaceURI, baseOffset, names)
		patches = closeAttrList(b, attrListPos, patches)
		b.WriteByte(binXMLCloseElement)
	}

	// System block. VariantAllString/VariantFourFieldsString (task 9e) keep
	// production's own OptionalSubstitution/dependency_id convention exactly
	// (that axis was already isolated and found null by task 9d's
	// VariantAllNormalSubstitution) and instead vary only the declared VALUE
	// TYPE of each substitution — routed through writeVariantSystemBlockTyped
	// instead of writeVariantSystemBlock. useOptional still selects
	// production's own convention for every other variant except
	// VariantAllNormalSubstitution, which reverts <System> to the
	// pre-F12c/F13a shape (NormalSubstitution + depIDNotSet everywhere) as
	// its own single variable under test.
	switch variant {
	case VariantAllString:
		dataSizeStack, patches = writeVariantSystemBlockTyped(b, baseOffset, names, dataSizeStack, patches, stringizeAll)
	case VariantFourFieldsString:
		dataSizeStack, patches = writeVariantSystemBlockTyped(b, baseOffset, names, dataSizeStack, patches, stringizeFour)
	default:
		useOptional := variant != VariantAllNormalSubstitution
		dataSizeStack, patches = writeVariantSystemBlock(b, baseOffset, names, dataSizeStack, patches, useOptional)
	}

	switch variant {
	case VariantSystemOnly:
		// Rung 1: no <EventData> at all.
	case VariantEventDataOnePair:
		dataSizeStack, patches = writeVariantEventData(b, baseOffset, names, dataSizeStack, patches, 1, true)
	case VariantEventDataLiteralNames:
		dataSizeStack, patches = writeVariantEventData(b, baseOffset, names, dataSizeStack, patches, 12, false)
	case VariantAllNormalSubstitution, VariantNoXmlns, VariantAllString, VariantFourFieldsString:
		// All four are control-scale: System + EventData, all 12 Data
		// pairs, substituted names — production's own convention. Data
		// pairs are already StringType in every variant, so task 9e's type
		// change is a no-op here; only <System>'s own 18 substitutions
		// above are affected.
		dataSizeStack, patches = writeVariantEventData(b, baseOffset, names, dataSizeStack, patches, 12, true)
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
// plain, which carry attributes) as buildTemplateBody's own <System>
// (binxml.go) — only the substitution indices differ (the v* constants
// above, 0-17, instead of the sub* constants interleaved with Data at
// 5-28). Every call below goes through the same low-level token writers
// buildTemplateBody itself uses.
//
// useOptional selects, for exactly the 8 elements/attributes production
// (F12c/F13a) ties to their own content substitution index:
//   - true  (every variant except VariantAllNormalSubstitution): the real
//     file's own convention — OptionalSubstitution (0x0E) content, and the
//     owning element's dependency_id equal to that same index.
//   - false (VariantAllNormalSubstitution, task 9d secondary rung 1): the
//     pre-F12c/F13a shape — NormalSubstitution (0x0D) content, and
//     dependency_id fixed at depIDNotSet, regardless of index.
//
// Channel/Computer/TimeCreated (already NormalSubstitution in production,
// never OptionalSubstitution) and Provider (never had a dependency_id tied
// to its own content) are unaffected by useOptional — matching production
// exactly in every variant.
func writeVariantSystemBlock(b *bytes.Buffer, baseOffset uint32, names *[]chunkRef, dataSizeStack []uint32, patches []fieldPatch, useOptional bool) ([]uint32, []fieldPatch) {
	var attrListPos uint32

	// writeContentSub/writeAttrSub select which token writer this call gets;
	// depIDFor selects which dependency_id an owning element gets. Both
	// pairs share their non-variant sibling's exact signature (see
	// writeSubstitution/writeOptionalSubstitution and
	// writeAttributeSub/writeAttributeOptional in binxml.go), so this is a
	// straight function-value swap, not a second code path.
	writeContentSub := writeOptionalSubstitution
	writeAttrSub := writeAttributeOptional
	depIDFor := func(idx uint16) uint16 { return idx }
	if !useOptional {
		writeContentSub = writeSubstitution
		writeAttrSub = writeAttributeSub
		depIDFor = func(uint16) uint16 { return depIDNotSet }
	}

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
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "EventID", depIDFor(vEventID), baseOffset, names, dataSizeStack)
	writeAttrSub(b, "Qualifiers", vEventIDQualifiers, binXMLTypeUint16, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	writeContentSub(b, vEventID, binXMLTypeUint16)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Version>%5</Version>
	dataSizeStack = pushOpenElement(b, "Version", false, depIDFor(vVersion), baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeContentSub(b, vVersion, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Level>%2</Level>
	dataSizeStack = pushOpenElement(b, "Level", false, depIDFor(vLevel), baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeContentSub(b, vLevel, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Task>%6</Task>
	dataSizeStack = pushOpenElement(b, "Task", false, depIDFor(vTask), baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeContentSub(b, vTask, binXMLTypeUint16)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Opcode>%7</Opcode>
	dataSizeStack = pushOpenElement(b, "Opcode", false, depIDFor(vOpcode), baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeContentSub(b, vOpcode, binXMLTypeUint8)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Keywords>%8</Keywords>
	dataSizeStack = pushOpenElement(b, "Keywords", false, depIDFor(vKeywords), baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeContentSub(b, vKeywords, binXMLTypeHexInt64)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <TimeCreated SystemTime="%3"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "TimeCreated", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeSub(b, "SystemTime", vSystemTime, binXMLTypeFiletime, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <EventRecordID>%9</EventRecordID>
	dataSizeStack = pushOpenElement(b, "EventRecordID", false, depIDFor(vEventRecordID), baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeContentSub(b, vEventRecordID, binXMLTypeUint64)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Correlation ActivityID="%10" RelatedActivityID="%11"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Correlation", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttrSub(b, "ActivityID", vActivityID, binXMLTypeNull, true, baseOffset, names)
	writeAttrSub(b, "RelatedActivityID", vRelatedActivityID, binXMLTypeNull, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Execution ProcessID="%12" ThreadID="%13"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Execution", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttrSub(b, "ProcessID", vProcessID, binXMLTypeNull, true, baseOffset, names)
	writeAttrSub(b, "ThreadID", vThreadID, binXMLTypeNull, false, baseOffset, names)
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
	writeAttrSub(b, "UserID", vSecurityUserID, binXMLTypeNull, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//   </System>
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	return dataSizeStack, patches
}

// writeVariantSystemBlockTyped is writeVariantSystemBlock's own <System>
// shape (same 14 children, same order, same elements/attributes) always
// held at production's own OptionalSubstitution/dependency_id convention
// (equivalent to writeVariantSystemBlock's useOptional=true path) — task
// 9e (VariantAllString/VariantFourFieldsString) does not touch that axis,
// which task 9d's VariantAllNormalSubstitution already isolated as a null
// result. The one thing this function varies is the declared VALUE TYPE
// each substitution token carries: stringize(idx) reports, for each of the
// 18 v* indices <System> uses, whether that substitution's type should be
// forced to StringType (0x01) instead of its production type. Every call
// site routes its normal type argument through typeFor so the choice is
// made in exactly one place per field.
func writeVariantSystemBlockTyped(b *bytes.Buffer, baseOffset uint32, names *[]chunkRef, dataSizeStack []uint32, patches []fieldPatch, stringize func(uint16) bool) ([]uint32, []fieldPatch) {
	var attrListPos uint32

	typeFor := func(idx uint16, production byte) byte {
		if stringize(idx) {
			return binXMLTypeString
		}
		return production
	}

	//   <System>
	dataSizeStack = pushOpenElement(b, "System", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)

	//     <Provider Name="%0" Guid="%16"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Provider", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeSub(b, "Name", vProviderName, typeFor(vProviderName, binXMLTypeString), true, baseOffset, names)
	writeAttributeSub(b, "Guid", vProviderGuid, typeFor(vProviderGuid, binXMLTypeString), false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <EventID Qualifiers="%17">%1</EventID>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "EventID", vEventID, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "Qualifiers", vEventIDQualifiers, typeFor(vEventIDQualifiers, binXMLTypeUint16), false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vEventID, typeFor(vEventID, binXMLTypeUint16))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Version>%5</Version>
	dataSizeStack = pushOpenElement(b, "Version", false, vVersion, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vVersion, typeFor(vVersion, binXMLTypeUint8))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Level>%2</Level>
	dataSizeStack = pushOpenElement(b, "Level", false, vLevel, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vLevel, typeFor(vLevel, binXMLTypeUint8))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Task>%6</Task>
	dataSizeStack = pushOpenElement(b, "Task", false, vTask, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vTask, typeFor(vTask, binXMLTypeUint16))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Opcode>%7</Opcode>
	dataSizeStack = pushOpenElement(b, "Opcode", false, vOpcode, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vOpcode, typeFor(vOpcode, binXMLTypeUint8))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Keywords>%8</Keywords>
	dataSizeStack = pushOpenElement(b, "Keywords", false, vKeywords, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vKeywords, typeFor(vKeywords, binXMLTypeHexInt64))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <TimeCreated SystemTime="%3"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "TimeCreated", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeSub(b, "SystemTime", vSystemTime, typeFor(vSystemTime, binXMLTypeFiletime), false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <EventRecordID>%9</EventRecordID>
	dataSizeStack = pushOpenElement(b, "EventRecordID", false, vEventRecordID, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeOptionalSubstitution(b, vEventRecordID, typeFor(vEventRecordID, binXMLTypeUint64))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Correlation ActivityID="%10" RelatedActivityID="%11"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Correlation", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "ActivityID", vActivityID, typeFor(vActivityID, binXMLTypeNull), true, baseOffset, names)
	writeAttributeOptional(b, "RelatedActivityID", vRelatedActivityID, typeFor(vRelatedActivityID, binXMLTypeNull), false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Execution ProcessID="%12" ThreadID="%13"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Execution", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "ProcessID", vProcessID, typeFor(vProcessID, binXMLTypeNull), true, baseOffset, names)
	writeAttributeOptional(b, "ThreadID", vThreadID, typeFor(vThreadID, binXMLTypeNull), false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Channel>%14</Channel>
	dataSizeStack = pushOpenElement(b, "Channel", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, vChannel, typeFor(vChannel, binXMLTypeString))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Computer>%4</Computer>
	dataSizeStack = pushOpenElement(b, "Computer", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, vComputer, typeFor(vComputer, binXMLTypeString))
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Security UserID="%15"/>
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Security", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "UserID", vSecurityUserID, typeFor(vSecurityUserID, binXMLTypeNull), false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//   </System>
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	return dataSizeStack, patches
}

// fourFieldStringSet names the exactly four v* substitution indices
// VariantFourFieldsString (task 9e secondary rung) forces to StringType —
// Security/@UserID, Execution/@ProcessID, Execution/@ThreadID, Keywords —
// the four fields task-8b-report.md's own Step 1 type table was later shown
// wrong about (F14, task 8e's correction note), so they carry the least
// evidence of any declared type in the template.
var fourFieldStringSet = map[uint16]bool{
	vSecurityUserID: true,
	vProcessID:      true,
	vThreadID:       true,
	vKeywords:       true,
}

// stringizeAll is the stringize predicate for VariantAllString: every
// substitution, no exceptions.
func stringizeAll(uint16) bool { return true }

// stringizeFour is the stringize predicate for VariantFourFieldsString: only
// the four indices in fourFieldStringSet.
func stringizeFour(idx uint16) bool { return fourFieldStringSet[idx] }

// isoFiletimeLayout formats a time.Time the way Windows renders a FILETIME
// substitution in XML: an ISO-8601 timestamp with 7 fractional-second
// digits (FILETIME's own 100ns tick resolution), always in UTC (hence the
// literal, not numeric-zone, "Z"). Used only by systemSubstitutionsTyped's
// SystemTime entry when stringize(vSystemTime) is true.
const isoFiletimeLayout = "2006-01-02T15:04:05.0000000Z"

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
	var subs []substitutionEntry
	switch variant {
	case VariantAllString:
		subs = systemSubstitutionsTyped(eventID, recordID, fields, stringizeAll)
	case VariantFourFieldsString:
		subs = systemSubstitutionsTyped(eventID, recordID, fields, stringizeFour)
	default:
		subs = systemSubstitutions(eventID, recordID, fields)
	}

	switch variant {
	case VariantSystemOnly:
		// No Data pairs.
	case VariantEventDataOnePair:
		subs = append(subs, dataPairSubstitutions(fields, 1, true)...)
	case VariantEventDataLiteralNames:
		subs = append(subs, dataPairSubstitutions(fields, 12, false)...)
	case VariantAllNormalSubstitution, VariantNoXmlns, VariantAllString, VariantFourFieldsString:
		// Control-scale: all 12 Data pairs, substituted names — production's
		// own convention. The substitution array's own VALUES are unaffected
		// by 0x0D-vs-0x0E (that distinction lives only in the template
		// body's token stream), by xmlns's presence, or by task 9e's type
		// change (Data pairs are already StringType), so this is identical
		// to VariantEventDataLiteralNames's sibling with names substituted.
		subs = append(subs, dataPairSubstitutions(fields, 12, true)...)
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

// systemSubstitutionsTyped is systemSubstitutions with each of the 18
// entries routed through stringize (task 9e): when stringize(idx) is true,
// the entry becomes {binXMLTypeString, encodeSubString(text)} instead of
// its production {type, data} pair, where text is that value formatted the
// way it would appear in rendered XML — decimal digits for an integer
// (EventID/Level/Version/Task/Opcode/EventRecordID), a hex string for
// Keywords (Windows' own convention for that field; go-evtx's Keywords is
// always 0, so this is "0x0"), an ISO-8601 string for SystemTime
// (isoFiletimeLayout), and an empty string for a field go-evtx has no
// source for at all (ActivityID, RelatedActivityID, ProcessID, ThreadID,
// UserID, EventID/@Qualifiers — each already NULL-typed/zero-length in
// production, so "no value" is the only faithful text). Fields already
// StringType in production (ProviderName, Computer, Channel,
// Provider/@Guid) pass their own field value through unchanged either way,
// so stringize's outcome for those four is a no-op by construction.
func systemSubstitutionsTyped(eventID int, recordID uint64, fields map[string]string, stringize func(uint16) bool) []substitutionEntry {
	systemTime := parseTimeCreated(fields)

	entry := func(idx uint16, production byte, data []byte, text string) substitutionEntry {
		if stringize(idx) {
			return substitutionEntry{binXMLTypeString, encodeSubString(text)}
		}
		return substitutionEntry{production, data}
	}

	subs := make([]substitutionEntry, 0, vSystemSubCount)
	subs = append(subs, entry(vProviderName, binXMLTypeString, encodeSubString(fields["ProviderName"]), fields["ProviderName"]))
	subs = append(subs, entry(vEventID, binXMLTypeUint16, uint16LEBytes(uint16(eventID)), strconv.Itoa(eventID)))
	subs = append(subs, entry(vLevel, binXMLTypeUint8, []byte{0}, "0"))
	subs = append(subs, entry(vSystemTime, binXMLTypeFiletime, uint64LEBytes(toFILETIME(systemTime)), systemTime.UTC().Format(isoFiletimeLayout)))
	subs = append(subs, entry(vComputer, binXMLTypeString, encodeSubString(fields["Computer"]), fields["Computer"]))
	subs = append(subs, entry(vVersion, binXMLTypeUint8, []byte{0}, "0"))
	subs = append(subs, entry(vTask, binXMLTypeUint16, uint16LEBytes(0), "0"))
	subs = append(subs, entry(vOpcode, binXMLTypeUint8, []byte{0}, "0"))
	subs = append(subs, entry(vKeywords, binXMLTypeHexInt64, uint64LEBytes(0), "0x0"))
	subs = append(subs, entry(vEventRecordID, binXMLTypeUint64, uint64LEBytes(recordID), strconv.FormatUint(recordID, 10)))
	subs = append(subs, entry(vActivityID, binXMLTypeNull, nil, ""))
	subs = append(subs, entry(vRelatedActivityID, binXMLTypeNull, nil, ""))
	subs = append(subs, entry(vProcessID, binXMLTypeNull, nil, ""))
	subs = append(subs, entry(vThreadID, binXMLTypeNull, nil, ""))
	subs = append(subs, entry(vChannel, binXMLTypeString, encodeSubString(fields["Channel"]), fields["Channel"]))
	subs = append(subs, entry(vSecurityUserID, binXMLTypeNull, nil, ""))
	subs = append(subs, entry(vProviderGuid, binXMLTypeString, encodeSubString(fields["ProviderGuid"]), fields["ProviderGuid"]))
	subs = append(subs, entry(vEventIDQualifiers, binXMLTypeUint16, nil, ""))
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
