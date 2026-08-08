// binxml.go — BinXML encoding for .evtx event records.
//
// No build tag: platform-agnostic BinXML encoding without OS dependencies.
//
// BinXML layout per MS-EVEN6 / python-evtx:
//
//	[FragmentHeader: 4B]
//	[TemplateInstanceNode: 10B]
//	[TemplateNode header: 24B]
//	[Template body: nested FragmentHeader (4B) + XML structure with
//	 NormalSubstitution tokens — verified against a real template in
//	 testdata/system.evtx]
//	[Substitution array: count + value_specs + value_data]
//
// Template structure per MS-EVEN6 / libevtx:
//
//	FragmentHeader → TemplateInstanceNode → TemplateNode (header + body) → SubstitutionArray
package evtx

import (
	"bytes"
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// BinXML token type constants (per libevtx / MS-EVEN6 specification).
const (
	binXMLFragmentHeader     = 0x0F // Fragment header token
	binXMLOpenElement        = 0x01 // Open start element (no attrs)
	binXMLOpenElementAttrs   = 0x41 // Open start element with attribute list flag
	binXMLCloseElement       = 0x02 // Close start element tag
	binXMLEndElement         = 0x04 // End element tag
	binXMLAttribute          = 0x06 // Attribute token
	binXMLTemplateInstance   = 0x0C // Template instance token
	binXMLNormalSubstitution = 0x0D // Normal substitution token

	binXMLTypeString   = 0x01 // Value type: UTF-16LE string (WSTRING)
	binXMLTypeUint16   = 0x06 // Value type: uint16 (UNSIGNED_WORD)
	binXMLTypeFiletime = 0x11 // Value type: FILETIME (uint64)
)

// evtxRecordsStart: chunk-relative offset where the first event record is placed.
// python-evtx hardcodes first_record() at chunk offset 0x200 (512).
const evtxRecordsStart = uint32(evtxChunkHeaderSize) // = 512

// evtxRecordHeaderSize is the fixed size of an event record header:
// signature(4) + size(4) + recordID(8) + timestamp(8) = 24 bytes.
const evtxRecordHeaderSize = 24


const (
	fragHeaderSize   = 4  // 0x0F + major + minor + flags
	templInstSize    = 10 // token + unknown0 + template_id + template_offset
	templNodeHdrSize = 24 // next_offset(4) + GUID(16, first 4B = template_id) + data_length(4)
	preambleSize     = fragHeaderSize + templInstSize + templNodeHdrSize // 38
)

// substitutionEntry holds one substitution value for the BinXML template.
type substitutionEntry struct {
	typ  byte   // BinXML value type (binXMLTypeString, etc.)
	data []byte // raw value bytes
}

// dataFieldNames defines the 12 data field names in substitution order.
var dataFieldNames = [12]string{
	"SubjectUserSid",
	"SubjectUserName",
	"SubjectDomainName",
	"SubjectLogonId",
	"ObjectServer",
	"ObjectType",
	"ObjectName",
	"HandleId",
	"AccessList",
	"AccessMask",
	"ProcessId",
	"ProcessName",
}

// chunkRef records where a NameNode or TemplateNode was emitted, as an offset
// relative to the start of the chunk.
//
// key is the value the corresponding hash table buckets on: sdbmHash(name) for
// names, guidHash(guid) for templates. Both are already-hashed uint32s, so
// fillHashTables needs no knowledge of which kind it is holding — it just
// reduces the key modulo the bucket count.
type chunkRef struct {
	key    uint32
	offset uint32
}

// binXMLResult is what buildBinXML produces: the encoded payload plus the
// chunk-relative location of every hashable node inside it, so the writer can
// register them in the chunk's hash tables at flush time.
type binXMLResult struct {
	payload   []byte
	names     []chunkRef
	templates []chunkRef
}

// buildBinXML encodes an event as template-based BinXML.
//
// eventID is the Windows Event ID. fields is a map of field name to value.
// binXMLChunkOffset is the chunk-relative byte offset where this BinXML
// payload starts (used for inline NameNode offset calculations).
//
// Reserved keys in fields:
//   - "ProviderName"  → substitution 0 (STRING)
//   - "Computer"      → substitution 4 (STRING)
//   - "TimeCreated"   → RFC3339Nano timestamp; fallback to time.Now()
//   - 12 data fields by name (see dataFieldNames)
func buildBinXML(eventID int, fields map[string]string, binXMLChunkOffset uint32) binXMLResult {
	// Template body starts after: fragment header + template instance + template node header.
	templateBodyBase := binXMLChunkOffset + preambleSize

	var names []chunkRef

	// Build template body with substitution placeholders.
	tbody := buildTemplateBody(templateBodyBase, &names)

	// Collect actual substitution values from the fields map.
	subs := collectSubstitutionsFromFields(eventID, fields)

	out := &bytes.Buffer{}

	// 1. Fragment header (4 bytes).
	//
	// B1: minor version is 0x01, not 0x00. Verified against testdata/system.evtx:
	// the byte sequence 0f 01 01 00 (major 1, minor 1) occurs 3312 times, the
	// 0x00-minor form only 7 (coincidental byte alignments, not real headers).
	out.WriteByte(binXMLFragmentHeader)
	out.WriteByte(0x01) // major version
	out.WriteByte(0x01) // minor version
	out.WriteByte(0x00) // flags

	// 2. TemplateInstanceNode (10 bytes).
	out.WriteByte(binXMLTemplateInstance) // token 0x0C
	out.WriteByte(0x01)                   // unknown0
	writeUint32LE(out, 1)                 // template_id
	// template_offset: chunk-relative offset of the TemplateNode (right after this node).
	templateOffset := binXMLChunkOffset + fragHeaderSize + templInstSize
	writeUint32LE(out, templateOffset)

	// 3. TemplateNode header (24 bytes).
	// python-evtx layout: next_offset(4) + GUID(16, first 4B also = template_id) + data_length(4).
	guid := make([]byte, 16)
	binary.LittleEndian.PutUint32(guid, 1) // GUID bytes [0:4] (= template_id); [4:16] stay zero
	writeUint32LE(out, 0)                  // next_offset (no chaining)
	out.Write(guid)
	writeUint32LE(out, uint32(len(tbody))) // data_length

	templates := []chunkRef{{key: guidHash(guid), offset: templateOffset}}

	// 4. Template body.
	out.Write(tbody)

	// 5. Substitution array.
	writeSubstitutionArray(out, subs)

	return binXMLResult{payload: out.Bytes(), names: names, templates: templates}
}

// buildTemplateBody constructs the BinXML template body with NormalSubstitution
// tokens (0x0D) as placeholders for event values.
//
// Substitution indices:
//
//	0:  ProviderName  (STRING)
//	1:  EventID       (UINT16)
//	2:  Level         (UINT16)
//	3:  SystemTime    (FILETIME)
//	4:  Computer      (STRING)
//	5+2i:  Data[i] Name attr  (STRING)   — 12 data fields
//	6+2i:  Data[i] value      (STRING)
//
// Total: 5 + 12*2 = 29 substitutions.
//
// names accumulates the chunk-relative offset and hash of every NameNode
// emitted along the way, in emission order.
func buildTemplateBody(baseOffset uint32, names *[]chunkRef) []byte {
	b := &bytes.Buffer{}

	// dataSizeStack tracks the chunk-relative token position of every
	// OpenStartElementTag whose EndElementTag has not yet been written, in
	// nesting order (innermost last) — pushed by writeOpenElement, popped by
	// writeEndElement. dataSizePatches accumulates one (pos, size) pair per
	// popped element; bytes.Buffer offers no in-place mutation of bytes
	// already written, so the patches are applied to the finished []byte
	// once, just before this function returns, rather than as each element
	// closes.
	var dataSizeStack []uint32
	var dataSizePatches []dataSizePatch

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

	// <Event>
	dataSizeStack = pushOpenElement(b, "Event", false, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)

	//   <System>
	dataSizeStack = pushOpenElement(b, "System", false, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)

	//     <Provider Name="%0"/>
	dataSizeStack = pushOpenElement(b, "Provider", true, baseOffset, names, dataSizeStack)
	writeAttributeSub(b, "Name", 0, binXMLTypeString, baseOffset, names)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)

	//     <EventID>%1</EventID>
	dataSizeStack = pushOpenElement(b, "EventID", false, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, 1, binXMLTypeUint16)
	dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)

	//     <Level>%2</Level>
	dataSizeStack = pushOpenElement(b, "Level", false, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, 2, binXMLTypeUint16)
	dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)

	//     <TimeCreated SystemTime="%3"/>
	dataSizeStack = pushOpenElement(b, "TimeCreated", true, baseOffset, names, dataSizeStack)
	writeAttributeSub(b, "SystemTime", 3, binXMLTypeFiletime, baseOffset, names)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)

	//     <Computer>%4</Computer>
	dataSizeStack = pushOpenElement(b, "Computer", false, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, 4, binXMLTypeString)
	dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)

	//   </System>
	dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)

	//   <EventData>
	dataSizeStack = pushOpenElement(b, "EventData", false, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)

	//     12 Data elements: <Data Name="%N">%N+1</Data>
	for i := 0; i < 12; i++ {
		nameIdx := uint16(5 + i*2)
		valueIdx := uint16(6 + i*2)
		dataSizeStack = pushOpenElement(b, "Data", true, baseOffset, names, dataSizeStack)
		writeAttributeSub(b, "Name", nameIdx, binXMLTypeString, baseOffset, names)
		b.WriteByte(binXMLCloseElement)
		writeSubstitution(b, valueIdx, binXMLTypeString)
		dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)
	}

	//   </EventData>
	dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)

	// </Event>
	dataSizeStack, dataSizePatches = writeEndElement(b, dataSizeStack, dataSizePatches)

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
	for _, p := range dataSizePatches {
		binary.LittleEndian.PutUint32(buf[p.pos+3:], p.size)
	}
	return buf
}

// dataSizePatch records where to write a back-patched data_size once the
// template body is complete: buf[pos+3:pos+7] = size (little-endian).
type dataSizePatch struct {
	pos  uint32 // position, within the template body buffer, of the OpenStartElementTag token byte
	size uint32 // computed data_size value
}

// pushOpenElement calls writeOpenElement and pushes the token position it
// reports onto stack, returning the updated stack. A thin wrapper rather than
// inlining `stack = append(stack, writeOpenElement(...))` at every call site,
// so buildTemplateBody's element list reads the same as it did before this
// task (one line per open, one line per close).
func pushOpenElement(b *bytes.Buffer, name string, hasAttrs bool, binXMLBase uint32, refs *[]chunkRef, stack []uint32) []uint32 {
	pos := writeOpenElement(b, name, hasAttrs, binXMLBase, refs)
	return append(stack, pos)
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
func writeEndElement(b *bytes.Buffer, stack []uint32, patches []dataSizePatch) ([]uint32, []dataSizePatch) {
	b.WriteByte(binXMLEndElement)
	n := len(stack)
	pos := stack[n-1]
	stack = stack[:n-1]
	size := uint32(b.Len()) - (pos + 7)
	patches = append(patches, dataSizePatch{pos: pos, size: size})
	return stack, patches
}

// collectSubstitutionsFromFields gathers all 29 substitution values from a fields map.
//
// Sub 0: ProviderName (STRING) from fields["ProviderName"]
// Sub 1: EventID (UINT16) from eventID parameter
// Sub 2: Level (UINT16) = 0
// Sub 3: SystemTime (FILETIME) from fields["TimeCreated"] parsed as RFC3339Nano; fallback time.Now()
// Sub 4: Computer (STRING) from fields["Computer"]
// Subs 5..28: 12 data field name+value pairs from fields map (see dataFieldNames)
func collectSubstitutionsFromFields(eventID int, fields map[string]string) []substitutionEntry {
	// Parse TimeCreated from fields, falling back to time.Now().
	var systemTime time.Time
	if s, ok := fields["TimeCreated"]; ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			systemTime = t
		}
	}
	if systemTime.IsZero() {
		systemTime = time.Now()
	}

	subs := make([]substitutionEntry, 0, 29)

	// Sub 0: ProviderName (STRING)
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["ProviderName"])})
	// Sub 1: EventID (UINT16)
	subs = append(subs, substitutionEntry{binXMLTypeUint16, uint16LEBytes(uint16(eventID))})
	// Sub 2: Level (UINT16)
	subs = append(subs, substitutionEntry{binXMLTypeUint16, uint16LEBytes(0)})
	// Sub 3: SystemTime (FILETIME)
	subs = append(subs, substitutionEntry{binXMLTypeFiletime, uint64LEBytes(toFILETIME(systemTime))})
	// Sub 4: Computer (STRING)
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["Computer"])})

	// Sub 5..28: Data field names and values (pairs).
	for _, name := range dataFieldNames {
		subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(name)})
		subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields[name])})
	}

	return subs
}

// writeSubstitutionArray writes the substitution array after the template body.
//
// Format:
//
//	[count: 4B LE]
//	[value_spec × count: WORD size + BYTE type + BYTE pad = 4B each]
//	[value_data: concatenated raw bytes]
func writeSubstitutionArray(b *bytes.Buffer, subs []substitutionEntry) {
	writeUint32LE(b, uint32(len(subs)))

	// Value specs.
	for _, s := range subs {
		writeUint16LE(b, uint16(len(s.data)))
		b.WriteByte(s.typ)
		b.WriteByte(0x00) // padding
	}

	// Value data.
	for _, s := range subs {
		b.Write(s.data)
	}
}

// ---------------------------------------------------------------------------
// BinXML token writers (used by buildTemplateBody)
// ---------------------------------------------------------------------------

// writeOpenElement writes an OpenStartElement token with inline NameNode, and
// returns the token byte's position within b (i.e. b.Len() as it stood
// before this call — a local offset into the template-body buffer, NOT
// adjusted by binXMLBase), so a caller building a stack of open elements
// (buildTemplateBody, via pushOpenElement) can later back-patch this token's
// data_size field once its EndElementTag is known: the patch is applied to
// the finished template-body byte slice as buf[pos+3:pos+7], so pos must
// stay in that slice's own coordinate space. data_size is written as 0
// here — a placeholder patched in by writeEndElement/buildTemplateBody's
// final patch pass, never left as 0 in the returned payload.
//
// Layout without attrs (0x01):
//
//	[token: 1B] [dep_id: 2B] [data_size: 4B] [name_offset: 4B] [NameNode]
//
// Layout with attrs (0x41):
//
//	[token: 1B] [dep_id: 2B] [data_size: 4B] [name_offset: 4B] [attr_list_size: 4B] [NameNode]
func writeOpenElement(b *bytes.Buffer, name string, hasAttrs bool, binXMLBase uint32, refs *[]chunkRef) uint32 {
	tokenPos := uint32(b.Len())
	if hasAttrs {
		b.WriteByte(binXMLOpenElementAttrs) // 0x41
	} else {
		b.WriteByte(binXMLOpenElement) // 0x01
	}
	// 0xffff is the "not set" sentinel (libyal EVTX docs: "-1 (0xffff) => not
	// set"). Writing 0 here does not mean "no dependency" — it is a valid
	// identifier referring to template value 0, which is a claim we have no
	// basis to make about every element. Confirmed against testdata/system.evtx:
	// unconditional elements (<Provider>, <TimeCreated>, <Correlation>, ...)
	// all carry 0xffff; only elements that wrap an OptionalSubstitution (0x0E)
	// token carry that substitution's own index instead. go-evtx never emits
	// OptionalSubstitution, so every element it writes is unconditional.
	writeUint16LE(b, 0xffff) // dependency_id: not set
	writeUint32LE(b, 0)      // data_size: placeholder, back-patched by writeEndElement

	headerSize := uint32(11) // token(1) + dep_id(2) + data_size(4) + name_offset(4)
	if hasAttrs {
		headerSize = 15 // + attr_list_size(4)
	}
	nameNodeOffset := binXMLBase + tokenPos + headerSize
	writeUint32LE(b, nameNodeOffset)

	if hasAttrs {
		writeUint32LE(b, 0) // attribute_list_size (python-evtx ignores the value)
	}

	writeNameNode(b, name, binXMLBase, refs)

	return tokenPos
}

// writeAttributeSub writes an Attribute token with inline NameNode, followed by
// a NormalSubstitution token as the attribute's value.
//
// Layout: [token: 1B] [name_offset: 4B] [NameNode] [0x0D subIdx subType]
func writeAttributeSub(b *bytes.Buffer, name string, subIndex uint16, subType byte, binXMLBase uint32, refs *[]chunkRef) {
	tokenPos := uint32(b.Len())
	b.WriteByte(binXMLAttribute)
	nameNodeOffset := binXMLBase + tokenPos + 5 // 5 = token(1) + offset(4)
	writeUint32LE(b, nameNodeOffset)
	writeNameNode(b, name, binXMLBase, refs)
	writeSubstitution(b, subIndex, subType)
}

// writeSubstitution writes a NormalSubstitution token (4 bytes).
//
// Layout: [token: 0x0D] [index: 2B LE] [type: 1B]
func writeSubstitution(b *bytes.Buffer, index uint16, valueType byte) {
	b.WriteByte(binXMLNormalSubstitution)
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

// encodeSubString encodes a string as raw UTF-16LE with null terminator
// for use in the substitution value data.
func encodeSubString(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	buf := make([]byte, len(u16)*2+2) // +2 for null terminator
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
