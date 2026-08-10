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
)

// BinXML token type constants (per libevtx / MS-EVEN6 specification).
const (
	binXMLFragmentHeader       = 0x0F // Fragment header token
	binXMLOpenElement          = 0x01 // Open start element (no attrs)
	binXMLOpenElementAttrs     = 0x41 // Open start element with attribute list flag
	binXMLCloseElement         = 0x02 // Close start element tag
	binXMLEndElement           = 0x04 // End element tag
	binXMLAttribute            = 0x06 // Attribute token (last attribute in the list)
	binXMLAttributeMore        = 0x46 // Attribute token, "more attributes follow" (F12b)
	binXMLTemplateInstance     = 0x0C // Template instance token
	binXMLNormalSubstitution   = 0x0D // Normal substitution token
	binXMLOptionalSubstitution = 0x0E // Optional substitution token (F12c)
	binXMLValueText            = 0x05 // Value token: literal (non-substituted) value

	binXMLTypeNull     = 0x00 // Value type: NULL — no data (F12c)
	binXMLTypeString   = 0x01 // Value type: UTF-16LE string (WSTRING)
	binXMLTypeUint8    = 0x04 // Value type: uint8 (UNSIGNED_BYTE) (F12a/F12b)
	binXMLTypeUint16   = 0x06 // Value type: uint16 (UNSIGNED_WORD)
	binXMLTypeUint32   = 0x08 // Value type: uint32 (UNSIGNED_DWORD) (F15)
	binXMLTypeUint64   = 0x0A // Value type: uint64 (UNSIGNED_QWORD) (F12b)
	binXMLTypeGuid     = 0x0F // Value type: GUID (F15)
	binXMLTypeFiletime = 0x11 // Value type: FILETIME (uint64)
	binXMLTypeSid      = 0x13 // Value type: SID (F15)
	binXMLTypeHexInt64 = 0x15 // Value type: HexInt64 (uint64, hex-rendered) (F12b)
)

// How the declared types below were arrived at — F14's two false starts, F15's
// resolution, F16's audit — is recorded in docs/evtx-format-notes.md, section
// "The substitution-type investigation, F14 through F16". The short version,
// because it is the rule the code depends on: an OptionalSubstitution's TOKEN
// declares the field's own type, while its entry in the SUBSTITUTION ARRAY
// declares NULL when the value is absent. Those are two different fields at
// opposite ends of the record, and conflating them cost two releases.

// depIDNotSet is the "not set" sentinel for an OpenStartElementTag's
// dependency_id field (libyal EVTX docs: "-1 (0xffff) => not set"). An
// element carrying this value always renders; F9 (Task 7c) established the
// sentinel, F12c (this task) is the first to also emit a REAL dependency_id
// — see the substitution index constants below.
const depIDNotSet = 0xffff

// F12b/F12c (Task 8b): substitution array indices for the nine <System>
// children testdata/system.evtx has and go-evtx did not. Named, rather than
// left as bare literals at each call site, because dependency_test.go and
// datasize_test.go need to recognise them as legitimate non-sentinel
// dependency identifiers rather than corruption.
//
// Version, Task, Opcode, Keywords, EventRecordID are each the sole content of
// a no-attribute element and use OptionalSubstitution (0x0E) with
// dependency_id equal to their own index — measured against
// testdata/system.evtx, where every element of this shape (including
// EventID and Level, which go-evtx already had) is encoded this way. Only
// EventRecordID has a real, always-available data source (the writer's own
// record ID); the other four have none, so they carry a zero value of the
// correct type rather than invented data.
//
// ActivityID/RelatedActivityID/ProcessID/ThreadID/UserID are attribute
// values of Correlation/Execution/Security — elements measured as always
// present (dependency_id stays depIDNotSet) whose individual attribute
// values the real file itself leaves NULL when unpopulated, which is exactly
// go-evtx's own position for these forensic fields it has no source for.
//
// Channel is a plain string like Computer, sourced from fields["Channel"];
// go-evtx always has a real value for it (possibly empty), so — like
// Computer — it stays a NormalSubstitution (0x0D) with dependency_id
// depIDNotSet rather than joining the OptionalSubstitution group above.
const (
	subVersion       = 29
	subTask          = 30
	subOpcode        = 31
	subKeywords      = 32
	subEventRecordID = 33

	subActivityID        = 34
	subRelatedActivityID = 35
	subProcessID         = 36
	subThreadID          = 37

	subChannel = 38

	// F18 named the two indices that had been written as bare literals, so
	// the OptionalSubstitution token and the element's dependency_id can be
	// seen to reference the same slot.
	subProviderName = 0
	subComputer     = 4

	subSecurityUserID = 39

	// F13b/F13c (Task 8c): the two remaining named divergences from
	// testdata/system.evtx's <System> block — Provider/@Guid and
	// EventID/@Qualifiers. Appended after the F12b/F12c range, not
	// interleaved, for the same reason that range was itself appended after
	// 0-28: nothing before this task's own indices renumbers.
	subProviderGuid      = 40
	subEventIDQualifiers = 41

	totalSubstitutions = 42
)

// subEventID and subLevel name the two pre-existing substitution indices
// (unchanged by this task — see indices 0-4 below) that Task 8c (F13a) also
// starts using as their own OpenStartElementTag's dependency_id. Named for
// the same reason the F12b constants above are: dependency_test.go's
// knownOptionalDependencyIDs needs to recognise them as legitimate
// non-sentinel dependency identifiers rather than corruption.
//
// Measured against testdata/system.evtx (task-8b-report.md's Step 1 table,
// extended by task-8c-report.md): the real file ties EventID's element-level
// dependency_id to its own content substitution's index — 0x0003 there, NOT
// the index of its Qualifiers attribute (0x0004) — and Level's the same way
// (0x0000, its own content index). Both match the convention F12b/F12c
// already established for Version/Task/Opcode/Keywords/EventRecordID:
// dependency_id equals the element's own content substitution index. F12b
// left EventID/Level at depIDNotSet as an explicit, permitted scope decision
// ("elements that are genuinely always present may legitimately stay
// 0x0D") — this task closes that out to match the real file exactly.
const (
	subEventID = 1
	subLevel   = 2
)

// eventNamespaceURI is the schema every real Windows .evtx record declares on
// its root <Event> element (F8). Verified directly against
// testdata/system.evtx: the UTF-16LE encoding of this exact string occurs 45
// times, once per template. Without it, elements are in no XML namespace at
// all, and every namespace-aware consumer's XPath — PowerShell's .ToXml(),
// .NET's EventLogRecord, python-evtx, Event Viewer's own XML view — matches
// nothing.
const eventNamespaceURI = "http://schemas.microsoft.com/win/2004/08/events/event"

// evtxRecordsStart: chunk-relative offset where the first event record is placed.
// python-evtx hardcodes first_record() at chunk offset 0x200 (512).
const evtxRecordsStart = uint32(evtxChunkHeaderSize) // = 512

// evtxRecordHeaderSize is the fixed size of an event record header:
// signature(4) + size(4) + recordID(8) + timestamp(8) = 24 bytes.
const evtxRecordHeaderSize = 24

const (
	fragHeaderSize   = 4                                                 // 0x0F + major + minor + flags
	templInstSize    = 10                                                // token + unknown0 + template_id + template_offset
	templNodeHdrSize = 24                                                // next_offset(4) + GUID(16, first 4B = template_id) + data_length(4)
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

	// defOffset is the chunk-relative offset of the template definition this
	// record's instance points at — the one it wrote itself, or the one an
	// earlier record in the chunk wrote. The writer remembers it so the next
	// record in the same chunk can reference it instead of duplicating it
	// (F19). Reset whenever a chunk is flushed: offsets are chunk-relative.
	defOffset uint32
}

// buildBinXML encodes an event as template-based BinXML.
//
// eventID is the Windows Event ID. recordID is the writer's own record
// identifier (F12b: it becomes the <EventRecordID> substitution — the one
// newly-added System child go-evtx has real data for). fields is a map of
// field name to value. binXMLChunkOffset is the chunk-relative byte offset
// where this BinXML payload starts (used for inline NameNode offset
// calculations).
//
// Reserved keys in fields:
//   - "ProviderName"  → substitution 0 (STRING)
//   - "Computer"      → substitution 4 (STRING)
//   - "TimeCreated"   → RFC3339Nano timestamp; fallback to time.Now()
//   - "Channel"       → substitution 38 (STRING); defaults to "" (F12b)
//   - "ProviderGuid"  → substitution 40 (STRING); defaults to "" (F13b)
//   - 12 data fields by name (see dataFieldNames)
//
// sharedTemplateOffset is the chunk-relative offset of a template definition
// already written into this chunk, or 0 when this record is the first and must
// declare it inline.
//
// F19: real Windows declares a template definition once per chunk and points
// every later instance backward at it — 545 definitions across the derivation
// corpus against 36 819 backward references, and not one forward reference.
// go-evtx used to inline a full copy in every record, which is valid (Windows
// reads it) but costs roughly 800 KB of duplication in a 1.7 MB 403-record
// file.
func buildBinXML(eventID int, recordID uint64, fields map[string]string, binXMLChunkOffset, sharedTemplateOffset uint32) binXMLResult {
	subs := collectSubstitutionsFromFields(eventID, recordID, fields)

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

	// 2. TemplateInstanceNode (10 bytes). Its template_offset either names the
	// definition this record is about to write inline, or the one an earlier
	// record in this chunk already wrote.
	inlineOffset := binXMLChunkOffset + fragHeaderSize + templInstSize
	templateOffset := sharedTemplateOffset
	if templateOffset == 0 {
		templateOffset = inlineOffset
	}
	out.WriteByte(binXMLTemplateInstance) // token 0x0C
	out.WriteByte(0x01)                   // unknown0
	writeUint32LE(out, 1)                 // template_id
	writeUint32LE(out, templateOffset)

	var names []chunkRef
	var templates []chunkRef
	if sharedTemplateOffset == 0 {
		// 3. TemplateNode header (24 bytes).
		// python-evtx layout: next_offset(4) + GUID(16, first 4B also =
		// template_id) + data_length(4).
		//
		// The body's own name offsets are chunk-relative, so it can only be
		// built once its position is known — which is why this is here and not
		// above.
		tbody := buildTemplateBody(binXMLChunkOffset+preambleSize, &names)
		guid := make([]byte, 16)
		binary.LittleEndian.PutUint32(guid, 1) // GUID bytes [0:4] (= template_id); [4:16] stay zero
		writeUint32LE(out, 0)                  // next_offset (no chaining)
		out.Write(guid)
		writeUint32LE(out, uint32(len(tbody))) // data_length
		templates = []chunkRef{{key: guidHash(guid), offset: templateOffset}}

		// 4. Template body.
		out.Write(tbody)
	}
	// A referencing record reports no names and no template: both are already
	// registered in this chunk's hash tables by the record that wrote them.

	// 5. Substitution array.
	writeSubstitutionArray(out, subs)

	// 6. Fragment EOF token (W1), then zero padding so the on-disk record —
	// 24-byte header + this payload + the 4-byte trailing size copy — is a
	// multiple of 8 (W2/F2).
	//
	// Both are measured absolutes in real output: every one of 37 364 real
	// records is 8-aligned in both size and offset, and every one carries 1
	// to 8 trailing bytes after its substitution array, never zero.
	//
	// These were implemented and reverted twice before. What blocked them was
	// not the trailing bytes themselves but F18: while go-evtx wrote a
	// zero-length value as {size 0, type String}, Windows' reader rejected
	// any record that also carried trailing bytes. With F18 in place all
	// three ship together — measured on Windows, 400 records read, ToXml
	// renders, and both Get-WinEvent orderings enumerate.
	//
	// The padding's content is this writer's own choice: real Windows padding
	// is measured non-zero, and a conforming reader checks only its length.
	out.WriteByte(0x00)
	for (evtxRecordHeaderSize+out.Len()+4)%8 != 0 {
		out.WriteByte(0x00)
	}

	return binXMLResult{
		payload:   out.Bytes(),
		names:     names,
		templates: templates,
		defOffset: templateOffset,
	}
}

// collectSubstitutionsFromFields gathers all 42 substitution values from a
// fields map plus the writer-tracked recordID (F12b/F12c raised this from
// 29 to 40; F13b/F13c raised it again to 42; see the sub* constants and
// buildTemplateBody's doc comment for the full index map).
//
// Sub 0: ProviderName (STRING) from fields["ProviderName"]
// Sub 1: EventID (UINT16) from eventID parameter
// Sub 2: Level (UINT8) = 0                                    — F12a: was UINT16
// Sub 3: SystemTime (FILETIME) from fields["TimeCreated"] parsed as RFC3339Nano; fallback time.Now()
// Sub 4: Computer (STRING) from fields["Computer"]
// Subs 5..28: 12 data field name+value pairs from fields map (see dataFieldNames)
// Subs 29..39: F12b's nine added System children — see buildTemplateBody
// Subs 40..41: F13b/F13c's Provider/@Guid and EventID/@Qualifiers — see buildTemplateBody
func collectSubstitutionsFromFields(eventID int, recordID uint64, fields map[string]string) []substitutionEntry {
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

	subs := make([]substitutionEntry, 0, totalSubstitutions)

	// Sub 0: ProviderName (STRING)
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["ProviderName"])})
	// Sub 1: EventID (UINT16)
	subs = append(subs, substitutionEntry{binXMLTypeUint16, uint16LEBytes(uint16(eventID))})
	// Sub 2: Level (UINT8) — F12a
	subs = append(subs, substitutionEntry{binXMLTypeUint8, []byte{0}})
	// Sub 3: SystemTime (FILETIME)
	subs = append(subs, substitutionEntry{binXMLTypeFiletime, uint64LEBytes(toFILETIME(systemTime))})
	// Sub 4: Computer (STRING)
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["Computer"])})

	// Sub 5..28: Data field names and values (pairs).
	for _, name := range dataFieldNames {
		subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(name)})
		subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields[name])})
	}

	// Sub 29..39 (F12b): the nine added System children. Version/Task/Opcode/
	// Keywords have no caller-supplied source, so they carry a typed zero
	// rather than invented data — matching Version's own real value (0) in
	// the sampled testdata/system.evtx record. EventRecordID uses the
	// writer's real record ID. Correlation/Execution/Security's attributes
	// have no source either; each is NULL (value-spec size 0, type
	// binXMLTypeNull/0x00) — reproducing exactly how the real file itself
	// encodes these fields for an event that doesn't populate them (F14/Task
	// 8e re-confirmed this directly, byte-for-byte, against the exact real
	// record task-8b-report.md's own Step 1 table cites, after an initial
	// attempt at this task briefly believed that table's claim of GUID/SID
	// types instead — see the F14 doc comment by the type constants for the
	// full story and how the correction was verified three independent
	// ways). Channel follows Computer's existing pattern.
	subs = append(subs, substitutionEntry{binXMLTypeUint8, []byte{0}})                           // 29 Version
	subs = append(subs, substitutionEntry{binXMLTypeUint16, uint16LEBytes(0)})                   // 30 Task
	subs = append(subs, substitutionEntry{binXMLTypeUint8, []byte{0}})                           // 31 Opcode
	subs = append(subs, substitutionEntry{binXMLTypeHexInt64, uint64LEBytes(0)})                 // 32 Keywords
	subs = append(subs, substitutionEntry{binXMLTypeUint64, uint64LEBytes(recordID)})            // 33 EventRecordID
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                  // 34 Correlation/@ActivityID
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                  // 35 Correlation/@RelatedActivityID
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                  // 36 Execution/@ProcessID
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                  // 37 Execution/@ThreadID
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["Channel"])}) // 38 Channel
	subs = append(subs, substitutionEntry{binXMLTypeNull, nil})                                  // 39 Security/@UserID

	// Sub 40..41 (F13b/F13c): the two remaining named divergences.
	//
	// Provider/@Guid varies per caller like ProviderName does, so it follows
	// Name's own pattern: a real substitution sourced from the fields map,
	// defaulting to "" when the caller doesn't supply one.
	//
	// EventID/@Qualifiers has no caller-supplied source (go-evtx's WriteRecord
	// API has no concept of an event qualifier code), so it is NULL —
	// declaring its own real type, UNSIGNED_WORD, with zero-length data, per
	// F13c. F14 (Task 8e) tried declaring it binXMLTypeNull instead, matching
	// a byte-for-byte re-parse of testdata/system.evtx's own record, and that
	// made Get-WinEvent's STAGE2 READ regress from all 403 records to failing
	// on record 0 — reverted back to UNSIGNED_WORD on that stronger, directly
	// measured signal. See the F14 doc comment by the type constants for the
	// full, unresolved story.
	subs = append(subs, substitutionEntry{binXMLTypeString, encodeSubString(fields["ProviderGuid"])}) // 40 Provider/@Guid
	subs = append(subs, substitutionEntry{binXMLTypeUint16, nil})                                     // 41 EventID/@Qualifiers

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
	//
	// F18: an absent value declares NULL. Measured across 333 100 records of
	// the derivation corpus — every one of the 1 686 434 zero-length
	// descriptors declares 0x00, and a zero-length String occurs zero times.
	//
	// This half alone is not the rule, and shipping it alone (F17) regressed
	// Windows' reader from 403 records to zero. The census says why: a
	// NormalSubstitution with a Null array entry occurs 0 times in 27 million
	// observations, while an OptionalSubstitution with one occurs 1 152 729
	// times. NULL in the array is only legal for a value the TEMPLATE also
	// marks optional — so buildTemplateBody's possibly-empty fields became
	// OptionalSubstitution in the same change.
	for _, s := range subs {
		typ := s.typ
		if len(s.data) == 0 {
			typ = binXMLTypeNull
		}
		writeUint16LE(b, uint16(len(s.data)))
		b.WriteByte(typ)
		b.WriteByte(0x00) // padding
	}

	// Value data.
	for _, s := range subs {
		b.Write(s.data)
	}
}
