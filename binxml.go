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
	binXMLEOF                  = 0x00 // Fragment end-of-file token (W1, v0.7.0 Task 7)

	binXMLTypeNull     = 0x00 // Value type: NULL — no data (F12c)
	binXMLTypeString   = 0x01 // Value type: UTF-16LE string (WSTRING)
	binXMLTypeUint8    = 0x04 // Value type: uint8 (UNSIGNED_BYTE) (F12a/F12b)
	binXMLTypeUint16   = 0x06 // Value type: uint16 (UNSIGNED_WORD)
	binXMLTypeUint64   = 0x0A // Value type: uint64 (UNSIGNED_QWORD) (F12b)
	binXMLTypeFiletime = 0x11 // Value type: FILETIME (uint64)
	binXMLTypeHexInt64 = 0x15 // Value type: HexInt64 (uint64, hex-rendered) (F12b)
)

// F14 (v0.7.0, Task 8e): two false starts and where they landed, kept here
// rather than silently squashed, per this release's own "record null
// results" discipline. Net effect on the encoder, after both corrections:
// none — every byte this function and buildTemplateBody write is identical
// to what F12b/F13c already wrote. The value was in what got measured along
// the way, not in a code change.
//
// task-8b-report.md's Step 1 table claims Correlation/@ActivityID and
// @RelatedActivityID are typed GUID (0x0f), Security/@UserID is typed SID
// (0x13), and EventID/@Qualifiers is typed UNSIGNED_WORD (0x06) — all at
// size 0 — and F13c (Task 8c) built Qualifiers to match.
//
// Attempt 1: believed the table and reclassified the other five NULL fields
// (which F12b had left as a generic binXMLTypeNull) to match it too. Broke
// python-evtx's own regression guard immediately, on record 0:
// `Evtx.Nodes.RootNode.substitutions()` computes each fixed-width type's
// length independent of the declared size (`GuidTypeNode.tag_length() ==
// 16`, unconditionally) and raises `ParseException("Invalid substitution
// value size")` when `abs(declared_size - type_length) > 4` — 16 vs. a
// declared 0 fails outright.
//
// Verified the table three independent ways before writing more code: (1) a
// byte-for-byte raw parse of testdata/system.evtx's own record 0 (the exact
// record the table cites, EventRecordID 12049), reading the substitution
// array's spec bytes directly with no decoding library involved, found
// substitution indices 4, 7, 12, and 18 — the positions the table names for
// Qualifiers/ActivityID/UserID/RelatedActivityID — are ALL declared type
// 0x00 (size 0) in the real file, not GUID/SID/UNSIGNED_WORD; every other
// row in the same table checks out exactly as stated. (2) `python-evtx==0.8.1`
// parses that same real record without error, which would be impossible if
// its ActivityID really were GUID-typed at size 0. (3)
// `UnsignedWordTypeNode.tag_length()` is a fixed 2, within the library's
// abs()<=4 tolerance of a declared 0 — why Qualifiers/UInt16/size-0 (F13c)
// never broke python-evtx even though it was, per (1), also apparently
// wrong.
//
// Attempt 2: reverted all six fields (the original five, plus Qualifiers) to
// binXMLTypeNull, matching (1)-(3) above. python-evtx's crash was fixed —
// but `Get-WinEvent`'s STAGE2 READ (Task 8c's own breakthrough,
// `EventLogReader.ReadEvent()` reading all 403 records) regressed to failing
// on record 0, an unambiguous, directly-measured Windows-side signal.
// Isolated with a third data point (`eecb372`: the five fields GUID/SID/
// UINT32-typed, Qualifiers left at UNSIGNED_WORD — STAGE2 READ failed after
// 384 records, a third distinct failure mode): the ONLY one of these three
// combinations Windows accepts in full is the original — five fields NULL,
// Qualifiers UNSIGNED_WORD. Reverted Qualifiers back to UNSIGNED_WORD on
// that evidence, restoring byte-for-byte parity with F12b/F13c.
//
// The two lines of evidence are not reconciled. Either this task's
// identification of "Qualifiers = substitution index 4 in the real file's
// own numbering" doesn't actually hold — the Step 1 table's index
// assignments, not just (as (1)-(3) initially suggested) some of its types,
// may themselves be unreliable, and this task did not independently
// re-derive them, only re-checked the types at the indices the table
// already named — or Windows' acceptance of a record ties to this declared
// type through a mechanism this investigation did not identify. See
// task-8e-report.md's "Concerns" section. task-8b-report.md carries its own
// correction note for the four-position type discrepancy regardless of
// which explanation is right — that byte-level finding (about real Windows
// output) stands on its own, independent of what go-evtx's own encoder
// needs to satisfy .NET's reader.
//
// F16 (v0.7.0, Task 9f): a full audit of all 42 substitutions' declared
// type vs. actual byte width (task-9f-report.md) found exactly one
// disagreement — sub 41 (Qualifiers) declared UNSIGNED_WORD (a fixed
// 2-byte type) but written with zero-length data — and tried a THIRD
// option distinct from Attempts 1/2 above: widen the data to a real 2-byte
// zero, leaving the type as UNSIGNED_WORD (not touching the type this
// time, only the width). CI evidence (commit 92a946a, reverted at
// 4c31d77): this ALSO regressed Get-WinEvent's STAGE2 READ, from all 403
// records to failing after 0 — the identical failure shape Attempt 2 above
// produced by changing the type. Reverted immediately, restoring
// byte-for-byte parity with F12b/F13c/F14's own final state (data length 0
// again). Three independent perturbations of this one substitution —
// type→NullType (Attempt 2), width→2 with type unchanged (F16), and the
// original type→NullType+other-five-fields→typed (Attempt 1) — have now
// ALL regressed some Windows-side signal. The only configuration Windows
// accepts in full, across every experiment run on this field so far, is
// the original: UNSIGNED_WORD, zero-length. The leading hypothesis this
// leaves for a future task: OptionalSubstitution's (0x0E) NULL-conditional
// "value absent" semantics may be signalled by a substitution's *size*
// being 0, independent of its declared *type* — i.e. a fixed-width type
// carrying zero-length data may be the format's actual, correct way to
// encode "this optional field's schema type is X, but this event doesn't
// populate it," and both "make it smaller" (impossible, already 0) and
// "make it match its type's width" (F16) break that contract in different
// ways. Untested: whether this same 0-width-regardless-of-type pattern
// holds for the OTHER four NULL-typed OptionalSubstitution fields
// (Correlation/@ActivityID/@RelatedActivityID, Execution/@ProcessID/
// @ThreadID, Security/@UserID) if they were ever given a real,
// non-zero-length value of their own declared type instead of NullType —
// that experiment was not run this task and remains open.

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
func buildBinXML(eventID int, recordID uint64, fields map[string]string, binXMLChunkOffset uint32) binXMLResult {
	// Template body starts after: fragment header + template instance + template node header.
	templateBodyBase := binXMLChunkOffset + preambleSize

	var names []chunkRef

	// Build template body with substitution placeholders.
	tbody := buildTemplateBody(templateBodyBase, &names)

	// Collect actual substitution values from the fields map.
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

	// 6. Fragment EOF token (W1, v0.7.0 Task 7). Real Windows always writes a
	// single 0x00 immediately after the substitution array — measured on all
	// 1601 records of testdata/system.evtx and on 100,683 of 100,683 records
	// across the wider corpus (docs/format-baseline.md). Without this byte no
	// go-evtx-written record can pass decodeBinXMLFragment's full-consumption
	// check, which every real Windows record satisfies exactly this way; this
	// project shipped without it through v0.6.0 because the reader that
	// existed until then never checked for it.
	out.WriteByte(binXMLEOF)

	// 7. 8-byte record alignment (W2, v0.7.0 Task 7). size % 8 == 0 holds for
	// 100,683 of 100,683 real records, where size = 24 (record header) +
	// payload + 4 (trailing size copy) — see wrapEventRecord. Real Windows
	// padding is measured NON-zero (docs/format-baseline.md); go-evtx
	// zero-fills instead. That is this writer's own choice, not something the
	// format requires: decodeBinXMLFragment (the read side) only checks the
	// padding's length, never its content.
	const evtxRecordTrailerSize = 4 // trailing Size copy, see wrapEventRecord
	onDiskSize := evtxRecordHeaderSize + out.Len() + evtxRecordTrailerSize
	if pad := (8 - onDiskSize%8) % 8; pad > 0 {
		out.Write(make([]byte, pad))
	}

	return binXMLResult{payload: out.Bytes(), names: names, templates: templates}
}

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
	writeAttributeSub(b, "Name", 0, binXMLTypeString, true, baseOffset, names)
	writeAttributeSub(b, "Guid", subProviderGuid, binXMLTypeString, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <EventID Qualifiers="%41">%1</EventID>                        (F13a/F13c)
	//
	// F13c declares Qualifiers UNSIGNED_WORD (0x06) at size 0.
	// task-8b-report.md's Step 1 table cites this as the real file's own
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
	// way not yet understood. See task-8e-report.md's "Concerns" for the
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
	writeAttributeOptional(b, "ActivityID", subActivityID, binXMLTypeNull, true, baseOffset, names)
	writeAttributeOptional(b, "RelatedActivityID", subRelatedActivityID, binXMLTypeNull, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Execution ProcessID="%36" ThreadID="%37"/>                   (F12b/F12c)
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Execution", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "ProcessID", subProcessID, binXMLTypeNull, true, baseOffset, names)
	writeAttributeOptional(b, "ThreadID", subThreadID, binXMLTypeNull, false, baseOffset, names)
	patches = closeAttrList(b, attrListPos, patches)
	b.WriteByte(binXMLCloseElement)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Channel>%38</Channel>                                        (F12b)
	dataSizeStack = pushOpenElement(b, "Channel", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, subChannel, binXMLTypeString)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Computer>%4</Computer>
	dataSizeStack = pushOpenElement(b, "Computer", false, depIDNotSet, baseOffset, names, dataSizeStack)
	b.WriteByte(binXMLCloseElement)
	writeSubstitution(b, 4, binXMLTypeString)
	dataSizeStack, patches = writeEndElement(b, dataSizeStack, patches)

	//     <Security UserID="%39"/>                                      (F12b/F12c)
	dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Security", depIDNotSet, baseOffset, names, dataSizeStack)
	writeAttributeOptional(b, "UserID", subSecurityUserID, binXMLTypeNull, false, baseOffset, names)
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
		dataSizeStack, attrListPos = pushOpenElementAttrs(b, "Data", depIDNotSet, baseOffset, names, dataSizeStack)
		writeAttributeSub(b, "Name", nameIdx, binXMLTypeString, false, baseOffset, names)
		patches = closeAttrList(b, attrListPos, patches)
		b.WriteByte(binXMLCloseElement)
		writeSubstitution(b, valueIdx, binXMLTypeString)
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
