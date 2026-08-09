// binxml_decode.go — generic BinXML token stream decoder.
//
// Replaces the template-specific reader this package shipped through v0.6.0,
// which assumed go-evtx's own 42-slot template and therefore produced
// confident nonsense on any real Windows file.
//
// Strictness is the point. Rules enforced here:
//  1. an unrecognised token or value type, or a length past the payload, is
//     an error;
//  2. the decode accounts for every byte — stopping early or running past a
//     fragment's EOF token is an error even when a plausible tree was built;
//  3. a BinXml-typed substitution is a nested TemplateInstance-shaped
//     fragment (measured: every one of 100 683 real substitutions across
//     three files), decoded by recursing through the same logic as the
//     record's own top-level payload, bounded by maxBinXMLDepth against a
//     corrupt or adversarial chunk driving unbounded recursion;
//  4. data_size, attr_list_size and a NameNode's stored hash are all
//     cross-checked against what the walker independently computes — this
//     decoder exists to be the writer's oracle, so it cannot ignore fields a
//     permissive parser would skip (see docs/evtx-format-notes.md's account
//     of the data_size defect this project already shipped once).
package evtx

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// BinXML token identifiers. The 0x40 bit means "more of this kind follows";
// libyal documents both forms for the tokens that carry it.
const (
	tokEOF               byte = 0x00
	tokOpenElement       byte = 0x01
	tokOpenElementAttrs  byte = 0x41
	tokCloseStartElement byte = 0x02
	tokCloseEmptyElement byte = 0x03
	tokEndElement        byte = 0x04
	tokValue             byte = 0x05
	tokValueMore         byte = 0x45
	tokAttribute         byte = 0x06
	tokAttributeMore     byte = 0x46
	tokCDATA             byte = 0x07
	tokCDATAMore         byte = 0x47
	tokCharRef           byte = 0x08
	tokCharRefMore       byte = 0x48
	tokEntityRef         byte = 0x09
	tokEntityRefMore     byte = 0x49
	tokPITarget          byte = 0x0a
	tokPIData            byte = 0x0b
	tokTemplateInstance  byte = 0x0c
	tokNormalSub         byte = 0x0d
	tokOptionalSub       byte = 0x0e
	tokFragmentHeader    byte = 0x0f
)

// maxBinXMLDepth bounds recursion into nested BinXml-typed substitutions.
// Real records nest exactly one level (the UserData/EventData fragment); this
// is headroom for legitimate deeper nesting, not an expected depth — it
// exists so a corrupt or adversarial chunk cannot drive unbounded recursion,
// since a BinXml substitution's own substitution array can itself carry
// further BinXml-typed values.
const maxBinXMLDepth = 32

// parseSubstitutions reads a substitution array:
//
//	[count u32][count × (size u16, type u8, pad u8)][values...]
//
// It returns the decoded values, each value's byte offset relative to
// data[0] (a caller resolving a chunk-relative substitution — recursing into
// a BinXml-typed one — needs this to locate the value's own bytes in the
// chunk), and the total bytes consumed so a caller can verify the payload was
// fully accounted for.
func parseSubstitutions(data []byte) (vals []Value, offsets []int, consumed int, err error) {
	if len(data) < 4 {
		return nil, nil, 0, fmt.Errorf("go_evtx: substitution array truncated: %d bytes, need at least 4", len(data))
	}
	count64 := uint64(binary.LittleEndian.Uint32(data[0:4]))
	// Each entry needs a 4-byte descriptor; anything larger cannot fit and is
	// a misparse rather than a real array.
	if count64 > uint64((len(data)-4)/4) {
		return nil, nil, 0, fmt.Errorf("go_evtx: substitution count %d cannot fit in %d bytes", count64, len(data))
	}
	count := int(count64)

	sizes := make([]int, count)
	types := make([]ValueType, count)
	for i := 0; i < count; i++ {
		off := 4 + i*4
		sizes[i] = int(binary.LittleEndian.Uint16(data[off : off+2]))
		types[i] = ValueType(data[off+2])
	}

	pos := 4 + count*4
	vals = make([]Value, count)
	offsets = make([]int, count)
	for i := 0; i < count; i++ {
		end := pos + sizes[i]
		if end > len(data) {
			return nil, nil, 0, fmt.Errorf(
				"go_evtx: substitution %d (%s) declares %d bytes at offset %d, past the %d-byte array",
				i, types[i], sizes[i], pos, len(data))
		}
		v, err := decodeValue(types[i], data[pos:end])
		if err != nil {
			return nil, nil, 0, fmt.Errorf("go_evtx: substitution %d: %w", i, err)
		}
		vals[i] = v
		offsets[i] = pos
		pos = end
	}
	return vals, offsets, pos, nil
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// Attr is one attribute on an element.
type Attr struct {
	Name  string `json:"name"`
	Value Value  `json:"value"`
}

// Node is a decoded element. Attributes and Children keep file order, which
// carries meaning for the positional <Data> elements real events emit.
//
// DependencyID is the OpenStartElementTag's own dependency_id field, verbatim
// — depIDNotSet (0xffff) for an unconditional element, otherwise the
// substitution index whose content this element's presence depends on. Real
// go-evtx-written files tie this to the element's own content substitution
// for seven elements (see CLAUDE.md's BinXML substitution index map); nothing
// downstream of this decoder consumes it yet, but a decoder meant to be that
// writer's oracle cannot drop a field the writer sets deliberately.
type Node struct {
	Name         string `json:"name"`
	DependencyID uint16 `json:"dependencyId"`
	Attributes   []Attr `json:"attributes,omitempty"`
	Children     []Node `json:"children,omitempty"`
	Value        *Value `json:"value,omitempty"`
}

// binxmlParser walks one template body, resolving substitutions against subs.
type binxmlParser struct {
	chunk []byte  // the whole chunk: name and template offsets are chunk-relative
	buf   []byte  // the body being walked
	base  int     // chunk-relative offset of buf[0]
	pos   int     // cursor within buf
	subs  []Value // substitution values for this record
	cache *templateCache

	// attrIndex is the position of the attribute currently being parsed within
	// its element's list. Only the shape hook reads it; the parse itself is
	// driven by each attribute token's own "more follow" bit.
	attrIndex int
}

// Shape event kinds. A shape is what the encoder chose, never what it encoded:
// which token form, which flags, which declared types. No names and no values
// ever enter a shapeEvent — the corpus these are censused over is full of
// account names, SIDs, machine names and IP addresses.
const (
	shapeKindBodyFragment = "body-fragment"
	shapeKindElement      = "element"
	shapeKindAttribute    = "attribute"
	shapeKindSubstitution = "substitution"
	shapeKindLiteral      = "literal"
)

// Attribute positions within a list, as reported by shapeEvent.AttrPos.
const (
	attrPosOnly   = "only"
	attrPosFirst  = "first"
	attrPosMiddle = "middle"
	attrPosLast   = "last"
)

// shapeEvent is one structural observation from a BinXML walk. It is
// deliberately comparable, so a census can use it directly as a map key.
type shapeEvent struct {
	Kind  string // one of the shapeKind* constants
	Token uint8  // the token byte: 0x41 vs 0x01, 0x46 vs 0x06, 0x0e vs 0x0d

	// Element.
	DepSet      bool // dependency_id is a real index, not the 0xffff sentinel
	DataSizeNil bool // declared data_size is zero
	EmptyClose  bool // closed by CloseEmptyElementTag, not EndElementTag
	HasValue    bool // carries a value token of its own
	HasChildren bool // carries child elements

	// Attribute.
	AttrPos string // one of the attrPos* constants

	// Substitution and literal.
	Declared ValueType // the type the template's token declares
	Actual   ValueType // the type the substitution array declares
}

// emit hands one observation to the profiler, if one is attached. Nil in every
// production path, so this is a predictable branch and nothing else.
func (p *binxmlParser) emit(e shapeEvent) {
	if p.cache != nil && p.cache.onShape != nil {
		p.cache.onShape(e)
	}
}

// attrPosition names where an attribute sits in its list, from its index and
// its own "more follow" bit. A lone attribute is "only" rather than "last":
// whether real encoders use token 0x06 for a single attribute is one of the
// questions the census exists to answer (see the F13b note in
// docs/evtx-format-notes.md).
// emitElement reports one element's shape once its terminator is known —
// emptyClose and the presence of a value or children are only settled there.
func (p *binxmlParser) emitElement(tok byte, depID uint16, dataSize uint32, emptyClose bool, node *Node) {
	p.emit(shapeEvent{
		Kind:        shapeKindElement,
		Token:       tok,
		DepSet:      depID != depIDNotSet,
		DataSizeNil: dataSize == 0,
		EmptyClose:  emptyClose,
		HasValue:    node.Value != nil,
		HasChildren: len(node.Children) > 0,
	})
}

func attrPosition(index int, more bool) string {
	switch {
	case index == 0 && !more:
		return attrPosOnly
	case index == 0:
		return attrPosFirst
	case !more:
		return attrPosLast
	default:
		return attrPosMiddle
	}
}

// decodeRecordBinXML decodes one record's BinXML payload into an element
// tree. cache owns the chunk the payload lives in (newTemplateCache(chunk));
// payloadOff/payloadLen locate the payload within cache.chunk. Deriving both
// the chunk and the payload from cache, rather than accepting a separate
// chunk argument, makes "cache built for a different chunk than payload
// lives in" unrepresentable — the same invariant Task 4 gave templateCache
// itself.
func decodeRecordBinXML(cache *templateCache, payloadOff, payloadLen int) (*Node, error) {
	if cache == nil {
		return nil, fmt.Errorf("go_evtx: decodeRecordBinXML: nil cache")
	}
	if payloadOff < 0 || payloadLen < 0 || payloadOff+payloadLen > len(cache.chunk) {
		return nil, fmt.Errorf("go_evtx: payload [%d:%d) outside the %d-byte chunk",
			payloadOff, payloadOff+payloadLen, len(cache.chunk))
	}
	return decodeBinXMLFragment(cache, payloadOff, payloadLen, true, 0)
}

// decodeBinXMLFragment decodes one TemplateInstance-shaped BinXML fragment: an
// optional fragment header, a required TemplateInstance, its (inline or
// chunk-shared) definition, and its substitution array — recursing into any
// BinXml-typed substitution the array holds. It is the record's own top-level
// payload the first time it runs (top==true, depth==0) and a nested
// substitution's raw bytes every time after (top==false).
//
// Measured (100 683 real records, three files): every nested BinXml
// substitution has this exact shape — a TemplateInstance, sometimes preceded
// by a fragment header (100 628 of them) and sometimes not (55 of them) — not
// a bare element tree. That is why this is the same function as the
// top-level decode rather than a second, simpler one.
//
// top controls the trailing-byte rule (see the rem check below): only the
// record's own top-level payload allows 0–7 bytes of padding after the
// fragment's EOF token, because only it is wrapped in an on-disk record that
// must 8-align. A nested fragment's value data ends exactly one EOF byte
// after its own substitution array, with no padding allowance.
func decodeBinXMLFragment(cache *templateCache, chunkOff, length int, top bool, depth int) (*Node, error) {
	if depth > maxBinXMLDepth {
		return nil, fmt.Errorf("go_evtx: nested BinXml recursion exceeded %d levels at chunk offset %d",
			maxBinXMLDepth, chunkOff)
	}
	chunk := cache.chunk
	if chunkOff < 0 || length < 0 || chunkOff+length > len(chunk) {
		return nil, fmt.Errorf("go_evtx: fragment [%d:%d) outside the %d-byte chunk", chunkOff, chunkOff+length, len(chunk))
	}
	payload := chunk[chunkOff : chunkOff+length]
	if len(payload) < 1 {
		return nil, fmt.Errorf("go_evtx: fragment at chunk offset %d is empty", chunkOff)
	}

	// The fragment header is optional here (unlike a template body's own,
	// which parseFragment still requires unconditionally) — measured above.
	pos := 0
	if payload[0] == tokFragmentHeader {
		if len(payload) < 4 {
			return nil, fmt.Errorf("go_evtx: fragment header truncated at chunk offset %d", chunkOff)
		}
		pos = 4
	}

	if pos >= len(payload) {
		return nil, fmt.Errorf("go_evtx: fragment at chunk offset %d ends before its template instance", chunkOff)
	}
	if payload[pos] != tokTemplateInstance {
		return nil, fmt.Errorf("go_evtx: expected a template instance at chunk offset %d, found %#02x",
			chunkOff+pos, payload[pos])
	}
	if pos+10 > len(payload) {
		return nil, fmt.Errorf("go_evtx: template instance truncated at chunk offset %d", chunkOff+pos)
	}
	defOffset := int(le32(payload[pos+6:]))
	pos += 10

	// The definition is inline when its offset names this very position;
	// otherwise it lives elsewhere in the chunk and is shared. Either way,
	// resolve through cache.get so there is exactly one path that ever
	// touches cache.defs (Task 4's invariant) — the inline case only adds the
	// extra step of skipping the body bytes that follow here in the stream.
	inline := defOffset == chunkOff+pos
	def, err := cache.get(defOffset)
	if err != nil {
		return nil, err
	}
	if inline {
		pos += templateDefHeaderSize + len(def.Body)
		// An inline definition's body length is validated against the whole
		// chunk (parseTemplateDef), not against this fragment: a corrupt or
		// truncated fragment can still fit legally inside the chunk. Guard
		// before slicing payload[pos:] below — this is what a fuzzed or
		// truncated record needs to fail on cleanly instead of panicking.
		if pos > len(payload) {
			return nil, fmt.Errorf(
				"go_evtx: inline template definition at chunk offset %d (%d-byte body) runs past this %d-byte fragment",
				defOffset, len(def.Body), len(payload))
		}
	}

	subs, offsets, consumed, err := parseSubstitutions(payload[pos:])
	if err != nil {
		return nil, err
	}

	// Every byte is accounted for: the fragment's own EOF token, plus — the
	// record's top-level payload only — 0–7 bytes of padding that 8-aligns
	// the on-disk record (24-byte header + payload + 4-byte size copy).
	// Measured against 100 683 real records (all of them) and every record of
	// testdata/system.evtx: the byte right after the substitution array is
	// always the EOF token; the padding after it is never zeroed, so only its
	// length is checked, never its content.
	//
	// One tolerated exception, and it is go-evtx's own doing: this writer stops
	// at the substitution array and emits neither the EOF token nor the
	// padding (tracked as #38/#39 — the writer is non-conformant, this check is
	// not wrong). Emitting both WAS implemented and then REVERTED: it regressed
	// Windows' own EventLogReader on our 403-record fixture from reading all of
	// them to failing on record 0, measured in CI and independently on the VM,
	// while single-record files kept working. Until that is understood, a
	// top-level payload ending exactly at the substitution array is accepted.
	// Anything present after it is still validated in full.
	rem := len(payload) - (pos + consumed)
	switch {
	case rem == 0 && top:
		// go-evtx's own output. Accepted; see above.
	case rem < 1 || payload[pos+consumed] != tokEOF:
		return nil, fmt.Errorf(
			"go_evtx: fragment at chunk offset %d: expected the EOF token at chunk offset %d, found %d trailing byte(s)",
			chunkOff, chunkOff+pos+consumed, rem)
	case top:
		if rem-1 > 7 || (28+pos+consumed+rem)%8 != 0 {
			return nil, fmt.Errorf(
				"go_evtx: record payload at chunk offset %d: %d padding byte(s) after the EOF token do not "+
					"8-align the on-disk record (24-byte header + payload + 4-byte size copy)",
				chunkOff, rem-1)
		}
	case rem != 1:
		return nil, fmt.Errorf(
			"go_evtx: nested fragment at chunk offset %d: %d byte(s) after the EOF token; "+
				"nested fragments carry no padding", chunkOff, rem-1)
	}

	// A BinXml-typed substitution is a nested fragment, recursed through this
	// same function. Measured to occur in every real record (rule 3 above).
	for i := range subs {
		if subs[i].Type == ValBinXML && !subs[i].IsAbsent() {
			childOff := chunkOff + pos + offsets[i]
			childLen := len(subs[i].raw)
			node, err := decodeBinXMLFragment(cache, childOff, childLen, false, depth+1)
			if err != nil {
				return nil, fmt.Errorf("go_evtx: nested BinXml in substitution %d at chunk offset %d: %w", i, childOff, err)
			}
			subs[i].node = node
		}
	}

	p := &binxmlParser{
		chunk: chunk,
		buf:   def.Body,
		base:  def.BodyChunkOffset,
		subs:  subs,
		cache: cache,
	}
	return p.parseFragment()
}

// parseFragment reads a fragment header then exactly one root element. Unlike
// decodeBinXMLFragment's own optional header, a template body's fragment
// header is unconditional — every measured one has it.
func (p *binxmlParser) parseFragment() (*Node, error) {
	if p.pos+4 > len(p.buf) || p.buf[p.pos] != tokFragmentHeader {
		return nil, fmt.Errorf("go_evtx: expected a fragment header at body offset %d", p.pos)
	}
	p.emit(shapeEvent{Kind: shapeKindBodyFragment, Token: tokFragmentHeader})
	p.pos += 4
	node, err := p.parseElement()
	if err != nil {
		return nil, err
	}
	// Trailing EOF is expected; anything else means we lost sync.
	for p.pos < len(p.buf) {
		switch p.buf[p.pos] {
		case tokEOF:
			p.pos++
		default:
			return nil, fmt.Errorf("go_evtx: unexpected token %#02x after the root element at body offset %d",
				p.buf[p.pos], p.pos)
		}
	}
	return node, nil
}

// parseElement reads one OpenStartElement through its matching terminator —
// either an EndElementTag (content follows CloseStartElement) or a
// CloseEmptyElementTag (the element is empty, no separate EndElementTag).
func (p *binxmlParser) parseElement() (*Node, error) {
	if p.pos >= len(p.buf) {
		return nil, fmt.Errorf("go_evtx: element expected at body offset %d, buffer exhausted", p.pos)
	}
	tok := p.buf[p.pos]
	if tok != tokOpenElement && tok != tokOpenElementAttrs {
		return nil, fmt.Errorf("go_evtx: expected an element token at body offset %d, found %#02x", p.pos, tok)
	}
	start := p.pos
	if p.pos+11 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: element header truncated at body offset %d", p.pos)
	}
	depID := le16(p.buf[p.pos+1:])
	declaredDataSize := le32(p.buf[p.pos+3:])
	nameOffset := int(le32(p.buf[p.pos+7:]))
	p.pos += 11

	name, err := p.readName(nameOffset, start+11)
	if err != nil {
		return nil, err
	}
	node := &Node{Name: name, DependencyID: depID}

	if tok == tokOpenElementAttrs {
		if p.pos+4 > len(p.buf) {
			return nil, fmt.Errorf("go_evtx: attribute list size truncated at body offset %d", p.pos)
		}
		attrListSizePos := p.pos
		declaredAttrListSize := int(le32(p.buf[p.pos:]))
		p.pos += 4 // attr_list_size; back-checked below once the list is known
		attrRegionStart := p.pos
		p.attrIndex = 0
		for {
			attr, more, err := p.parseAttribute()
			if err != nil {
				return nil, err
			}
			node.Attributes = append(node.Attributes, *attr)
			if !more {
				break
			}
			p.attrIndex++
		}
		// attr_list_size counts only the attribute list itself (measured,
		// binxml.go's closeAttrList doc comment) — cross-check it for free,
		// the same discipline data_size gets below.
		if actual := p.pos - attrRegionStart; actual != declaredAttrListSize {
			return nil, fmt.Errorf(
				"go_evtx: element %q: attr_list_size at body offset %d declares %d bytes, attributes actually span %d",
				name, attrListSizePos, declaredAttrListSize, actual)
		}
	}

	if p.pos >= len(p.buf) {
		return nil, fmt.Errorf("go_evtx: element %q has no close-start token", name)
	}
	switch p.buf[p.pos] {
	case tokCloseEmptyElement:
		p.pos++
		p.emitElement(tok, depID, declaredDataSize, true, node)
		return p.finishElement(node, name, start, declaredDataSize)
	case tokCloseStartElement:
		p.pos++
	default:
		return nil, fmt.Errorf("go_evtx: element %q: expected close-start, found %#02x at body offset %d",
			name, p.buf[p.pos], p.pos)
	}

	for {
		if p.pos >= len(p.buf) {
			return nil, fmt.Errorf("go_evtx: element %q is not terminated", name)
		}
		tokPos := p.pos
		switch t := p.buf[p.pos]; t {
		case tokEndElement:
			p.pos++
			p.emitElement(tok, depID, declaredDataSize, false, node)
			return p.finishElement(node, name, start, declaredDataSize)
		case tokOpenElement, tokOpenElementAttrs:
			child, err := p.parseElement()
			if err != nil {
				return nil, err
			}
			node.Children = append(node.Children, *child)
		case tokNormalSub, tokOptionalSub:
			v, err := p.parseSubstitutionRef()
			if err != nil {
				return nil, err
			}
			if err := setElementValue(node, name, v, tokPos, p.base); err != nil {
				return nil, err
			}
		case tokValue, tokValueMore:
			v, err := p.parseLiteralValue()
			if err != nil {
				return nil, err
			}
			if err := setElementValue(node, name, v, tokPos, p.base); err != nil {
				return nil, err
			}
		case tokCDATA, tokCDATAMore, tokCharRef, tokCharRefMore,
			tokEntityRef, tokEntityRefMore, tokPITarget, tokPIData:
			return nil, fmt.Errorf(
				"go_evtx: token %#02x in element %q is not implemented "+
					"(zero occurrences across the measured corpus)", t, name)
		default:
			return nil, fmt.Errorf("go_evtx: unrecognised token %#02x in element %q at body offset %d",
				t, name, p.pos)
		}
	}
}

// setElementValue assigns v to node.Value, rejecting only a second value
// token — measured to never occur — where naively overwriting would silently
// drop the first one. A value token on an element that already has child
// elements is NOT rejected: measured against real data (testdata/system.evtx
// and others), this is the normal shape for a conditional EventData/UserData
// subtree — <Event>'s content is the fixed <System> element followed by a
// bare substitution reference (often BinXml-typed) with no wrapping element
// of its own, present only for event types that carry it. Rejecting that
// combination, tried first, made all but a handful of 1 601 real records in
// testdata/system.evtx fail to decode. tokPos/base are body/chunk offsets of
// the value token, for the error message only.
func setElementValue(node *Node, name string, v *Value, tokPos, base int) error {
	if node.Value != nil {
		return fmt.Errorf(
			"go_evtx: element %q already has a value; a second value token is not supported (at body offset %d, chunk offset %d)",
			name, tokPos, base+tokPos)
	}
	node.Value = v
	return nil
}

// finishElement cross-checks data_size against the element's own measured
// span and returns node. data_size = (offset immediately after this
// element's terminator) − (element_start + 7); "+7" is token(1) +
// dependency_id(2) + data_size(4), the fixed bytes common to both
// OpenStartElementTag forms, after which data_size's own count begins.
// Measured directly against testdata/system.evtx (binxml.go's writeEndElement
// doc comment) for the EndElementTag case; the same formula applies whether
// the element closed via CloseEmptyElementTag or EndElementTag, since both
// are simply "the terminator this walk actually found".
func (p *binxmlParser) finishElement(node *Node, name string, start int, declared uint32) (*Node, error) {
	actual := uint32(p.pos - (start + 7))
	if actual != declared {
		return nil, fmt.Errorf(
			"go_evtx: element %q: data_size at body offset %d declares %d bytes, element actually spans %d",
			name, start+3, declared, actual)
	}
	return node, nil
}

// parseAttribute reads one attribute: token(1) name_offset(4) [NameNode] then
// exactly one value token. more reports whether the token was
// tokAttributeMore (0x46, "more follow") as opposed to tokAttribute (0x06,
// "last") — the caller must drive its loop from this, not by peeking at the
// next byte, since a 0x46 not actually followed by another attribute is
// itself the error a peek-based loop would silently swallow.
func (p *binxmlParser) parseAttribute() (attr *Attr, more bool, err error) {
	if p.pos >= len(p.buf) {
		return nil, false, fmt.Errorf("go_evtx: attribute expected at body offset %d, buffer exhausted", p.pos)
	}
	tok := p.buf[p.pos]
	if tok != tokAttribute && tok != tokAttributeMore {
		return nil, false, fmt.Errorf(
			"go_evtx: expected an attribute token (%#02x or %#02x) at body offset %d, found %#02x",
			tokAttribute, tokAttributeMore, p.pos, tok)
	}
	start := p.pos
	if p.pos+5 > len(p.buf) {
		return nil, false, fmt.Errorf("go_evtx: attribute header truncated at body offset %d", p.pos)
	}
	nameOffset := int(le32(p.buf[p.pos+1:]))
	p.pos += 5
	name, err := p.readName(nameOffset, start+5)
	if err != nil {
		return nil, false, err
	}
	if p.pos >= len(p.buf) {
		return nil, false, fmt.Errorf("go_evtx: attribute %q has no value", name)
	}
	var v *Value
	switch p.buf[p.pos] {
	case tokNormalSub, tokOptionalSub:
		v, err = p.parseSubstitutionRef()
	case tokValue, tokValueMore:
		v, err = p.parseLiteralValue()
	default:
		return nil, false, fmt.Errorf("go_evtx: attribute %q: unexpected value token %#02x", name, p.buf[p.pos])
	}
	if err != nil {
		return nil, false, err
	}
	more = tok == tokAttributeMore
	p.emit(shapeEvent{
		Kind:    shapeKindAttribute,
		Token:   tok,
		AttrPos: attrPosition(p.attrIndex, more),
		Actual:  v.Type,
	})
	return &Attr{Name: name, Value: *v}, more, nil
}

// parseSubstitutionRef reads token(1) index(2) type(1) and resolves it.
func (p *binxmlParser) parseSubstitutionRef() (*Value, error) {
	if p.pos+4 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: substitution token truncated at body offset %d", p.pos)
	}
	tok := p.buf[p.pos]
	idx := int(le16(p.buf[p.pos+1:]))
	// declared is the type the template's substitution token states. It does
	// not drive the decode: where it disagrees with the type the substitution
	// array declares, the ARRAY governs, because the array
	// describes the bytes that are actually present and those are the bytes
	// being decoded.
	//
	// Documented, not guessed. libyal's EVTX specification says of both the
	// normal and the optional substitution token: "If the value type is Size
	// (0x10) the corresponding substitution value should be a 32-bit
	// hexadecimal integer (0x14) or 64-bit hexadecimal integer (0x15)."
	// SizeT is a pointer width, and which one the emitting process used is
	// exactly what the array is there to say. That covers 61 674 of the
	// 62 089 disagreements measured across the derivation corpus — and they
	// are not defects, they are the format working as specified.
	//
	// The remaining 415 declare UInt8 against an array of UInt16. No source
	// documents that pairing; it is measured only. The general rule covers it
	// for the same reason: a 2-byte value read as a 1-byte type is wrong
	// whichever declaration one prefers.
	//
	// It is still read, because the disagreement itself is a shape worth
	// censusing.
	declared := ValueType(p.buf[p.pos+3])
	p.pos += 4
	if idx >= len(p.subs) {
		return nil, fmt.Errorf("go_evtx: substitution index %d out of range: the array declares %d entries",
			idx, len(p.subs))
	}
	v := p.subs[idx]
	p.emit(shapeEvent{
		Kind:     shapeKindSubstitution,
		Token:    tok,
		Declared: declared,
		Actual:   v.Type,
	})
	return &v, nil
}

// parseLiteralValue reads token(1) type(1) then a type-specific payload. Only
// StringType has a literal form in this format.
func (p *binxmlParser) parseLiteralValue() (*Value, error) {
	if p.pos+2 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: value token truncated at body offset %d", p.pos)
	}
	tokenPos := p.pos
	typ := ValueType(p.buf[p.pos+1])
	if typ != ValString {
		return nil, fmt.Errorf(
			"go_evtx: literal value of type %s at body offset %d: only StringType has a literal form",
			typ, p.pos)
	}
	if p.pos+4 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: value length truncated at body offset %d", p.pos)
	}
	units := int(le16(p.buf[p.pos+2:]))
	start := p.pos + 4
	end := start + units*2
	if end > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: literal string of %d units at body offset %d runs past the body",
			units, p.pos)
	}
	p.pos = end
	v, err := decodeValue(ValString, p.buf[start:end])
	if err != nil {
		return nil, err
	}
	p.emit(shapeEvent{
		Kind:     shapeKindLiteral,
		Token:    p.buf[tokenPos],
		Declared: typ,
		Actual:   v.Type,
	})
	return &v, nil
}

// readName resolves a NameNode and verifies its stored hash against
// sdbmHash(name) (chunkhash.go — measured 386/386 against real files). The
// offset is chunk-relative; when it names the position immediately after the
// current token header the node is inline and the cursor advances past it.
//
// NameNode: next_offset(4) hash(2) length(2) UTF-16 × length, null(2)
func (p *binxmlParser) readName(nameOffset, inlineAt int) (string, error) {
	if nameOffset == p.base+inlineAt {
		name, hash, size, err := readNameAt(p.buf, inlineAt)
		if err != nil {
			return "", err
		}
		if err := verifyNameHash(name, hash); err != nil {
			return "", err
		}
		p.pos = inlineAt + size
		return name, nil
	}
	// Shared NameNode elsewhere in the current buffer.
	if rel := nameOffset - p.base; rel >= 0 && rel < len(p.buf) {
		name, hash, _, err := readNameAt(p.buf, rel)
		if err != nil {
			return "", err
		}
		return name, verifyNameHash(name, hash)
	}
	// Shared NameNode elsewhere in the chunk.
	if nameOffset < 0 || nameOffset >= len(p.chunk) {
		return "", fmt.Errorf("go_evtx: name offset %d outside the chunk", nameOffset)
	}
	name, hash, _, err := readNameAt(p.chunk, nameOffset)
	if err != nil {
		return "", err
	}
	return name, verifyNameHash(name, hash)
}

// verifyNameHash reports a mismatch between a NameNode's stored hash and
// sdbmHash(name) — the signature of a name_offset that landed mid-structure
// and decoded a plausible-looking but wrong string.
func verifyNameHash(name string, stored uint16) error {
	if got := uint16(sdbmHash(name)); got != stored {
		return fmt.Errorf("go_evtx: name %q hashes to %#04x, NameNode declares %#04x", name, got, stored)
	}
	return nil
}

// readNameAt decodes a NameNode at off, returning the name, its stored hash,
// and its total size.
func readNameAt(b []byte, off int) (name string, hash uint16, size int, err error) {
	if off < 0 || off+8 > len(b) {
		return "", 0, 0, fmt.Errorf("go_evtx: name node at %d is truncated", off)
	}
	hash = le16(b[off+4:])
	units := int(le16(b[off+6:]))
	start := off + 8
	end := start + units*2
	if end+2 > len(b) {
		return "", 0, 0, fmt.Errorf("go_evtx: name node at %d declares %d units, past the buffer", off, units)
	}
	u16 := make([]uint16, units)
	for i := range u16 {
		u16[i] = le16(b[start+i*2:])
	}
	return string(utf16.Decode(u16)), hash, 8 + units*2 + 2, nil
}
