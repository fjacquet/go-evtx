// binxml_decode.go — generic BinXML token stream decoder.
//
// Replaces the template-specific reader this package shipped through v0.6.0,
// which assumed go-evtx's own 42-slot template and therefore produced
// confident nonsense on any real Windows file.
//
// Strictness is the point. Three rules, all enforced here:
//  1. an unrecognised token or value type, or a length past the payload, is
//     an error;
//  2. the decode accounts for every byte — stopping early or running past the
//     fragment's EOF is an error even when a plausible tree was built;
//  3. the substitutions consumed must equal the count the array declares.
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

// parseSubstitutions reads a substitution array:
//
//	[count u32][count × (size u16, type u8, pad u8)][values...]
//
// It returns the decoded values and the total bytes consumed, so a caller can
// verify the payload was fully accounted for.
func parseSubstitutions(data []byte) ([]Value, int, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("go_evtx: substitution array truncated: %d bytes, need at least 4", len(data))
	}
	count64 := uint64(binary.LittleEndian.Uint32(data[0:4]))
	// Each entry needs a 4-byte descriptor; anything larger cannot fit and is
	// a misparse rather than a real array.
	if count64 > uint64((len(data)-4)/4) {
		return nil, 0, fmt.Errorf("go_evtx: substitution count %d cannot fit in %d bytes", count64, len(data))
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
	vals := make([]Value, count)
	for i := 0; i < count; i++ {
		end := pos + sizes[i]
		if end > len(data) {
			return nil, 0, fmt.Errorf(
				"go_evtx: substitution %d (%s) declares %d bytes at offset %d, past the %d-byte array",
				i, types[i], sizes[i], pos, len(data))
		}
		v, err := decodeValue(types[i], data[pos:end])
		if err != nil {
			return nil, 0, fmt.Errorf("go_evtx: substitution %d: %w", i, err)
		}
		vals[i] = v
		pos = end
	}
	return vals, pos, nil
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
type Node struct {
	Name       string `json:"name"`
	Attributes []Attr `json:"attributes,omitempty"`
	Children   []Node `json:"children,omitempty"`
	Value      *Value `json:"value,omitempty"`
}

// binxmlParser walks one template body, resolving substitutions against subs.
type binxmlParser struct {
	chunk []byte  // the whole chunk: name and template offsets are chunk-relative
	buf   []byte  // the body being walked
	base  int     // chunk-relative offset of buf[0]
	pos   int     // cursor within buf
	subs  []Value // substitution values for this record
	cache *templateCache
}

// decodeRecordBinXML decodes one record payload into an element tree.
//
// payloadChunkOffset is the chunk-relative offset of payload[0]; template and
// name offsets in the stream are chunk-relative, so resolving them needs it.
// cache must have been constructed over the same chunk (newTemplateCache(chunk)) —
// its own chunk-ownership invariant is what this call relies on.
func decodeRecordBinXML(chunk, payload []byte, payloadChunkOffset int, cache *templateCache) (*Node, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("go_evtx: payload is %d bytes, too short for a fragment header", len(payload))
	}
	if payload[0] != tokFragmentHeader {
		return nil, fmt.Errorf("go_evtx: payload starts with %#02x, want the fragment header token %#02x",
			payload[0], tokFragmentHeader)
	}
	pos := 4

	if pos >= len(payload) || payload[pos] != tokTemplateInstance {
		return nil, fmt.Errorf("go_evtx: expected a template instance at offset %d", pos)
	}
	if pos+10 > len(payload) {
		return nil, fmt.Errorf("go_evtx: template instance truncated at offset %d", pos)
	}
	defOffset := int(le32(payload[pos+6:]))
	pos += 10

	// The definition is inline when its offset names this very position;
	// otherwise it lives elsewhere in the chunk and is shared.
	if defOffset == payloadChunkOffset+pos {
		def, err := parseTemplateDef(chunk, defOffset)
		if err != nil {
			return nil, err
		}
		cache.defs[defOffset] = def
		pos += templateDefHeaderSize + len(def.Body)
	}
	def, err := cache.get(defOffset)
	if err != nil {
		return nil, err
	}

	subs, consumed, err := parseSubstitutions(payload[pos:])
	if err != nil {
		return nil, err
	}
	// Rule 2: account for every byte. Trailing bytes mean we misread something.
	if pos+consumed != len(payload) {
		return nil, fmt.Errorf(
			"go_evtx: decode consumed %d of %d payload bytes; %d unaccounted for",
			pos+consumed, len(payload), len(payload)-(pos+consumed))
	}

	// A BinXml-typed substitution is a nested fragment. It occurs in every real
	// record, so this is the nominal path, not an edge case.
	for i := range subs {
		if subs[i].Type == ValBinXML && !subs[i].IsAbsent() {
			p := &binxmlParser{chunk: chunk, buf: subs[i].raw, base: 0, subs: nil, cache: cache}
			node, err := p.parseFragment()
			if err != nil {
				return nil, fmt.Errorf("go_evtx: nested BinXml in substitution %d: %w", i, err)
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

// parseFragment reads a fragment header then exactly one root element.
func (p *binxmlParser) parseFragment() (*Node, error) {
	if p.pos+4 > len(p.buf) || p.buf[p.pos] != tokFragmentHeader {
		return nil, fmt.Errorf("go_evtx: expected a fragment header at body offset %d", p.pos)
	}
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

// parseElement reads one OpenStartElement through its matching EndElement.
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
	nameOffset := int(le32(p.buf[p.pos+7:]))
	p.pos += 11

	name, err := p.readName(nameOffset, start+11)
	if err != nil {
		return nil, err
	}
	node := &Node{Name: name}

	if tok == tokOpenElementAttrs {
		if p.pos+4 > len(p.buf) {
			return nil, fmt.Errorf("go_evtx: attribute list size truncated at body offset %d", p.pos)
		}
		p.pos += 4 // attr_list_size; the attribute tokens that follow are self-delimiting
		for {
			if p.pos >= len(p.buf) {
				return nil, fmt.Errorf("go_evtx: attribute list ran off the end of the body")
			}
			at := p.buf[p.pos]
			if at != tokAttribute && at != tokAttributeMore {
				break
			}
			attr, err := p.parseAttribute()
			if err != nil {
				return nil, err
			}
			node.Attributes = append(node.Attributes, *attr)
		}
	}

	if p.pos >= len(p.buf) {
		return nil, fmt.Errorf("go_evtx: element %q has no close-start token", name)
	}
	switch p.buf[p.pos] {
	case tokCloseEmptyElement:
		p.pos++
		return node, nil
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
		switch t := p.buf[p.pos]; t {
		case tokEndElement:
			p.pos++
			return node, nil
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
			node.Value = v
		case tokValue, tokValueMore:
			v, err := p.parseLiteralValue()
			if err != nil {
				return nil, err
			}
			node.Value = v
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

// parseAttribute reads one attribute token: token(1) name_offset(4) [NameNode]
// followed by exactly one value token.
func (p *binxmlParser) parseAttribute() (*Attr, error) {
	start := p.pos
	if p.pos+5 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: attribute header truncated at body offset %d", p.pos)
	}
	nameOffset := int(le32(p.buf[p.pos+1:]))
	p.pos += 5
	name, err := p.readName(nameOffset, start+5)
	if err != nil {
		return nil, err
	}
	if p.pos >= len(p.buf) {
		return nil, fmt.Errorf("go_evtx: attribute %q has no value", name)
	}
	var v *Value
	switch p.buf[p.pos] {
	case tokNormalSub, tokOptionalSub:
		v, err = p.parseSubstitutionRef()
	case tokValue, tokValueMore:
		v, err = p.parseLiteralValue()
	default:
		return nil, fmt.Errorf("go_evtx: attribute %q: unexpected value token %#02x", name, p.buf[p.pos])
	}
	if err != nil {
		return nil, err
	}
	return &Attr{Name: name, Value: *v}, nil
}

// parseSubstitutionRef reads token(1) index(2) type(1) and resolves it.
func (p *binxmlParser) parseSubstitutionRef() (*Value, error) {
	if p.pos+4 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: substitution token truncated at body offset %d", p.pos)
	}
	idx := int(le16(p.buf[p.pos+1:]))
	declared := ValueType(p.buf[p.pos+3])
	p.pos += 4
	if idx >= len(p.subs) {
		return nil, fmt.Errorf("go_evtx: substitution index %d out of range: the array declares %d entries",
			idx, len(p.subs))
	}
	v := p.subs[idx]
	// The template's declared type and the array's are expected to agree; a
	// disagreement is exactly the class of defect this decoder exists to
	// surface, so it is reported rather than silently preferred one way.
	if !v.IsAbsent() && v.Type != declared {
		return nil, fmt.Errorf(
			"go_evtx: substitution %d: template declares %s, substitution array declares %s",
			idx, declared, v.Type)
	}
	return &v, nil
}

// parseLiteralValue reads token(1) type(1) then a type-specific payload. Only
// StringType has a literal form in this format.
func (p *binxmlParser) parseLiteralValue() (*Value, error) {
	if p.pos+2 > len(p.buf) {
		return nil, fmt.Errorf("go_evtx: value token truncated at body offset %d", p.pos)
	}
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
	return &v, nil
}

// readName resolves a NameNode. The offset is chunk-relative; when it names
// the position immediately after the current token header the node is inline
// and the cursor advances past it.
//
// NameNode: next_offset(4) hash(2) length(2) UTF-16 × length, null(2)
func (p *binxmlParser) readName(nameOffset, inlineAt int) (string, error) {
	if p.base != 0 && nameOffset == p.base+inlineAt {
		name, size, err := readNameAt(p.buf, inlineAt)
		if err != nil {
			return "", err
		}
		p.pos = inlineAt + size
		return name, nil
	}
	// Shared NameNode elsewhere in the chunk.
	rel := nameOffset - p.base
	if p.base != 0 && rel >= 0 && rel < len(p.buf) {
		name, _, err := readNameAt(p.buf, rel)
		return name, err
	}
	if nameOffset < 0 || nameOffset >= len(p.chunk) {
		return "", fmt.Errorf("go_evtx: name offset %d outside the chunk", nameOffset)
	}
	name, _, err := readNameAt(p.chunk, nameOffset)
	return name, err
}

// readNameAt decodes a NameNode at off, returning the name and its total size.
func readNameAt(b []byte, off int) (string, int, error) {
	if off < 0 || off+8 > len(b) {
		return "", 0, fmt.Errorf("go_evtx: name node at %d is truncated", off)
	}
	units := int(le16(b[off+6:]))
	start := off + 8
	end := start + units*2
	if end+2 > len(b) {
		return "", 0, fmt.Errorf("go_evtx: name node at %d declares %d units, past the buffer", off, units)
	}
	u16 := make([]uint16, units)
	for i := range u16 {
		u16[i] = le16(b[start+i*2:])
	}
	return string(utf16.Decode(u16)), 8 + units*2 + 2, nil
}
