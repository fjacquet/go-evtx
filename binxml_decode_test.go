package evtx

import (
	"strings"
	"testing"
)

func TestParseSubstitutions(t *testing.T) {
	// count=2; [size 4, UInt32], [size 0, UInt16 (absent)]; then 4 bytes of data.
	data := []byte{
		0x02, 0, 0, 0,
		0x04, 0x00, byte(ValUInt32), 0x00,
		0x00, 0x00, byte(ValUInt16), 0x00,
		0x2a, 0x00, 0x00, 0x00,
	}
	vals, offsets, n, err := parseSubstitutions(data)
	if err != nil {
		t.Fatalf("parseSubstitutions: %v", err)
	}
	if n != len(data) {
		t.Errorf("consumed %d bytes, want %d", n, len(data))
	}
	if len(vals) != 2 {
		t.Fatalf("got %d values, want 2", len(vals))
	}
	if got, _ := vals[0].Uint64(); got != 42 {
		t.Errorf("vals[0] = %d, want 42", got)
	}
	if !vals[1].IsAbsent() {
		t.Error("vals[1] should be absent (declared size 0)")
	}
	if vals[1].Type != ValUInt16 {
		t.Errorf("vals[1].Type = %s, want UInt16 — the declared type must survive", vals[1].Type)
	}
	// The descriptor array is 4 (count) + 2*4 (two descriptors) = 12 bytes;
	// vals[0]'s 4-byte payload starts there, vals[1]'s starts right after it
	// (it declares zero bytes, so both share that offset).
	if offsets[0] != 12 {
		t.Errorf("offsets[0] = %d, want 12", offsets[0])
	}
	if offsets[1] != 16 {
		t.Errorf("offsets[1] = %d, want 16", offsets[1])
	}
}

func TestParseSubstitutions_TruncatedIsError(t *testing.T) {
	// Declares one 8-byte value but supplies only 2 bytes of data.
	data := []byte{
		0x01, 0, 0, 0,
		0x08, 0x00, byte(ValUInt64), 0x00,
		0x01, 0x02,
	}
	if _, _, _, err := parseSubstitutions(data); err == nil {
		t.Fatal("expected an error for a truncated value blob")
	}
}

func TestParseSubstitutions_AbsurdCountIsError(t *testing.T) {
	data := []byte{0xff, 0xff, 0xff, 0xff}
	if _, _, _, err := parseSubstitutions(data); err == nil {
		t.Fatal("expected an error for a count that cannot fit in the payload")
	}
}

// testNameNode builds a NameNode's bytes for name, including the real
// sdbmHash — every hand-built fixture in this file needs this for its
// NameNodes to pass the decoder's stored-hash cross-check (I4).
func testNameNode(name string) []byte {
	u := []rune(name)
	h := uint16(sdbmHash(name))
	// next_offset(4, unused by these fixtures) + hash(2) + length(2).
	b := []byte{0, 0, 0, 0, byte(h), byte(h >> 8), byte(len(u)), 0}
	for _, r := range u {
		b = append(b, byte(r), 0)
	}
	return append(b, 0, 0)
}

// buildSimpleRecord lays out one real-format record payload inside a chunk
// buffer: fragment header, template instance with an inline definition whose
// body is <Event><EventID>{sub 0}</EventID></Event>, a one-entry
// substitution array holding UInt16 4624, the fragment's EOF token, and 4
// bytes of padding — chosen so (28 + len(payload)) % 8 == 0, matching every
// real record's own on-disk alignment (24-byte header + payload + 4-byte
// size copy; see decodeBinXMLFragment's rem check). Padding content is
// deliberately non-zero: measured real records never zero it either.
func buildSimpleRecord(t *testing.T) (chunk []byte, payload []byte, payloadOff int) {
	t.Helper()
	chunk = make([]byte, evtxChunkSize)
	copy(chunk[0:8], evtxChunkMagic)
	payloadOff = 512

	// element builds an OpenStartElement with an inline NameNode at the fixed
	// 11-byte header offset the encoder uses.
	element := func(name string, base int, inner []byte) []byte {
		nn := testNameNode(name)
		b := []byte{tokOpenElement, 0xff, 0xff, 0, 0, 0, 0}
		b = append(b, 0, 0, 0, 0) // name_offset, patched below
		le32put(b[7:], uint32(base+11))
		b = append(b, nn...)
		b = append(b, tokCloseStartElement)
		b = append(b, inner...)
		b = append(b, tokEndElement)
		le32put(b[3:], uint32(len(b)-7)) // data_size: bytes after data_size
		return b
	}

	defOff := payloadOff + 4 + 10
	bodyBase := defOff + 24
	inner := []byte{tokNormalSub, 0x00, 0x00, byte(ValUInt16)}
	eventID := element("EventID", bodyBase+4+11+len(testNameNode("Event"))+1, inner)
	body := []byte{tokFragmentHeader, 0x01, 0x01, 0x00}
	body = append(body, element("Event", bodyBase+4, eventID)...)
	body = append(body, tokEOF)

	p := []byte{tokFragmentHeader, 0x01, 0x01, 0x00,
		tokTemplateInstance, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	le32put(p[10:], uint32(defOff))
	def := make([]byte, 24)
	le32put(def[20:], uint32(len(body)))
	p = append(p, def...)
	p = append(p, body...)
	p = append(p, 0x01, 0, 0, 0, 0x02, 0x00, byte(ValUInt16), 0x00, 0x10, 0x12)
	p = append(p, tokEOF)                 // fragment EOF: C4's mandatory 1 byte
	p = append(p, 0xaa, 0xbb, 0xcc, 0xdd) // 4 bytes of (non-zero) alignment padding
	if (28+len(p))%8 != 0 {
		t.Fatalf("test bug: (28+%d) %% 8 = %d, want 0", len(p), (28+len(p))%8)
	}

	copy(chunk[payloadOff:], p)
	return chunk, chunk[payloadOff : payloadOff+len(p)], payloadOff
}

func le32put(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

// buildRecordWithBinXMLSub is buildSimpleRecord's shape simplified to one
// element, <Event>{sub 0}</Event>, whose substitution is BinXml-typed with
// value bytes subValue — so a test can control exactly what
// decodeBinXMLFragment recurses into for C1's nested path.
func buildRecordWithBinXMLSub(t *testing.T, subValue []byte) (chunk []byte, payload []byte, payloadOff int) {
	t.Helper()
	chunk = make([]byte, evtxChunkSize)
	copy(chunk[0:8], evtxChunkMagic)
	payloadOff = 512

	element := func(name string, base int, inner []byte) []byte {
		nn := testNameNode(name)
		b := []byte{tokOpenElement, 0xff, 0xff, 0, 0, 0, 0}
		b = append(b, 0, 0, 0, 0)
		le32put(b[7:], uint32(base+11))
		b = append(b, nn...)
		b = append(b, tokCloseStartElement)
		b = append(b, inner...)
		b = append(b, tokEndElement)
		le32put(b[3:], uint32(len(b)-7))
		return b
	}

	defOff := payloadOff + 4 + 10
	bodyBase := defOff + 24
	inner := []byte{tokNormalSub, 0x00, 0x00, byte(ValBinXML)}
	body := []byte{tokFragmentHeader, 0x01, 0x01, 0x00}
	body = append(body, element("Event", bodyBase+4, inner)...)
	body = append(body, tokEOF)

	p := []byte{tokFragmentHeader, 0x01, 0x01, 0x00,
		tokTemplateInstance, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	le32put(p[10:], uint32(defOff))
	def := make([]byte, 24)
	le32put(def[20:], uint32(len(body)))
	p = append(p, def...)
	p = append(p, body...)
	// Substitution array: count=1, one descriptor (size, type, pad), then the
	// value bytes verbatim.
	p = append(p, 0x01, 0, 0, 0)
	p = append(p, byte(len(subValue)), byte(len(subValue)>>8), byte(ValBinXML), 0x00)
	p = append(p, subValue...)
	p = append(p, tokEOF)
	for (28+len(p))%8 != 0 {
		p = append(p, 0xee)
	}
	if (28+len(p))%8 != 0 {
		t.Fatalf("test bug: (28+%d) %% 8 = %d, want 0", len(p), (28+len(p))%8)
	}

	copy(chunk[payloadOff:], p)
	return chunk, chunk[payloadOff : payloadOff+len(p)], payloadOff
}

// TestDecodeRecordBinXML_NestedBareFragmentHeaderIsError is the nested
// variant of the round-2 regression above: a BinXml-typed substitution whose
// value is exactly a 4-byte fragment header and nothing else. This is what
// makes the round-1 panic attacker-reachable rather than merely a top-level
// truncation concern — the nested fragment's length is controlled entirely
// by the substitution array's own declared size, corruptible independently
// of the outer record's own length.
func TestDecodeRecordBinXML_NestedBareFragmentHeaderIsError(t *testing.T) {
	chunk, payload, off := buildRecordWithBinXMLSub(t, []byte{tokFragmentHeader, 0x01, 0x01, 0x00})
	cache := newTemplateCache(chunk)
	if _, err := decodeRecordBinXML(cache, off, len(payload)); err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestDecodeRecordBinXML_ResolvesSubstitution(t *testing.T) {
	chunk, payload, off := buildSimpleRecord(t)
	cache := newTemplateCache(chunk)
	root, err := decodeRecordBinXML(cache, off, len(payload))
	if err != nil {
		t.Fatalf("decodeRecordBinXML: %v", err)
	}
	if root.Name != "Event" {
		t.Fatalf("root.Name = %q, want %q", root.Name, "Event")
	}
	if root.DependencyID != depIDNotSet {
		t.Errorf("root.DependencyID = %#04x, want the not-set sentinel %#04x (I7)", root.DependencyID, depIDNotSet)
	}
	if len(root.Children) != 1 {
		t.Fatalf("root has %d children, want 1", len(root.Children))
	}
	child := root.Children[0]
	if child.Name != "EventID" {
		t.Errorf("child.Name = %q, want %q", child.Name, "EventID")
	}
	if child.Value == nil {
		t.Fatal("child.Value is nil; the substitution was not applied")
	}
	if got, _ := child.Value.Uint64(); got != 4624 {
		t.Errorf("EventID = %d, want 4624", got)
	}
}

// TestDecodeRecordBinXML_NegativeCases is a table-driven suite of payload
// corruptions, each expected to produce an error rather than a panic or a
// silently-wrong tree. mutate receives a copy of buildSimpleRecord's own
// valid payload and corrupts it in place; it may also return a different
// length (for truncation/extension cases).
func TestDecodeRecordBinXML_NegativeCases(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, payload []byte) []byte
	}{
		{
			name: "empty payload",
			mutate: func(t *testing.T, payload []byte) []byte {
				return nil
			},
		},
		{
			name: "first byte is neither fragment header nor template instance",
			mutate: func(t *testing.T, payload []byte) []byte {
				payload[0] = 0x7f
				return payload
			},
		},
		{
			name: "unrecognised token inside the template body's element tree",
			mutate: func(t *testing.T, payload []byte) []byte {
				// The EventID element's content is a NormalSubstitution token
				// (0x0d) at payload offset 110 — see the offset trace in this
				// test file's history; corrupting it must reach parseElement's
				// own unrecognised-token branch, not an earlier structural check.
				if payload[110] != tokNormalSub {
					t.Fatalf("test bug: payload[110] = %#02x, want tokNormalSub %#02x — fixture layout changed",
						payload[110], tokNormalSub)
				}
				payload[110] = 0x7f
				return payload
			},
		},
		// A top-level payload ending exactly at the substitution array used to
		// be tested here as an error. It is now accepted: go-evtx's own writer
		// produces exactly that shape, and making the writer conformant was
		// implemented and then reverted because it regressed Windows' own
		// EventLogReader from 403 records to failing on record 0. See the
		// tolerance comment in decodeBinXMLFragment, and #38/#39. The rem < 1
		// rejection still applies to every nested fragment, which the
		// "nested fragment with trailing bytes" case below covers.
		{
			name: "EOF token present but wrong value",
			mutate: func(t *testing.T, payload []byte) []byte {
				eofPos := len(payload) - 5 // buildSimpleRecord appends [EOF][4 bytes padding]
				if payload[eofPos] != tokEOF {
					t.Fatalf("test bug: payload[%d] = %#02x, want tokEOF", eofPos, payload[eofPos])
				}
				payload[eofPos] = 0x01
				return payload
			},
		},
		{
			name: "padding is 8 bytes: past the 0-7 byte allowance",
			mutate: func(t *testing.T, payload []byte) []byte {
				return append(payload, 0, 0, 0, 0) // 4 + 4 = 8 padding bytes
			},
		},
		{
			name: "padding present but total record size does not 8-align",
			mutate: func(t *testing.T, payload []byte) []byte {
				return append(payload, 0) // 4 + 1 = 5 padding bytes; rem-1=5<=7 but misaligned
			},
		},
		{
			name: "template instance def_offset points outside the chunk",
			mutate: func(t *testing.T, payload []byte) []byte {
				le32put(payload[10:], 0xffffffff)
				return payload
			},
		},
		{
			// Fix round 2, regression for the panic the round-1 re-review found:
			// a fragment that is exactly a 4-byte fragment header and nothing
			// else. decodeBinXMLFragment advances pos to 4 after reading the
			// header, finds pos >= len(payload), and must report that as an
			// error rather than index payload[pos] to build the error message.
			// This table only threads mutate's returned LENGTH through to
			// decodeRecordBinXML (see the loop below) — every other chunk byte
			// stays whatever buildSimpleRecord wrote — so truncate via a real
			// subslice of payload, not a fresh literal, to actually land on
			// buildSimpleRecord's own fragment-header bytes rather than
			// coincidentally matching them.
			name: "bare 4-byte fragment header with nothing after it",
			mutate: func(t *testing.T, payload []byte) []byte {
				if payload[0] != tokFragmentHeader {
					t.Fatalf("test bug: payload[0] = %#02x, want tokFragmentHeader %#02x", payload[0], tokFragmentHeader)
				}
				return payload[:4]
			},
		},
		{
			name: "NameNode hash corrupted",
			mutate: func(t *testing.T, payload []byte) []byte {
				// The Event element's inline NameNode starts at payload offset
				// 38 (bodyBase(550) + 4 - payloadOff(512), see buildSimpleRecord);
				// its hash field is 2 bytes at +4.
				hashPos := 38 + 4
				payload[hashPos] ^= 0xff
				return payload
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chunk, payload, off := buildSimpleRecord(t)
			mutated := tc.mutate(t, payload)
			cache := newTemplateCache(chunk)
			// Only mutated's length is threaded through here; decodeRecordBinXML
			// reads bytes from cache.chunk[off:off+len(mutated)], not from
			// mutated itself. Every mutate above therefore corrupts payload (or a
			// subslice/append of it) in place — payload aliases chunk — rather
			// than returning an unrelated byte slice, so the corruption actually
			// lands in the bytes this call reads.
			if _, err := decodeRecordBinXML(cache, off, len(mutated)); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// elemBuilder assembles one element's byte span (OpenStartElement through its
// terminator) with correctly self-computed name_offset, attr_list_size and
// data_size — the same relationships binxml.go's own writer maintains — so a
// unit test can deliberately break exactly one field and know every other
// field in the fixture is correct. base is always 0 in these tests: buf
// stands in for a chunk of its own, addressed from position 0.
type elemBuilder struct{ buf []byte }

func (e *elemBuilder) len() int      { return len(e.buf) }
func (e *elemBuilder) bytes() []byte { return e.buf }

// open writes an OpenStartElementTag (dep_id = the not-set sentinel) with an
// inline NameNode and, when hasAttrs, an attr_list_size placeholder.
func (e *elemBuilder) open(name string, hasAttrs bool) (start, dataSizePos, attrListPos int) {
	start = e.len()
	tok := byte(tokOpenElement)
	if hasAttrs {
		tok = tokOpenElementAttrs
	}
	e.buf = append(e.buf, tok, 0xff, 0xff, 0, 0, 0, 0) // tok(1) dep_id(2) data_size(4)
	dataSizePos = start + 3
	e.buf = append(e.buf, 0, 0, 0, 0) // name_offset placeholder
	le32put(e.buf[start+7:], uint32(e.len()))
	e.buf = append(e.buf, testNameNode(name)...)
	attrListPos = -1
	if hasAttrs {
		attrListPos = e.len()
		e.buf = append(e.buf, 0, 0, 0, 0) // attr_list_size placeholder
	}
	return
}

// attr appends one attribute: tokAttribute (more==false) or tokAttributeMore
// (more==true), an inline NameNode, then value verbatim.
func (e *elemBuilder) attr(more bool, name string, value []byte) {
	tok := byte(tokAttribute)
	if more {
		tok = tokAttributeMore
	}
	start := e.len()
	e.buf = append(e.buf, tok, 0, 0, 0, 0) // tok(1) name_offset(4)
	le32put(e.buf[start+1:], uint32(e.len()))
	e.buf = append(e.buf, testNameNode(name)...)
	e.buf = append(e.buf, value...)
}

// closeAttrs back-patches attr_list_size from attrListPos (open's return) and
// writes CloseStartElementTag.
func (e *elemBuilder) closeAttrs(attrListPos int) {
	le32put(e.buf[attrListPos:], uint32(e.len()-(attrListPos+4)))
	e.buf = append(e.buf, tokCloseStartElement)
}

// closeNoAttrs writes CloseStartElementTag for an element with no attr region.
func (e *elemBuilder) closeNoAttrs() { e.buf = append(e.buf, tokCloseStartElement) }

// raw appends content bytes verbatim (value tokens, nested elements built on
// the same builder, ...).
func (e *elemBuilder) raw(b []byte) { e.buf = append(e.buf, b...) }

// end writes EndElementTag and back-patches data_size from start/dataSizePos
// (open's return).
func (e *elemBuilder) end(start, dataSizePos int) {
	e.buf = append(e.buf, tokEndElement)
	le32put(e.buf[dataSizePos:], uint32(e.len()-(start+7)))
}

func mustUInt16(t *testing.T, n uint16) Value {
	t.Helper()
	v, err := decodeValue(ValUInt16, []byte{byte(n), byte(n >> 8)})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestParseElement_AttributeList covers I2 (attr_list_size is cross-checked,
// not just skipped past) and I3 (the 0x06/0x46 "more attributes follow"
// contract is enforced by driving the loop from the token actually parsed,
// not by peeking at the next byte and silently stopping).
func TestParseElement_AttributeList(t *testing.T) {
	subs := []Value{mustUInt16(t, 7)}
	subRef := []byte{tokNormalSub, 0x00, 0x00, byte(ValUInt16)}
	build := func() []byte {
		var e elemBuilder
		start, dataSizePos, attrListPos := e.open("X", true)
		e.attr(false, "A", subRef) // the list's only attribute, correctly marked "last"
		e.closeAttrs(attrListPos)
		e.end(start, dataSizePos)
		return e.bytes()
	}

	t.Run("valid one-attribute element decodes cleanly", func(t *testing.T) {
		buf := build()
		p := &binxmlParser{chunk: buf, buf: buf, subs: subs}
		node, err := p.parseElement()
		if err != nil {
			t.Fatalf("parseElement: %v", err)
		}
		if len(node.Attributes) != 1 || node.Attributes[0].Name != "A" {
			t.Fatalf("got %+v, want exactly one attribute named A", node.Attributes)
		}
	})

	t.Run("I3: 0x46 more-follows not actually followed by another attribute is an error", func(t *testing.T) {
		buf := build()
		// The lone attribute's own token sits right after the 11-byte header,
		// the NameNode("X") and the 4-byte attr_list_size field.
		tokPos := 11 + len(testNameNode("X")) + 4
		if buf[tokPos] != tokAttribute {
			t.Fatalf("test bug: buf[%d] = %#02x, want tokAttribute %#02x", tokPos, buf[tokPos], tokAttribute)
		}
		buf[tokPos] = tokAttributeMore // falsely claims another attribute follows
		p := &binxmlParser{chunk: buf, buf: buf, subs: subs}
		if _, err := p.parseElement(); err == nil {
			t.Fatal("expected an error: 0x46 promised another attribute that never came")
		}
	})

	t.Run("I2: corrupted attr_list_size is an error", func(t *testing.T) {
		buf := build()
		attrListPos := 11 + len(testNameNode("X"))
		le32put(buf[attrListPos:], le32(buf[attrListPos:])+1) // one byte off from the real span
		p := &binxmlParser{chunk: buf, buf: buf, subs: subs}
		if _, err := p.parseElement(); err == nil {
			t.Fatal("expected an attr_list_size mismatch error")
		}
	})
}

// TestParseElement_ValueDedup covers I5. Two value tokens on the same
// element must error rather than silently keep only the last one written —
// that combination is never measured to occur. A value token alongside child
// elements, in either order, must NOT error: this was tried first (erroring
// on both shapes) and broke on real data immediately — testdata/system.evtx
// and every other real fixture checked route a record's conditional
// EventData/UserData subtree as exactly this shape, a bare (often
// BinXml-typed) substitution reference sitting among <Event>'s children
// alongside the always-present <System> element, wrapped in no element of
// its own. Rejecting it made all but a handful of 1 601 real records fail.
func TestParseElement_ValueDedup(t *testing.T) {
	subs := []Value{mustUInt16(t, 7)}
	subRef := []byte{tokNormalSub, 0x00, 0x00, byte(ValUInt16)}

	t.Run("two value tokens in a row is an error", func(t *testing.T) {
		var e elemBuilder
		start, dataSizePos, _ := e.open("Y", false)
		e.closeNoAttrs()
		e.raw(subRef)
		e.raw(subRef)
		e.end(start, dataSizePos)
		buf := e.bytes()

		p := &binxmlParser{chunk: buf, buf: buf, subs: subs}
		if _, err := p.parseElement(); err == nil {
			t.Fatal("expected an error: element has two value tokens")
		} else if !strings.Contains(err.Error(), "already has a value") {
			t.Errorf("error = %v, want it to mention %q", err, "already has a value")
		}
	})

	t.Run("child element followed by a value token decodes cleanly", func(t *testing.T) {
		var e elemBuilder
		outerStart, outerDataSizePos, _ := e.open("Outer", false)
		e.closeNoAttrs()
		innerStart, innerDataSizePos, _ := e.open("Inner", false)
		e.closeNoAttrs()
		e.end(innerStart, innerDataSizePos) // </Inner>
		e.raw(subRef)                       // the real EventData/UserData shape
		e.end(outerStart, outerDataSizePos)
		buf := e.bytes()

		p := &binxmlParser{chunk: buf, buf: buf, subs: subs}
		node, err := p.parseElement()
		if err != nil {
			t.Fatalf("parseElement: %v", err)
		}
		if len(node.Children) != 1 || node.Children[0].Name != "Inner" {
			t.Errorf("Children = %+v, want one element named Inner", node.Children)
		}
		if node.Value == nil {
			t.Error("Value is nil, want the trailing substitution's value")
		}
	})

	t.Run("value token followed by a child element decodes cleanly", func(t *testing.T) {
		var e elemBuilder
		outerStart, outerDataSizePos, _ := e.open("Outer", false)
		e.closeNoAttrs()
		e.raw(subRef) // a value token first
		innerStart, innerDataSizePos, _ := e.open("Inner", false)
		e.closeNoAttrs()
		e.end(innerStart, innerDataSizePos) // </Inner>
		e.end(outerStart, outerDataSizePos)
		buf := e.bytes()

		p := &binxmlParser{chunk: buf, buf: buf, subs: subs}
		node, err := p.parseElement()
		if err != nil {
			t.Fatalf("parseElement: %v", err)
		}
		if len(node.Children) != 1 || node.Children[0].Name != "Inner" {
			t.Errorf("Children = %+v, want one element named Inner", node.Children)
		}
		if node.Value == nil {
			t.Error("Value is nil, want the leading substitution's value")
		}
	})
}

// TestDecodeBinXMLFragment_DepthLimitIsError exercises C1's recursion guard
// directly: once nested BinXml substitutions parse for real, a corrupt or
// adversarial chunk could otherwise drive decodeBinXMLFragment arbitrarily
// deep. Genuinely constructing maxBinXMLDepth levels of nested BinXml isn't
// worth the fixture complexity; calling in with depth already past the limit
// exercises the same guard at the entry point where every recursive call
// checks it.
func TestDecodeBinXMLFragment_DepthLimitIsError(t *testing.T) {
	chunk := make([]byte, evtxChunkSize)
	cache := newTemplateCache(chunk)
	if _, err := decodeBinXMLFragment(cache, 0, 0, false, maxBinXMLDepth+1); err == nil {
		t.Fatal("expected an error once recursion exceeds maxBinXMLDepth")
	}
}

// TestDecodeRecordBinXML_RealFixture decodes record 0 of testdata/system.evtx
// chunk 0 — a real Windows-generated record, ground-truthed by
// testdata/system-expected-windows.xml's "RECORD 1" (EventRecordID 12049).
// This is the test the review that produced this fix round said would have
// caught C1 (nested BinXml is a TemplateInstance, not a bare element tree —
// this record's <UserData><AutoBackup>...</AutoBackup></UserData> is exactly
// that) and C4 (this record's own trailing bytes are EOF + 4 bytes of
// non-zero padding) immediately, because both are real shapes no synthetic,
// go-evtx-shaped fixture produces.
func TestDecodeRecordBinXML_RealFixture(t *testing.T) {
	chunk := readFixtureChunk(t, 0)
	const recOff = evtxChunkHeaderSize // first record in the chunk
	size := int(le32(chunk[recOff+4 : recOff+8]))
	payloadOff := recOff + 24
	payloadLen := size - 24 - 4

	cache := newTemplateCache(chunk)
	root, err := decodeRecordBinXML(cache, payloadOff, payloadLen)
	if err != nil {
		t.Fatalf("decodeRecordBinXML on testdata/system.evtx record 0: %v", err)
	}

	if root.Name != "Event" {
		t.Fatalf("root.Name = %q, want %q", root.Name, "Event")
	}
	if len(root.Children) != 2 {
		t.Fatalf("root has %d children, want 2 (System, UserData): %+v", len(root.Children), root.Children)
	}

	system := root.Children[0]
	if system.Name != "System" {
		t.Fatalf("root.Children[0].Name = %q, want %q", system.Name, "System")
	}
	findChild := func(t *testing.T, n Node, name string) Node {
		t.Helper()
		for _, c := range n.Children {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("%q has no child named %q; children: %+v", n.Name, name, n.Children)
		return Node{}
	}

	provider := findChild(t, system, "Provider")
	var gotName, gotGUID string
	for _, a := range provider.Attributes {
		switch a.Name {
		case "Name":
			gotName = a.Value.String()
		case "Guid":
			gotGUID = a.Value.String()
		}
	}
	if gotName != "Microsoft-Windows-Eventlog" {
		t.Errorf("Provider/@Name = %q, want %q", gotName, "Microsoft-Windows-Eventlog")
	}
	if gotGUID == "" {
		t.Errorf("Provider/@Guid is empty")
	}

	eventID := findChild(t, system, "EventID")
	if eventID.Value == nil {
		t.Fatal("EventID has no value")
	}
	if got, _ := eventID.Value.Uint64(); got != 105 {
		t.Errorf("EventID = %d, want 105", got)
	}

	computer := findChild(t, system, "Computer")
	if computer.Value == nil || computer.Value.String() != "WKS-WIN764BITB.shieldbase.local" {
		t.Errorf("Computer value = %v, want %q", computer.Value, "WKS-WIN764BITB.shieldbase.local")
	}

	// UserData wraps the nested BinXml fragment — C1's linchpin case. Its
	// content is a substitution reference to the BinXml-typed value, so the
	// decoded <AutoBackup> tree hangs off userData.Value.Node(), not
	// userData.Children — the substitution array entry is what recursed.
	userData := root.Children[1]
	if userData.Name != "UserData" {
		t.Fatalf("root.Children[1].Name = %q, want %q", userData.Name, "UserData")
	}
	if userData.Value == nil || userData.Value.Node() == nil {
		t.Fatalf("UserData has no resolved BinXml value; got %+v", userData)
	}
	autoBackup := *userData.Value.Node()
	if autoBackup.Name != "AutoBackup" {
		t.Fatalf("UserData's nested fragment root is %q, want %q", autoBackup.Name, "AutoBackup")
	}
	channel := findChild(t, autoBackup, "Channel")
	if channel.Value == nil || channel.Value.String() != "System" {
		t.Errorf("AutoBackup/Channel = %v, want %q", channel.Value, "System")
	}
	backupPath := findChild(t, autoBackup, "BackupPath")
	if backupPath.Value == nil || !strings.Contains(backupPath.Value.String(), "Archive-System-2012-03-14-04-17-39-932.evtx") {
		t.Errorf("AutoBackup/BackupPath = %v, want it to contain the archive file name", backupPath.Value)
	}
}

// TestParseSubstitutionRef_ArrayTypeGoverns pins the rule that where the
// template's substitution token and the substitution array disagree about a
// value's type, the array governs.
//
// This is documented behaviour for SizeT, not a tolerance. libyal's EVTX
// specification, for both the normal and the optional substitution token: "If
// the value type is Size (0x10) the corresponding substitution value should be
// a 32-bit hexadecimal integer (0x14) or 64-bit hexadecimal integer (0x15)."
// Measured across the derivation corpus: 61 674 records pair SizeT with
// HexInt32 or HexInt64, and 415 pair UInt8 with UInt16 — the latter documented
// nowhere, measured only.
func TestParseSubstitutionRef_ArrayTypeGoverns(t *testing.T) {
	tests := []struct {
		name         string
		templateType ValueType
		arrayType    ValueType
		data         []byte
	}{
		{"SizeT token, HexInt64 value", ValSizeT, ValHexInt64, []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{"SizeT token, HexInt32 value", ValSizeT, ValHexInt32, []byte{2, 0, 0, 0}},
		{"UInt8 token, UInt16 value", ValUInt8, ValUInt16, []byte{3, 0}},
		{"types agree", ValUInt16, ValUInt16, []byte{4, 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := decodeValue(tc.arrayType, tc.data)
			if err != nil {
				t.Fatalf("decodeValue: %v", err)
			}
			// NormalSubstitution: token(1) index(2) declared type(1).
			p := &binxmlParser{
				buf:  []byte{tokNormalSub, 0x00, 0x00, byte(tc.templateType)},
				subs: []Value{v},
			}
			got, err := p.parseSubstitutionRef()
			if err != nil {
				t.Fatalf("parseSubstitutionRef: %v", err)
			}
			if got.Type != tc.arrayType {
				t.Errorf("value type = %s, want the array's %s", got.Type, tc.arrayType)
			}
			if p.pos != 4 {
				t.Errorf("cursor = %d, want 4", p.pos)
			}
		})
	}
}
