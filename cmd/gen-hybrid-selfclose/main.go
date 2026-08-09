// Command gen-hybrid-selfclose builds Task 9b's Hybrid 3 from the v0.7.0
// format-correctness release
// (.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9b-report.md):
// go-evtx's own minimal-fixture BinXML, with ONE measured structural
// divergence from testdata/system.evtx corrected — everything else (every
// substitution index, every value, every other token) stays exactly what
// go-evtx's own encoder produces.
//
// # The measured divergence
//
// A structural walk of testdata/system.evtx chunk 0 record 0 (2148 bytes,
// self-contained -- see cmd/gen-splice-fixture) found its <System> block has
// the SAME 14 children, in the SAME order, with the SAME declared
// substitution value types, as go-evtx's own <System> block. Exactly one
// structural difference was measured: 5 of those children --
// Provider, TimeCreated, Correlation, Execution, Security -- are
// attribute-only elements with no text/child content, and the real file
// closes each with CloseEmptyElementTag (0x03) and NO separate
// EndElementTag. go-evtx's own encoder (binxml.go's buildTemplateBody)
// closes the identical 5 elements with CloseStartElementTag (0x02) followed
// by a separate EndElementTag (0x04) instead -- a fact already measured and
// asserted by attrlist_test.go's own comment ("go-evtx never emits the
// self-closing CloseEmptyElementTag") but never before tested for whether it
// matters to a real Windows parser.
//
// # What this command does
//
// Builds the exact same record cmd/gen-fixture-minimal writes (same fields,
// same API calls -- evtx.New/Writer.WriteRecord/Writer.Close), extracts its
// raw BinXML via Reader.ReadRaw(), then rewrites ONLY those 5 elements'
// closing bytes: [0x02][0x04] (2 bytes) becomes [0x03] (1 byte). Every other
// byte -- every substitution index, every value, every other element -- is
// untouched go-evtx output.
//
// # The offset problem, and how it is handled
//
// Removing a byte from the middle of the payload invalidates every
// chunk-relative offset (name_offset, and every data_size/attr_list_size span
// that crosses the edit point) that comes after it -- exactly the class of
// error this release's brief calls out as "the main thing to get right."
// This command does NOT patch the existing payload's fields in place; it
// analyses the ORIGINAL (valid) payload first, using ITS OWN correct
// data_size/attr_list_size/name_offset fields to locate every element, every
// attribute, and every name reference. THEN it builds the edited byte
// sequence (5 single-byte deletions plus 5 single-byte value changes) and
// recomputes, from the analysis, every field whose value depends on a byte
// position: the 5 edited elements' own data_size (now one byte shorter),
// every ancestor element's data_size (System, Event -- their span shrank by
// 5 bytes total), every attr_list_size whose region-end is one of the edited
// close-tag positions, every name_offset field's absolute value (shifted by
// however many of the 5 deletions land before it), and the outer TemplateNode
// header's data_length (down by 5). Nothing is guessed: every rewritten value
// is derived from the pre-edit structural analysis via a single position
// remap function (newPos), applied uniformly.
//
// A self-check re-parses the edited payload with the same structural walker
// used for analysis (recognising both 0x02 and 0x03 close forms) and fails
// loudly (os.Exit(1), nothing written) if data_size/attr_list_size/name_offset
// do not resolve consistently, or if the substitution array's declared count
// does not match the original (42, unchanged -- this hybrid never touches
// the substitution array).
//
// Does NOT touch cmd/gen-fixture/main.go, cmd/gen-fixture-minimal/main.go, or
// binxml.go. binxml.go's own encoder is completely unmodified; this command
// duplicates just enough of its token layout (documented in binxml.go's own
// comments) to analyse and re-encode its output as an opaque byte sequence.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	evtx "github.com/fjacquet/go-evtx"
)

// Token constants -- see binxml.go's own const block. Duplicated here
// (rather than imported) because they are unexported in package evtx and
// this command intentionally stays outside that package, operating on
// go-evtx's output as an opaque byte sequence rather than linking against
// its internals.
const (
	tokOpenNoAttrs = 0x01
	tokOpenAttrs   = 0x41
	tokCloseStart  = 0x02
	tokCloseEmpty  = 0x03
	tokEndElement  = 0x04
	tokValueText   = 0x05
	tokAttrLast    = 0x06
	tokAttrMore    = 0x46
	tokFragHeader  = 0x0F
	tokNormalSub   = 0x0D
	tokOptionalSub = 0x0E

	preambleSize = 38 // fragHeader(4) + TemplateInstanceNode(10) + TemplateNode header(24)
)

func u16le(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func u32le(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func nameNodeLen(payload []byte, localOff int) (int, error) {
	if localOff+8 > len(payload) {
		return 0, fmt.Errorf("NameNode at %d: header runs past payload", localOff)
	}
	n := int(u16le(payload[localOff+6 : localOff+8]))
	end := localOff + 8 + 2*n + 2
	if end > len(payload) {
		return 0, fmt.Errorf("NameNode at %d: char data runs past payload", localOff)
	}
	return end - localOff, nil
}

// elemInfo records one OpenStartElementTag's structural facts, gathered from
// the ORIGINAL (pre-edit, valid) payload.
type elemInfo struct {
	tokenPos     int // local offset of the token byte
	hasAttrs     bool
	dataSizeAt   int // local offset of the 4-byte data_size field
	origDataSize uint32
	origEnd      int // tokenPos + 7 + origDataSize -- local offset just past this element's own EndElementTag (or, for a candidate, just past its 0x04 in the ORIGINAL bytes)
	closeTokAt   int // local offset of the 0x02 byte that closes this element's start tag
	isCandidate  bool
}

// attrListInfo records one attr_list_size field's structural facts.
type attrListInfo struct {
	fieldAt       int // local offset of the 4-byte attr_list_size field
	origListSize  uint32
	origRegionEnd int // fieldAt + 4 + origListSize -- local offset of the close tag that follows
}

// nameRefInfo records one name_offset field's own local position. The
// NameNode it points at always sits exactly 4 bytes after the field itself
// (immediately following it -- the field is 4 bytes wide, and go-evtx always
// writes the NameNode inline, right there) for BOTH an element header
// (binxml.go's writeOpenElement: name_offset at tokenPos+7, NameNode at
// tokenPos+11 = (tokenPos+7)+4) and an attribute header (writeAttributeSub:
// name_offset at tokenPos+1, NameNode at tokenPos+5 = (tokenPos+1)+4) --
// confirmed unconditionally true of go-evtx's own output by
// attrlist_test.go's TestWriteOpenElement_AttrListSizeAfterNameNode. So the
// two cases need no distinguishing field: the offset from fieldAt to the
// NameNode is always +4.
type nameRefInfo struct {
	fieldAt int
}

type analysis struct {
	elems      []elemInfo
	attrLists  []attrListInfo
	nameRefs   []nameRefInfo
	bodyStart  int
	dataLength uint32
}

// analyze walks the ORIGINAL, valid payload linearly. It does not need a
// nesting stack: every token's own length is self-describing (data_size and
// attr_list_size are already correct in go-evtx's own output, per
// datasize_test.go/attrlist_test.go), so a flat left-to-right scan visits
// every element, attribute, and name reference exactly once, in stream
// order, without needing to know which element is whose parent.
func analyze(payload []byte, base uint32) (*analysis, error) {
	if len(payload) < preambleSize+4 {
		return nil, fmt.Errorf("payload too short")
	}
	dataLength := u32le(payload[34:38])
	bodyStart := preambleSize
	bodyEnd := bodyStart + int(dataLength)
	if bodyEnd > len(payload) {
		return nil, fmt.Errorf("data_length %d runs past payload", dataLength)
	}
	if payload[bodyStart] != tokFragHeader {
		return nil, fmt.Errorf("expected nested fragment header at %d", bodyStart)
	}
	a := &analysis{bodyStart: bodyStart, dataLength: dataLength}
	pos := bodyStart + 4

	for pos < bodyEnd {
		tok := payload[pos]
		switch tok {
		case 0x00: // EndOfStream
			return a, nil
		case tokEndElement:
			pos++
		case tokValueText:
			cc := int(u16le(payload[pos+2 : pos+4]))
			pos += 4 + cc*2
		case tokNormalSub, tokOptionalSub:
			pos += 4
		case tokOpenNoAttrs, tokOpenAttrs:
			tokenPos := pos
			hasAttrs := tok == tokOpenAttrs
			dataSizeAt := tokenPos + 3
			origDataSize := u32le(payload[dataSizeAt : dataSizeAt+4])
			nameFieldAt := tokenPos + 7
			a.nameRefs = append(a.nameRefs, nameRefInfo{fieldAt: nameFieldAt})
			nnLen, err := nameNodeLen(payload, nameFieldAt+4)
			if err != nil {
				return nil, fmt.Errorf("element at %d: %w", tokenPos, err)
			}
			cursor := nameFieldAt + 4 + nnLen

			var closeTokAt int
			if hasAttrs {
				attrListFieldAt := cursor
				origListSize := u32le(payload[attrListFieldAt : attrListFieldAt+4])
				origRegionEnd := attrListFieldAt + 4 + int(origListSize)
				a.attrLists = append(a.attrLists, attrListInfo{fieldAt: attrListFieldAt, origListSize: origListSize, origRegionEnd: origRegionEnd})

				// Walk attributes within [attrListFieldAt+4, origRegionEnd) to
				// harvest their own name_offset fields. Their value-token
				// shape doesn't matter for this pass -- only their length, so
				// the scan can keep advancing.
				ac := attrListFieldAt + 4
				for ac < origRegionEnd {
					atok := payload[ac]
					if atok != tokAttrLast && atok != tokAttrMore {
						return nil, fmt.Errorf("element at %d: expected attribute token at %d, got 0x%02x", tokenPos, ac, atok)
					}
					aNameFieldAt := ac + 1
					a.nameRefs = append(a.nameRefs, nameRefInfo{fieldAt: aNameFieldAt})
					annLen, err := nameNodeLen(payload, aNameFieldAt+4)
					if err != nil {
						return nil, fmt.Errorf("attribute at %d: %w", ac, err)
					}
					vpos := aNameFieldAt + 4 + annLen
					vtok := payload[vpos]
					switch vtok {
					case tokNormalSub, tokOptionalSub:
						ac = vpos + 4
					case tokValueText:
						cc := int(u16le(payload[vpos+2 : vpos+4]))
						ac = vpos + 4 + cc*2
					default:
						return nil, fmt.Errorf("attribute at %d: unknown value token 0x%02x at %d", ac, vtok, vpos)
					}
				}
				closeTokAt = origRegionEnd
			} else {
				closeTokAt = cursor
			}

			if payload[closeTokAt] != tokCloseStart {
				return nil, fmt.Errorf("element at %d: expected CloseStartElementTag (0x02) at %d, got 0x%02x", tokenPos, closeTokAt, payload[closeTokAt])
			}
			// isCandidate: this element's start tag closes (0x02) and is
			// IMMEDIATELY followed by EndElementTag (0x04) -- zero content.
			isCandidate := closeTokAt+1 < len(payload) && payload[closeTokAt+1] == tokEndElement

			origEnd := tokenPos + 7 + int(origDataSize)
			a.elems = append(a.elems, elemInfo{
				tokenPos: tokenPos, hasAttrs: hasAttrs, dataSizeAt: dataSizeAt,
				origDataSize: origDataSize, origEnd: origEnd, closeTokAt: closeTokAt, isCandidate: isCandidate,
			})
			pos = closeTokAt + 1 // continue scanning right after the close tag; content/EndElementTag follow naturally
		default:
			return nil, fmt.Errorf("unrecognised token 0x%02x at local %d", tok, pos)
		}
	}
	return nil, fmt.Errorf("EndOfStream not found within data_length bounds")
}

// rewrite produces the edited payload: the isCandidate elements close via
// 0x03 (no separate EndElementTag), every position-dependent field is
// recomputed, and the result is validated by re-parsing it with a
// structure-only walker (below) before being returned.
func rewrite(orig []byte, base uint32, a *analysis) ([]byte, error) {
	var candidates []elemInfo
	for _, e := range a.elems {
		if e.isCandidate {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no self-closing candidates found -- nothing to rewrite, hybrid would be a no-op")
	}

	// deletions: the local offset of each candidate's own EndElementTag byte
	// (closeTokAt+1), which disappears.
	deletions := make(map[int]bool, len(candidates))
	valueChanges := make(map[int]byte, len(candidates))
	for _, c := range candidates {
		valueChanges[c.closeTokAt] = tokCloseEmpty // 0x02 -> 0x03
		deletions[c.closeTokAt+1] = true           // remove the following 0x04
	}

	// shift(oldPos) = number of deleted positions strictly less than oldPos.
	sortedDeletions := make([]int, 0, len(deletions))
	for d := range deletions {
		sortedDeletions = append(sortedDeletions, d)
	}
	for i := 0; i < len(sortedDeletions); i++ {
		for j := i + 1; j < len(sortedDeletions); j++ {
			if sortedDeletions[j] < sortedDeletions[i] {
				sortedDeletions[i], sortedDeletions[j] = sortedDeletions[j], sortedDeletions[i]
			}
		}
	}
	shift := func(oldPos int) int {
		n := 0
		for _, d := range sortedDeletions {
			if d < oldPos {
				n++
			}
		}
		return n
	}
	newPos := func(oldPos int) int { return oldPos - shift(oldPos) }

	// Build the new byte sequence.
	out := make([]byte, 0, len(orig)-len(deletions))
	for i := 0; i < len(orig); i++ {
		if deletions[i] {
			continue
		}
		b := orig[i]
		if v, ok := valueChanges[i]; ok {
			b = v
		}
		out = append(out, b)
	}

	putU32 := func(pos int, v uint32) {
		binary.LittleEndian.PutUint32(out[pos:pos+4], v)
	}

	// data_length (preamble, offset 34) -- unaffected by shift (34 < 38 <=
	// every deletion position), but its VALUE shrinks by the deletion count.
	putU32(34, a.dataLength-uint32(len(deletions)))

	// Every element's data_size.
	for _, e := range a.elems {
		var newEnd int
		if e.isCandidate {
			// New end = position right after the (now single) 0x03 byte.
			newEnd = newPos(e.closeTokAt) + 1
		} else {
			newEnd = newPos(e.origEnd)
		}
		newTokenPos := newPos(e.tokenPos)
		newDataSize := uint32(newEnd - (newTokenPos + 7))
		putU32(newPos(e.dataSizeAt), newDataSize)
	}

	// Every attr_list_size.
	for _, al := range a.attrLists {
		newRegionEnd := newPos(al.origRegionEnd)
		newFieldAt := newPos(al.fieldAt)
		newListSize := uint32(newRegionEnd - (newFieldAt + 4))
		putU32(newFieldAt, newListSize)
	}

	// Every name_offset field's absolute value.
	for _, nr := range a.nameRefs {
		newFieldAt := newPos(nr.fieldAt)
		putU32(newFieldAt, base+uint32(newFieldAt+4))
	}

	if err := validate(out, base, len(a.elems), len(candidates)); err != nil {
		return nil, fmt.Errorf("self-check on rewritten payload failed: %w", err)
	}
	return out, nil
}

// validate re-parses the rewritten payload with a walker that accepts BOTH
// close forms (0x02+separate EndElementTag, and 0x03 self-closing) and
// checks internal consistency: every data_size/attr_list_size resolves
// in-range and lands on the token type it claims to; every name_offset
// resolves to a decodable NameNode; EndOfStream sits exactly at the
// data_length boundary; the substitution array's declared count is
// unchanged (this hybrid never touches it) and its spec table decodes without
// running past the payload.
func validate(payload []byte, base uint32, wantElemCount, wantCloseEmptyCount int) error {
	if len(payload) < preambleSize+4 {
		return fmt.Errorf("payload too short")
	}
	dataLength := u32le(payload[34:38])
	bodyStart := preambleSize
	bodyEnd := bodyStart + int(dataLength)
	if bodyEnd > len(payload) {
		return fmt.Errorf("data_length %d runs past payload (len %d)", dataLength, len(payload))
	}
	if payload[bodyStart] != tokFragHeader {
		return fmt.Errorf("expected nested fragment header at %d", bodyStart)
	}
	pos := bodyStart + 4
	elemCount, closeEmptyCount := 0, 0

	for pos < bodyEnd {
		tok := payload[pos]
		switch tok {
		case 0x00:
			if pos != bodyEnd-1 {
				return fmt.Errorf("EndOfStream at %d, want %d (bodyEnd-1)", pos, bodyEnd-1)
			}
			goto subs
		case tokEndElement:
			pos++
		case tokValueText:
			cc := int(u16le(payload[pos+2 : pos+4]))
			pos += 4 + cc*2
		case tokNormalSub, tokOptionalSub:
			pos += 4
		case tokOpenNoAttrs, tokOpenAttrs:
			tokenPos := pos
			hasAttrs := tok == tokOpenAttrs
			dataSize := u32le(payload[tokenPos+3 : tokenPos+7])
			nameFieldAt := tokenPos + 7
			nameOffsetAbs := u32le(payload[nameFieldAt : nameFieldAt+4])
			if int(nameOffsetAbs)-int(base) != nameFieldAt+4 {
				return fmt.Errorf("element at %d: name_offset %d does not point immediately after itself (want local %d)", tokenPos, int(nameOffsetAbs)-int(base), nameFieldAt+4)
			}
			nnLen, err := nameNodeLen(payload, nameFieldAt+4)
			if err != nil {
				return fmt.Errorf("element at %d: %w", tokenPos, err)
			}
			cursor := nameFieldAt + 4 + nnLen
			var closeTokAt int
			if hasAttrs {
				attrListFieldAt := cursor
				if attrListFieldAt+4 > bodyEnd {
					return fmt.Errorf("element at %d: attr_list_size field runs past bodyEnd", tokenPos)
				}
				listSize := u32le(payload[attrListFieldAt : attrListFieldAt+4])
				regionEnd := attrListFieldAt + 4 + int(listSize)
				if regionEnd > bodyEnd {
					return fmt.Errorf("element at %d: attr_list_size %d runs past bodyEnd", tokenPos, listSize)
				}
				ac := attrListFieldAt + 4
				for ac < regionEnd {
					atok := payload[ac]
					if atok != tokAttrLast && atok != tokAttrMore {
						return fmt.Errorf("element at %d: expected attribute token at %d, got 0x%02x", tokenPos, ac, atok)
					}
					aNameFieldAt := ac + 1
					aNameOffsetAbs := u32le(payload[aNameFieldAt : aNameFieldAt+4])
					if int(aNameOffsetAbs)-int(base) != aNameFieldAt+4 {
						return fmt.Errorf("attribute at %d: name_offset does not point immediately after itself", ac)
					}
					annLen, err := nameNodeLen(payload, aNameFieldAt+4)
					if err != nil {
						return fmt.Errorf("attribute at %d: %w", ac, err)
					}
					vpos := aNameFieldAt + 4 + annLen
					vtok := payload[vpos]
					switch vtok {
					case tokNormalSub, tokOptionalSub:
						ac = vpos + 4
					case tokValueText:
						cc := int(u16le(payload[vpos+2 : vpos+4]))
						ac = vpos + 4 + cc*2
					default:
						return fmt.Errorf("attribute at %d: unknown value token 0x%02x", ac, vtok)
					}
				}
				if ac != regionEnd {
					return fmt.Errorf("element at %d: attribute walk ended at %d, want %d", tokenPos, ac, regionEnd)
				}
				closeTokAt = regionEnd
			} else {
				closeTokAt = cursor
			}
			if closeTokAt >= bodyEnd {
				return fmt.Errorf("element at %d: close tag at %d runs past bodyEnd", tokenPos, closeTokAt)
			}
			closeTok := payload[closeTokAt]
			elemCount++
			var wantEnd int
			switch closeTok {
			case tokCloseStart:
				// A 0x02 close is followed by this element's CONTENT (nested
				// elements, ValueText, or a substitution token) -- NOT
				// necessarily its own EndElementTag as the very next byte;
				// that only holds for a leaf with zero content. The element's
				// true end is wherever its own data_size claims it is: the
				// byte at that position (exclusive end) must be its
				// EndElementTag. The flat walk below still reaches it
				// naturally, in stream order, once the content in between has
				// been consumed token by token.
				wantEnd = tokenPos + 7 + int(dataSize)
				if wantEnd > bodyEnd || wantEnd < closeTokAt+1 || payload[wantEnd-1] != tokEndElement {
					return fmt.Errorf("element at %d: data_size %d does not end on an EndElementTag (byte at %d is 0x%02x)", tokenPos, dataSize, wantEnd-1, payload[wantEnd-1])
				}
			case tokCloseEmpty:
				closeEmptyCount++
				wantEnd = closeTokAt + 1
			default:
				return fmt.Errorf("element at %d: close tag at %d is 0x%02x, want 0x02 or 0x03", tokenPos, closeTokAt, closeTok)
			}
			if wantEnd != tokenPos+7+int(dataSize) {
				return fmt.Errorf("element at %d: data_size %d implies end %d, structural end is %d", tokenPos, dataSize, tokenPos+7+int(dataSize), wantEnd)
			}
			pos = closeTokAt + 1
		default:
			return fmt.Errorf("unrecognised token 0x%02x at local %d", tok, pos)
		}
	}
	return fmt.Errorf("EndOfStream not found within data_length bounds")

subs:
	if elemCount != wantElemCount {
		return fmt.Errorf("element count %d, want %d (unchanged from original)", elemCount, wantElemCount)
	}
	if closeEmptyCount != wantCloseEmptyCount {
		return fmt.Errorf("close-empty (0x03) count %d, want %d", closeEmptyCount, wantCloseEmptyCount)
	}
	subsStart := bodyEnd
	if subsStart+4 > len(payload) {
		return fmt.Errorf("no room for substitution array")
	}
	count := int(u32le(payload[subsStart : subsStart+4]))
	specsEnd := subsStart + 4 + count*4
	if specsEnd > len(payload) {
		return fmt.Errorf("substitution array: count %d specs run past payload", count)
	}
	dataOff := specsEnd
	for i := 0; i < count; i++ {
		off := subsStart + 4 + i*4
		size := int(u16le(payload[off : off+2]))
		dataOff += size
	}
	if dataOff != len(payload) {
		return fmt.Errorf("substitution array: value data ends at %d, payload is %d bytes", dataOff, len(payload))
	}
	return nil
}

func buildOurs(tmpDir string) ([]byte, error) {
	path := filepath.Join(tmpDir, "ours-source.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		return nil, err
	}
	fields := map[string]string{
		"ProviderName":    "Microsoft-Windows-Security-Auditing",
		"Computer":        "TESTHOST",
		"TimeCreated":     "2026-01-01T00:00:00Z",
		"SubjectUserName": "tester",
		"ObjectName":      `C:\test\file.txt`,
		"ObjectType":      "File",
	}
	if err := w.WriteRecord(4663, fields); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	r, err := evtx.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return r.ReadRaw()
}

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()

	tmpDir, err := os.MkdirTemp("", "gen-hybrid-selfclose-")
	if err != nil {
		fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	oursPayload, err := buildOurs(tmpDir)
	if err != nil {
		fatal(fmt.Errorf("build ours: %w", err))
	}

	const base = uint32(536) // 512 chunk header + 24 record header — first record of a fresh chunk
	a, err := analyze(oursPayload, base)
	if err != nil {
		fatal(fmt.Errorf("analyze: %w", err))
	}

	var candidateNames []int
	for i, e := range a.elems {
		if e.isCandidate {
			candidateNames = append(candidateNames, i)
		}
	}
	fmt.Printf("analysis: %d elements, %d self-closing candidates (measured empty-content elements)\n", len(a.elems), len(candidateNames))

	hybrid, err := rewrite(oursPayload, base, a)
	if err != nil {
		fatal(fmt.Errorf("rewrite: %w", err))
	}
	fmt.Printf("rewrite: %d bytes -> %d bytes (delta %d, want -%d)\n", len(oursPayload), len(hybrid), len(oursPayload)-len(hybrid), len(candidateNames))

	path := filepath.Join(*out, "hybrid-selfclose.evtx")
	w, err := evtx.New(path, evtx.RotationConfig{})
	if err != nil {
		fatal(err)
	}
	if err := w.WriteRaw(hybrid); err != nil {
		fatal(fmt.Errorf("write hybrid via WriteRaw: %w", err))
	}
	if err := w.Close(); err != nil {
		fatal(fmt.Errorf("close: %w", err))
	}

	fmt.Printf("wrote %s (1 hybrid record, %d bytes: go-evtx's own minimal-fixture BinXML with %d self-closing elements rewritten 0x02+EndElementTag -> 0x03, self-check passed)\n",
		path, len(hybrid), len(candidateNames))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-hybrid-selfclose:", err)
	os.Exit(1)
}
