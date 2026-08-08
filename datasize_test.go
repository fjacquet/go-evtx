// datasize_test.go — every OpenStartElementTag must carry a data_size that
// spans exactly to the end of its own element. Zero, which is what go-evtx
// wrote through v0.6.0, is a length field contradicting its content — the
// canonical reason a strict parser aborts. python-evtx never reads the field
// (its source says "TODO: use this size() field"), which is why our own
// differential could not see this.
//
// The formula (data_size = structural_end_of_this_element − (element_start +
// 7)) was measured, not assumed: a throwaway probe walked testdata/system.evtx
// chunk 0 record 0 and record 1 with a data_size-blind structural parser (one
// that finds each element's own end purely by matching CloseEmptyElementTag/
// EndElementTag, never reading data_size), then compared that independently
// derived end against element_start+7+data_size. All 33 elements checked (17
// + 16, at nesting depths 0/1/2, across two differently-shaped templates)
// matched exactly — see task-7e-report.md for the full table.
package evtx

import (
	"encoding/binary"
	"testing"
)

func TestWriteOpenElement_DataSizeIsNonZero(t *testing.T) {
	res := buildBinXML(4663, 1, goldenFields(), uint32(evtxRecordsStart+evtxRecordHeaderSize))

	checked := 0
	for i := preambleSize; i+7 < len(res.payload); i++ {
		tok := res.payload[i]
		if tok != binXMLOpenElement && tok != binXMLOpenElementAttrs {
			continue
		}
		if binary.LittleEndian.Uint16(res.payload[i+1:]) != 0xffff {
			continue // not an element header we recognise
		}
		size := binary.LittleEndian.Uint32(res.payload[i+3:])
		if size == 0 {
			t.Errorf("offset %d: OpenStartElement data_size is 0", i)
			continue
		}
		if end := i + 7 + int(size); end > len(res.payload) {
			t.Errorf("offset %d: data_size %d runs past the payload (end %d > %d)",
				i, size, end, len(res.payload))
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no OpenStartElement tokens examined — the scan is wrong")
	}
	t.Logf("%d elements carry a plausible data_size", checked)
}

// TestWriteOpenElement_DataSizeNesting asserts the rule Step 1 measured
// against the real fixture: an element's data_size span is its OWN span, not
// its outermost ancestor's — so a properly-nested inner element's span
// (element_start+7+data_size) must end at or before its enclosing element's
// span. buildTemplateBody's structure is entirely tail-nested (every element
// closes with EndElementTag before its parent does), so this also indirectly
// confirms the back-patching stack pops in the right order: a LIFO bug (e.g.
// patching the wrong open element) would make some inner span run past its
// parent's.
func TestWriteOpenElement_DataSizeNesting(t *testing.T) {
	res := buildBinXML(4663, 1, goldenFields(), uint32(evtxRecordsStart+evtxRecordHeaderSize))
	payload := res.payload

	type span struct {
		start, end int
	}
	var stack []span
	checked := 0

	for i := preambleSize; i+7 < len(payload); i++ {
		tok := payload[i]
		if tok != binXMLOpenElement && tok != binXMLOpenElementAttrs {
			continue
		}
		if binary.LittleEndian.Uint16(payload[i+1:]) != 0xffff {
			continue
		}
		size := binary.LittleEndian.Uint32(payload[i+3:])
		end := i + 7 + int(size)

		// Pop any spans on the stack that this element's start has already
		// moved past — they were closed before this one opened.
		for len(stack) > 0 && i >= stack[len(stack)-1].end {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			parent := stack[len(stack)-1]
			if end > parent.end {
				t.Errorf("element at %d: span ends at %d, past its enclosing element's span end %d",
					i, end, parent.end)
			}
			checked++
		}
		stack = append(stack, span{start: i, end: end})
	}
	if checked == 0 {
		t.Fatal("no nested element pair examined — the scan is wrong")
	}
	t.Logf("%d nested element spans confirmed within their parent's", checked)
}
