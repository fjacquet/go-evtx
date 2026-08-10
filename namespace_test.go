// namespace_test.go — the <Event> root must declare the Windows event schema.
// Without it, every namespaced XPath a real consumer uses matches nothing,
// which is how the v0.7.0 baseline enumerated 400 records and extracted zero
// field values from them.
package evtx

import (
	"strings"
	"testing"
	"unicode/utf16"
)

const eventSchemaURI = "http://schemas.microsoft.com/win/2004/08/events/event"

// TestBuildBinXML_DeclaresEventNamespace looks for the schema URI in the
// encoded payload as UTF-16LE, which is how BinXML stores strings.
func TestBuildBinXML_DeclaresEventNamespace(t *testing.T) {
	res := buildBinXML(4663, 1, testFields(), uint32(evtxRecordsStart+evtxRecordHeaderSize), 0)

	var want strings.Builder
	for _, u := range utf16.Encode([]rune(eventSchemaURI)) {
		want.WriteByte(byte(u))
		want.WriteByte(byte(u >> 8))
	}
	if !strings.Contains(string(res.payload), want.String()) {
		t.Error("encoded payload does not contain the event schema URI; " +
			"the <Event> root is missing its xmlns declaration")
	}

	var wantAttr strings.Builder
	for _, u := range utf16.Encode([]rune("xmlns")) {
		wantAttr.WriteByte(byte(u))
		wantAttr.WriteByte(byte(u >> 8))
	}
	if !strings.Contains(string(res.payload), wantAttr.String()) {
		t.Error("encoded payload does not contain the attribute name 'xmlns'")
	}
}
