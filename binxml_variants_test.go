// binxml_variants_test.go — self-validation for the task 9c ladder's
// variant builders (binxml_variants.go): structural consistency of each
// variant's own BinXML, round-trip fidelity through the existing
// Writer/Reader container, and a direct check that this file's additions
// leave buildBinXML/buildTemplateBody's own production output untouched.
package evtx

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

// variantTestFields is a minimal ASCII field set shared by every variant
// test below, matching cmd/gen-fixture-minimal's own style (plain ASCII,
// fixed timestamp) so the numbers this test pins are reproducible.
func variantTestFields() map[string]string {
	return map[string]string{
		"ProviderName":   "Microsoft-Windows-Security-Auditing",
		"Computer":       "TESTHOST",
		"TimeCreated":    "2026-01-01T00:00:00Z",
		"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-512",
		"ObjectName":     `C:\test\file.txt`,
		"ObjectType":     "File",
		"Channel":        "Security",
		"ProviderGuid":   "{54849625-5478-4994-A5BA-3E3B0328C30D}",
	}
}

// TestBuildVariantBinXML_ProductionEncoderUntouched confirms this file
// changes nothing about buildBinXML/collectSubstitutionsFromFields's own
// output: it is a disjoint call graph (BuildVariantBinXML never calls
// buildBinXML or buildTemplateBody), and this test additionally re-runs
// nodecollect_test.go's own golden-file comparison directly, so a CI
// failure here would point straight at the addition rather than requiring
// cross-referencing another file's test.
func TestBuildVariantBinXML_ProductionEncoderUntouched(t *testing.T) {
	want, err := os.ReadFile("testdata/binxml-golden.bin")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	res := buildBinXML(4663, 1, goldenFields(), uint32(evtxRecordsStart+evtxRecordHeaderSize))
	if !bytes.Equal(res.payload, want) {
		t.Fatalf("buildBinXML's production payload changed: got %d bytes, want %d — "+
			"binxml_variants.go must not affect buildBinXML/buildTemplateBody", len(res.payload), len(want))
	}
}

// TestBuildVariantBinXML_RoundTripsThroughContainer writes each variant via
// the existing, unmodified Writer.WriteRaw and reads it back via Reader —
// the same container-fidelity check cmd/gen-splice-fixture used before
// relying on its own payload for a CI probe (task-9a-report.md).
func TestBuildVariantBinXML_RoundTripsThroughContainer(t *testing.T) {
	const binXMLChunkOffset = uint32(evtxRecordsStart + evtxRecordHeaderSize) // 536: first record, fresh chunk

	variants := []struct {
		name    string
		variant Variant
	}{
		{"SystemOnly", VariantSystemOnly},
		{"EventDataOnePair", VariantEventDataOnePair},
		{"EventDataLiteralNames", VariantEventDataLiteralNames},
	}

	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			payload := BuildVariantBinXML(tc.variant, 4663, 1, variantTestFields(), binXMLChunkOffset)

			path := filepath.Join(t.TempDir(), "variant.evtx")
			w, err := New(path, RotationConfig{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := w.WriteRaw(payload); err != nil {
				t.Fatalf("WriteRaw: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			r, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = r.Close() }()

			got, err := r.ReadRaw()
			if err != nil {
				t.Fatalf("ReadRaw: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("round trip changed the payload: wrote %d bytes, read back %d", len(payload), len(got))
			}
		})
	}
}

// TestBuildVariantBinXML_StructuralConsistency independently re-derives
// every OpenStartElementTag's data_size and every attr_list_size from the
// payload's own bytes (following each element's name_offset self-reference
// to confirm genuineness, the same technique datasize_test.go/
// attrlist_test.go use against production's own output) and checks the
// substitution array's declared count and byte length exactly match what
// the template body references and what remains of the payload. This is
// the "self-validated before relying on it" discipline task 9b's
// cmd/gen-hybrid-selfclose used for its own offset rewrite, applied here to
// freshly-built (not edited) payloads.
func TestBuildVariantBinXML_StructuralConsistency(t *testing.T) {
	const binXMLChunkOffset = uint32(evtxRecordsStart + evtxRecordHeaderSize)

	cases := []struct {
		name       string
		variant    Variant
		wantSubs   int // declared substitution count this variant's own builders imply
		wantMaxSub int // highest substitution index referenced in the body (wantSubs-1)
	}{
		{"SystemOnly", VariantSystemOnly, vSystemSubCount, vSystemSubCount - 1},
		{"EventDataOnePair", VariantEventDataOnePair, vSystemSubCount + 2, vSystemSubCount + 1},
		{"EventDataLiteralNames", VariantEventDataLiteralNames, vSystemSubCount + 12, vSystemSubCount + 11},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := BuildVariantBinXML(tc.variant, 4663, 1, variantTestFields(), binXMLChunkOffset)
			base := binXMLChunkOffset

			if len(payload) < preambleSize+4 {
				t.Fatalf("payload too short: %d bytes", len(payload))
			}
			dataLength := int(binary.LittleEndian.Uint32(payload[34:38]))
			bodyEnd := preambleSize + dataLength
			if bodyEnd > len(payload) {
				t.Fatalf("data_length %d runs past payload (%d bytes)", dataLength, len(payload))
			}

			// EndOfStream must sit exactly at the declared body boundary.
			if payload[bodyEnd-1] != 0x00 {
				t.Errorf("byte at data_length boundary (%d) = 0x%02x, want EndOfStream 0x00", bodyEnd-1, payload[bodyEnd-1])
			}

			// Substitution array: count, then count*4 spec bytes, then the
			// concatenated value data — must exactly reach the end of payload.
			subsStart := bodyEnd
			if subsStart+4 > len(payload) {
				t.Fatalf("no room for substitution count at %d", subsStart)
			}
			count := int(binary.LittleEndian.Uint32(payload[subsStart:]))
			if count != tc.wantSubs {
				t.Errorf("declared substitution count = %d, want %d", count, tc.wantSubs)
			}
			specsEnd := subsStart + 4 + count*4
			if specsEnd > len(payload) {
				t.Fatalf("substitution specs run past payload: specsEnd=%d, len=%d", specsEnd, len(payload))
			}
			dataOff := specsEnd
			for i := 0; i < count; i++ {
				specOff := subsStart + 4 + i*4
				size := int(binary.LittleEndian.Uint16(payload[specOff:]))
				dataOff += size
			}
			if dataOff != len(payload) {
				t.Errorf("substitution value data ends at %d, want exactly %d (end of payload)", dataOff, len(payload))
			}

			// Walk every OpenStartElement(Attrs) token in the template body,
			// verifying it via its own name_offset self-reference before
			// trusting its data_size/attr_list_size — same genuineness check
			// dependency_test.go/attrlist_test.go use against production.
			checkedElements := 0
			checkedAttrLists := 0
			maxSubRef := -1
			for i := preambleSize + fragHeaderSize; i+3 < bodyEnd; i++ {
				tok := payload[i]

				if tok == binXMLNormalSubstitution || tok == binXMLOptionalSubstitution {
					if i+3 < len(payload) {
						idx := int(binary.LittleEndian.Uint16(payload[i+1:]))
						typ := payload[i+3]
						// Only trust this as a genuine substitution token if its
						// declared type is one this file's own builders ever
						// emit and its index is in range — reduces (does not
						// eliminate) false positives from coincidental bytes,
						// consistent with how heavily attrlist_test.go/
						// dependency_test.go caveat the same tradeoff for
						// production's own scan.
						if idx < count && isPlausibleSubType(typ) && idx > maxSubRef {
							maxSubRef = idx
						}
					}
				}

				if tok != binXMLOpenElement && tok != binXMLOpenElementAttrs {
					continue
				}
				if i+11 > len(payload) {
					continue
				}
				dep := binary.LittleEndian.Uint16(payload[i+1:])
				if dep != depIDNotSet && int(dep) >= count {
					continue // not a plausible dependency_id for this variant
				}
				nameOffset := binary.LittleEndian.Uint32(payload[i+7:])
				const headerSize = 11
				if nameOffset != base+uint32(i)+headerSize {
					continue // not a genuine element header
				}

				size := binary.LittleEndian.Uint32(payload[i+3:])
				end := i + 7 + int(size)
				if end > bodyEnd {
					t.Errorf("element at %d: data_size %d runs past body end (%d > %d)", i, size, end, bodyEnd)
				}
				checkedElements++

				if tok == binXMLOpenElementAttrs {
					nn := nameOffset - base
					if int(nn)+8 > len(payload) {
						t.Errorf("element at %d: NameNode at %d runs past payload", i, nn)
						continue
					}
					n := int(binary.LittleEndian.Uint16(payload[int(nn)+6:]))
					nameNodeEnd := int(nn) + 8 + 2*n + 2
					if nameNodeEnd+4 > len(payload) {
						t.Errorf("element at %d: attr_list_size field at %d runs past payload", i, nameNodeEnd)
						continue
					}
					attrListSize := binary.LittleEndian.Uint32(payload[nameNodeEnd:])
					closeAt := nameNodeEnd + 4 + int(attrListSize)
					if closeAt >= len(payload) || payload[closeAt] != binXMLCloseElement {
						t.Errorf("element at %d: attr_list_size %d does not land on CloseStartElementTag", i, attrListSize)
						continue
					}
					checkedAttrLists++
				}

				i += 11 - 1 // skip this element's own fixed header before resuming the scan
			}

			if checkedElements == 0 {
				t.Fatal("no OpenStartElement tokens verified — the scan is wrong")
			}
			if maxSubRef != tc.wantMaxSub {
				t.Errorf("highest substitution index referenced in the body = %d, want %d", maxSubRef, tc.wantMaxSub)
			}
			t.Logf("%s: %d elements, %d attribute lists, %d substitutions (max ref %d)",
				tc.name, checkedElements, checkedAttrLists, count, maxSubRef)
		})
	}
}

// isPlausibleSubType reports whether typ is one of the value types this
// file's own builders ever declare on a substitution token — narrows the
// substitution-token scan in TestBuildVariantBinXML_StructuralConsistency
// against coincidental byte matches.
func isPlausibleSubType(typ byte) bool {
	switch typ {
	case binXMLTypeNull, binXMLTypeString, binXMLTypeUint8, binXMLTypeUint16,
		binXMLTypeUint64, binXMLTypeFiletime, binXMLTypeHexInt64:
		return true
	}
	return false
}

// TestBuildVariantBinXML_SystemOnlyHasNoEventData confirms VariantSystemOnly
// really emits no EventData/Data NameNode at all — the UTF-16LE encoding of
// neither name occurs anywhere in the payload.
func TestBuildVariantBinXML_SystemOnlyHasNoEventData(t *testing.T) {
	const binXMLChunkOffset = uint32(evtxRecordsStart + evtxRecordHeaderSize)
	payload := BuildVariantBinXML(VariantSystemOnly, 4663, 1, variantTestFields(), binXMLChunkOffset)

	for _, name := range []string{"EventData", "Data"} {
		if bytes.Contains(payload, utf16leBytes(name)) {
			t.Errorf("VariantSystemOnly payload unexpectedly contains the UTF-16LE encoding of %q", name)
		}
	}
}

// TestBuildVariantBinXML_LiteralNamesAreLiteral confirms
// VariantEventDataLiteralNames really embeds each Data/@Name as literal
// UTF-16LE bytes in the template body (not just referenced by substitution
// index) by checking every one of the 12 dataFieldNames' UTF-16LE encodings
// occurs in the template-body region.
func TestBuildVariantBinXML_LiteralNamesAreLiteral(t *testing.T) {
	const binXMLChunkOffset = uint32(evtxRecordsStart + evtxRecordHeaderSize)
	payload := BuildVariantBinXML(VariantEventDataLiteralNames, 4663, 1, variantTestFields(), binXMLChunkOffset)

	dataLength := int(binary.LittleEndian.Uint32(payload[34:38]))
	body := payload[preambleSize : preambleSize+dataLength]

	for _, name := range dataFieldNames {
		if !bytes.Contains(body, utf16leBytes(name)) {
			t.Errorf("template body does not contain literal UTF-16LE %q", name)
		}
	}
}

func utf16leBytes(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	buf := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	return buf
}
