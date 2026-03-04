// binxml_reader.go — BinXML payload decoder for .evtx event records.
//
// Decodes the specific template format written by binxml.go:
//
//	preamble (38 B): FragmentHeader(4) + TemplateInstanceNode(10) + TemplateNodeHeader(24)
//	template body (data_length bytes): BinXML tokens with NormalSubstitution placeholders
//	substitution array: [count:4B][count × spec:4B each][value_data...]
//
// Substitution index → Record field mapping (per buildTemplateBody):
//
//	0   ProviderName  STRING
//	1   EventID       UINT16
//	2   Level         UINT16
//	3   SystemTime    FILETIME
//	4   Computer      STRING
//	5+2i DataField[i] name   STRING  (== dataFieldNames[i])
//	6+2i DataField[i] value  STRING
package evtx

import (
	"encoding/binary"
	"unicode/utf16"
)

// decodeBinXML parses a BinXML payload and populates rec.
// Silently ignores payloads that do not match the expected template structure.
func decodeBinXML(payload []byte, rec *Record) {
	if len(payload) < preambleSize {
		return
	}
	// data_length is the last 4 bytes of the TemplateNode header (offset 34..38).
	dataLength := int(binary.LittleEndian.Uint32(payload[34:38]))
	subsStart := preambleSize + dataLength
	if subsStart > len(payload) {
		return
	}
	subs := parseSubstitutionArray(payload[subsStart:])
	applySubstitutions(subs, rec)
}

// parseSubstitutionArray parses the substitution array portion of a BinXML payload.
//
// Format:
//
//	[count: 4B LE]
//	[count × spec: (size:2B)(type:1B)(pad:1B)]
//	[value_data: concatenated raw bytes, one blob per substitution]
func parseSubstitutionArray(data []byte) []substitutionEntry {
	if len(data) < 4 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(data[0:4]))
	specsEnd := 4 + count*4
	if specsEnd > len(data) {
		return nil
	}

	// Collect sizes and types from spec section.
	sizes := make([]int, count)
	subs := make([]substitutionEntry, count)
	for i := range subs {
		off := 4 + i*4
		sizes[i] = int(binary.LittleEndian.Uint16(data[off : off+2]))
		subs[i].typ = data[off+2]
	}

	// Slice value_data blobs from the data section.
	dataOff := specsEnd
	for i := range subs {
		end := dataOff + sizes[i]
		if end > len(data) {
			break
		}
		subs[i].data = data[dataOff:end]
		dataOff = end
	}
	return subs
}

// applySubstitutions maps parsed substitution values onto rec.
func applySubstitutions(subs []substitutionEntry, rec *Record) {
	if len(subs) == 0 {
		return
	}

	getString := func(idx int) string {
		if idx >= len(subs) {
			return ""
		}
		return decodeSubString(subs[idx].data)
	}
	getUint16 := func(idx int) uint16 {
		if idx >= len(subs) || len(subs[idx].data) < 2 {
			return 0
		}
		return binary.LittleEndian.Uint16(subs[idx].data)
	}
	rec.Provider = getString(0)
	rec.EventID = getUint16(1)
	rec.Level = getUint16(2)
	if len(subs) > 3 && len(subs[3].data) == 8 {
		rec.TimeCreated = fromFILETIME(binary.LittleEndian.Uint64(subs[3].data))
	}
	rec.Computer = getString(4)

	rec.Fields = make(map[string]string, 12)
	for i := 0; i < 12; i++ {
		nameIdx := 5 + i*2
		valueIdx := 6 + i*2
		name := getString(nameIdx)
		if name == "" {
			name = dataFieldNames[i]
		}
		rec.Fields[name] = getString(valueIdx)
	}
}

// decodeSubString decodes a UTF-16LE byte slice (with null terminator) to a Go string.
// This is the inverse of encodeSubString in binxml.go.
func decodeSubString(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// Strip trailing null terminator if present.
	end := len(data)
	if data[end-2] == 0 && data[end-1] == 0 {
		end -= 2
	}
	if end == 0 {
		return ""
	}
	u16 := make([]uint16, end/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(u16))
}
