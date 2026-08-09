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
