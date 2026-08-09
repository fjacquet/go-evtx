// value.go — typed substitution values.
//
// Every substitution in a BinXML payload carries a declared type. We keep that
// type rather than flattening to a string: the JSON encoding is type-dependent,
// and the writer investigation turns on declared types (see the F14/F16 notes
// in docs/evtx-format-notes.md), so a decoder that discards them cannot serve
// as an oracle.
package evtx

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// ValueType is the value type declared in the file. Values are from libyal's
// complete table; the array variants are the scalar identifier with 0x80 set.
type ValueType uint8

const (
	ValNull       ValueType = 0x00
	ValString     ValueType = 0x01
	ValAnsiString ValueType = 0x02
	ValInt8       ValueType = 0x03
	ValUInt8      ValueType = 0x04
	ValInt16      ValueType = 0x05
	ValUInt16     ValueType = 0x06
	ValInt32      ValueType = 0x07
	ValUInt32     ValueType = 0x08
	ValInt64      ValueType = 0x09
	ValUInt64     ValueType = 0x0a
	ValReal32     ValueType = 0x0b
	ValReal64     ValueType = 0x0c
	ValBool       ValueType = 0x0d
	ValBinary     ValueType = 0x0e
	ValGuid       ValueType = 0x0f
	ValSizeT      ValueType = 0x10
	ValFileTime   ValueType = 0x11
	ValSysTime    ValueType = 0x12
	ValSid        ValueType = 0x13
	ValHexInt32   ValueType = 0x14
	ValHexInt64   ValueType = 0x15
	ValEvtHandle  ValueType = 0x20
	ValBinXML     ValueType = 0x21
	ValEvtXML     ValueType = 0x23

	valArrayFlag ValueType = 0x80
)

// Node is a placeholder so this file compiles ahead of Task 5, which replaces
// it with the real element-tree type in binxml_decode.go. Delete this
// declaration there — do not define Node twice.
type Node struct{}

var valueTypeNames = map[ValueType]string{
	ValNull: "Null", ValString: "String", ValAnsiString: "AnsiString",
	ValInt8: "Int8", ValUInt8: "UInt8", ValInt16: "Int16", ValUInt16: "UInt16",
	ValInt32: "Int32", ValUInt32: "UInt32", ValInt64: "Int64", ValUInt64: "UInt64",
	ValReal32: "Real32", ValReal64: "Real64", ValBool: "Bool", ValBinary: "Binary",
	ValGuid: "Guid", ValSizeT: "SizeT", ValFileTime: "FileTime", ValSysTime: "SysTime",
	ValSid: "Sid", ValHexInt32: "HexInt32", ValHexInt64: "HexInt64",
	ValEvtHandle: "EvtHandle", ValBinXML: "BinXml", ValEvtXML: "EvtXml",
}

func (t ValueType) String() string {
	if n, ok := valueTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("ValueType(%#02x)", uint8(t))
}

// Value is one decoded substitution value. Type is the type declared in the
// file and is preserved even when the value is absent.
type Value struct {
	Type ValueType

	absent bool   // declared type present, zero-length data
	num    uint64 // every fixed-width scalar, as raw bits
	str    string // String; also the rendered form of Guid and Sid
	raw    []byte // Binary
	node   *Node  // BinXML — populated in Task 5
}

// IsAbsent reports an optional substitution that carries a declared type but
// no data. Real Windows records use this: testdata/system.evtx encodes
// EventID/@Qualifiers as [size 0, type UNSIGNED_WORD].
func (v Value) IsAbsent() bool { return v.absent || v.Type == ValNull }

// Uint64 returns the raw bits of a fixed-width scalar. ok is false for absent
// values and for types that are not fixed-width scalars.
func (v Value) Uint64() (uint64, bool) {
	if v.absent {
		return 0, false
	}
	switch v.Type {
	case ValInt8, ValUInt8, ValInt16, ValUInt16, ValInt32, ValUInt32,
		ValInt64, ValUInt64, ValBool, ValFileTime, ValHexInt32, ValHexInt64, ValSizeT:
		return v.num, true
	}
	return 0, false
}

// Bytes returns the payload of a Binary value, or nil.
func (v Value) Bytes() []byte { return v.raw }

// Node returns the decoded fragment of a BinXml value, or nil.
func (v Value) Node() *Node { return v.node }

// Time converts a FileTime value. ok is false for any other type.
func (v Value) Time() (time.Time, bool) {
	if v.absent || v.Type != ValFileTime {
		return time.Time{}, false
	}
	return fromFILETIME(v.num), true
}

// String renders the value for human consumption. JSON uses MarshalJSON, which
// is type-aware in ways this is not.
func (v Value) String() string {
	if v.absent || v.Type == ValNull {
		return ""
	}
	switch v.Type {
	case ValString, ValGuid, ValSid:
		return v.str
	case ValInt8:
		return strconv.FormatInt(int64(int8(v.num)), 10)
	case ValInt16:
		return strconv.FormatInt(int64(int16(v.num)), 10)
	case ValInt32:
		return strconv.FormatInt(int64(int32(v.num)), 10)
	case ValInt64:
		return strconv.FormatInt(int64(v.num), 10)
	case ValUInt8, ValUInt16, ValUInt32, ValUInt64, ValSizeT:
		return strconv.FormatUint(v.num, 10)
	case ValBool:
		return strconv.FormatBool(v.num != 0)
	case ValReal32:
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(v.num))), 'g', -1, 32)
	case ValReal64:
		return strconv.FormatFloat(math.Float64frombits(v.num), 'g', -1, 64)
	case ValHexInt32:
		return fmt.Sprintf("0x%08x", uint32(v.num))
	case ValHexInt64:
		return fmt.Sprintf("0x%016x", v.num)
	case ValFileTime:
		return fromFILETIME(v.num).UTC().Format(time.RFC3339Nano)
	case ValBinary:
		return fmt.Sprintf("%x", v.raw)
	}
	return ""
}

// fixedWidths gives the exact byte width each fixed-width type requires.
var fixedWidths = map[ValueType]int{
	ValInt8: 1, ValUInt8: 1,
	ValInt16: 2, ValUInt16: 2,
	ValInt32: 4, ValUInt32: 4, ValReal32: 4, ValBool: 4, ValHexInt32: 4,
	ValInt64: 8, ValUInt64: 8, ValReal64: 8, ValFileTime: 8, ValHexInt64: 8,
}

// decodeValue decodes one substitution value. It is strict: an unknown type,
// an unsupported type, or a width that does not match the declared type is an
// error. Zero-length data is NOT an error — it means the optional substitution
// is absent, which real Windows records rely on.
func decodeValue(t ValueType, data []byte) (Value, error) {
	if t&valArrayFlag != 0 {
		return Value{}, fmt.Errorf("go_evtx: array value type %#02x is not supported "+
			"(measured zero occurrences across the corpus)", uint8(t))
	}
	if len(data) == 0 {
		return Value{Type: t, absent: true}, nil
	}
	if w, ok := fixedWidths[t]; ok {
		if len(data) != w {
			return Value{}, fmt.Errorf("go_evtx: %s declares %d bytes, got %d", t, w, len(data))
		}
		var n uint64
		switch w {
		case 1:
			n = uint64(data[0])
		case 2:
			n = uint64(binary.LittleEndian.Uint16(data))
		case 4:
			n = uint64(binary.LittleEndian.Uint32(data))
		case 8:
			n = binary.LittleEndian.Uint64(data)
		}
		return Value{Type: t, num: n}, nil
	}

	switch t {
	case ValNull:
		if len(data) > 0 {
			return Value{}, fmt.Errorf("go_evtx: Null value declares %d bytes of data", len(data))
		}
		return Value{Type: t, absent: true}, nil
	case ValString:
		s, err := decodeUTF16(data)
		if err != nil {
			return Value{}, err
		}
		return Value{Type: t, str: s}, nil
	case ValBinary:
		b := make([]byte, len(data))
		copy(b, data)
		return Value{Type: t, raw: b}, nil
	case ValGuid:
		if len(data) != 16 {
			return Value{}, fmt.Errorf("go_evtx: Guid declares 16 bytes, got %d", len(data))
		}
		return Value{Type: t, str: formatGUID(data)}, nil
	case ValSid:
		s, err := formatSID(data)
		if err != nil {
			return Value{}, err
		}
		return Value{Type: t, str: s}, nil
	case ValSizeT:
		switch len(data) {
		case 4:
			return Value{Type: t, num: uint64(binary.LittleEndian.Uint32(data))}, nil
		case 8:
			return Value{Type: t, num: binary.LittleEndian.Uint64(data)}, nil
		}
		return Value{}, fmt.Errorf("go_evtx: SizeT must be 4 or 8 bytes, got %d", len(data))
	case ValBinXML:
		// The nested fragment is decoded by the caller, which owns the chunk
		// context this decoder does not have. Task 5 fills in node.
		b := make([]byte, len(data))
		copy(b, data)
		return Value{Type: t, raw: b}, nil
	case ValAnsiString:
		return Value{}, fmt.Errorf("go_evtx: AnsiString is not supported: the format " +
			"carries no codepage, and it occurs zero times across the measured corpus")
	case ValSysTime, ValEvtHandle, ValEvtXML:
		return Value{}, fmt.Errorf("go_evtx: value type %s is not implemented "+
			"(zero occurrences across the measured corpus)", t)
	}
	return Value{}, fmt.Errorf("go_evtx: unknown value type %#02x", uint8(t))
}

// decodeUTF16 decodes UTF-16LE, tolerating one trailing null terminator.
// It returns an error if the remaining data (after null-terminator strip) has odd length.
func decodeUTF16(data []byte) (string, error) {
	end := len(data)
	if end >= 2 && data[end-2] == 0 && data[end-1] == 0 {
		end -= 2
	}
	if end == 0 {
		return "", nil
	}
	if end%2 != 0 {
		return "", fmt.Errorf("go_evtx: UTF-16 data has odd length %d", end)
	}
	u16 := make([]uint16, end/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return string(utf16.Decode(u16)), nil
}

// formatGUID renders the on-disk little-endian GUID struct in canonical form.
func formatGUID(g []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(g[0:4]),
		binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		binary.BigEndian.Uint16(g[8:10]),
		g[10:16])
}

// formatSID renders an NT security identifier as S-R-A-S1-S2-...
// Layout: revision(1), sub-authority count(1), authority(6, big-endian),
// then count little-endian uint32 sub-authorities.
func formatSID(data []byte) (string, error) {
	if len(data) < 8 {
		return "", fmt.Errorf("go_evtx: Sid needs at least 8 bytes, got %d", len(data))
	}
	revision := data[0]
	count := int(data[1])
	if len(data) != 8+count*4 {
		return "", fmt.Errorf("go_evtx: Sid with %d sub-authorities needs %d bytes, got %d",
			count, 8+count*4, len(data))
	}
	var authority uint64
	for _, b := range data[2:8] {
		authority = authority<<8 | uint64(b)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", revision, authority)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(data[8+i*4:]))
	}
	return sb.String(), nil
}

// maxExactJSONInt is the largest integer a JSON number holds exactly. Above
// it, encoders that parse into a float64 lose precision silently, so we quote.
const maxExactJSONInt = uint64(1) << 53

// MarshalJSON renders the value according to its declared type: numbers stay
// numbers, hex types keep their hex form, binary is base64, times are RFC 3339.
func (v Value) MarshalJSON() ([]byte, error) {
	if v.IsAbsent() {
		return []byte("null"), nil
	}
	switch v.Type {
	case ValString, ValGuid, ValSid:
		return json.Marshal(v.str)
	case ValBinary:
		return json.Marshal(base64.StdEncoding.EncodeToString(v.raw))
	case ValBool:
		return json.Marshal(v.num != 0)
	case ValInt8:
		return json.Marshal(int8(v.num))
	case ValInt16:
		return json.Marshal(int16(v.num))
	case ValInt32:
		return json.Marshal(int32(v.num))
	case ValUInt8:
		return json.Marshal(uint8(v.num))
	case ValUInt16:
		return json.Marshal(uint16(v.num))
	case ValUInt32:
		return json.Marshal(uint32(v.num))
	case ValInt64:
		n := int64(v.num)
		if n >= int64(maxExactJSONInt) || n <= -int64(maxExactJSONInt) {
			return json.Marshal(strconv.FormatInt(n, 10))
		}
		return json.Marshal(n)
	case ValUInt64:
		if v.num >= maxExactJSONInt {
			return json.Marshal(strconv.FormatUint(v.num, 10))
		}
		return json.Marshal(v.num)
	case ValSizeT:
		// SizeT shares UInt64's quoting rule: an 8-byte SizeT can exceed 2^53, and
		// a silently rounded number is the same defect quoting exists to prevent.
		if v.num >= maxExactJSONInt {
			return json.Marshal(strconv.FormatUint(v.num, 10))
		}
		return json.Marshal(v.num)
	case ValReal32:
		return json.Marshal(math.Float32frombits(uint32(v.num)))
	case ValReal64:
		return json.Marshal(math.Float64frombits(v.num))
	case ValHexInt32, ValHexInt64, ValFileTime:
		return json.Marshal(v.String())
	case ValBinXML:
		if v.node == nil {
			return nil, fmt.Errorf("go_evtx: BinXml value has no decoded fragment")
		}
		return json.Marshal(v.node)
	}
	return nil, fmt.Errorf("go_evtx: cannot marshal value type %s", v.Type)
}
