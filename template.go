// template.go — template definitions and their per-chunk cache.
//
// Layout, confirmed against real files of both format versions and matching
// libyal's table once its offsets are renumbered from the definition start
// rather than from the enclosing template instance:
//
//	next_offset  u32   chain within the chunk's template hash bucket
//	guid         16 B  template identifier
//	data_size    u32   length of the body that follows
//	body         data_size bytes, itself starting with a fragment header
package evtx

import "fmt"

const templateDefHeaderSize = 24 // next_offset(4) + guid(16) + data_size(4)

// templateDef is one template definition resolved inside a chunk.
type templateDef struct {
	GUID [16]byte
	Body []byte // the BinXML body, aliasing the chunk buffer

	// BodyChunkOffset is the chunk-relative offset of Body[0]. Name and
	// template offsets inside the body are chunk-relative, so resolving them
	// needs this base.
	BodyChunkOffset int
}

// parseTemplateDef reads the definition at chunk-relative offset off.
func parseTemplateDef(chunk []byte, off int) (*templateDef, error) {
	if off < 0 || off+templateDefHeaderSize > len(chunk) {
		return nil, fmt.Errorf("go_evtx: template definition offset %d outside the chunk", off)
	}
	dataSize := int(le32(chunk[off+20:]))
	bodyStart := off + templateDefHeaderSize
	bodyEnd := bodyStart + dataSize
	if dataSize < 0 || bodyEnd > len(chunk) {
		return nil, fmt.Errorf(
			"go_evtx: template definition at %d declares a %d-byte body ending at %d, past the %d-byte chunk",
			off, dataSize, bodyEnd, len(chunk))
	}
	def := &templateDef{
		Body:            chunk[bodyStart:bodyEnd],
		BodyChunkOffset: bodyStart,
	}
	copy(def.GUID[:], chunk[off+4:off+20])
	return def, nil
}

// templateCache memoises definitions by their chunk-relative offset. It is
// valid for one chunk only; the reader discards it when it loads the next.
type templateCache map[int]*templateDef

func (c templateCache) get(chunk []byte, off int) (*templateDef, error) {
	if def, ok := c[off]; ok {
		return def, nil
	}
	def, err := parseTemplateDef(chunk, off)
	if err != nil {
		return nil, err
	}
	c[off] = def
	return def, nil
}
