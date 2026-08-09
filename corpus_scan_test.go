package evtx

// corpus_scan_test.go — a fact dumper for a local corpus of real .evtx files.
//
// Why a test and not a cmd/: the facts worth measuring live in unexported
// structures (templateCache, parseSubstitutions, the template-definition
// header), and a cmd/ package cannot reach them. Exporting them would mean
// carrying a permanent public contract for what is scaffolding. An in-package
// test sees everything, adds no public surface, and skips unless a corpus
// path is handed to it — so CI never runs it.
//
// Why a dumper and not a suite of named invariants: an invariant only answers
// the question it was written for. One pass that emits structural facts as
// JSON Lines answers the questions we have not thought of yet — each becomes a
// one-line query over the output. Once a rule is confirmed, it graduates into
// a real assertion elsewhere.
//
// Two rules the output obeys, both load-bearing:
//
//   - Facts are reported for records the strict decoder REJECTS, with the
//     rejection recorded alongside. Measuring only what already decodes is the
//     round-trip blindness that hid every v0.6.0 defect.
//   - No string values are ever emitted — element and attribute names, types,
//     sizes, offsets and counts only. Real logs carry account names, SIDs,
//     machine names and IP addresses, and this output ends up quoted in docs/.
//
// Usage:
//
//	EVTX_CORPUS=/path/to/corpus go test -run TestCorpusScan -v .
//
// Writes JSON Lines to $EVTX_CORPUS_OUT (default: a file in os.TempDir(),
// whose path the test logs).

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fileFact, chunkFact and recordFact are the three record shapes the dumper
// emits. Kind discriminates them; every field is a count, an offset, a type or
// a hash — never content.
type fileFact struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Major   uint16 `json:"major"`
	Minor   uint16 `json:"minor"`
	Chunks  int    `json:"chunks"`
	Records int    `json:"records"`
	Decoded int    `json:"decoded"`
}

type chunkFact struct {
	Kind       string   `json:"kind"`
	Path       string   `json:"path"`
	Chunk      int      `json:"chunk"`
	Records    int      `json:"records"`
	FreeOff    int      `json:"free_off"`
	NameSlots  int      `json:"name_slots"`
	TmplSlots  int      `json:"tmpl_slots"`
	TmplOffs   []int    `json:"tmpl_offs"`
	TmplGUIDs  []string `json:"tmpl_guids"`
	DistinctID int      `json:"distinct_template_defs"`
}

type recordFact struct {
	Kind     string         `json:"kind"`
	Path     string         `json:"path"`
	Chunk    int            `json:"chunk"`
	Off      int            `json:"off"`
	Size     int            `json:"size"`
	SizeMod8 int            `json:"size_mod8"`
	OffMod8  int            `json:"off_mod8"`
	Payload  int            `json:"payload_len"`
	FragHdr  bool           `json:"frag_header"`
	DefOff   int            `json:"def_off"`
	Inline   bool           `json:"def_inline"`
	DefWhere string         `json:"def_where"` // before | inside | after — relative to this record
	GUID     string         `json:"tmpl_guid"`
	Subs     int            `json:"subs"`
	Types    map[string]int `json:"sub_types"`
	Trailing int            `json:"trailing"` // bytes after the substitution array
	ScanErr  string         `json:"scan_err,omitempty"`
	DecErr   string         `json:"decode_err,omitempty"`
}

// fragScan walks the top of one record payload exactly as
// decodeBinXMLFragment does, but records what it finds instead of validating
// it. Deliberately a separate walk: the decoder returns on the first rule
// violation, and a violated rule is precisely what this dumper exists to
// measure.
func fragScan(cache *templateCache, chunkOff, length int, f *recordFact) {
	chunk := cache.chunk
	if chunkOff < 0 || length < 0 || chunkOff+length > len(chunk) {
		f.ScanErr = "payload outside chunk"
		return
	}
	payload := chunk[chunkOff : chunkOff+length]

	pos := 0
	if len(payload) > 0 && payload[0] == tokFragmentHeader {
		f.FragHdr = true
		pos = 4
	}
	if pos+10 > len(payload) || payload[pos] != tokTemplateInstance {
		f.ScanErr = "no template instance"
		return
	}
	f.DefOff = int(le32(payload[pos+6:]))
	pos += 10
	f.Inline = f.DefOff == chunkOff+pos

	def, err := cache.get(f.DefOff)
	if err != nil {
		f.ScanErr = err.Error()
		return
	}
	f.GUID = hex.EncodeToString(def.GUID[:])
	if f.Inline {
		pos += templateDefHeaderSize + len(def.Body)
		if pos > len(payload) {
			f.ScanErr = "inline definition runs past the fragment"
			return
		}
	}

	subs, _, consumed, err := parseSubstitutions(payload[pos:])
	if err != nil {
		f.ScanErr = err.Error()
		return
	}
	f.Subs = len(subs)
	f.Types = make(map[string]int, len(subs))
	for i := range subs {
		f.Types[fmt.Sprintf("%#02x", uint8(subs[i].Type))]++
	}
	f.Trailing = len(payload) - (pos + consumed)
}

// scanEVTX walks one file's chunks and records, emitting one fact per file,
// per chunk and per record. It never stops on a bad record: a corpus scan that
// aborts at the first surprise measures nothing.
func scanEVTX(path, label string, emit func(any)) error {
	b, err := os.ReadFile(path) // #nosec G304 — a developer-supplied corpus path
	if err != nil {
		return err
	}
	if len(b) < int(evtxFileHeaderSize) || string(b[0:8]) != evtxFileMagic {
		return fmt.Errorf("not an evtx file")
	}
	ff := fileFact{
		Kind:   "file",
		Path:   label,
		Minor:  binary.LittleEndian.Uint16(b[36:38]),
		Major:  binary.LittleEndian.Uint16(b[38:40]),
		Chunks: int(binary.LittleEndian.Uint16(b[42:44])),
	}

	for ci := 0; ci < ff.Chunks; ci++ {
		start := int(evtxFileHeaderSize) + ci*int(evtxChunkSize)
		if start+int(evtxChunkSize) > len(b) {
			break
		}
		chunk := b[start : start+int(evtxChunkSize)]
		if string(chunk[0:8]) != evtxChunkMagic {
			continue
		}
		cache := newTemplateCache(chunk)

		cf := chunkFact{Kind: "chunk", Path: label, Chunk: ci,
			FreeOff: int(binary.LittleEndian.Uint32(chunk[48:52]))}
		for i := 0; i < 64; i++ {
			if binary.LittleEndian.Uint32(chunk[128+4*i:]) != 0 {
				cf.NameSlots++
			}
		}
		for i := 0; i < 32; i++ {
			if off := int(binary.LittleEndian.Uint32(chunk[384+4*i:])); off != 0 {
				cf.TmplSlots++
				cf.TmplOffs = append(cf.TmplOffs, off)
				if def, err := cache.get(off); err == nil {
					cf.TmplGUIDs = append(cf.TmplGUIDs, hex.EncodeToString(def.GUID[:]))
				}
			}
		}

		seenDefs := map[int]bool{}
		off := int(evtxChunkHeaderSize)
		for off+24 <= cf.FreeOff && cf.FreeOff <= len(chunk) {
			if binary.LittleEndian.Uint32(chunk[off:]) != evtxRecordSignature {
				break
			}
			size := int(binary.LittleEndian.Uint32(chunk[off+4:]))
			if size < 28 || off+size > len(chunk) {
				break
			}
			rf := recordFact{Kind: "record", Path: label, Chunk: ci, Off: off,
				Size: size, SizeMod8: size % 8, OffMod8: off % 8, Payload: size - 28}
			fragScan(cache, off+24, size-28, &rf)

			switch {
			case rf.DefOff >= off && rf.DefOff < off+size:
				rf.DefWhere = "inside"
			case rf.DefOff < off:
				rf.DefWhere = "before"
			default:
				rf.DefWhere = "after"
			}
			seenDefs[rf.DefOff] = true

			if _, err := decodeRecordBinXML(cache, off+24, size-28); err != nil {
				rf.DecErr = err.Error()
			} else {
				ff.Decoded++
			}
			emit(rf)

			cf.Records++
			off += size
		}
		cf.DistinctID = len(seenDefs)
		ff.Records += cf.Records
		emit(cf)
	}
	emit(ff)
	return nil
}

func TestCorpusScan(t *testing.T) {
	root := os.Getenv("EVTX_CORPUS")
	if root == "" {
		t.Skip("set EVTX_CORPUS to a directory of real .evtx files")
	}
	outPath := os.Getenv("EVTX_CORPUS_OUT")
	if outPath == "" {
		outPath = filepath.Join(os.TempDir(), "corpus-facts.jsonl")
	}
	out, err := os.Create(outPath) // #nosec G304 — a developer-supplied output path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	enc := json.NewEncoder(out)
	emit := func(v any) {
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
	}

	files, failed := 0, 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".evtx") {
			return nil //nolint:nilerr // an unreadable entry is skipped, not fatal
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			rel = filepath.Base(p)
		}
		if scanErr := scanEVTX(p, rel, emit); scanErr != nil {
			t.Logf("skip %s: %v", rel, scanErr)
			failed++
			return nil
		}
		files++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("scanned %d files (%d unreadable) -> %s", files, failed, outPath)
}

// decodedFloor is how many of testdata/system.evtx's 1601 records the strict
// decoder reads today.
//
// It is a crash-regression smoke gate, NOT a conformance target. system.evtx
// is excluded as evidence about the format: 55 of its records carry a
// Null-typed substitution with data, a construct occurring zero times in the
// other 320 398 records of the local corpus, and every rule this project mined
// it mined from this one file (see the plan's "Why system.evtx is out"). No
// task is judged by moving this number; it exists so that a decoder change
// which silently starts refusing records fails loudly.
//
// Asserted as a floor, never an equality, so it can only go up. 1496 before
// StringArray (0x81) landed; the 55 remaining failures are the Null-with-data
// construct, which stays deliberately unimplemented.
const decodedFloor = 1546

// TestCorpusScanTracked runs the dumper over the one fixture the repository
// tracks, so the scanner itself stays honest in CI. The counts are the file's
// own, measured: 3.1, 1601 records.
func TestCorpusScanTracked(t *testing.T) {
	var files []fileFact
	var records int
	err := scanEVTX("testdata/system.evtx", "system.evtx", func(v any) {
		switch f := v.(type) {
		case fileFact:
			files = append(files, f)
		case recordFact:
			records++
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d file facts, want 1", len(files))
	}
	got := files[0]
	if got.Major != 3 || got.Minor != 1 {
		t.Errorf("format version = %d.%d, want 3.1", got.Major, got.Minor)
	}
	if got.Records != 1601 || records != 1601 {
		t.Errorf("records = %d (emitted %d), want 1601", got.Records, records)
	}
	if got.Decoded < decodedFloor {
		t.Errorf("decoded %d of %d records, below the %d floor — a decoder regression",
			got.Decoded, got.Records, decodedFloor)
	}
	t.Logf("strict decoder read %d of %d records (floor %d)", got.Decoded, got.Records, decodedFloor)
}
