# EVTX format notes (v0.7.0)

This document is the durable record of what the v0.7.0 "format correctness"
release learned about the `.evtx` binary format. It exists because that
knowledge was produced by roughly twenty measurement tasks whose reports live
in `.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/` — a directory
excluded from git (`.superpowers/sdd/.gitignore`) — and in
`docs/format-baseline.md`, a 2,800-line chronological measurement log. Neither
survives as project memory once that branch is gone. This document does not
replace either: `docs/format-baseline.md` is the primary, blow-by-blow record
(commit hashes, CI run IDs, verbatim job output) and the task reports are the
primary record of *how* each thing was measured. This document is the
distillation a maintainer should read first, with pointers back to both for
anyone who needs the raw evidence.

**Convention used throughout:** every claim below is tagged **[measured]** —
derived by decoding real bytes from `testdata/system.evtx` (or a CI-run
fixture) ourselves, before or independent of writing code — or **[read: X]** —
taken from a named source's own prose. Where a claim was *both* read somewhere
and independently measured, both are cited. This distinction is not
decorative: see "Evidence discipline" at the end for why it mattered twice
during this release, once expensively.

## Sources, and whether they are worth reading

| Source | Verdict |
|---|---|
| **[MS-EVEN6]**, Microsoft's EventLog Remoting Protocol v6.0 | **Read this.** It is the *normative* specification for BinXml — the only source in this list Windows itself is implemented against. |
| **libyal / libevtx** format documentation | **Read this.** The most detailed *reverse-engineered* description available, and the only source with a complete value-type table. |
| **python-evtx** (`williballenthin/python-evtx`) | Useful as a working parser and as the source of our vendored fixture — **not** as an authority on correctness. See caveat below. |
| **0xrawsec/golang-evtx** | Skim its `doc/binxml.txt` for orientation; do not use its Go source. GPL-3.0. |
| Microsoft's "Event Log File Format" Win32 page | **Do not read this for EVTX.** It documents a different, obsolete format. |
| forensics.wiki and general forensics blog posts | Not worth the fetch. |

### [MS-EVEN6] — read this first

<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/>

Microsoft's own normative specification for the EventLog Remoting Protocol
v6.0, which defines BinXml as part of the wire/file encoding. This is the
document Windows' own `EventLogReader`/`Get-WinEvent`/`ToXml()` are
implemented against, which is why it out-ranks every reverse-engineered
source when the two disagree (see F9's `dependency_id` semantics below, where
MS-EVEN6's optionality model resolved an ambiguity libyal's prose alone left
open).

The sections that matter for this library:

| Section | GUID | What it covers |
|---|---|---|
| BinXml | `e6fc7c72-b8c0-475b-aef7-25eaf1a64530` | The token grammar itself |
| BinXml Templates | `522b3b91-f50c-4b69-ae69-1e978e61694a` | Template instance/definition structure |
| Optional Substitutions | `d58b2f89-ae8d-4cec-9acf-08631d946247` | `dependency_id`, `OptionalSubstitution` semantics |
| Type System | `8aa98312-f199-4e37-a51f-d3a2ccb50d60` | The value-type enumeration |
| Worked example | `f59be2a3-315d-43b2-987f-ddb8f81f022e` | An annotated hex dump of a real `<Event>` template, token by token |

The worked example is the single most useful page in the whole specification
tree: it is a real byte sequence with Microsoft's own per-token commentary,
which is what let this release cross-check its own `testdata/system.evtx`
decodes against a second, independently-authored source rather than trusting
either alone.

### libyal / libevtx — read this second

<https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc>

The most detailed reverse-engineered description of the EVTX container and
BinXml encoding available outside Microsoft, and the only source consulted
this release with a *complete* value-type table (reproduced in full below —
see "The substitution array"). Where its prose was ambiguous or silent (e.g.
the with-attributes `OpenStartElementTag` layout), this release resolved the
question by decoding `testdata/system.evtx` directly rather than guessing
from the prose — libyal is a strong reference, not a substitute for
measurement.

### python-evtx — a working parser, not an authority

<https://github.com/williballenthin/python-evtx> (Apache-2.0)

Used two ways this release: as `scripts/verify_python_evtx.py`'s parsing
engine in CI (`.github/workflows/format-verify.yml`), and as the source of
`testdata/system.evtx` (vendored from its `tests/data/` directory, itself
originally from the plaso project — see `testdata/README.md` for the full
chain and md5). Both uses are legitimate; treating a green python-evtx run as
proof of a well-formed file is not, and this release found that out directly.

**The caveat this release discovered the hard way: python-evtx is
permissive.** Its own source contains `# TODO: use this size() field` —
`data_size` (F10 below) is a field it parses but never validates against, so
a `data_size` that lies about its own content cannot break it — and,
independently, its `RootNode.substitutions()` tolerates a fixed-width type
(e.g. `GUID`, 16 bytes) whose declared size is off by up to 4 bytes rather
than rejecting the mismatch outright [measured: `task-8e-report.md`, Attempt
1's crash and its explanation]. **python-evtx going green after F1–F15 fixed
every structural divergence it can see is not evidence the file is
well-formed** — `Get-WinEvent`/`ToXml()` still reject every go-evtx-produced
file after all of them, including on record 0 of the simplest record the
encoder can produce (see "What is still unknown" below). Do not mistake
python-evtx compatibility for Windows compatibility again.

### 0xrawsec/golang-evtx — orientation only, not code

<https://github.com/0xrawsec/golang-evtx> — **GPL-3.0** [confirmed via the
repository itself].

An independent Go EVTX parser. Its `doc/binxml.txt` is what pointed this
release at MS-EVEN6 in the first place, so it is worth a skim for
orientation. Its Go source must never be copied into this library: go-evtx is
MIT-licensed, golang-evtx is GPL-3.0, and the two licenses are incompatible
for that purpose. If a second, independent Go-side format checker is ever
wanted for CI, it belongs in a separate repository/binary that calls out to
this one, not in-tree.

### Microsoft's "Event Log File Format" Win32 page — not applicable

<https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format>

**Do not use this page for EVTX work.** It documents the legacy `.evt`
format and says so itself: it is "no longer used starting with Windows
Vista." It describes `ELF_LOGFILE_HEADER` and a circular buffer of
fixed-layout records — EVTX (this library's format, `.evtx`) shares none of
that structure. Recorded explicitly so nobody on a future release loses an
afternoon to it the way an earlier draft of this project's own research
nearly did.

### forensics.wiki and general blog posts — skip

Index pages and analysis-oriented articles with no structural byte-level
detail beyond what libyal and MS-EVEN6 already give directly. Not worth
fetching for format work.

## The format, as this release verified it

Everything below reflects `HEAD` of `feat/v0.7.0-format-correctness` as of
this document. Every wire-format detail is cross-referenced against the Go
source (`binformat.go`, `binxml.go`, `chunkhash.go`) so it cannot drift
silently from the code; where this release found a divergence from an
earlier state, the defect ID (`F`-number or `B`-number) and fixing commit
are given so the history is traceable.

### File header (4096 bytes)

**[read: libyal, cross-checked measured against `testdata/system.evtx`]**
via `buildFileHeader` (`binformat.go`):

| Offset | Field | Notes |
|---|---|---|
| `[0:8]` | Signature | `"ElfFile\x00"` |
| `[8:16]` | `FirstChunkNumber` | always `0` |
| `[16:24]` | `LastChunkNumber` | `chunkCount - 1`, or `0` when `chunkCount == 0` — **F5**: previously computed as `uint64(chunkCount-1)` with no zero guard, which underflowed to `0xFFFFFFFFFFFFFFFF` and wrote garbage into every placeholder header |
| `[24:32]` | `NextRecordIdentifier` | the writer's own running record ID |
| `[32:36]` | `HeaderSize` | `128` |
| `[36:38]` | `MinorVersion` | `1` |
| `[38:40]` | `MajorVersion` | `3` |
| `[40:42]` | `BlockSize` | `4096` |
| `[42:44]` | `ChunkCount` | uint16 — **F5**: unbounded before this release; a file could reach 65536 chunks and wrap the counter, silently overwriting chunk 0. Now sticky-errors via `ErrTooManyChunks` at `maxChunksPerFile = 65535` |
| `[44:120]` | reserved | zeros |
| `[120:124]` | Flags | **F4**: never written before this release. `evtxFlagDirty` (`0x0001`) set while the log is open/rotating, cleared on a clean `Close()`; `evtxFlagFull` (`0x0002`) set once the file reaches a configured size limit |
| `[124:128]` | CRC32 | over `buf[0:120]` only — flags at `[120:124]` sit outside the checksum's range on purpose, so setting/clearing them on `Close()`/rotation never has to recompute it |
| `[128:4096]` | padding | zeros |

### Chunk header (512 bytes)

**[read: libyal, cross-checked measured]** via `buildChunkHeader`
(`evtx.go`) and `patchChunkCRC` (`binformat.go`):

| Offset | Field | Notes |
|---|---|---|
| `[0:8]` | Signature | `"ElfChnk\x00"` |
| `[8:16]` | `FirstEventRecordNumber` | |
| `[16:24]` | `LastEventRecordNumber` | |
| `[24:32]` | `FirstEventRecordIdentifier` | |
| `[32:40]` | `LastEventRecordIdentifier` | |
| `[40:44]` | `HeaderSize` | `128` |
| `[44:48]` | `LastEventRecordDataOffset` | **F3**: previously a duplicate of `FreeSpaceOffset` (`[48:52]`) instead of the chunk-relative offset where the *last* record's own data begins. A chunk with any records must never carry the same value in both fields — `TestChunkHeader_LastEventRecordDataOffset` pins this. |
| `[48:52]` | `FreeSpaceOffset` | where the next record would start |
| `[52:56]` | Event records CRC32 | `crc32(chunk[recordsStart:recordsEnd])`, written by `patchEventRecordsCRC` |
| `[120:124]` | unknown/constant | **B3** [measured against `testdata/system.evtx`]: every one of 9 real chunks carries `0x00000001` here; go-evtx never wrote it before this release. libyal's own docs label the field "Unknown" — lower-confidence than most fixes in this list, included because the real file both carries it and still verifies its own header CRC with that byte set. Must be written *inside* `patchChunkCRC`, not by an earlier caller — the function used to zero `[120:128]` unconditionally before computing the CRC, which would destroy this value if set beforehand. |
| `[124:128]` | Chunk header CRC32 | over `buf[0:120]` **and** `buf[128:512]` — i.e. it *does* cover the two hash tables below, and deliberately skips `[120:128]` so the constant above and the CRC itself don't need to be computed in a fixed order relative to each other |
| `[128:384]` | common-string hash table | 64 × uint32 buckets — see below |
| `[384:512]` | template hash table | 32 × uint32 buckets — see below |

**Ordering constraint, easy to get backwards:** `fillHashTables` (populating
`[128:512]`) must run *before* `patchChunkCRC`, since the CRC covers that
range. Reversing the order leaves every chunk with a stored CRC that doesn't
match its own bytes — a regression test
(`TestWrittenFile_ChunkHeaderCRCCoversTables`) pins the ordering by
recomputing the CRC over the written bytes.

### Event record wrapper

**[read: libyal/python-evtx layout, measured against `testdata/system.evtx`
for the trailing size copy]** via `wrapEventRecord` (`binformat.go`):

```text
[0:4]                 Signature = 0x00002A2A (LE)
[4:8]                 Size = 24 + len(BinXML payload) + 4
[8:16]                EventRecordID
[16:24]               TimeCreated (FILETIME, 100ns units since 1601-01-01)
[24:24+len(payload)]  BinXML payload
[end-4:end]           Size copy (same value as offset 4)
```

**Known gap: 8-byte record alignment (F2) was never implemented.** The
original spec (`docs/superpowers/specs/2026-08-08-durability-and-format-correctness-design.md`,
§F2) calls for rounding every record's `Size` up to the next multiple of 8,
with the padding bytes placed *between* the BinXML payload and the trailing
size copy — never inside the BinXML token stream itself, which would corrupt
parsing. A full task brief for it exists
(`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-7-brief.md`,
"Task 7b: 8-byte record alignment (F2)"), including the planned
`alignment_test.go`. **It was never executed**: during the Task 7 reorder,
the original alignment task was renamed "Task 7b" and the slot was filled
instead by the B1/B2/B3 fixes (fragment header, nested template fragment
header, chunk `[120:124]`) — a different, unrelated set of findings. No
commit in this release's history touches record alignment; `alignment_test.go`
does not exist; `wrapEventRecord`'s `Size` computation is unchanged from
before the release. This is a real, unresolved gap in this release's own
coverage, not a candidate that was tried and eliminated — flag it for
whoever picks this up next.

### The per-chunk hash tables

**[measured]** Two lookup structures let a parser find a name or template by
hash instead of walking every record. Both use the same SDBM rolling hash
(`chunkhash.go`):

```go
h = 0
for each 16-bit code unit c:
    h = uint32(c) + (h << 6) + (h << 16) - h
```

| Table | Buckets | Hash input | Bucket index |
|---|---|---|---|
| Common strings | 64 (`[128:384]`) | the name's UTF-16 code units | `sdbm(name) % 64` |
| Templates | 32 (`[384:512]`) | the **full 16-byte template GUID, read as 8 little-endian `uint16` units** | `sdbm(guid-as-8-uint16) % 32` |

Each bucket holds a chunk-relative offset to the first node with that key, or
`0` if empty; nodes in the same bucket chain through a `next_offset` field
that is the first 4 bytes of both the `NameNode` and `TemplateNode`
structures. **Registration rule** [measured, `chunkhash.go`'s own design]:
the *first* node with a given key wins its bucket slot; later nodes with the
same key are left unregistered (each record still reaches its own copy
through its own inline `name_offset`, so nothing is unreachable) — but
distinct keys that collide on a bucket *do* chain, in emission order, which
is what a parser walking the table expects.

**The measurement that established the template rule.** The original spec
text asserted templates bucket by `template_id % 32`, where `template_id` is
read as the first 4 bytes of the GUID interpreted as a little-endian
`uint32` — this was never checked before being written down. Measured
directly against two independent Windows-generated fixtures from
python-evtx's own test corpus, walking every populated bucket in every chunk
and re-deriving the assignment:

| Fixture | Chunks | Template entries | `template_id % 32` matched | SDBM-over-GUID-as-uint16 `% 32` matched |
|---|---|---|---|---|
| `system.evtx` | 17 | 146 | 10 | **146** |
| `security.evtx` | 33 | 240 | 0 | **240** |
| **Combined** | 50 | **386** | **10 / 386** | **386 / 386** |

The discredited rule scored at chance (10 of 386); hashing the 16 GUID bytes
individually rather than as 8 16-bit units scored zero on both files. The
corrected rule is not really a special case of the name rule — Windows feeds
the SDBM hash 16-bit units throughout, and a GUID is simply eight of them,
so template bucketing and name bucketing are one routine fed two different
inputs. The name-bucketing rule itself (`sdbm(name) % 64`) was confirmed
separately at 170/170 real `NameNode`s in `system.evtx`.

**Scope correction (2026-08-09): the template rule above holds for format
version 3.1 only.** Both fixtures behind the 386/386 figure are 3.1 files.
Measured against a larger corpus of format **3.2** files, the same rule scores
at zero. The name rule is unaffected and gains a large corroboration. See
"Format version 3.1 vs 3.2" immediately below.

**Hashing UTF-16 code units, not UTF-8 bytes, is what the format requires**
[read: libyal + MS-EVEN6, both describing names as UTF-16LE]. The two
encodings agree for ASCII, which is every name go-evtx currently emits, and
diverge above U+007F — worth remembering if a future caller ever needs a
non-ASCII field or element name.

Fixed as **F1**, commit `3c9e825` (wiring; the hash routines themselves
landed in earlier same-release commits). Populating the tables correctly was
necessary — `TestWrittenFile_ChunkTablesArePopulated` walks every bucket
chain in a real written file and re-derives each name's bucket from its own
hash — but **measured not sufficient on its own** to make Windows accept the
file (see "What is still unknown").

### Format version 3.1 vs 3.2

**[measured, 2026-08-09]** `MinorVersion` at file header `[36:38]` is 1 or 2.
Until this date every measurement in this release ran against 3.1 files only.
go-evtx writes 3.1 (`binformat.go:107-108`).

| Version | Windows | Source |
|---|---|---|
| 3.1 | Vista and later | libyal |
| 3.2 | Windows 10 (2004) and later | libyal |

**[read: libyal]** libyal documents **no** structural difference between 3.1
and 3.2 — it maps each to a Windows release and describes one uniform layout.

**[read: MS-EVEN6 scope]** Microsoft's normative spec covers *BinXml*, the
record payload encoding. The container — file header, chunks, the two hash
tables — is not in MS-EVEN6 and is not documented by Microsoft anywhere. Every
container claim in this file is therefore reverse-engineered by construction,
and no specification can settle a container question. This is the one area
where the project's "normative sources first" rule has no normative source to
reach for.

**[measured]** Every fixed field of the file header and the chunk header was
dumped side by side across a 3.1 file and two 3.2 files. `MinorVersion` is the
**only** differing structural field. Layout, field order, sizes and the CRC
placements are identical. The template definition layout is also identical
across versions — `next_offset(0) | GUID(4) | data_size(20) | fragment(24)` —
which matches libyal's own table once its offsets are renumbered from the
definition start rather than from the enclosing template instance.

**[measured]** The bucket rules, re-derived across four real files (2516
chunks). Distinct-key counts matter more than entry counts: a template
repeated in 40 chunks is one piece of evidence, not 40.

| File | Version | Name entries | Names matched | Distinct template GUIDs | Templates matched |
|---|---|---|---|---|---|
| `system.evtx` | 3.1 | 306 | **306** | 36 | **36** |
| `system2.evtx` | 3.2 | 9563 | **9563** | 13 | ~0 |
| `app.evtx` | 3.2 | 5906 | **5906** | 55 | **0** |
| `security.evtx` | 3.2 | 55388 | **55388** | 11 | **0** |
| **Combined** | — | **71163** | **71163** | — | — |

So:

- **The name rule is version-independent and now very strongly held**:
  `sdbm(name-as-UTF-16) % 64`, 71163 of 71163, both versions, no exception.
  This supersedes the earlier 170/170 figure.
- **The template rule is version-specific.** `sdbm(guid-as-8-uint16) % 32` is
  exact on 3.1 (36 of 36 *distinct* GUIDs; chance is 32⁻³⁶) and scores zero on
  3.2 (0 of 55 distinct GUIDs in `app.evtx`).

**What the 3.2 template rule is: still unknown.** Ruled out by measurement,
not by argument:

- *Not a layout shift.* Candidate GUID offsets 0..40 were swept; only +4
  produces the 3.1 result, and the surrounding fields (`data_size` at +20, the
  `0f 01 01 00` fragment header at +24) confirm +4 in 3.2 too.
- *Not a chaining artefact.* Head nodes — those addressed directly by the
  bucket array — score 0/1284 in `app.evtx` on their own.
- *Not a constant displacement.* The `(actual − predicted) mod 32` histogram is
  spread, not a spike.
- *Not keyed on libyal's "template identifier".* That 4-byte field 8 bytes
  before the definition is simply the GUID's first four bytes as a
  little-endian `uint32`; it is not an independent key.
- *Not any of twelve candidate hashes*: SDBM over raw bytes / big-endian
  `uint16`s, CRC-32 IEEE and Castagnoli, `Data1`, XOR-fold, byte sum, and the
  GUID hashed as canonical text in UTF-16 (upper and lower case, with and
  without braces). All at chance on 3.2.
- The bucket *is* a deterministic function of the GUID in 3.2 — each distinct
  GUID occupies exactly one bucket across all chunks — so a rule exists; we
  have not found it.

**Why this may not matter.** The tables are an index, not a requirement: a
parser can resolve every template through each record's inline
`template_offset`, which is what python-evtx does (`chunkhash.go:13-15`).
go-evtx declares 3.1 and writes the verified 3.1 rule, so it is internally
consistent. Declaring 3.2 while writing 3.1 tables would *introduce* an
inconsistency rather than remove one — the version byte is not a free knob.

**A correction to an earlier judgement in this session.** On first seeing the
version split I proposed bumping the writer to 3.2 as a cheap CI experiment.
That was too quick: it is a two-variable experiment (declared version × table
rule) in which only one cell is known. It is still worth running, but as a
deliberate probe with that caveat recorded, not as a likely fix.

### BinXML: fragment header, template instance, template definition

**[measured against `testdata/system.evtx`, cross-checked read: MS-EVEN6 /
libyal]** via `buildBinXML`/`buildTemplateBody` (`binxml.go`):

```text
[FragmentHeader:        4 bytes]
[TemplateInstanceNode:  10 bytes]
[TemplateNode header:   24 bytes]
[Template body:         nested FragmentHeader (4B) + XML token stream]
[Substitution array:    count + value-spec descriptors + value data]
```

**Fragment header (4 bytes), both outer and the nested one inside the
template body:**

```text
[token: 0x0F] [major: 0x01] [minor: 0x01] [flags: 0x00]
```

**[measured]** — the byte sequence `0f 01 01 00` occurs 3312 times in
`testdata/system.evtx`; the `0x00`-minor form (what go-evtx wrote before
this release) occurs only 7 times, all coincidental byte alignments
unrelated to real fragment headers. Fixed as **B1**.

Real templates also nest a second copy of this same 4-byte fragment header
at the very start of the template *body*, before the first element token —
**[measured]**: the template at chunk offset 24508 in `testdata/system.evtx`
declares `data_length 52` and its body at offset 24532 begins
`0f 01 01 00 01 ff …`. go-evtx did not emit this nested header before this
release; every downstream offset inside the template body shifts by 4 bytes
once it's added. Fixed as **B2**.

**TemplateInstanceNode (10 bytes):**

```text
[token: 0x0C] [unknown0: 1B] [template_id: uint32 LE] [template_offset: uint32 LE]
```

`template_offset` is the chunk-relative offset of the `TemplateNode` header
that immediately follows it in go-evtx's output (go-evtx always defines its
template inline, self-referencing — see "What is still unknown" for why that
matters).

**TemplateNode header (24 bytes)** [read: python-evtx's own layout,
structurally consistent with what `testdata/system.evtx` decodes to]:

```text
[next_offset: uint32 LE]   -- chaining slot for the template hash table
[GUID: 16 bytes]           -- first 4 bytes double as template_id
[data_length: uint32 LE]   -- length of the template body that follows
```

### The element token

**[measured against `testdata/system.evtx`, cross-checked read: libyal /
MS-EVEN6]** — `OpenStartElementTag`, both forms:

```text
without attributes: [token: 1B] [dependency_id: 2B] [data_size: 4B] [name_offset: 4B] [NameNode]
with attributes:     [token: 1B] [dependency_id: 2B] [data_size: 4B] [name_offset: 4B] [NameNode] [attr_list_size: 4B] [attributes…]
```

The inline `NameNode` sits at the **same fixed offset (`token_pos + 11`) in
both forms** — real Windows does not grow the element's own fixed header for
the with-attributes case, it moves `attr_list_size` out of the fixed header
and places it *after* the `NameNode`, immediately before the attribute list.
go-evtx wrote `attr_list_size` *before* the `NameNode` (in the fixed header)
until this release, which desynchronised a strict parser on the very first
attribute-bearing element it read — a parser following go-evtx's old stream
would read the `NameNode`'s own `next_offset` field (always `0`) as
`attr_list_size`, conclude the element had no attributes, and then look for
the next token at the wrong byte entirely. Fixed as **F11**, commit
`7631f93`.

- **Token byte**: `0x01` open-element / `0x41` "open-element, has attributes"
  — the high bit signals "more follows," the same convention `0x06`/`0x46`
  uses for attribute lists.
- **`dependency_id`** (2 bytes): **`0xffff` means "not set"** — the element
  always renders [read: libyal: `"-1 (0xffff) => not set"`]. Any other value
  is a live substitution index: MS-EVEN6 defines this as an *optionality*
  mechanism — the element is omitted from the rendered document when that
  substitution's value is `NULL`. **[measured]** every unconditional element
  in `testdata/system.evtx` (`<EventData>`, `<Provider>`, `<TimeCreated>`,
  `<Correlation>`, `<Execution>`, `<Security>`, `<Data Name=…>`) carries
  `0xffff`; elements whose sole content is one substitution
  (`<EventID>`, `<Level>`, `<Version>`, `<Task>`, `<Opcode>`, `<Keywords>`,
  `<EventRecordID>`) carry that substitution's own index. go-evtx wrote a
  bare `0` (a live reference to substitution 0, not the sentinel) for
  *every* element it ever emitted, before this release — fixed as **F9**,
  commit `4510103`.
- **`data_size`** (4 bytes): the byte count of everything from immediately
  after this field to the end of the element's own `EndElementTag`/
  `CloseEmptyElementTag` — i.e. `element_start + 7 + data_size` lands
  exactly on the element's structural end (`7` = token(1) +
  dependency_id(2) + data_size(4), the fixed bytes common to both forms
  before `data_size`'s own count begins). **[measured]**, formula matched
  33/33 elements across two structurally different real records at three
  nesting depths each, using a decoder that never itself reads `data_size`
  (it finds each element's end purely by matching open/close tokens) —
  and matches MS-EVEN6's own worked example exactly
  (`<Event>` at `0x1E`, `data_size 0x4E3`, `0x1E + 7 + 0x4E3 = 0x508`).
  go-evtx hardcoded this to `0` for every element before this release, fixed
  as **F10**, commit `9b8e974`.
- **`name_offset`** (4 bytes): chunk-relative offset of the inline
  `NameNode`; always `token_pos + 11` for go-evtx's own inline-only output.
- **`attr_list_size`** (4 bytes, with-attributes form only): counts *only*
  the attribute list itself — from immediately after its own 4 bytes up to,
  but not including, the following `Close(Start|Empty)ElementTag`. It does
  **not** cover the element's children or its own `EndElementTag` (those are
  already covered by `data_size`, which spans the whole element).
  **[measured]**: `attr_region_start + attr_list_size` landed exactly on the
  close-tag byte for all 3 elements sampled, with a value that summed
  exactly from the attribute's own bytes independently. go-evtx used to
  write this field with a value of `0` (before the NameNode-position fix,
  it wasn't even being read as this field by a real parser) — corrected
  alongside the position fix, same commit (**F11**, `7631f93`).

### Attribute tokens

**[measured]**:

```text
[token: 1B] [name_offset: 4B] [NameNode] [tail]
```

- Token `0x06` for the last (or only) attribute in a list, `0x46` ("more
  attributes follow") for every non-final one — the same high-bit
  convention as the element token. go-evtx's own template never wrote more
  than one attribute per element until Task 8b/8c added `Provider/@Guid` and
  the `Correlation`/`Execution`/`Security` attribute pairs, at which point
  `0x46` became live and necessary (F13b, commit `2e86005`).
- `NameNode` is inline in every attribute go-evtx emits, at the same
  self-referencing layout as element `NameNode`s.
- `tail` is one of: a literal `ValueText` (token `0x05`) for a fixed value
  known at encode time (`Provider/@Name` is a substitution in go-evtx despite
  the real file encoding it as a literal — a provider name/GUID varies per
  caller, so go-evtx keeps it a substitution rather than matching the real
  file byte-for-byte here); a `NormalSubstitution` (`0x0D`); or an
  `OptionalSubstitution` (`0x0E`) for an attribute whose value may be absent.

### The substitution array

**[measured layout, read: libyal for the complete value-type table]** via
`writeSubstitutionArray` (`binxml.go`):

```text
[count: uint32 LE]
[value_spec × count: uint16 size, uint8 type, uint8 padding]   -- 4 bytes each
[value_data: every value's raw bytes, concatenated, in array order]
```

The descriptor array is fixed-width and comes first, so a parser can compute
every value's start offset from the descriptors alone before reading any
value data.

**libyal's complete value-type table** [read:
libevtx's own "Value types" documentation — reproduced in full here because
it was the single most useful reference this release found; the array
variant bit is real Windows structure but go-evtx has never emitted one]:

| Hex | Name | Notes |
|---|---|---|
| `0x00` | `NullType` | NULL / empty |
| `0x01` | `StringType` | UTF-16LE, **no** end-of-string character in the value form (see below) |
| `0x02` | `AnsiStringType` | codepage-encoded, no end-of-string character |
| `0x03` | `Int8Type` | signed 8-bit |
| `0x04` | `UInt8Type` | unsigned 8-bit |
| `0x05` | `Int16Type` | signed 16-bit |
| `0x06` | `UInt16Type` | unsigned 16-bit |
| `0x07` | `Int32Type` | signed 32-bit |
| `0x08` | `UInt32Type` | unsigned 32-bit |
| `0x09` | `Int64Type` | signed 64-bit |
| `0x0a` | `UInt64Type` | unsigned 64-bit |
| `0x0b` | `Real32Type` | IEEE single precision |
| `0x0c` | `Real64Type` | IEEE double precision |
| `0x0d` | `BoolType` | 32-bit int, must be `0x00` or `0x01` |
| `0x0e` | `BinaryType` | raw binary data |
| `0x0f` | `GuidType` | 16 bytes, little-endian |
| `0x10` | `SizeTType` | 32 or 64-bit, context-dependent |
| `0x11` | `FileTimeType` | 64-bit FILETIME, little-endian |
| `0x12` | `SysTimeType` | 128-bit SYSTEMTIME, little-endian |
| `0x13` | `SidType` | NT Security Identifier |
| `0x14` | `HexInt32Type` | 32-bit int, rendered as hex |
| `0x15` | `HexInt64Type` | 64-bit int, rendered as hex |
| `0x20` | `EvtHandle` | undocumented by libyal |
| `0x21` | `BinXmlType` | a nested BinXML fragment (used for cache-referenced/nested templates) |
| `0x23` | `EvtXml` | undocumented by libyal |
| `0x80` (MSB) | array flag | set on the base type's byte to indicate an array variant (`0x81`–`0x95` for the applicable base types) |

**[measured]**: every value-type byte this release observed in real chunks
— `0x00, 0x04, 0x06, 0x08, 0x0A, 0x11, 0x13, 0x15, 0x21` — is in this table;
go-evtx currently emits a subset of it: `NullType`, `StringType`,
`UInt8Type` (F12a — `<Level>` is `UInt8`, not `UInt16` as earlier releases
wrote), `UInt16Type`, `UInt64Type`, `FileTimeType`, `HexInt64Type`. See
`binxml.go`'s `binXMLType*` constants and the substitution index map in
`CLAUDE.md` for exactly which index carries which type.

**String values are the one type with a documented asymmetry between two
different string occurrences** — do not conflate them:

- **`NameNode` strings** (element/attribute names) **are** null-terminated
  in the real file: `"Event"` decodes as `00000000 bc0f 0500 45 00 76 00 65
  00 6e 00 74 00 00 00` — 5 UTF-16LE characters followed by `00 00`.
- **Substitution-array `String`-typed *values*** carry **no** trailing null
  terminator [measured: 28/28 non-empty `String` substitution values sampled
  across 45 records, each with declared size exactly `char_count * 2`]. Fixed
  as **F15**, commit `b41ac76` (`encodeSubString` used to always append one).
- **Literal `ValueText` string attributes** (see below) also carry no
  trailing null terminator [measured directly against `xmlns`'s own 106-byte
  value in `testdata/system.evtx`].

### The rule that only `StringType` has a literal form

**[read: MS-EVEN6's own ABNF grammar, cross-checked read: libyal, then
measured against `testdata/system.evtx`]**. MS-EVEN6 defines exactly one
production for a literal value:

```abnf
ValueText = ValueTextToken StringType LengthPrefixedUnicodeString
```

`StringType` is hardcoded into the grammar — it is not a variable the
encoder selects — and there is no alternative `ValueText` production for any
of the other 20+ value types the same grammar defines. Every non-string
typed field is reachable **only** through the substitution array, via
`NormalSubstitution` (`0x0D`) or `OptionalSubstitution` (`0x0E`), never via a
literal. libyal's independent documentation agrees ("the value text …
consists of … `0x01` (StringType)"). Measured directly against two
self-contained real templates in `testdata/system.evtx` (each boundary
validated by an exact match between the walked length and the template's own
declared `data_length`): **15/15 real `ValueText` literals found are
`StringType`, zero exceptions; 35/35 real typed-scalar fields go through a
substitution, never a literal.**

Practical consequence: any future encoder change that tries to avoid the
substitution mechanism for a typed field (an integer, a FILETIME, a GUID) is
not expressible in the format at all — real Windows-authored files cannot
avoid it either, and still render correctly, which is itself informative (it
rules out "stop using substitutions here" as a category of fix — see below).

### Declared type vs. actual width: audited (1 of 42 disagreed), fix attempted and reverted (F16)

**[measured]** Task 9f audited all 42 of go-evtx's substitutions —
comparing the type declared in the template token, the type declared in
the value-spec descriptor, the byte width actually written, and the width
the normative type table above requires — and cross-checked the result
against a fresh, independent decode of `testdata/system.evtx`'s own record
0 substitution array (20 entries, done without reusing any earlier task's
byte-level claims). Two findings:

1. **Every one of the real file's 20 substitution entries, across all
   three records sampled, is width-consistent with its own declared type,
   without exception** — nine `NullType` entries at size 0, every
   fixed-width entry (`UInt8`/`UInt16`/`UInt32`/`UInt64`/`FileTime`/
   `HexInt64`) at exactly its required width. This is a general structural
   rule, not specific to any one field: real Windows never emits a
   fixed-width-typed substitution whose data doesn't fill that width.
2. **go-evtx violated that rule in exactly one of its 42 substitutions**:
   sub 41 (`EventID/@Qualifiers`) declared `UNSIGNED_WORD` (a 2-byte
   fixed-width type, per F13c) but was written with zero-length data.

**F16 tried the obvious correction — widen the data to 2 bytes, leave the
type unchanged — and it regressed `STAGE2 READ`**, from all 403 records to
failing after 0, the identical failure shape F14's *type*-change attempt
(Task 8e) already produced. Committed as `92a946a`, measured directly
against CI (`get-winevent` job, run `31295743089`, head SHA confirmed
matching), and reverted immediately at `4c31d77` per this release's own
"regress the hard-won win, revert first" rule. **The audit finding stands
— it is real and independently measured — but the obvious fix for it is
now eliminated, not merely untried**, alongside F14's type-change attempt.

Three independent perturbations of this one substitution have now all
regressed some Windows-side signal: changing the type to `NullType` (F14
Attempt 2), reclassifying it alongside five other fields to their
schema-normative types (F14 Attempt 1), and widening its data while
keeping the type (F16). The only configuration Windows has ever accepted
in full is the original: `UNSIGNED_WORD`, zero-length. **The leading
hypothesis this leaves**: `OptionalSubstitution`'s (`0x0E`) NULL-conditional
"value absent" semantics may be signalled by a substitution's *size* being
0, independent of its declared *type* — a fixed-width type carrying
zero-length data may be the format's actual, correct encoding for "this
field has a schema type, but this event doesn't populate it," and both
"change the type" and "fill the width" break that contract in different
ways. Untested: whether the other four `NullType`/`OptionalSubstitution`
fields (`Correlation/@ActivityID`/`@RelatedActivityID`,
`Execution/@ProcessID`/`@ThreadID`, `Security/@UserID`) would show the same
pattern if ever given a real, non-zero-length value of their own declared
type instead of `NullType` — not run this task, remains open.

The six fields the task brief flagged as never-audited against MS-EVEN6's
schema types (`Provider/@Guid` → `GuidType`, `Correlation/@ActivityID` and
`@RelatedActivityID` → `GuidType`, `Security/@UserID` → `SidType`,
`Execution/@ProcessID` and `@ThreadID` → `UInt32Type`) were all found
internally self-consistent as go-evtx actually declares them —
`NullType` for the four fields with no data source, `StringType` for
`Provider/@Guid` (go-evtx's `WriteRecord` API takes a GUID as a
caller-supplied string, not raw bytes) — even though none of them match
what a populated real record would declare for the same conceptual field.
Full table: `task-9f-report.md`.

## Everything this release fixed, in one table

Every row was measured against `testdata/system.evtx` before being coded,
using the CI harness in `.github/workflows/format-verify.yml` to check the
observable effect after. "Windows verdict" columns track this release's two
load-bearing signals: whether `python-evtx` extracts fields correctly, and
the two-stage `Get-WinEvent` harness this release built (`STAGE1 OPEN` /
`STAGE2 READ` via `.NET`'s `EventLogReader`, then the legacy
`Get-WinEvent`/`ToXml()` assertion). See `docs/format-baseline.md` for the
verbatim CI output behind every "changed"/"no change" cell.

| ID | Defect | Commit | python-evtx effect | Get-WinEvent effect |
|---|---|---|---|---|
| F3 | `LastEventRecordDataOffset` duplicated `FreeSpaceOffset` | `173fcf2` | none | none |
| F4 | Dirty/full flags never written | `173fcf2` | none | none |
| F5 | `chunkCount` overflow / `LastChunkNumber` underflow | `173fcf2` | none | none |
| F1 | Chunk string/template hash tables left zero | `3c9e825` | none | none |
| B1 | Fragment header minor version `0x00`→`0x01` | `62de633` | none | none |
| B2 | Template body missing its own nested fragment header | `62de633` | none | none |
| B3 | Chunk header `[120:124]` left `0` instead of `0x00000001` | `62de633` | none | none |
| F9 | `OpenStartElementTag.dependency_id` written `0` instead of the `0xffff` sentinel | `4510103` | none | none |
| F10 | `OpenStartElementTag.data_size` hardcoded `0` | `9b8e974` | none (python-evtx never reads this field) | none |
| F11 | `attr_list_size` misplaced (before `NameNode` instead of after) and zero | `7631f93` | none | none |
| F8 | No `xmlns` on `<Event>` | `3b3f575` | **`ObjectName 0/403` → PASS** | none |
| F12a | `<Level>` typed `UInt16`, real file uses `UInt8` | `deefe13` | none (stayed green) | none |
| F12b | `<System>` had 5 of 14 real children | `deefe13` | none (stayed green) | none |
| F12c | go-evtx never emitted `OptionalSubstitution` (`0x0E`) | `deefe13` | none (stayed green) | none |
| F13a | `EventID`/`Level` reclassified `0x0D`→`0x0E`, real `dependency_id` | `2e86005` | none (stayed green) | **`STAGE2 READ` 0 → all 403 records** (batched with F13b/F13c — see caveat below) |
| F13b | `<Provider>` gains a second attribute, `Guid` | `2e86005` | none (stayed green) | see F13a |
| F13c | `<EventID>` gains a NULL `Qualifiers` attribute | `2e86005` | none (stayed green) | see F13a |
| F15 | Substitution-array `String` values carried a spurious null terminator | `b41ac76` | none (stayed green) | none |
| F2 | 8-byte record alignment | **never implemented** | — | — |

**F13's attribution is genuinely unresolved, not simplified for this table.**
F13a/F13b/F13c were deliberately batched against one Step-1 measurement (the
same reasoning F12a/b/c used) and no CI run applied only one of the three.
Isolating which sub-fix (or combination) produced the `STAGE2 READ`
breakthrough would need a splice/bisection experiment that was never run —
state it as "the combination did it," not as a claim about any one of the
three.

**F14 is not in this table because it made no net code change.** Task 8e's
investigation (two attempts, both reverted) is documented in `binxml.go`'s
own doc comment above the `binXMLType*` constants and in `CLAUDE.md`'s
substitution index map section — read those before touching any of the six
NULL-valued `<System>`/`<EventID>` attribute fields again, since the
evidence there is genuinely contradictory (see "Evidence discipline" below).

**F16 is not in this table either, for the same reason.** Task 9f audited
all 42 substitutions' declared type against actual byte width, found one
disagreement (sub 41, `EventID/@Qualifiers`), and fixed it (widen the data
to match the declared type's required width) — but that fix regressed
`STAGE2 READ` and was reverted (commit `4c31d77`, after `92a946a`). Net
code change: none. See "Declared type vs. actual width" above and
`task-9f-report.md` for the full audit table and the size-not-type
hypothesis the regression leaves open.

## What is still unknown

**The central open question, stated precisely.** `.NET`'s
`EventLogReader.ReadEvent()`, called forward one record at a time, reads all
403 records of go-evtx's own test fixture without throwing (`STAGE2 READ:
ok, 403 records`, established at F13, commit `2e86005`). But
`EventLogRecord.ToXml()` — called either directly on a record `ReadEvent()`
already returned, or implicitly inside `Get-WinEvent`'s own assertion —
throws `"The data is invalid."` on **every** go-evtx-produced record this
release has ever measured, including the single simplest ASCII record the
encoder can produce. python-evtx renders the same records' XML successfully.
Two Windows APIs, reading identical bytes, give two different verdicts; the
gap is specifically in BinXML→XML *rendering* (template walk + substitution
application), not in record fetching, enumeration order, or file/log-level
metadata.

### Eliminated by construction — do not re-test these

- **The container (file header, chunk header, record wrapper, CRCs) is
  proven sound.** A real record's own BinXML (`testdata/system.evtx` chunk
  0 record 0, 2148 bytes, extracted via `Reader.ReadRaw()` and written back
  via `Writer.WriteRaw()` into an otherwise ordinary go-evtx file) renders
  completely under both `EventLogReader` and `Get-WinEvent`/`ToXml()` —
  Task 9a's "splice" experiment. The defect is entirely inside
  `binxml.go`'s own BinXML generation.
- **The outer preamble (fragment header + `TemplateInstanceNode` +
  `TemplateNode` header) is cleared in both directions.** Task 9b's hybrid
  fixtures: real body/substitutions with go-evtx's own trivial
  `template_id`/GUID → PASS; go-evtx's own body/substitutions with the real
  file's `template_id`/GUID → FAIL, identically to every other
  go-evtx-authored record. Neither direction changes the outcome.
- **Scale, chunk count, non-BMP strings, and boundary-sized records are not
  the trigger.** A minimal fixture — 1 record, 1 chunk, pure ASCII — fails
  identically to the 403-record, 27-chunk, non-BMP-bearing production
  fixture (Task 9a, Experiment A).
- **`<EventData>`'s structure and the substitution array's count/shape are
  not the trigger.** A ladder from `<System>` alone (18 substitutions, no
  `<EventData>` at all) up through one `Data` pair, to the full 12-pair
  control (42 substitutions) fails identically at every rung — no pass/fail
  boundary exists anywhere on that axis (Task 9c).
- **The hypothesis that `Data/@Name` must be a template-fixed literal rather
  than a substitution is refuted**, not merely untried — a variant with
  literal `Data/@Name`s at full 12-pair scale fails identically to the
  substituted-name control (Task 9c, rung 4).
- **The `<System>` self-closing-tag convention (5 attribute-only children
  closing via `0x03` in the real file vs. `0x02`+`EndElementTag` in
  go-evtx's own output) is eliminated** — correcting it, with every
  downstream offset rigorously recomputed, produces the identical exception
  (Task 9b, hybrid 3).
- **`OptionalSubstitution`/`dependency_id` as a mechanism is exonerated as
  the sole cause** — reverting every `0x0E` in `<System>` back to `0x0D`
  (with sentinel `dependency_id`s) at full control scale changes nothing
  (Task 9d, secondary rung A).
- **`xmlns`'s presence or absence changes nothing for `ToXml`/`Get-WinEvent`**
  — it is necessary for python-evtx's namespaced query (confirmed from both
  the addition direction, F8, and the removal direction, Task 9d rung B) but
  is orthogonal to the `ToXml` defect specifically.
- **"Don't use substitutions for typed values" is incoherent as a
  hypothesis** — MS-EVEN6's grammar gives no literal form for any non-string
  type, and real Windows files use the substitution mechanism for every
  typed scalar and still render (see "The rule that only `StringType`..."
  above). The decisive all-literal experiment this would require could not
  even be built.

### What remains live

- **A ten-substitution subset, narrowed but not resolved.** Forcing *every*
  substitution to `StringType` (`VariantAllString`, Task 9e) doesn't just
  fail to render — it regresses `STAGE2 READ` itself, from reading all
  records to failing on record 0, a strictly earlier failure than any
  control-scale measurement since F13. A paired secondary experiment
  (`VariantFourFieldsString`, forcing only `Security/@UserID`,
  `Execution/@ProcessID`, `Execution/@ThreadID`, `Keywords` to `StringType`)
  does **not** reproduce the regression, clearing those four. The
  regression's cause is therefore isolated to one or more of the other ten:
  `EventID`, `Level`, `SystemTime`, `Version`, `Task`, `Opcode`,
  `EventRecordID`, `Correlation/@ActivityID`, `Correlation/@RelatedActivityID`,
  `EventID/@Qualifiers`. This is a real, CI-measured finding — value types
  are **not** exonerated as a category, contrary to what the shrink ladder
  alone (Task 9c) suggested — but no experiment run this release narrows
  further than these ten. The concrete next step named in `task-9e-report.md`
  is a bisecting secondary rung starting with `EventID`/`Level`/`SystemTime`,
  the three fields Task 8d's own `PROP` probe showed `.NET` reads
  independent of `ToXml`.
- **`Qualifiers`'s declared type is an open, evidence-contradicting
  question**, not a settled one. `task-8b-report.md`'s own hex-decoded Step 1
  table said real Windows declares `EventID/@Qualifiers` as `UInt16Type`
  at size 0; a later byte-for-byte re-parse of the *same* real record found
  it declared `0x00` (`NullType`) there instead — but changing go-evtx to
  match that re-parse **regressed** `STAGE2 READ` from 403 records to
  failing on record 0. go-evtx currently ships with `Qualifiers` declared
  `UInt16Type` at size 0, chosen because CI accepts it, not because either
  hex-level reading has been confirmed to be the accurate one. Task 9f
  (F16) added a third, orthogonal data point: keeping the type
  (`UInt16Type`) but widening the data to a real 2 bytes **also**
  regressed `STAGE2 READ`, the identical failure shape. Every perturbation
  of this one field tried so far — change the type, or fill the width —
  has regressed something; only the original (`UInt16Type`, zero-length)
  survives. See `binxml.go`'s doc comment above the `binXMLType*` constants
  for the full, unreconciled account, including F16's size-not-type
  hypothesis (`OptionalSubstitution`'s NULL-conditional omission may key
  on size==0 regardless of declared type). The likeliest reconciliation,
  itself unchecked: the Step 1 table's *index* assignments — not only some
  of its *type* claims — may themselves be unreliable, and no task has
  independently re-derived them from scratch.
- **No go-evtx fixture in this entire release has ever produced a
  genuinely cache-referenced `TemplateInstance`.** Every record go-evtx
  writes defines its own template inline (a self-referencing
  `template_offset`, pointing at the `TemplateNode` header immediately
  following it), where every real Windows chunk this release decoded shares
  one template definition across many records via a real offset
  back-reference. Observed along the way (Task 9d), not tested — the spliced
  real record used in Task 9a's decisive experiment *also* defines its
  template inline and still passed, so inline definition per se is not
  disqualifying, but a genuinely shared/cache-referenced template has never
  been attempted from go-evtx's own encoder. Named here as the most concrete
  untried structural lead.
- **8-byte record alignment (F2) was never implemented** (see the Event
  record wrapper section above) — not eliminated, simply never attempted
  after the Task 7 reorder dropped it. Given that every other named
  candidate in the original spec and every candidate discovered along the
  way has now been tried, this is the most concrete *unattempted* item
  remaining, alongside the cache-referenced-template lead above.
- **`ToXml()` itself is not exonerated or implicated by the Task 9e
  finding.** Every variant that experiment measured that *reached*
  `ToXml()` (the four-field variant, the main fixture) still failed there
  with the same message every rung has shown since F13. What blocks
  `ToXml()` specifically, once a record is successfully read, remains
  completely open.

## Evidence discipline: what this release learned about its own process

Two habits turned out to matter more than any single byte-level fix, and are
worth stating explicitly for whoever continues this work.

**A changed error message is not evidence of a fix unless the fixture is
byte-identical.** Between the release's first two measurements,
`Get-WinEvent`'s error text changed from `"The event log file is corrupted."`
to `"The data is invalid."` with **zero writer code changed** — only the test
fixture did (record count, chunk count, a near-maximum record). Windows'
rejection message is content-dependent, not a stable fingerprint of one
specific defect. Every later row in `docs/format-baseline.md` records the
fixture's own record/chunk count and a `largestAccepted()`-derived boundary
length precisely so a later reader can check this before trusting a message
change — and several genuinely did move for reasons unrelated to any fix
(adding `xmlns`, adding `<System>` children, and similar growth all shift
the binary-searched `ObjectName` ceiling and the chunk count as pure
side effects of payload size, independent of whether the change fixed
anything).

**This release corrected its own written specification from measurement
twice, and regressed once by trusting a hex dump over CI.**

1. The spec's original F1 template-bucket rule (`template_id % 32`, the
   first 4 GUID bytes as a little-endian uint32) was never checked before
   being written down. Measurement scored it 10 of 386 real entries across
   two fixtures; the corrected rule (SDBM over the full GUID as 8
   little-endian uint16 units, `% 32`) scored 386 of 386. The spec document
   itself was rewritten to match (commit `828ad31`).
2. Task 8b's own brief framed `OptionalSubstitution` (`0x0E`) as needed only
   "for any element added in F12b whose value can be absent." The Step 1
   measurement against the real file showed Windows uses `0x0E` for *every*
   `<System>` child whose sole content is one substitution — including
   `EventID`/`Level`, fields go-evtx always supplies and which are never
   actually absent. The measured table, not the brief's summary prose, is
   what F13a's later work correctly extended from.
3. **The regression.** Task 8e trusted `task-8b-report.md`'s own
   hex-decoded Step 1 table — itself a real measurement, not a guess — and
   reclassified five NULL-valued `<System>`/`<EventID>` attribute fields
   from a generic `NullType` marker to their "real" types (`GuidType`,
   `SidType`, `UInt32Type`). This broke python-evtx immediately. Reverting
   to match a byte-for-byte *re*-re-parse of the real file's own bytes (which
   turned out to disagree with the original hex-decoded table at four
   positions) fixed python-evtx — but then **broke** `Get-WinEvent`'s
   `STAGE2 READ`, regressing it from reading all 403 records to failing on
   record 0. The fix that was demonstrably, byte-for-byte faithful to the
   real file's own hex dump was rejected by CI. `Qualifiers` was reverted
   again, on CI's evidence rather than the hex dump's, restoring the
   original byte-identical output. **The distinction that mattered: being
   correct about what the real file's bytes say is not the same claim as
   being correct about what makes Windows accept a file, and when the two
   disagree, CI is the one that gets to decide** — a hex dump proves what a
   real file contains, not what a given consumer requires.

**Select CI runs by matching `headSha` to `git rev-parse HEAD`, never by
recency.** An early row in `docs/format-baseline.md` cited a CI run whose
`head_sha` predated its own fix by two commits, because `gh run list --limit
N` was read by list position rather than checked against the actual pushed
SHA. The byte-identical result it reported was mechanically certain
regardless of whether the fix under test did anything — a wasted
measurement dressed as a real one. Every row after that correction verifies
`head_sha` via `gh run view <id> --json headSha` (or the `gh api` equivalent)
against `git rev-parse HEAD` before citing a run's output.
