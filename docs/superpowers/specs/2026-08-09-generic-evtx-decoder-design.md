# Generic EVTX decoder — design

**Date:** 2026-08-09
**Status:** proposed, awaiting review
**Supersedes:** the reader portion of `2026-08-08-durability-and-format-correctness-design.md`

## Why

Two things are true at once, and this design serves both.

**A library gap.** go-evtx claims a read API. Pointed at a real Windows file
it returns records with empty `Provider`, zero `EventID`, and field names
fabricated from raw bytes read as UTF-16 — and reports **no error**. Colleagues
have asked for generic structured reading and JSON export, which the current
implementation cannot support at all.

**A stalled investigation.** The v0.7.0 format hunt has fixed thirteen
divergences and moved Windows from rejecting the file outright to
`STAGE2 READ: ok, 403 records`, but `EventRecord.ToXml()` still throws
`The data is invalid.`, `EvtGetExtendedStatus` returns empty, and every
remaining hypothesis costs a five-minute CI round trip to test. A decoder
validated against real files is the local oracle that loop lacks.

One component serves both. That is the argument for building it now rather
than either alone.

## What was measured

Two measurements from 2026-08-09 shape this design. Both are recorded in
`docs/evtx-format-notes.md`.

**The current decoder cannot detect its own failure.** Across 37 534 real
Windows records from two files:

| | `system.evtx` (3.1) | `app.evtx` (3.2) |
|---|---|---|
| decoded without error | 1601 | 35933 |
| non-empty `Provider` | 0 | 0 |
| non-zero `EventID` | 0 | 0 |

It emits field names like `"覱嫿䒦䒛܊캧䕘"` alongside our own hardcoded
`dataFieldNames` (`AccessList`, `SubjectLogonId` — Security-log names served
for an Application record), and occasionally lands real fragments
(`"Microsoft-Windows-User Profiles Service"`). It is reading the right bytes
and framing them wrongly, then reporting success.

This is not an undisclosed bug: `CLAUDE.md` already states the decoder targets
our own template format. The defect is that it cannot *tell* it is out of its
depth. That is precisely what disqualifies it as an oracle.

**Format version 3.1 vs 3.2.** The name bucket rule holds across both versions
(71 163 / 71 163). The template bucket rule is exact on 3.1 and scores zero on
3.2, and the 3.2 rule is undocumented by every available source. Consequence
for this design: **the test corpus must include a 3.2 file**, which the single
tracked fixture does not provide.

## Goals

1. Open any Windows-generated `.evtx` and return structured, typed events.
2. Serialise to JSON with types preserved, for downstream pipelines.
3. Fail loudly and precisely on anything not fully accounted for.
4. Serve as the differential oracle for the writer investigation.

## Non-goals

Explicitly out of scope, chosen with the requester:

- **XML rendering.** No `ToXml()` equivalent. We decode structure, not
  presentation. This removes the need for byte-faithful XML reproduction.
- **Filtering / query.** No selection by EventID, provider or time range, and
  therefore no lazy two-phase decode.
- **Writing anything new.** The writer is untouched by this work.

## Architecture

Single package `evtx`, zero external dependencies — both unchanged. The
decomposition is by file, one responsibility each.

| File | Responsibility |
|---|---|
| `value.go` | `ValueType`, `Value`, per-type decode, `MarshalJSON` |
| `binxml_decode.go` | token stream → node tree (replaces `binxml_reader.go`) |
| `template.go` | template definition parsing, per-chunk cache |
| `event.go` | `Event`/`System`/`Data` types, node tree → `Event` |
| `reader.go` | unchanged role: file, chunks, record framing |

The current decoder is replaced, not extended. It assumes 42 substitution
slots at fixed positions and reads field names from a hardcoded table; it never
reads a template definition from the file because it only ever re-read our own
writes. Generic decoding requires actually interpreting the stream: read the
chunk's template definition, rebuild the element tree, apply the substitution
array to it. The existing decoder becomes a special case of that, not the
other way round.

**The per-chunk template cache is not a gratuitous optimisation.** Many records
in a chunk reference the same definition by offset; `security.evtx` holds 9358
definitions against 184 000 records. Without a cache the same definition is
reparsed hundreds of times.

## Data model

### Values keep their declared type

The format carries a declared type per value. Converting to `string` or `any`
at decode time destroys it, and two consumers need it.

The JSON pipeline needs type-dependent rendering: `ProcessId` as a number, a
SID as `S-1-5-18`, a FILETIME as RFC 3339, binary as base64.

The oracle needs it absolutely. The entire F14/F16 investigation was about
declared types. A decoder that discards them cannot arbitrate the question it
is being built to answer.

```go
type Value struct {
    Type ValueType   // as declared in the file
    // typed payload, typed accessors, type-aware MarshalJSON
}
```

**Complete type table** [read: libyal/libevtx]. The codebase currently defines
seven of these. Array variants are the scalar identifier with bit 0x80 set.

| Hex | Name | | Hex | Name |
|---|---|---|---|---|
| 0x00 | NullType | | 0x0e | BinaryType |
| 0x01 | StringType (UTF-16LE) | | 0x0f | GuidType |
| 0x02 | AnsiStringType (codepage) | | 0x10 | SizeTType (32 or 64-bit) |
| 0x03 | Int8Type | | 0x11 | FileTimeType |
| 0x04 | UInt8Type | | 0x12 | SysTimeType (128-bit) |
| 0x05 | Int16Type | | 0x13 | SidType |
| 0x06 | UInt16Type | | 0x14 | HexInt32Type |
| 0x07 | Int32Type | | 0x15 | HexInt64Type |
| 0x08 | UInt32Type | | 0x20 | EvtHandle |
| 0x09 | Int64Type | | 0x21 | BinXmlType (nested fragment) |
| 0x0a | UInt64Type | | 0x23 | EvtXml |
| 0x0b | Real32Type | | 0x81–0x95 | array variants |
| 0x0c | Real64Type | | | |
| 0x0d | BoolType (32-bit, 0 or 1) | | | |

Two entries deserve attention at implementation. `BinXmlType` (0x21) is a
nested BinXML fragment — real files use it for `UserData`, so the decoder must
recurse. `SizeTType` (0x10) is 32- or 64-bit depending on the writer, so its
width comes from the value descriptor, not the type.

### Structure follows the format, not our template

```go
type Event struct {
    System    System   // fixed schema, typed
    EventData []Data   // ordered; Name empty when positional
    UserData  *Node    // arbitrary XML tree, nil when absent
}

type Data struct {
    Name  string
    Value Value
}

// Node is the generic decoded element tree, used where the format allows
// arbitrary XML rather than a known schema — UserData above all. It is what
// binxml_decode.go produces; System and EventData are assembled from it.
type Node struct {
    Name       string
    Attributes []Attr   // ordered
    Children   []Node   // ordered
    Value      *Value   // leaf content, nil for container elements
}

type Attr struct {
    Name  string
    Value Value
}
```

The ordered slice is required, not stylistic: many real events emit `<Data>`
elements with no `Name` attribute, which a `map[string]string` cannot represent
at all, and whose order carries the meaning.

### JSON mapping

Type-dependent, since preserving the declared type is the point. This table is
the contract for the pipeline goal:

| Value type | JSON |
|---|---|
| Null | `null` |
| String, AnsiString | string |
| Int8–Int64, UInt8–UInt64, Real32/64 | number |
| UInt64, Int64 | string when the value exceeds 2^53, else number — JSON numbers lose precision above that |
| Bool | boolean |
| Binary | base64 string |
| Guid | `"6e5c6d2d-…"`, canonical lower-case, no braces |
| FileTime, SysTime | RFC 3339 string, UTC |
| Sid | `"S-1-5-18"` |
| HexInt32, HexInt64 | `"0x0000000000000010"` — hex is the point of the type |
| SizeT | number |
| BinXml | the nested fragment's own decoded object |
| array variants | JSON array of the above |

`EventData` marshals as an array of `{name, value}` objects rather than an
object, because names are optional and may repeat; an object would silently
drop positional and duplicate entries.

## Errors and strictness

Strictness is the core property, not an option. The defect measured today is
not "the decoder is wrong" but "the decoder does not know it is wrong". A
decoder that emits content without being able to assert it accounted for every
byte reproduces that failure in a quieter form.

**Three checkable rules:**

1. Any unrecognised token, unrecognised value type, or length exceeding the
   payload is an error. The token table must be handled exhaustively —
   including `CloseEmptyElementTag` (0x03), CDATA (0x07/0x47), CharRef
   (0x08/0x48), EntityRef (0x09/0x49) and processing instructions (0x0a/0x0b),
   none of which the current code knows.
2. The decode must account for every byte of the payload. Stopping before the
   fragment's EOF token, or consuming past it, is an error even when a
   plausible tree was produced.
3. The number of substitutions consumed must equal the number the substitution
   array declares. **This rule alone would have caught the current decoder.**

**No partial output.** On error, return `nil` and the error — never an
incomplete `Event` with a `Partial` flag. A flag is today's defect repainted.

**Framing survives a decode failure.** The 24-byte record header carries the
size independently of the BinXML, so a failed record never prevents advancing
to the next. `ReadEvent()` returns `(*Event, error)` per record: across 184 000
events the caller learns record 91 234 is unreadable and decides for itself
whether to stop or continue.

**The error is the diagnostic.** It carries chunk index, record ID, byte offset
within the payload, what was expected and what was found. This is what makes it
usable as an oracle rather than merely as a failure signal.

## Test corpus

The three real files acquired on 2026-08-09 stay local and uncommitted: real
logs carry account names, SIDs, machine names and IP addresses, and this
repository is public; a real Security log also exceeds GitHub's 100 MB
per-file limit. Only derived results belong in the repo.

CI still needs material, and it now needs 3.2, which the tracked fixture does
not provide. Three sources with deliberately separated roles:

| Source | Version | Role |
|---|---|---|
| `testdata/system.evtx` (tracked, md5-pinned) | 3.1 | **Deterministic** tests: golden values, exact assertions |
| `wevtutil epl` on the `windows-latest` runner | 3.2 | **Non-deterministic** sweep: "decodes without error", never a golden |
| The four local files, behind an env var | 3.1 + 3.2 | Development coverage: 284 000 records, skipped cleanly when absent |

The runner-generated file costs nothing — no licence, no personal data, no
repository weight — but its content varies per run. **That distinction must be
written into the test itself**, or someone will hang a content assertion on it
and it will become intermittent.

## API break

`Record.Fields` changes type, so the public API breaks. The project is 0.x,
which semver permits, and the decision is to remove the old shape outright
rather than carry a deprecated adapter that lies.

Naming follows the format: a file holds *event records* (header: ID, timestamp,
size) each carrying an *event* (the decoded BinXML). `Record` keeps the header
level; `Event` becomes the decoded content. Today's `Record` conflates them.

Blast radius, all in-repo: `example_test.go`, `rotation_test.go`,
`reader_concurrency_test.go`, `reader_test.go`, `reader.go`, plus `docs/PRD.md`
and `CHANGELOG.md`.

## How this feeds the investigation

Once the strict decoder passes on real files of both versions, point it at our
own output. It will not say "Windows rejects this" — it will say "this differs
from what real files do", which is the question we have never been able to ask
except at five minutes per attempt. It becomes a test rather than a manoeuvre.

**Its limit, stated plainly.** Nothing guarantees the remaining defect lies
within what the decoder covers. It may sit in something real files and ours
encode identically, which Windows evaluates elsewhere. The oracle sharply
narrows the search space; it does not close it by construction. The splice
bisection — start from the real record that renders in our container, transform
stepwise toward our encoding — is the approach that converges, and it stays
queued behind this one because this one makes each of its steps local and
instant instead of a CI round trip.

## Sequencing constraint

**F2 (8-byte alignment) stays last**, unchanged from the earlier decision. It
changes record sizes, which would invalidate the 21-row measurement chain in
`docs/format-baseline.md` mid-investigation.

## Open risks

- **The 3.2 template bucket rule is unknown.** It does not block this work —
  the tables are an index, and a decoder can resolve every template through
  each record's inline `template_offset`. It is recorded so that no one later
  assumes the decoder validated it.
- **`AnsiStringType` needs a codepage** the format does not carry. Real files
  in the corpus should be checked for its frequency before choosing between
  assuming a codepage and erroring.
- **The corpus is one person's machine.** Four files from a single Windows
  install is broad coverage of records, narrow coverage of provider diversity.
