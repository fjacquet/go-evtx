# Task 8b report: make the record a real event — `<System>`, value types, `OptionalSubstitution` (F12)

## Summary

Batched, per the brief: F12a (value types), F12b (the sparse `<System>`
block) and F12c (`OptionalSubstitution`) are three facets of one thing —
go-evtx's record didn't describe an event the way Windows describes an
event — fixed together against a single Step 1 measurement of
`testdata/system.evtx` rather than three single-defect tasks.

**Both numbers the brief asked for, up front:**

- **`STAGE2 READ`: still `FAILED after 0 records`** — unchanged, `"The data
  is invalid."`, identical to every row since row 5. No breakthrough on
  Windows.
- **python-evtx differential: stayed GREEN** —
  `OK: 403 records, all chunk checksums verify`, unchanged from the previous
  task. The regression guard the brief named held: this task did not break
  what Task 8 fixed.

## Step 1: decoding `<System>` from `testdata/system.evtx`, before any code changed

Re-ran the from-scratch BinXML walker built for the earlier tokendiff
investigation (`scratchpad/tokendiff/decode.py`) fresh against
`testdata/system.evtx`, not trusted from a prior task's cached output —
confirmed byte-identical output to the file already on disk
(`scratchpad/tokendiff/real_decoded.txt`), and cross-checked the position
arithmetic against Task 7e/7f's own independently-measured `data_size` for
`<Provider>` (783, 217) and `<System>` (749, 1158), which matched exactly.

Chunk 0, record 0 (`EventRecordID 12049`, provider
`Microsoft-Windows-Eventlog`), absolute file offsets. `<System>` opens at
749 (token `0x01`, no attributes, `dependency_id` `0xffff`, `data_size`
1158) and its own `EndElementTag` sits at 1913. Every child, in the real
file's own order:

| Element | Attribute(s) | Sub. token | dependency_id | Value-spec type | Size |
|---|---|---|---|---|---|
| `Provider` (783) | `Name` (824), `Guid` (903) | literal `ValueText` (`0x05`), not a substitution | `0xffff` | n/a (literal WSTRING) | 27 / 39 chars |
| `EventID` (1007) | `Qualifiers` (1046) | `0x0e` idx 4 | `0x0003` (= its own content idx) | `UNSIGNED_WORD` (`0x06`) | 0 (NULL) |
| — content (1086) | | `0x0e` idx 3 | | `UNSIGNED_WORD` (`0x06`) | 2 |
| `Version` (1091) | — | `0x0e` idx 11 | `0x000b` | `UNSIGNED_BYTE` (`0x04`) | 1 |
| `Level` (1132) | — | `0x0e` idx 0 | `0x0000` | **`UNSIGNED_BYTE` (`0x04`)** | 1 |
| `Task` (1169) | — | `0x0e` idx 2 | `0x0002` | `UNSIGNED_WORD` (`0x06`) | 2 |
| `Opcode` (1204) | — | `0x0e` idx 1 | `0x0001` | `UNSIGNED_BYTE` (`0x04`) | 1 |
| `Keywords` (1243) | — | `0x0e` idx 5 | `0x0005` | `HEX64` (`0x15`) | 8 |
| `TimeCreated` (1286) | `SystemTime` (1333) | `0x0e` idx 6 | `0xffff` | `FILETIME` (`0x11`) | 8 |
| `EventRecordID` (1373) | — | `0x0e` idx 10 | `0x000a` | `UNSIGNED_QWORD` (`0x0a`) | 8 |
| `Correlation` (1426) | `ActivityID` (1473), `RelatedActivityID` (1512) | both `0x0e`, idx 7 / 18 | `0xffff` | both `GUID` (`0x0f`) | 0 / 0 (NULL) |
| `Execution` (1566) | `ProcessID` (1609), `ThreadID` (1646) | both `0x0e`, idx 8 / 9 | `0xffff` | both `UNSIGNED_DWORD` (`0x08`) | 4 / 4 |
| `Channel` (1682) | — | literal `ValueText` (`0x05`) | `0xffff` | n/a (literal WSTRING) | 6 chars |
| `Computer` (1735) | — | literal `ValueText` (`0x05`) | `0xffff` | n/a (literal WSTRING) | 32 chars |
| `Security` (1840) | `UserID` (1881) | `0x0e` idx 12 | `0xffff` | `SID` (`0x13`) | 0 (NULL) |

**Where the brief's prose loses to this table.** F12c frames `0x0E` as
needed "for any element added in F12b whose value can be absent." The
measured table shows real Windows uses `0x0E` for **every** `<System>`
child whose sole content is one substitution value — including `EventID`
and `Level`, both pre-existing, both fields go-evtx always has real data
for (never absent). The brief's own text anticipates this exact case
("elements that are genuinely always present may legitimately stay
`0x0D`"), so `EventID`/`Level` were deliberately left `0x0D`/`0xffff` in
this implementation — the report says so loudly rather than silently
matching real Windows byte-for-byte, since that reclassification is
optional per the brief's own words and out of this task's named scope. A
future task revisiting this should read the table above, not the prose
summary.

## Step 2: failing tests, before implementation

`system_test.go` (new): `TestCollectSubstitutions_LevelIsUint8` (asserts
substitution 2's value type is `binXMLTypeUint8`) and
`TestBuildTemplateBody_NewSystemChildrenPresent` (asserts all fourteen new
element/attribute names' UTF-16LE encodings appear in the payload). Both
confirmed to fail against the pre-fix encoder — verified by inspecting
`git show HEAD~1:binxml.go` before writing the fix: `Level`'s substitution
was `binXMLTypeUint16` (`writeSubstitution(b, 2, binXMLTypeUint16)`), and
none of the fourteen new names appeared anywhere in the file (`grep -c
'"Version"'` etc. all `0`).

## Step 3: implementation

**F12a.** `collectSubstitutionsFromFields`'s substitution 2 now writes a
1-byte `binXMLTypeUint8` (`0x04`) entry instead of a 2-byte
`binXMLTypeUint16`; `buildTemplateBody`'s own `writeSubstitution(b, 2, ...)`
call matches. `Level`'s position, token (`0x0D`) and `dependency_id`
(`0xffff`) are unchanged — only the declared type moved.

**F12b.** Nine children added in the measured order: `Provider`, `EventID`,
`Version`, `Level`, `Task`, `Opcode`, `Keywords`, `TimeCreated`,
`EventRecordID`, `Correlation`, `Execution`, `Channel`, `Computer`,
`Security` — `Version` now sits between `EventID` and `Level`, a real
reordering (Task 8's release had `Level` immediately after `EventID`).
`EventRecordID` carries the writer's real record ID (`w.recordID`, plumbed
through a new `recordID` parameter on `buildBinXML`/
`collectSubstitutionsFromFields`). `Version`/`Task`/`Opcode`/`Keywords` have
no caller-supplied source, so each carries a typed zero rather than
invented data — matching `Version`'s own real value (`0`) in the sampled
record. `Correlation`/`Execution`/`Security`'s five attributes
(`ActivityID`/`RelatedActivityID`/`ProcessID`/`ThreadID`/`UserID`) have no
source either; each is NULL (value-spec size 0, type `0x00`) — reproducing
exactly how the real file itself encodes these fields for an event that
doesn't populate them (`Correlation`'s own `ActivityID` in the sampled
record is itself NULL per the table above), not inventing forensic data.
`Channel` follows `Computer`'s existing pattern: `NormalSubstitution`,
sourced from `fields["Channel"]`, defaulting to `""`.

**F12c.** New `writeOptionalSubstitution`/`writeAttributeOptional` mirror
the existing `writeSubstitution`/`writeAttributeSub`, emitting token `0x0E`.
`writeOpenElement`/`pushOpenElement`/`pushOpenElementAttrs` gained a real
`depID uint16` parameter (a new `depIDNotSet = 0xffff` constant replaces the
literal that used to be hardcoded inside `writeOpenElement`):
`Version`/`Task`/`Opcode`/`Keywords`/`EventRecordID`'s own
`OpenStartElementTag` now carries that substitution's own index as
`dependency_id`, matching the real file's convention exactly. `Correlation`/
`Execution`/`Security` stay `dependency_id` `0xffff` (element itself always
present, matching the real file) with their individual attribute values
`0x0E`-wrapped. `writeAttributeSub` gained a `moreAttrs bool` parameter
(token `0x46`, "more attributes follow") because `Correlation` and
`Execution` each need two attributes in one list — a token go-evtx had
never emitted before this task.

## Substitution index map: how it changed, and how everything was kept in sync

0–28 are **unchanged** — the 12 caller-facing data fields
(`dataFieldNames`, indices 5–28) keep their exact original indices and
semantics; nothing calling `WriteRecord` needs to change, and no caller is
renumbered out from under it. New indices 29–39 are appended after the
existing ones (not interleaved), specifically so this guarantee holds
without special-casing:

| Index | Field | Type |
|---|---|---|
| 29 | Version | UINT8 (always 0, no source) |
| 30 | Task | UINT16 (always 0, no source) |
| 31 | Opcode | UINT8 (always 0, no source) |
| 32 | Keywords | HEXINT64 (always 0, no source) |
| 33 | EventRecordID | UINT64 (writer's own record ID) |
| 34 | Correlation/@ActivityID | NULL |
| 35 | Correlation/@RelatedActivityID | NULL |
| 36 | Execution/@ProcessID | NULL |
| 37 | Execution/@ThreadID | NULL |
| 38 | Channel | STRING (`fields["Channel"]`) |
| 39 | Security/@UserID | NULL |

`binxml.go` (encoder), `binxml_reader.go` (decoder) and `CLAUDE.md` were
updated together in the same commit, per the task's instructions.
`binxml_reader.go` needed one real behavioural change beyond the doc
comment: `Level` decodes as a 1-byte value now, not 2 — a new `getUint8`
helper (the pre-existing `getUint16` requires `len(data) >= 2` and would
have silently returned `0` for every record's `Level` field otherwise, a
regression a byte-for-byte decoder change like this could easily have
introduced unnoticed). Indices 29–39 are parsed by
`parseSubstitutionArray` like every other entry (it is already fully
generic over count and per-entry size, including `0`) but are not surfaced
on `Record`: most have no caller-supplied source, and `EventRecordID`'s
value is already exposed as `Record.RecordID` from the event record
header, not from BinXML. `CLAUDE.md`'s "BinXML substitution index map"
table and the surrounding prose were rewritten to match, including an
explicit note on the `EventID`/`Level` scope decision above.

`reader_test.go`'s round trip (`TestReadRecord_RoundTrip`,
`TestReadRecord_MultipleRecords`) passed unmodified, confirming encoder and
decoder agree.

## Round trip and the hash-table integration test, run deliberately

```text
=== RUN   TestReadRecord_RoundTrip
--- PASS: TestReadRecord_RoundTrip (0.01s)
=== RUN   TestReadRecord_MultipleRecords
--- PASS: TestReadRecord_MultipleRecords (0.01s)
=== RUN   TestWrittenFile_ChunkTablesArePopulated
    hashtable_integration_test.go:66: 26 names reachable through the table
--- PASS: TestWrittenFile_ChunkTablesArePopulated (0.02s)
=== RUN   TestWrittenFile_ChunkHeaderCRCCoversTables
--- PASS: TestWrittenFile_ChunkHeaderCRCCoversTables (0.02s)
```

26 names, not Task 8's 12: the 14 new unique names this task adds
(`Version`, `Task`, `Opcode`, `Keywords`, `EventRecordID`, `Correlation`,
`ActivityID`, `RelatedActivityID`, `Execution`, `ProcessID`, `ThreadID`,
`Channel`, `Security`, `UserID`) — exactly `12 + 14 = 26`. Offsets moved
substantially (every element after `EventID` shifted, and `Version`'s
insertion moved `Level` too) and re-verified clean: every reported bucket
offset decodes to a `NameNode` whose hash matches the bucket it's chained
into.

`attrlist_test.go` needed no logic changes (only the `buildBinXML` call
signature): its scan is keyed off `attr_list_size` arithmetic that is
identical regardless of attribute count or the `0x06`/`0x46` distinction,
and it found 18 attribute-bearing elements (up from 15: `Correlation`,
`Execution`, `Security` added; `Event`/`Provider`/`TimeCreated`/12×`Data`
unchanged).

`dependency_test.go` needed two real changes:

1. **Bounded the scan to the template body** (`preambleSize` through
   `preambleSize + data_length`, the same region `decodeBinXML` locates
   from `payload[34:38]`) instead of the whole payload. The pre-existing
   test scanned past the template body into the substitution array/value
   data — harmless before this task, but Task 8b's new bytes (a NULL
   entry's absence of data, `EventRecordID`'s small `uint64`, encoded as
   `01 00 00 00 00 00 00 00`) produced one genuine coincidental
   false-positive header match there (`dependency_id 0x0000` at payload
   offset 2589) that was never in this scanner's actual scope.
2. **Recognises the five legitimate new dependency IDs** (29–33, via a new
   `knownOptionalDependencyIDs` map and `isRecognisedDependencyID` helper,
   shared with `datasize_test.go` if a future change needs it) instead of
   flagging them as corruption. Also extended the existing "more attributes
   follow" collision guard to cover `0x46`, not just `0x06`, for the same
   reason Task 8's own guard was needed for `0x06`.

`datasize_test.go` needed no logic changes: its filter (`dependency_id ==
0xffff`) simply skips the five new non-sentinel elements rather than
erroring, so its existing 24-element check (up from 20 — the net effect of
Task 8b's changes among `0xffff`-dependency elements: `+Correlation
+Execution +Channel +Security`, `Version`/`Task`/`Opcode`/`Keywords`/
`EventRecordID` excluded by design) still exercises the same back-patch
mechanism (`writeEndElement`) every new element also goes through, so its
correctness for the five skipped elements is not independently
demonstrated by this test but is guaranteed by the shared code path.

## Golden file: +649 bytes

`testdata/binxml-golden.bin` grew from **1950 to 2599 bytes (+649)** — the
eleven new substitution slots' value-spec entries plus the nine new
elements' full token structure (open tags, attribute lists, NameNodes,
substitution/value tokens, end tags). Regenerated via the documented
procedure: a throwaway `TestCaptureGolden` (written, run once, output
verified, then deleted before commit — never committed itself).

## Verification: all four gates

```console
$ go build ./...
$ GOOS=windows go build ./...
$ go test -race ./... -count=1
ok  	github.com/fjacquet/go-evtx	16.259s
$ go vet ./...
$ golangci-lint run
0 issues.
```

## Commit and push

- `deefe13` — `fix: make the record a real event — System, value types,
  optional substitution (F12)`. Files: `CLAUDE.md`, `attrlist_test.go`,
  `binxml.go`, `binxml_reader.go`, `datasize_test.go`, `dependency_test.go`,
  `evtx.go`, `evtx_test.go`, `namespace_test.go`, `nodecollect_test.go`,
  `reader_concurrency_test.go`, `system_test.go` (new),
  `testdata/binxml-golden.bin` (regenerated).

Pushed to `feat/v0.7.0-format-correctness`.

### Run selection, by head SHA (not by recency)

```console
$ git rev-parse HEAD
deefe13b72e5da62436c0524914d26f21ff068c4
$ gh api repos/fjacquet/go-evtx/actions/runs/31278789309 --jq '.head_sha'
deefe13b72e5da62436c0524914d26f21ff068c4
$ gh api repos/fjacquet/go-evtx/actions/runs/31278789562 --jq '.head_sha'
deefe13b72e5da62436c0524914d26f21ff068c4
```

Both `Format Verify` (`31278789309`) and the standard `CI` workflow
(`31278789562`, build/test/lint on push) confirmed at this exact commit.
`CI` completed with `success` (`ci / ci` and `security / security` both
succeeded). `Format Verify`'s overall conclusion is `failure` — per-job:

```console
$ gh run view 31278789309 --json jobs --jq '.jobs[] | {name, conclusion}'
{"name":"generate","conclusion":"success"}
{"name":"get-winevent","conclusion":"failure"}
{"name":"python-evtx-differential","conclusion":"success"}
```

### Fixture identity — NOT byte-identical to row 10

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31248 runes)
...
go_evtx_chunk_flushed path=artifacts/generated.evtx chunk=25 total_chunks=26
```

31248 runes (down from 31573) and **26 chunks (up from 22)**: the larger
per-record payload settles `largestAccepted()`'s binary search lower and
pushes more chunk-fill boundaries — the same mechanism Task 8's own
139-byte growth produced, scaled up (this task adds far more bytes per
record). Per every prior task in this series, this makes any record-count
or message comparison to rows 2-9 invalid on its own — only the open/read
stage split and the python-evtx result stay interpretable across the
boundary.

Job log (`generate`):
<https://github.com/fjacquet/go-evtx/actions/runs/31278789309/job/93156614017>

### python-evtx differential: stayed GREEN — the regression guard the brief named held

```text
OK: 403 records, all chunk checksums verify
```

Unchanged from the previous task's row. This is the number the brief said
mattered most to check first — a regression here would mean this task
broke what Task 8 fixed, and that would be worse than any Windows result.
It did not regress: python-evtx still parses every record, every `<Data>`
element, and every chunk checksum cleanly, including all nine new
`<System>` children and every `0x0E` token — python-evtx's own parser does
not specially validate `OptionalSubstitution`'s NULL-omission semantics, so
this is expected, but it is still the checkable, independent confirmation
the brief asked to protect.

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31278789309/job/93156675064>

### Get-WinEvent measurement — verbatim

```text
STAGE1 OPEN: ok
STAGE2 READ: FAILED after 0 records - System.Management.Automation.MethodInvocationException: Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31278789309/job/93156675052>

## `STAGE2 READ` and python-evtx: the two numbers that matter, read plainly

**`STAGE2 READ`: still zero.** Identical exception type, wording, and
record count to every row since row 5, including row 10, whose fixture and
payload shape were both very different from this one. This was the
release's strongest remaining candidate by the brief's own framing — a
record that finally describes itself the way Windows describes an event,
fixed as one batch rather than one field at a time — and it still did not
move `Get-WinEvent`'s record-1 rejection off zero.

**python-evtx: `OK: 403 records, all chunk checksums verify` — PASS,
unchanged.** The regression guard held. A null result on `Get-WinEvent`
with python-evtx still green is, per the brief's own framing, a real,
reportable outcome — not a failure of this task, and not softened here.

**Together**, these results say: whatever `.NET`'s `EventLogReader`
requires is not fully captured by any single divergence this release's
investigation found — a value-type mismatch, a sparse `<System>` block, and
the complete absence of `OptionalSubstitution`, all now fixed, individually
and in combination — or it requires several of these in combination with
something not yet identified in `tokendiff-report.md` or the escalation
report. Thirteen tasks (F1/F3-F11, B1-B3, F8, F12) have now each
independently corrected a real, measured divergence from the real file with
zero effect on `STAGE2 READ`.

## Files changed

- `binxml.go` — new `binXMLAttributeMore` (`0x46`), `binXMLOptionalSubstitution`
  (`0x0E`), `binXMLTypeNull`/`binXMLTypeUint8`/`binXMLTypeUint64`/
  `binXMLTypeHexInt64` constants; new `depIDNotSet` sentinel constant; new
  `sub*` substitution-index constants (29–39); `buildTemplateBody` reordered
  and extended to the real file's 14-child `<System>`;
  `collectSubstitutionsFromFields` gained a `recordID` parameter and 11 new
  entries; `writeOpenElement`/`pushOpenElement`/`pushOpenElementAttrs`
  gained a `depID` parameter; `writeAttributeSub` gained a `moreAttrs`
  parameter; new `writeAttributeOptional`/`writeOptionalSubstitution`.
- `binxml_reader.go` — `Level` now decoded via a new `getUint8` helper;
  doc comments updated for the new index range.
- `evtx.go` — both `buildBinXML` call sites in `WriteRecord` pass
  `w.recordID`.
- `CLAUDE.md` — "BinXML substitution index map" table extended to 29–39
  with the F12a/F12b/F12c scope decisions explained.
- `dependency_test.go` — scan bounded to the template body; recognises the
  five new legitimate dependency IDs; extended the attribute-skip guard to
  `0x46`.
- `attrlist_test.go`, `datasize_test.go`, `evtx_test.go`,
  `namespace_test.go`, `nodecollect_test.go`, `reader_concurrency_test.go`
  — `buildBinXML` call sites updated for the new `recordID` parameter; no
  logic changes.
- `system_test.go` (new) — Task 8b's Step 2 tests:
  `TestCollectSubstitutions_LevelIsUint8`,
  `TestBuildTemplateBody_NewSystemChildrenPresent`.
- `testdata/binxml-golden.bin` — regenerated; 1950 → 2599 bytes (+649).
- `docs/format-baseline.md` — row 11 and a new "Task 8b" section recording
  this measurement.

## Concerns / things a follow-up task should know

1. **`EventID` and `Level` are not encoded exactly like the real file.**
   Both are pre-existing fields go-evtx always has real data for, so both
   were left `NormalSubstitution` (`0x0D`) / `dependency_id` `0xffff`
   rather than reclassified to `OptionalSubstitution` (`0x0E`) with a real
   dependency_id — a choice the brief's own text explicitly permits
   ("elements that are genuinely always present may legitimately stay
   `0x0D`"), but the measured table shows the real file uses `0x0E` for
   both anyway. If a future task wants to match the real file byte-for-byte
   on this specific point, the Step 1 table above already has the exact
   values needed (`EventID` → `0x0003`, `Level` → `0x0000`).
2. **`Provider`'s `Guid` attribute and `EventID`'s `Qualifiers` attribute
   are still absent.** The real file has both; F12b's brief did not name
   either, and this task did not add them (out of scope as written). Noted
   here so the next task doesn't have to re-derive it from the diff.
3. **Fourteen tasks into this release, `STAGE2 READ` has never moved off
   zero**, including this one, which was explicitly framed as the
   strongest remaining candidate. Every named lead from
   `tokendiff-report.md` and the escalation report has now been
   individually fixed. A future task should treat this as strong evidence
   that either .NET's `EventLogReader` requires a defect not yet
   identified by this release's investigation method (byte-level diff
   against two real records plus MS-EVEN6's worked example), or requires a
   combination of already-fixed pieces this task's own batching did not
   fully replicate (e.g. `Provider/@Guid`, `EventID/@Qualifiers`, or the
   `EventID`/`Level` `0x0E` reclassification noted in concern 1) — worth
   trying the remaining known-real-but-unimplemented details as one more
   batch before assuming the defect lies entirely outside what has been
   measured so far.

## Correction note (Task 8e, F14)

**The Step 1 table above is wrong at exactly four positions.** It states
`Correlation/@ActivityID` (idx 7) and `@RelatedActivityID` (idx 18) are
typed `GUID (0x0f)`, `Security/@UserID` (idx 12) is typed `SID (0x13)`, and
`EventID/@Qualifiers` (idx 4) is typed `UNSIGNED_WORD (0x06)` — all at
size 0. Task 8e re-parsed the exact real record this table cites
(`EventRecordID 12049`, chunk 0 record 0) byte-for-byte, independent of
both this table's own generator script and go-evtx's own decoder: the
substitution array's spec bytes at those four indices are `00 00 00 00` in
every case — declared type `0x00` (generic NULL), not `GUID`/`SID`/
`UNSIGNED_WORD`. Cross-checked two further ways: `python-evtx==0.8.1`
parses this exact real record's `.xml()` without error, which would be
impossible if `ActivityID` really were `GUID`-typed at size 0 (its own
parser rejects a declared size more than 4 bytes short of a fixed type's
real width, and `GUID`'s is 16); and `EventID/@Qualifiers`'s wrong
`UNSIGNED_WORD` type never broke that same parser only because
`UNSIGNED_WORD`'s fixed width (2) is within that 4-byte tolerance of 0,
while `GUID`'s (16) is not — the discrepancy this table's own error masked
until Task 8e's build made it load-bearing.

Every other row in this table (Level, Task, Opcode, Keywords, TimeCreated,
EventRecordID, Version, EventID's own content, Execution's two *non-null*
attributes) was re-checked the same way and found exactly as stated — the
error is localized to these four NULL-valued positions, not a wholesale
problem with the table or the method that produced it.

**Where go-evtx's own code ended up does not fully match this correction,
and that gap is itself unresolved.** Three of the four positions
(`Correlation/@ActivityID`/`@RelatedActivityID`, `Security/@UserID`) were
reverted to `binXMLTypeNull`, matching this note. The fourth,
`EventID/@Qualifiers`, was NOT — reverting it to `binXMLTypeNull` (matching
this note's own finding) made `Get-WinEvent`'s `STAGE2 READ` regress from
reading all 403 records to failing on record 0, so it was reverted back to
`UNSIGNED_WORD` (F13c's original) on that stronger, directly-measured
signal. The two lines of evidence — this table's byte-level correction, and
`STAGE2 READ`'s behavior — disagree for this one field, and Task 8e did not
reconcile them; see `task-8e-report.md`'s "Concerns" section. This note is
added, not a rewrite of the table above, per this release's own practice of
keeping historical measurements visible rather than silently corrected.
