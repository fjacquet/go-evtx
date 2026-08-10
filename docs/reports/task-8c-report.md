# Task 8c report: exhaust the named list (F13)

**Written after the fact.** This task's code landed in commit `2e86005` and
CI confirmed it green (`Format Verify` run `31285813636`, `CI` run
`31285813757`, both head `2e86005`), but the report and the
`docs/format-baseline.md` row were never written — the agent that implemented
it stalled waiting on CI rather than writing up what was already measured.
This document reconstructs the report from the commit itself and the CI logs;
nothing here required new investigation.

## What changed

Per the task brief (`task-8c-brief.md`), three named divergences from
`testdata/system.evtx`'s `<System>` block remained after Task 8b, all
previously identified and deliberately deferred:

**F13a — `EventID`/`Level` reclassified to `OptionalSubstitution`.** Task
8b's own Step 1 table had already measured that real Windows uses token
`0x0E` for every scalar `<System>` child, including these two, but F12b left
them at `0x0D`/`dependency_id 0xffff` as an explicit, permitted scope
decision (go-evtx always supplies real data for both, so "always present"
was a defensible reading). This task closes that out: both elements now use
`0x0E`, with `dependency_id` set to the element's own **content**
substitution index — `subEventID = 1` and `subLevel = 2` — not the index of
any attribute the element also carries. The commit is explicit that this
distinction was checked, not assumed: real Windows ties `EventID`'s
`dependency_id` to its own content substitution (`0x0003` in the real
file's numbering), not to its `Qualifiers` attribute's index (`0x0004`).

**F13b — `Provider/@Guid`.** `<Provider>` gains a second attribute, `Guid`
(new substitution index 40, STRING, sourced from `fields["ProviderGuid"]`,
defaulting to `""`). This is the first element go-evtx emits with more than
one attribute, which forces a second fix: `Name`'s own attribute token
switches from `binXMLAttribute` (`0x06`) to `binXMLAttributeMore` (`0x46`)
— a previous task (7f) had already confirmed real Windows writes `0x46` for
every non-final attribute in a list and `0x06` only for the last one, but
go-evtx had never had occasion to emit `0x46` until this task, since every
prior element carried at most one attribute. `Guid` (the last attribute)
keeps `0x06`. `Guid`'s value is written as a substitution rather than a
literal — even though the real file happens to encode `Provider`'s own
`Guid` as a literal `ValueText` — for the same reason `Name` already is one:
a provider GUID varies per caller.

**F13c — `EventID/@Qualifiers`.** New attribute (substitution index 41),
encoded as an `OptionalSubstitution` whose value is NULL. This is go-evtx's
first NULL-valued `OptionalSubstitution` attribute whose declared type is
not a generic null-type marker: `testdata/system.evtx` encodes this exact
attribute as `[size 0, type UNSIGNED_WORD (0x06)]` — its own real declared
type — and MS-EVEN6's own worked example shows the same shape. (F12b's five
earlier NULL fields all declare `binXMLTypeNull`; the commit notes this
inconsistency explicitly as a pre-existing pattern, out of this task's named
scope, flagged for a future task to reconcile if it revisits those fields.)

## Implementation

- `binxml.go`: substitution index map extended from 40 to **42** total slots
  (`subProviderGuid = 40`, `subEventIDQualifiers = 41`); new named constants
  `subEventID = 1`, `subLevel = 2` document the F13a dependency-id mapping;
  `<Provider>`'s open tag now emits two attributes via `pushOpenElementAttrs`
  + `writeAttributeSub(..., true, ...)` (moreAttrs) + `writeAttributeSub(...,
  false, ...)`; `<EventID>` gains `pushOpenElementAttrs` with a `Qualifiers`
  attribute written via the (also new) `writeAttributeOptional`, and its
  content substitution switches from `writeSubstitution` to
  `writeOptionalSubstitution`; `<Level>`'s content substitution does the
  same. `collectSubstitutionsFromFields` appends the two new substitution
  entries (index 40: STRING from `fields["ProviderGuid"]`; index 41: NULL,
  declared type UINT16).
- `binxml_reader.go`: index-map comments updated to match (18 lines changed;
  no behavioral change to decoding — `decodeBinXML` reads `data_length` from
  the fixed header and jumps to the substitution array, so new attribute
  tokens in the template body don't change how records are read, same as
  every prior attribute-adding task).
- `CLAUDE.md`: substitution index table extended with rows 40/41 and the
  surrounding prose updated to describe F13a/F13b/F13c together with F12b's
  existing text, per the CLAUDE.md-maintenance convention this series has
  followed throughout.
- `dependency_test.go`: the generic byte-scanner needed a real fix, not just
  new expected values. F13a's reuse of small substitution indices (1, 2) as
  legitimate `dependency_id`s created two coincidental byte collisions that
  newly passed the scanner's old, weaker "plausible header" size heuristic —
  the nested template-body fragment header's own bytes, and the
  `Provider`/`Name`↔`Guid` attribute boundary. Strengthened to verify
  `name_offset` the same way `attrlist_test.go` already does for attribute
  tokens (checking the field holds the exact absolute address its `NameNode`
  sits at), which is a strictly stronger check than the size heuristic it
  replaces — the same fix shape Task 8 used for an analogous collision.
- `system_test.go`: 192 new lines of regression coverage for the F13a/b/c
  encoding (not itemized further here; see the file directly).
- `testdata/binxml-golden.bin`: regenerated, **2599 → 2679 bytes (+80)** —
  the two new substitution slots' value-spec entries (`Guid`'s STRING data,
  `Qualifiers`' zero-length NULL) plus the new attribute-token/NameNode
  structure for `Guid` and `Qualifiers`, and the `0x46` byte change on
  `Provider/@Name`'s own token.

## Verification

Reconstructed by re-running all four gates locally against `2e86005` while
writing this report (not merely re-stating the commit message's own claims):

```console
$ go build ./...
$ GOOS=windows go build ./...
$ go vet ./...
$ go test -race ./... -count=1
ok  	github.com/fjacquet/go-evtx	16.563s
?   	github.com/fjacquet/go-evtx/cmd/gen-fixture	[no test files]
$ golangci-lint run
golangci-lint: No issues found
```

All four gates clean.

## CI, by head SHA

```console
$ git rev-parse HEAD
2e860058cb78c1aae14bb31b7d6ed74a14a4a810
$ gh api repos/fjacquet/go-evtx/actions/runs/31285813636 --jq '.head_sha'
2e860058cb78c1aae14bb31b7d6ed74a14a4a810
$ gh api repos/fjacquet/go-evtx/actions/runs/31285813757 --jq '.head_sha'
2e860058cb78c1aae14bb31b7d6ed74a14a4a810
```

`CI` (`31285813757`): **success** — build/test/lint on push, unaffected by
the format-verification question this whole series is chasing.

`Format Verify` (`31285813636`): per-job —

```console
$ gh api repos/fjacquet/go-evtx/actions/runs/31285813636/jobs --jq '.jobs[] | {name,conclusion}'
{"name":"generate","conclusion":"success"}
{"name":"get-winevent","conclusion":"failure"}
{"name":"python-evtx-differential","conclusion":"success"}
```

**Fixture, from the `generate` job log:**

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31208 runes)
...
go_evtx_chunk_flushed path=artifacts/generated.evtx chunk=26 total_chunks=27
```

31208 runes, **27 chunks** — not byte-identical to row 11 (`deefe13`: 31248
runes, 26 chunks), exactly as expected: F13b/F13c add real bytes (the second
`Provider` attribute, the `EventID` attribute) to every record's encoded
payload, so `largestAccepted()`'s probe settles lower and the chunk-fill
boundary shifts by one chunk, the same mechanism every prior growing task in
this series has produced.

**python-evtx differential — unchanged, still green:**

```text
OK: 403 records, all chunk checksums verify
```

The regression guard held; F13 did not break what Task 8/8b fixed.

**`get-winevent` — this is the breakthrough this document exists to record.**
Verbatim from the job log:

```text
STAGE1 OPEN: ok
STAGE2 READ: ok, 403 records
```

**This is the first time in the entire release that `STAGE2 READ` reported
anything other than `FAILED after 0 records`.** .NET's `EventLogReader`,
reading forward one record at a time via `ReadEvent()`, now decodes **all
403 records** without throwing. Fourteen prior single-defect or
single-structural tasks (F1/F3-F11, B1-B3, F8, F12) each independently
corrected a real, measured divergence from `testdata/system.evtx` and none
moved this number off zero; this task's three fixes are the ones that did.

**The workflow does not stop at stage 2.** The pre-existing, unmodified
assertion block further down the same step still runs:

```powershell
$events = @(Get-WinEvent -Path artifacts/generated.evtx -ErrorAction Stop)
```

and this throws, verbatim:

```text
Get-WinEvent: D:\a\_temp\dae63c47-4ecf-44d3-99ee-98126b65f182.ps1:40
Line |
  40 |  $events = @(Get-WinEvent -Path artifacts/generated.evtx -ErrorAction …
     |             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | The data is invalid.
```

`Format Verify`'s overall conclusion is therefore still `failure` — but the
failure has moved from "record 0 of `EventLogReader.ReadEvent()`, forward
iteration" to "the `Get-WinEvent` cmdlet's own call, which enumerates
**newest-first** by default." Two different Windows APIs, reading the same
bytes, giving two different verdicts. That gap is Task 8d's subject, not
this one's — recorded here only because it is the reason `Format Verify`'s
own conclusion still reads `failure` despite `STAGE2 READ` now succeeding.

## Do not guess which fix moved it

**This task's brief explicitly batched F13a/F13b/F13c against one Step 1
measurement, the same way Task 8b batched F12a/F12b/F12c** — three named
divergences from one real-file decode, fixed and measured together, not
one commit per sub-finding. The CI signal (`STAGE2 READ`) is a single
pass/fail over the whole file; it does not attribute success to F13a, F13b,
or F13c individually, and no other measurement in this branch's history
does either — python-evtx was already green before this task and stayed
green after, so it gives no discriminating signal here, and no run exists
with only one of the three fixes applied.

**Which of the three actually mattered is not established by this
measurement and is not guessed here.** Plausible candidates for why *this
particular* combination was the one that finally worked, if a future task
wants to bisect it:

- F13a reclassifies `EventID`/`Level`'s **content** substitution to
  `OptionalSubstitution`, which — unlike F13b/F13c — touches every one of
  the 403 records' two most fundamental fields (`EventID` is also the field
  `WriteRecord`'s own caller supplies per call), not an attribute most
  callers leave at its zero-value default.
- F13b is the first multi-attribute element go-evtx has ever emitted,
  exercising the `0x46`/"more attributes follow" encoding for the first
  time in a real written file (not just in the isolated test Task 7f added
  for it).
- F13c is the first NULL `OptionalSubstitution` whose declared type is not
  `binXMLTypeNull` — a value-encoding shape none of F12b's five earlier NULL
  fields exercise.

Any of the three, or some interaction between them and the ten prior fixes
in this release, could be load-bearing. Isolating which would require a
splice experiment (apply each in isolation against the row-11 baseline and
re-measure `STAGE2 READ` against real CI) that this task did not run and
this report does not fabricate. Per the task's own instruction: guessing
here would undo the discipline that makes this table trustworthy, so this
is stated as an open question, not resolved by inference.

## Correction note (Task 8e, F14)

**F13c's premise about the real file was disputed, then the code was kept
as F13c originally wrote it — for a reason unrelated to the dispute.** This
report describes `EventID/@Qualifiers` as "go-evtx's first NULL-valued
`OptionalSubstitution` whose declared type is not a generic null-type
marker," declaring it `UNSIGNED_WORD (0x06)` at size 0 to match what
task-8b-report.md's Step 1 table claimed the real file does. Task 8e
re-parsed the real record that table cites byte-for-byte and found this
attribute's actual declared type is `0x00` (generic NULL) there — the
table was wrong on this specific byte, and at three other positions (see
task-8b-report.md's own correction note).

Task 8e briefly changed `EventID/@Qualifiers` to `binXMLTypeNull` to match
that finding. **This regressed `Get-WinEvent`'s `STAGE2 READ`** from
reading all 403 records (this task's own breakthrough) to failing on
record 0 — an unambiguous, directly-measured signal. Reverted back to
`UNSIGNED_WORD`, restoring this report's original F13c choice byte-for-byte.
**So: F13c's implementation is unchanged by Task 8e, but its stated
justification (the Step 1 table's real-file byte claim) is now disputed by
a separate, independently-verified measurement of the same real record.**
The two are not reconciled — see `task-8e-report.md`'s "Concerns" section
for the open question this leaves about whether Task 8e's index-to-field
identification of "`Qualifiers` = index 4" itself holds.
