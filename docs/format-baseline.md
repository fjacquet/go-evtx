# Format verification baseline

Recorded so every later task has a signal that moves: a fix that changes the
failure mode is progress, and a fix that changes nothing is aimed at the
wrong defect.

**Read this before trusting a message change as progress.** Between
measurements 1 and 2 below, `Get-WinEvent`'s error text changed —
`"The event log file is corrupted."` to `"The data is invalid."` — with
**zero writer code changed**. Only the fixture changed (record count, chunk
count, and the addition of a near-maximum record and a chunk-fill boundary
pair). That is not progress and must not be read as a defect being fixed:
Windows' open-time rejection message is **content-dependent**, not a stable
fingerprint of one specific defect. **From this point on, a changed message
counts as evidence of a fix only when the fixture that produced it is
byte-identical across the two runs being compared.** If a later task's
re-measurement uses a different fixture (a different record count, a
different probed boundary length, anything), a changed message proves
nothing on its own — check the fixture first.

Measurement 1's fixture no longer exists (superseded by the boundary-case
fix below); its row is kept for the record, but **measurement 2 is the
baseline the rest of the release compares against.**

| # | Commit | Fixture | python-evtx | Get-WinEvent |
|---|---|---|---|---|
| 1 | `35392ac` | 400 records, 18 chunks, no boundary case | FAIL: ObjectName 0/400 | FAIL: `"The event log file is corrupted."` |
| 2 | `6f3485e` | 403 records, 21 chunks, incl. near-max + chunk-fill boundary | FAIL: ObjectName 0/403 | FAIL: `"The data is invalid."` |
| 3 | `173fcf2` | 403 records, 21 chunks — byte-identical generator output to row 2 (Task 3 touched no fixture code) | FAIL: ObjectName 0/403 | FAIL: `"The data is invalid."` |
| 4 | `3c9e825` | 403 records, 21 chunks — byte-identical generator output to rows 2-3 (Task 6 touched no fixture code) | FAIL: ObjectName 0/403 | FAIL: `"The data is invalid."` |
| 5 | `ff33b7e` | 403 records, 21 chunks — byte-identical generator output to rows 2-4 (Task 7 Part A touched only the workflow) | FAIL: ObjectName 0/403 | FAIL: **STAGE1 OPEN: ok** / **STAGE2 READ: FAILED after 0 records**, `"The data is invalid."` — see "Task 7 Part A" below |
| 6 | `62de633` | 403 records, 21 chunks, max ObjectName **31642** runes — NOT byte-identical to rows 2-5 (B2 shifts every record 4 bytes; see "Task 7 Part B" below) | FAIL: ObjectName 0/403 | FAIL: **STAGE1 OPEN: ok** / **STAGE2 READ: FAILED after 0 records**, `"The data is invalid."` — identical stage split and wording to row 5 |
| 7 | `4510103` | 403 records, 21 chunks, max ObjectName **31642** runes — byte-identical generator output to row 6 (Task 7c changed two bytes' *value* per element, not any length; see "Task 7c" below) | FAIL: ObjectName 0/403 | FAIL: **STAGE1 OPEN: ok** / **STAGE2 READ: FAILED after 0 records**, `"The data is invalid."` — identical stage split and wording to rows 5-6 |
| 8 | `9b8e974` | 403 records, 21 chunks, max ObjectName **31642** runes — byte-identical generator output to rows 6-7 (Task 7e changes 4 bytes' *value* per element — the data_size field — not any length; see "Task 7e" below) | FAIL: ObjectName 0/403 | FAIL: **STAGE1 OPEN: ok** / **STAGE2 READ: FAILED after 0 records**, `"The data is invalid."` — identical stage split and wording to rows 5-7 |
| 9 | `7631f93` | 403 records, 21 chunks, max ObjectName **31642** runes — byte-identical generator output to rows 6-8 (Task 7f reorders and gives a real value to attr_list_size — a field-ordering fix, not a length change; see "Task 7f" below) | FAIL: ObjectName 0/403 | FAIL: **STAGE1 OPEN: ok** / **STAGE2 READ: FAILED after 0 records**, `"The data is invalid."` — identical stage split and wording to rows 5-8 |
| 10 | `3b3f575` | 403 records, 22 chunks, max ObjectName **31573** runes — NOT byte-identical to rows 6-9 (F8 adds 139 bytes to `<Event>`'s own encoding — the xmlns attribute plus its attr_list_size — pushing the fixture from 21 to 22 chunks and settling `largestAccepted()` lower; see "Task 8" below) | **PASS: `OK: 403 records, all chunk checksums verify`** | FAIL: **STAGE1 OPEN: ok** / **STAGE2 READ: FAILED after 0 records**, `"The data is invalid."` — identical stage split and wording to rows 5-9 |
| 11 | `deefe13` | 403 records, 26 chunks, max ObjectName **31248** runes — NOT byte-identical to row 10 (Task 8b/F12 adds 11 substitution slots and 9 `<System>` children to every record's encoding — see "Task 8b" below) | **PASS: `OK: 403 records, all chunk checksums verify`** (stayed green — the regression guard this task's brief named held) | FAIL: **STAGE1 OPEN: ok** / **STAGE2 READ: FAILED after 0 records**, `"The data is invalid."` — identical stage split and wording to rows 5-10 |
| 12 | `2e86005` | 403 records, 27 chunks, max ObjectName **31208** runes — NOT byte-identical to row 11 (Task 8c/F13 adds 2 substitution slots and `<Provider>`'s second attribute plus `<EventID>`'s new attribute to every record's encoding — see "Task 8c" below) | **PASS: `OK: 403 records, all chunk checksums verify`** (stayed green) | **BREAKTHROUGH: STAGE1 OPEN: ok / STAGE2 READ: ok, 403 records** — the first non-zero `STAGE2 READ` in this entire table. `Get-WinEvent`'s own older assertion (`$events = @(Get-WinEvent ...)`) still throws `"The data is invalid."` on the same file — see "Task 8c" below |
| 13 | `72f63a0` | 403 records, 27 chunks, max ObjectName **31208** runes — byte-identical generator output to row 12 (`cmd/gen-fixture/main.go` untouched by this task or its intermediate commit `bdc3ec1`) | **PASS: `OK: 403 records, all chunk checksums verify`** (stayed green) | `STAGE1 OPEN: ok` / `STAGE2 READ: ok, 403 records` unchanged. **`GETWINEVENT default` and `GETWINEVENT -Oldest` BOTH FAILED, identical `"The data is invalid."`** — kills the reverse-iteration-metadata hypothesis outright, not just deprioritizes it. Follow-up probes in the same job: `LOGINFO` (`EventLogSession.GetLogInformation()`) ok, `records=403 oldest=1 full=False`; six typed record properties (`Id`, `Level`, `ProviderName`, `TimeCreated`, `RecordId`, `MachineName`) all read without throwing but print **empty**; **`PROP ToXml` FAILED with the identical `"The data is invalid."` string** — the same exception both `Get-WinEvent` orderings throw. Narrows the defect specifically to **XML rendering of a record's content**, not enumeration and not file-level metadata — see "Task 8d" below |
| 14a | `eecb372` | 403 records, 27 chunks, max ObjectName **31208** runes — byte-identical to row 13 (pure type-byte substitution, no length change) | **FAIL (regression): `Evtx.BinaryParser.ParseException: Invalid substitution value size`** on record 0 — see "Task 8e" below | `STAGE1 OPEN: ok` / **`STAGE2 READ: FAILED after 384 records`** — a third, distinct failure mode, neither "fails at 0" nor "reads all 403" |
| 14b | `e1f8aca` | byte-identical to row 13/14a | **PASS (regression fixed): `OK: 403 records, all chunk checksums verify`** | `STAGE1 OPEN: ok` / **`STAGE2 READ: FAILED after 0 records`** — a *different* regression from row 13's `ok, 403 records` |
| 14 | `ab6ae57` | byte-identical to row 13/14a/14b; `binxml.go`'s emitted payload is MD5-identical to row 13's (net zero functional change across 14a/14b/this commit) | **PASS: `OK: 403 records, all chunk checksums verify`** (stayed green) | **Restored exactly to row 13's result** — `STAGE1 OPEN: ok` / `STAGE2 READ: ok, 403 records`, `LOGINFO` ok, six `PROP` scalars empty-but-no-throw, `PROP ToXml`/`GETWINEVENT default`/`GETWINEVENT -Oldest` all still FAILED with `"The data is invalid."` — see "Task 8e" below |
| 15 | `b41ac76` | 403 records, 27 chunks, max ObjectName **31236** runes — NOT byte-identical to rows 12-14 (F15 drops `encodeSubString`'s null terminator, shrinking every String-typed substitution value by 2 bytes; chunk count unchanged at 27, but the binary-searched near-maximum ObjectName ceiling moves from 31208 to 31236 runes as a direct consequence — see "Task 8f" below) | **PASS: `OK: 403 records, all chunk checksums verify`** (stayed green) | `STAGE1 OPEN: ok` / `STAGE2 READ: ok, 403 records` (held — the win stayed protected). `PROP ToXml FAILED - "The data is invalid."`, `GETWINEVENT default`/`-Oldest` both FAILED, same message — byte-for-byte the same failure shape as row 14. NULL RESULT: the null-terminator fix did not change the outcome — see "Task 8f" below |
| 16 | `07f81f0` | 403 records, 27 chunks, max ObjectName **31236** runes — byte-identical generator output to row 15 (Task 9a touched no fixture or `binxml.go`/`evtx.go` code; this row is a regression check, not a fix attempt — see "Task 9a" below) | **PASS: `OK: 403 records, all chunk checksums verify`** (stayed green) | Identical to row 15 in every respect: `STAGE1 OPEN: ok` / `STAGE2 READ: ok, 403 records`, `PROP ToXml`/`GETWINEVENT default`/`GETWINEVENT -Oldest` all FAILED with `"The data is invalid."`. **The release's hard-won win held; no regression.** Two new fixtures measured alongside this one — see "Task 9a" below |
| 17 | `92b5a3f` | 403 records, 27 chunks, max ObjectName **31236** runes — byte-identical generator output to rows 15-16 (Task 9b touched no fixture, `binxml.go`, or `evtx.go` code; this row is a regression check — three new hybrid fixtures measured alongside it, not fixture-generator changes — see "Task 9b" below) | **PASS: `OK: 403 records, all chunk checksums verify`** (stayed green) | Identical to row 16 in every respect: `STAGE1 OPEN: ok` / `STAGE2 READ: ok, 403 records`, `PROP ToXml`/`GETWINEVENT default`/`GETWINEVENT -Oldest` all FAILED with `"The data is invalid."`. **The release's hard-won win held; no regression.** Three hybrid fixtures measured alongside this one — see "Task 9b" below |
| 18 | `69ca68a` | 403 records, 27 chunks, max ObjectName **31236** runes — byte-identical generator output to rows 15-17, confirmed two ways (empty `git diff --stat` on `binxml.go`/`evtx.go`/`cmd/gen-fixture/main.go`, and a matching SHA-256 hash of the fixture bytes before/after this task's change — Task 9c touched no fixture or production encoder code; four new ladder-rung fixtures measured alongside it — see "Task 9c" below) | **PASS: `OK: 403 records, all chunk checksums verify`** (stayed green) | Identical to row 17 in every respect: `STAGE1 OPEN: ok` / `STAGE2 READ: ok, 403 records`, `PROP ToXml`/`GETWINEVENT default`/`GETWINEVENT -Oldest` all FAILED with `"The data is invalid."`. **The release's hard-won win held; no regression.** Four ladder-rung fixtures measured alongside this one — see "Task 9c" below |

CI runs: [`31263194648`](https://github.com/fjacquet/go-evtx/actions/runs/31263194648) (row 1), [`31267775745`](https://github.com/fjacquet/go-evtx/actions/runs/31267775745) (row 2, re-confirmed stable via `gh run rerun --failed` reusing the identical uploaded artifact — see "Message stability" below), [`31268668199`](https://github.com/fjacquet/go-evtx/actions/runs/31268668199) (row 3, head `173fcf2`, after Task 3's F3/F4/F5 header fixes — see "After Task 3" below; independently re-confirmed by [`31268734614`](https://github.com/fjacquet/go-evtx/actions/runs/31268734614), head `c13b724`, the very next push), [`31270735835`](https://github.com/fjacquet/go-evtx/actions/runs/31270735835) (row 4, head `3c9e825`, after Task 6's F1 hash-table fix — see "After Task 6" below), [`31272448023`](https://github.com/fjacquet/go-evtx/actions/runs/31272448023) (row 5, head `ff33b7e`, harness stage split only — see "Task 7 Part A" below), [`31272639129`](https://github.com/fjacquet/go-evtx/actions/runs/31272639129) (row 6, head `62de633`, after Task 7 Part B's B1/B2/B3 fixes — see "Task 7 Part B" below), [`31273985286`](https://github.com/fjacquet/go-evtx/actions/runs/31273985286) (row 7, head `4510103`, after Task 7c's dependency_id sentinel fix — see "Task 7c" below), [`31275896296`](https://github.com/fjacquet/go-evtx/actions/runs/31275896296) (row 8, head `9b8e974`, after Task 7e's data_size fix — see "Task 7e" below), [`31276703107`](https://github.com/fjacquet/go-evtx/actions/runs/31276703107) (row 9, head `7631f93`, after Task 7f's attr_list_size reordering fix — see "Task 7f" below), [`31277415872`](https://github.com/fjacquet/go-evtx/actions/runs/31277415872) (row 10, head `3b3f575`, after Task 8's xmlns namespace fix — see "Task 8" below), [`31278789309`](https://github.com/fjacquet/go-evtx/actions/runs/31278789309) (row 11, head `deefe13`, after Task 8b's System/value-type/OptionalSubstitution fix — see "Task 8b" below), [`31285813636`](https://github.com/fjacquet/go-evtx/actions/runs/31285813636) (row 12, head `2e86005`, after Task 8c's F13 fix — see "Task 8c" below; standard `CI` workflow confirmed green at the same head in run [`31285813757`](https://github.com/fjacquet/go-evtx/actions/runs/31285813757)).

**Parser version.** All seven rows above were produced by `python-evtx==0.8.1`
— confirmed by grepping each run's job log for uv's `+ python-evtx==X.Y.Z`
install line (every run listed above was checked, not sampled). The
`python-evtx-differential` job in `.github/workflows/format-verify.yml`
originally ran `uv pip install python-evtx` with no version pin, which
happened to resolve 0.8.1 for every run to date, but was one upstream release
away from silently invalidating the whole comparison chain: two rows could
then differ for a reason that has nothing to do with go-evtx. The workflow
now pins `python-evtx==0.8.1` explicitly, continuous with the version that
produced every row recorded here. A future bump to a newer parser version
must be noted here, next to the row it first affects.

## Row 2: the fixture

`cmd/gen-fixture` writes 403 `WriteRecord`-only records spanning 21 chunks:

- 400 records cycling through four `ObjectName` shapes (plain ASCII,
  non-ASCII BMP, non-BMP/surrogate-pair, and a 2000-rune long name).
- **1 near-maximum record.** `largestAccepted()` binary-searches, against
  throwaway temp-dir writers, the longest `ObjectName` the writer will
  accept, and the fixture uses exactly that length: **31644 runes** for this
  run (`expected.json`'s `max_object_name_len` field). Derived from the
  writer's own behavior via the public API, not a hardcoded byte count, so
  it tracks `maxRecordPayload` automatically if a later task moves it
  (Task 7's 8-byte alignment change moves it by 7 bytes).
- **2 chunk-fill boundary records**, each ~55% of that same probed length
  (17404 runes), back to back. Two of them cannot both fit in one chunk, so
  writing the second is guaranteed to flush the chunk holding the first.
  Confirmed by the writer's own `go_evtx_chunk_flushed` log: adding these
  three records raised the chunk count from 18 (the 400-record set alone) to
  21 — the near-max record and each half-chunk record each land in their own
  distinct chunk.

Row 1's fixture had no record within a factor of 30 of `maxRecordPayload`
and nothing sized to force a chunk-fill boundary, despite the task brief's
own prose requiring "boundary-sized records" — a real gap found on code
review (see "Harness bugs" below), fixed before row 2 was measured.

## Row 2: python-evtx differential (Linux) — verbatim

```text
FAIL
  - ObjectName count: got 0, want 403
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31267775745/job/93128669608>

**Chunk CRCs: confirmed still clean, all 21 chunks.** The checker's
chunk-checksum block runs unconditionally after the record/ObjectName check
and would append a `chunk N: header checksum mismatch` or `chunk N: data
checksum mismatch` line for any failure; the full step output above is
*every* line the step printed — there is no CRC failure line. The
near-maximum record and the chunk-fill boundary pair did not break either
checksum. This is the same clean result row 1 established, now re-confirmed
across a fixture that actually exercises the size ceiling — the checksum
elimination remains load-bearing for the diagnosis below.

Root cause of the `ObjectName` failure is unchanged from row 1: go-evtx's
`<Event>` root carries no `xmlns` attribute at all, while a real
Windows-generated file always declares
`xmlns="http://schemas.microsoft.com/win/2004/08/events/event"` (confirmed
directly against `testdata/system.evtx`). Tracked as **F8** with its own
task (Task 8, "Emit the Event namespace declaration") in the current plan.

## Row 2: Get-WinEvent (windows-latest) — verbatim

```text
Get-WinEvent: D:\a\_temp\19a577c2-d883-4bcf-b32f-f5f081b0f652.ps1:6
Line |
   6 |  $events = @(Get-WinEvent -Path artifacts/generated.evtx -ErrorAction  …
     |              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | The data is invalid.
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31267775745/job/93128669622>

`Get-WinEvent -Path` throws on the call itself, before returning any events
— the same open-time rejection shape as row 1.

### Message stability (why this isn't run-to-run noise)

Before drawing any conclusion from the changed wording, I re-ran
`get-winevent` a second time via `gh run rerun 31267775745 --failed`.
GitHub Actions serves that by reusing `generate`'s existing artifact rather
than re-executing it — confirmed by `generate`'s attempt-2 log carrying the
identical fixture-summary line, timestamped within microseconds of
attempt 1's (`wrote artifacts/generated.evtx (403 records, max ObjectName
31644 runes)`, both attempts). Against that byte-identical artifact, on a
different runner VM, `get-winevent`'s second attempt threw the same
`"The data is invalid."` — not a different message, not the row-1 wording.
So the wording is stable for a given fixture; it correlates with the
fixture's structural shape, not with noise in Windows' error selection.

### What the change from row 1 does and does not mean

**Not evidence of progress.** No writer code changed between rows 1 and 2 —
only `cmd/gen-fixture/main.go` did. The underlying defect(s) are exactly as
present now as before; only the message text differs. See the caveat at the
top of this document.

**Two explanations remain open, and this task does not distinguish them:**

1. The underlying defect is the same one as row 1 (most likely the zeroed
   chunk string/template hash tables, F1) and Windows' generic error
   selection for the same class of open-time rejection is sensitive to the
   file's structural shape (chunk count, record sizes) even when the root
   cause is identical.
2. The boundary-sized records (near-`maxRecordPayload`, or the two
   half-chunk records landing exactly at a chunk-fill boundary) exercise a
   code path the smaller, uniform fixture never touched, and that path has
   its own defect the row-1 fixture was too uniform to expose.

This is a **hypothesis to record, not to chase** — out of scope for this
task. Whoever picks up Task 3 or the hash-table tasks should keep both
readings open rather than assuming (1).

One fact narrows the space regardless of which explanation is right:
`"The data is invalid."` is the **exact** wording the Task 1 brief's own
symptom table gives as its first-row example, where row 1's wording was
only approximately in that bucket. Combined with the CRC elimination above,
that keeps the zeroed hash tables (F1) and the two still-untried header
fields ahead of the interning chain (F3/F4/F5, now Task 3) as the leading
candidates — a reading the plan already reflects independent of this
finding, since Task 3 was reordered ahead of the hash-table chain on the
row-1 evidence alone.

### Reading the symptom against the task table

| Symptom | Likely cause |
|---|---|
| "The data is invalid" on open | Chunk header checksum, or the zero hash tables |
| Opens, zero records | `LastEventRecordDataOffset` or `FreeSpaceOffset` |
| Opens, wrong record count | 8-byte alignment |
| Records present, fields empty | Template resolution through the template table |

Row 2 is a direct, verbatim match to row 1 of this table. Checksums are
independently confirmed clean (above), which points at the zeroed hash
tables side of that row rather than the checksum side. Per the current plan
(`docs/superpowers/plans/2026-08-08-v0.7.0-format-correctness.md`), Task 3
(`LastEventRecordDataOffset`, the dirty/full flags, and the chunk-count
guard — F3/F4/F5) runs before the three-task hash-table chain (Tasks 4–6,
ending in F1) specifically because the rejection is structural and happens
before any record is read, and two of the four structural-field candidates
are a few lines each; Task 3 ends with a mandatory harness re-run. **This
remains a hypothesis to be confirmed by the signal changing** — and per the
caveat above, "the signal changing" must be checked against an unchanged
fixture to mean anything.

## Harness bugs found and fixed while building this baseline

None of the following is a format finding.

1. **`astral-sh/setup-uv@v8` does not resolve.** The action stopped
   publishing a floating major-version tag as of its own `v8.0.0`
   ("immutable releases and secure tags"); only fully-qualified tags exist
   from `v8.0.0` onward. The Linux job failed in `Set up job`, before the
   checkout step ran — `##[error]Unable to resolve action`
   `astral-sh/setup-uv@v8`, `unable to find version` `v8`. Zero relation to
   `.evtx` content. Fixed by pinning to the commit SHA
   `c771a70e6277c0a99b617c7a806ffedaca235ff9` (verified against the upstream
   `v9.0.0` tag ref), matching this repo's fleet convention of SHA-pinning
   third-party actions with a trailing `# vX.Y.Z` comment. `actions/checkout`,
   `actions/setup-go`, `actions/upload-artifact` and `actions/download-artifact`
   were pinned the same way, each SHA verified against its own tag ref
   before use.

2. **`get-winevent: needs: python-evtx-differential` skipped the Windows job
   entirely** the first time both jobs ran for real, because GitHub Actions'
   default `needs` semantics only run a dependent job if everything it
   depends on succeeded, and `python-evtx-differential` is *expected* to
   fail. Restructured into three jobs: `generate` builds and uploads the
   fixture once, and `python-evtx-differential` / `get-winevent` both depend
   only on `generate`, not on each other.

3. **The fixture itself had no boundary-sized records**, despite the task
   brief's own prose requiring them ("multiple chunks, non-ASCII and
   non-BMP strings, boundary-sized records"). The brief's code block's
   longest `ObjectName` was a hardcoded 2000-rune string — 2008 bytes
   against a 64996-byte `maxRecordPayload`, over 30x away from the ceiling
   that matters, and its own comment said `// long, but well under the
   limit`. Found on code review, not by a CI run. Fixed by adding
   `largestAccepted()` (probes the real ceiling via the public API rather
   than hardcoding a number Task 7's alignment change would immediately
   invalidate) and a chunk-fill boundary pair. This produced row 2 above.

## What this baseline does and does not prove

- **Does not** prove any specific one of F1–F5/F8 is the sole cause —
  `Get-WinEvent` gives one terminating error for the whole file, not a
  defect-by-defect breakdown, and the message text itself moved between two
  measurements of unmodified writer code (see the caveat at the top).
- **Does** prove the harness itself works end to end: fixture generation
  (including a probed, self-adjusting boundary case), cross-job artifact
  handoff, an independent Python parser, and a real Windows Event Log stack
  all ran against unmodified output and produced real, reproducible,
  content-based errors — confirmed reproducible via an artifact-identical
  rerun, not just a single sample.
- **Does** confirm chunk header/data CRC32 checksums are clean on both
  fixtures measured so far, including one with a record at the probed size
  ceiling — checksum defects are ruled out as the open-time rejection's
  cause.
- **Does** surface one defect (missing `xmlns` on the `Event` root, F8) that
  was not in the spec's original F1–F7 list, now tracked as its own task.
- **Does** establish that the exact wording of a Windows rejection is
  content-dependent, not a stable fingerprint of one specific defect — the
  central caveat this document opens with.

Per the task's own exit criteria: do **not** add `continue-on-error`, weaken
an assertion, or delete a job to turn this green. A red `Format Verify` is
the correct state of this branch until the fixes land in later tasks.

## After Task 3 (F3, F4, F5 — header fields)

Task 3 fixed three header fields ahead of the hash-table chain, specifically
because the open-time rejection happens before any record is read and these
were cheap to try: `LastEventRecordDataOffset` (chunk header `[44:]`, F3) was
a duplicate of `FreeSpaceOffset` instead of pointing at the last record;
the file header's dirty/full flags at `[120:124]` (F4) were never written at
all; `LastChunkNumber` could underflow when `chunkCount == 0` and the
uint16 `chunkCount` counter had no ceiling before it would silently wrap and
overwrite chunk 0 (F5). Commit `173fcf2`. `cmd/gen-fixture/main.go` was not
touched, so this row's fixture is directly comparable to row 2's.

Measured from CI run [`31268668199`](https://github.com/fjacquet/go-evtx/actions/runs/31268668199),
head commit `173fcf2` (the fix commit itself — verified by checking the
run's `headSha` before citing it, see the correction note below).

**Fixture identity, confirmed from that run's `generate` job log:**
`wrote artifacts/generated.evtx (403 records, max ObjectName 31644 runes)` —
byte-identical summary line to row 2's (same record count, same probed
`ObjectName` ceiling, same 21 chunks). The comparison below is therefore
valid under the content-dependence caveat at the top of this document.

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31268668199/job/93130835405>

python-evtx differential: FAIL

```text
FAIL
  - ObjectName count: got 0, want 403
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31268668199/job/93130919628>

No chunk-checksum failure line appeared — CRCs remain clean, consistent with
every prior measurement.

Get-WinEvent: FAIL

```text
Get-WinEvent: D:\a\_temp\7ee74807-309b-4443-87e3-a5e1fab3098f.ps1:6
Line |
   6 |  $events = @(Get-WinEvent -Path artifacts/generated.evtx -ErrorAction  …
     |              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | The data is invalid.
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31268668199/job/93130919633>

(The `.ps1` temp-file hash in the first line is CI-generated per run and
carries no significance; every other token is identical to row 2's verbatim
output.)

**Independently re-confirmed** by CI run
[`31268734614`](https://github.com/fjacquet/go-evtx/actions/runs/31268734614),
head commit `c13b724` (the very next push, docs-only, no writer code
changed) — same fixture summary line, same `python-evtx` failure, same
`Get-WinEvent` wording. Two separate runs against two separate commits that
both contain the F3/F4/F5 fix rule out this specific result being CI-run
flakiness.

**Change from baseline: none.** Same fixture (byte-identical generator
summary line), same `Get-WinEvent` open-time exception, same exact wording
(`"The data is invalid."`), same `python-evtx` failure
(`ObjectName count: got 0, want 403`), same absence of any CRC failure line.
Run IDs for the comparison: row 2 = [`31267775745`](https://github.com/fjacquet/go-evtx/actions/runs/31267775745),
row 3 = [`31268668199`](https://github.com/fjacquet/go-evtx/actions/runs/31268668199) (head `173fcf2`).

**Correction note.** An earlier version of this row cited run `31268034433`,
whose head was `eec9e1a` — a commit that predates this task's fix by two
commits and contains none of F3/F4/F5. That citation was wrong: the branch
had one commit (`e6fb332`) sitting locally-unpushed before this task began,
so the first `git push` of this task sent two commits to origin in one
push (`eec9e1a..173fcf2`), and a `gh run list --limit 5` issued immediately
afterward returned the still-most-recent-at-that-instant run — the one
GitHub had already created for the pre-existing tip — before the new run
for `173fcf2` had been created and become visible. The run ID was taken from
that list by recency (top of a `--limit 5` list) rather than verified
against `git rev-parse HEAD`, so the mismatch went unnoticed. A
byte-identical result from a run that never contained the fix proves
nothing about the fix; it was mechanically certain regardless of whether
F3/F4/F5 changed anything. This row now cites `31268668199` (head `173fcf2`,
matched by SHA, not by list position) and its own verbatim job output,
re-pulled from that run rather than reused from the earlier, misattributed
citation. **Lesson for later tasks: after a push, select the CI run by
matching `headSha` to `git rev-parse HEAD` — via `gh run list --json
headSha,databaseId` filtered for a match, polling if the new run has not
yet appeared — never by taking the top entry of a recency-sorted list.**

**Reading this result.** F3/F4/F5 were not the open-time blocker.
`LastEventRecordDataOffset` being a duplicate of `FreeSpaceOffset` was a real
defect — the new `TestChunkHeader_LastEventRecordDataOffset` in
`fileheader_test.go` proves the field was previously wrong and is now
correct — but it is not what `Get-WinEvent` is objecting to at open time,
since Windows still fails at the identical point with the identical wording
after the fix. Two of the four structural-field candidates the "Reading the
symptom against the task table" section above named are now eliminated. That
narrows the remaining open-time-rejection suspects to the zeroed chunk
string/template hash tables (F1) and the chunk header checksum — and the
checksum side was already ruled out independently (CRCs confirmed clean
again in this run, as in every prior one). This strengthens, rather than
weakens, the case for Tasks 4–6 (the hash-table chain ending in F1) as the
next place to look. It does not by itself prove F1 is the cause — only that
the two cheap candidates tried in this task are not.

## After Task 6 (F1 — chunk hash tables)

Task 6 wired `fillHashTables` (built in Tasks 4–5) into both flush paths.
`flushChunkLocked` and `tickFlushLocked` each now call it on the assembled
`chunkBytes` immediately after copying the chunk header and records in, and
**before** `patchEventRecordsCRC`/`patchChunkCRC` — the chunk header
checksum covers `chunk[0:120]` and `chunk[128:512]`, and `[128:512]` is
exactly the 64-bucket common-string table and 32-bucket template table this
task populates. Calling it after the checksum would leave every chunk
carrying a stored CRC that does not match its own bytes — a new
`TestWrittenFile_ChunkHeaderCRCCoversTables` test recomputes the stored CRC
over the written bytes to pin that ordering; manually swapping the call
order during development reproduced the exact failure this test is meant to
catch (`chunk header CRC = 0x...`, recomputes to a different value) before
being reverted. Commit `3c9e825`. `cmd/gen-fixture/main.go` was not touched,
so this row's fixture is directly comparable to rows 2 and 3.

Measured from CI run [`31270735835`](https://github.com/fjacquet/go-evtx/actions/runs/31270735835),
head commit `3c9e82594d9aa2a4ef68adcc3d8f59856ecccc8f` — verified directly
against the run object, not taken from the top of a recency-sorted list:

```console
$ git rev-parse HEAD
3c9e82594d9aa2a4ef68adcc3d8f59856ecccc8f
$ gh api repos/fjacquet/go-evtx/actions/runs/31270735835 --jq '.head_sha'
3c9e82594d9aa2a4ef68adcc3d8f59856ecccc8f
```

**Fixture identity, confirmed from that run's `generate` job log:**
`wrote artifacts/generated.evtx (403 records, max ObjectName 31644 runes)` —
byte-identical summary line to rows 2 and 3's (same record count, same
probed `ObjectName` ceiling, same 21 chunks). The comparison below is
therefore valid under the content-dependence caveat at the top of this
document.

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31270735835/job/93136149239>

python-evtx differential: FAIL

```text
FAIL
  - ObjectName count: got 0, want 403
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31270735835/job/93136231729>

No chunk-checksum failure line appeared — CRCs remain clean, consistent with
every prior measurement, and consistent with `fillHashTables` running before
`patchChunkCRC` as designed.

Get-WinEvent: FAIL

```text
Get-WinEvent: D:\a\_temp\91a2a9dc-0923-4cbc-9650-7c44c83c78c0.ps1:6
Line |
   6 |  $events = @(Get-WinEvent -Path artifacts/generated.evtx -ErrorAction  …
     |              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | The data is invalid.
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31270735835/job/93136231733>

(The `.ps1` temp-file hash in the first line is CI-generated per run and
carries no significance; every other token is identical to row 3's verbatim
output.)

**Change from row 3: none.** Same fixture (byte-identical generator summary
line), same `Get-WinEvent` open-time exception, same exact wording
(`"The data is invalid."`), same `python-evtx` failure (`ObjectName count:
got 0, want 403`), same absence of any CRC failure line. Run IDs for the
comparison: row 3 = [`31268668199`](https://github.com/fjacquet/go-evtx/actions/runs/31268668199),
row 4 = [`31270735835`](https://github.com/fjacquet/go-evtx/actions/runs/31270735835).

**Reading this result, plainly, without adjusting anything to chase a
greener outcome.** The chunk hash tables — the leading hypothesis carried
forward from the baseline, and the reason Tasks 4–6 existed at all — were
**not** the open-time blocker either. `Get-WinEvent` fails at the identical
point with the identical wording whether the tables are zero (rows 1–3) or
correctly populated and self-consistent (row 4, confirmed in-process by
`TestWrittenFile_ChunkTablesArePopulated`, which walks every bucket chain in
a real written file and re-derives each name's bucket from its hash). This
is a genuine negative result, not a wasted task: populating the tables was
still necessary work — a parser that resolves through them (unlike
python-evtx, which follows inline offsets) would have found nothing
regardless of what else is broken — but it is not sufficient to open the
file in Windows.

This eliminates every defect the plan's F1–F5 covered. What remains open,
per the "Reading the symptom against the task table" list above, is F2
(8-byte record alignment, Task 7) and F8 (the missing `xmlns` declaration,
Task 8). Per the release's own exit criterion: if neither of those changes
the `Get-WinEvent` result either, the honest outcome is to ship v0.7.0 with
Windows Event Viewer support documented as unsupported rather than to keep
searching without a harness signal to guide the search — this document is
not adjusted to soften that possibility.

## Task 7 Part A: the harness could not tell open-time from record-1

**The premise behind every row above was unsound.** Rows 1–4 all describe the
`Get-WinEvent` failure as an "open-time rejection" and used that framing to
rule out defects living in record content — including F8's missing `xmlns`
and the sparse `<System>` block. The harness runs
`$events = @(Get-WinEvent -Path ... -ErrorAction Stop)`; `@( )` forces eager
enumeration, so an exception thrown while decoding record 1 lands on the
exact same line as one thrown while opening the file. Nothing measured
through row 4 could actually distinguish the two. This task fixes the
instrument before touching any encoding, per the task brief's explicit
ordering requirement.

**Change:** `.github/workflows/format-verify.yml`'s `get-winevent` job gained
a two-stage diagnostic in front of the existing (unchanged) `Get-WinEvent`
assertions: stage 1 opens the file via
`[System.Diagnostics.Eventing.Reader.EventLogReader]`/`EventLogQuery`; stage
2 reads records one at a time via `$reader.ReadEvent()`, so a decode failure
names the record it failed on. `cmd/gen-fixture/main.go` was **not**
touched — this row's fixture is byte-identical to rows 2–4, so only the
`Get-WinEvent`/stage-split column changes meaning, not the fixture.

Commit `ff33b7e` ("test: split Get-WinEvent harness into open-stage /
read-stage (Part A)"), pushed to `feat/v0.7.0-format-correctness`.

**Run selection, by head SHA, not recency** (the lesson from the "After Task
3" correction note above):

```console
$ git rev-parse HEAD
ff33b7ef2588d6c942cb218b2e3c46940e6bbb8a
$ gh run view 31272448023 --json status,conclusion,headSha
{"conclusion":"failure","headSha":"ff33b7ef2588d6c942cb218b2e3c46940e6bbb8a","status":"completed"}
```

**Fixture identity, confirmed from the `generate` job log:**
`wrote artifacts/generated.evtx (403 records, max ObjectName 31644 runes)` —
byte-identical to rows 2–4.

Job log (`generate`):
<https://github.com/fjacquet/go-evtx/actions/runs/31272448023/job/93140580024>

python-evtx differential: FAIL, unchanged —

```text
FAIL
  - ObjectName count: got 0, want 403
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31272448023/job/93140655466>

**`get-winevent` — verbatim, the load-bearing result of this task:**

```text
STAGE1 OPEN: ok
STAGE2 READ: FAILED after 0 records - System.Management.Automation.MethodInvocationException: Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
ParentContainsErrorRecordException: D:\a\_temp\709a3d11-cfe2-4bd1-b114-4c224efec2f0.ps1:27
Line |
  27 |          $rec = $reader.ReadEvent()
     |          ~~~~~~~~~~~~~~~~~~~~~~~~~~
     | Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31272448023/job/93140655454>

The script threw out of the stage-2 `catch` block before reaching the
existing (unchanged) `Get-WinEvent` assertions further down the same step —
expected, since the stage split is scaffolding placed *in front of* them, not
a replacement, and a `throw` inside a `pwsh` step with
`$ErrorActionPreference = 'Stop'` aborts the rest of the script.

### Reading this result

**Stage 1 passes. Stage 2 fails at record 0 (the first record), not at
open.** `EventLogReader`'s constructor makes a real, synchronous call into
the native Windows Event Log API (`EvtQuery`, confirmed from .NET's
reference source) — not a trivial object-construction no-op — and that call
returned without throwing. What `EvtQuery` validates internally is
undocumented, closed-source behavior inside `wevtapi.dll`; `STAGE1 OPEN: ok`
proves the call succeeded, not what specifically it checked (in particular,
it does **not** establish that it validated the file/chunk headers — that
was an unsupported inference in an earlier draft of this document).

The fact that stands on its own, without any claim about `EvtQuery`'s
internals, is in stage 2: `$n` starts at `0` and is incremented only after a
successful, non-null `$reader.ReadEvent()` (see the script above), so
`STAGE2 READ: FAILED after 0 records` unambiguously means the very first
call to `ReadEvent()` threw before it could return anything to count. That
is what proves the failure is in decoding record 0, not in opening the file.

This is exactly the second branch the task brief laid out, and it inverts the
reading of every earlier row in this document:

- `EventLogReader`'s native open call accepted the file, whatever it checks.
  The **failure is demonstrably in record content**, not file structure —
  specifically, in decoding the very first event, per the stage-2 counter
  argument above. F8 (missing `xmlns` on `<Event>`) and the sparse `<System>`
  block, both previously ruled out as "can't matter, this is an open-time
  rejection," are back in play and now the **leading candidates**, not a
  fallback. So are the three BinXML encoding divergences Part B of this task
  addresses (B1: fragment header minor version, B2: template body's missing
  nested fragment header, B3: chunk header `[120:124]`) — each is exactly the
  kind of defect that would make a real record's first `ReadEvent()` throw
  while the file itself still opens.
- **The plan's remaining task order needs revisiting**, per the task brief's
  own instruction: three tasks' worth of candidate elimination (ruling out
  F8 and the `<System>` gap because "the rejection is structural and happens
  before any record is read") rested on a distinction this harness was
  incapable of making. That elimination is retracted, not confirmed.

This does not identify *which* record-content defect is responsible — stage
2 fails on `ReadEvent()` itself, inside the .NET Event Log provider, which
gives no finer-grained diagnostic than the exception above. It does establish
*which half of the file* to keep looking in, which is the one fact this task
set out to recover.

## Task 7 Part B: B1/B2/B3 (fragment header, nested template header, chunk field)

**Change:** three BinXML/chunk-header encoding divergences measured directly
against `testdata/system.evtx` — B1 (`binxml.go`): fragment header minor
version `0x00` → `0x01`; B2 (`binxml.go`): template bodies now emit their own
nested 4-byte fragment header before the first element token; B3
(`binformat.go`): chunk header `[120:124]` now carries the constant
`0x00000001` every real chunk carries, written inside `patchChunkCRC` so it
survives the function's zeroing step. `testdata/binxml-golden.bin`
regenerated in the same commit (1807 → 1811 bytes). Full detail and the
direct-against-`system.evtx` verification of each finding is in the Task 7
implementation commit and report; not repeated here.

Commit `62de633` ("fix: three BinXML/chunk-header divergences from a real
Windows file (B1-B3)"), pushed to `feat/v0.7.0-format-correctness`.

**Run selection, by head SHA:**

```console
$ git rev-parse HEAD
62de6330e2fba265dd803e30fea4b1b614f9f20b
$ gh run view 31272639129 --json status,conclusion,headSha
{"conclusion":"failure","headSha":"62de6330e2fba265dd803e30fea4b1b614f9f20b","status":"completed"}
```

**Fixture is NOT byte-identical to rows 2–5, exactly as the task brief
predicted.** From the `generate` job log:

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31642 runes)
```

31642 runes, not 31644: B2 adds 4 bytes to every record's encoded BinXML
payload, so `cmd/gen-fixture`'s `largestAccepted()` probe (which binary-searches
the real `maxRecordPayload` ceiling via the public API, deliberately not a
hardcoded number) settled 2 runes lower. Per the brief, this makes a message
or record-count comparison to rows 2–5 invalid on its own — only whether the
file opens, and the stage-1/stage-2 split, stay interpretable across this
boundary.

python-evtx differential: FAIL, unchanged —

```text
FAIL
  - ObjectName count: got 0, want 403
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31272639129/job/93141122166>

**`get-winevent` — verbatim:**

```text
STAGE1 OPEN: ok
STAGE2 READ: FAILED after 0 records - System.Management.Automation.MethodInvocationException: Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
ParentContainsErrorRecordException: D:\a\_temp\a7427665-afab-4590-b7db-f6fe894d10b9.ps1:27
Line |
  27 |          $rec = $reader.ReadEvent()
     |          ~~~~~~~~~~~~~~~~~~~~~~~~~~
     | Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31272639129/job/93141122173>

### Reading this result, plainly, without adjusting anything to chase a greener outcome

**Stage split and wording are identical to row 5**, despite the fixture not
being byte-identical: stage 1 still opens cleanly, stage 2 still throws on
the very first `ReadEvent()` with the identical exception type and message.
B1, B2, and B3 did not change the observable `Get-WinEvent` outcome. This is
one of the outcomes the task brief explicitly named as legitimate ("all
three fixes changing nothing"), and it is reported as such.

This does **not** mean B1–B3 were wrong — all three were verified directly
against real chunks/templates in `testdata/system.evtx` (not inferred), and
`TestFixture_TemplateTableBucketRule` (all 146 real templates) and the
hash-table integration test still pass after B2's 4-byte offset shift,
confirming the encoder's own internal consistency held. It means .NET's
`EventLogReader` either does not check these three particular fields, or
checks them but the true blocker lies elsewhere in the first record and
these three fixes are necessary-but-not-sufficient. The stage-1/stage-2 split
from Part A remains the standing, confirmed fact: the failure is still in
decoding record 0, not in opening the file. What differs about that record's
content and blocks the .NET reader is still open — F8 (missing `xmlns`) and
the sparse `<System>` block (5 of the real file's 14 elements) are the
next candidates the "Reading this result" section above already named,
neither of which this task touched.

## Task 7c: F9 (element dependency identifier)

**Change:** `writeOpenElement` (`binxml.go`) wrote `0` for every
OpenStartElement token's dependency identifier field. libyal's EVTX
documentation defines that field as `"-1 (0xffff) => not set"` — `0` is a
valid identifier referring to template value 0, not the "no dependency"
sentinel, so every element go-evtx has ever written asserted a spurious
dependency on substitution 0. Fixed to write `0xffff`.

**Independently confirmed against `testdata/system.evtx`**, going beyond the
single element cited in the task brief: a full token walk of chunk 0's first
template body (starting chunk-relative 24532) shows every *unconditional*
element (`<EventData>`, `<Provider>`, `<TimeCreated>`, `<Correlation>`,
`<Execution>`, `<Security>`, `<Data Name=...>`) carries `dependency_id =
0xffff`, while the two elements that wrap an `OptionalSubstitution` (token
`0x0E`) — `<Data>` and `<Binary>`, gating on substitution indices 0 and 2 —
carry that same substitution's own index (`0x0000`, `0x0002`) instead of the
sentinel. This matches `[MS-EVEN6]`'s documented semantics exactly: the
dependency identifier ties an element's presence to an *optional*
substitution, omitting the element from rendered XML when that substitution
is null. go-evtx never emits `OptionalSubstitution` — every substitution it
writes uses the normal (`0x0D`) token — so every element it writes is
unconditional, and `0xffff` is the only value ever correct for it.

**`writeAttributeSub` judgment call: no change, decided from the real file.**
The libyal EVTX documentation's Attribute token layout (token(1) +
name_offset(4), no dependency field) was cross-checked against ten real
Attribute tokens pulled directly out of `testdata/system.evtx` chunk 0 —
including `<Provider Name=...>`, `<TimeCreated SystemTime=...>`,
`<Correlation ActivityID=...>`, `<Execution ProcessID=...>`, `<Security
UserID=...>`, and three `<Data Name=...>` instances. Every one goes straight
from the token byte (`0x06`/`0x46`) to a 4-byte name_offset with no
intervening 2-byte field, matching `writeAttributeSub`'s existing code
exactly. Left unchanged.

**`binxml_reader.go`: no change needed.** It never parses `dependency_id` —
`decodeBinXML` reads `data_length` from the TemplateNode header and jumps
straight to the substitution array; it does not walk element tokens at all.
The full `-race` suite (including every reader round-trip test) passes
unmodified against the new encoding.

**Test.** `dependency_test.go` adds `TestWriteOpenElement_DependencyIDIsUnset`
per the task brief, with one adjustment: the brief's byte-scan started at
payload offset 0, but two bytes in the fixed 38-byte preamble (the outer
FragmentHeader's minor-version byte, and the low byte of the TemplateNode's
GUID/template_id, both coincidentally `0x01`) pass the scan's own "plausible
header" guard and produced false-positive failures unrelated to the fix —
confirmed by hand-decoding the payload bytes at those offsets. Real
OpenStartElement tokens only occur in the template body, which starts at
`preambleSize`; the scan now starts there instead of 0. With that change the
test passes cleanly (20 sentinel-carrying elements found, 0 false positives).

**Golden file: length unchanged, as predicted.** `testdata/binxml-golden.bin`
was 1811 bytes before this change and 1811 bytes after — only two bytes'
*value* differ per `OpenStartElement` token (20 of them in the golden
payload), no bytes added or removed, so every downstream offset in the
payload is untouched.

Commit `4510103` ("fix: write the 'not set' sentinel in element
dependency_id (F9)"), pushed to `feat/v0.7.0-format-correctness`.

**Run selection, by head SHA:**

```console
$ git rev-parse HEAD
45101039cdf14baa17f3b0cd7b079af479e4ed30
$ gh api repos/fjacquet/go-evtx/actions/runs/31273985286 --jq '.head_sha'
45101039cdf14baa17f3b0cd7b079af479e4ed30
```

**Fixture identity, confirmed from the `generate` job log:**

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31642 runes)
```

**Byte-identical to row 6** (`31642` runes, same 403 records, same 21
chunks) — exactly as predicted, since this task changes two bytes' *value*
per element, not any length, so `cmd/gen-fixture`'s `largestAccepted()`
probe settles on the identical ceiling it found for row 6. The comparison
below is therefore fully valid, not merely stage-split-comparable.

Job log (`generate`):
<https://github.com/fjacquet/go-evtx/actions/runs/31273985286/job/93144495078>

python-evtx differential: FAIL, unchanged —

```text
FAIL
  - ObjectName count: got 0, want 403
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31273985286/job/93144550403>

**`get-winevent` — verbatim, the load-bearing result of this task:**

```text
STAGE1 OPEN: ok
STAGE2 READ: FAILED after 0 records - System.Management.Automation.MethodInvocationException: Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
ParentContainsErrorRecordException: D:\a\_temp\5a7f688b-835c-4891-af0a-c092738abd94.ps1:27
Line |
  27 |          $rec = $reader.ReadEvent()
     |          ~~~~~~~~~~~~~~~~~~~~~~~~~~
     | Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31273985286/job/93144550388>

### Reading this result, plainly, without adjusting anything to chase a greener outcome

**STAGE2 READ: FAILED after 0 records — no breakthrough.** Stage 1 still
opens cleanly; stage 2 still throws on the very first `ReadEvent()`, same
exception type, same exact wording, same record count (0), as rows 5 and 6.
The dependency identifier fix did not change the observable outcome at all,
against a byte-identical fixture — the strongest form of "no effect" this
document has recorded, since row 6's comparison had to go through the
content-dependence caveat (different `ObjectName` probe length) and this
one does not.

This is a **null result and is reported as such.** F9 was a real, confirmed
defect — independently verified from two directions (libyal's documented
sentinel value, and a full token walk of the real fixture showing the
unconditional/optional distinction holds exactly as `[MS-EVEN6]` describes)
— but it was not what blocks `EventLogReader.ReadEvent()` on record 0.
Per the task's own framing: this was the cheapest remaining candidate and
the only one backed by a written specification, and it has now been tried
and eliminated. What differs about record 0's content and blocks the .NET
reader remains open — F8 (missing `xmlns` on `<Event>`) and the sparse
`<System>` block (5 of the real file's 14 elements) remain the leading
candidates named in the "Task 7 Part A" reading above, neither of which
this task touched.

## Task 7e: F10 (`OpenStartElementTag.data_size` hardcoded to zero)

**Found differently from every task before it.** Not by parity with
`testdata/system.evtx` alone, but by decoding one of go-evtx's own records
and a real Windows record token-by-token with a fresh standalone decoder and
diffing the whole streams (`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/tokendiff-report.md`,
not part of this task's own deliverables). That investigation's finding F1 —
`data_size` is unconditionally `0` on every `OpenStartElementTag`, while real
Windows always writes a content-derived, non-zero value — is the "arithmetic
against Microsoft's own normative specification" this task's brief
described, not merely parity with one vendored file.

**Step 1: the formula, measured fresh before any code changed.** A throwaway
probe (`scratchpad/datasize-probe/probe.py`, not committed) parsed chunk 0 of
`testdata/system.evtx` with a decoder that **never reads `data_size`**: it
finds each element's own end purely by matching its `OpenStartElementTag` to
its own `CloseEmptyElementTag` (`0x03`) or `EndElementTag` (`0x04`),
recursing through children by token structure alone. That independently
derived "structural end" was then compared against
`element_start + 7 + data_size` computed from the header field the parser
never consulted.

Run against **two different records** (different templates, one using
inline `NameNode`s throughout, the other using chunk-relative back-references
for every name — S10 in the tokendiff report), at three nesting depths each:

| Record | Elements checked | Depths | Formula matched structural end |
|---|---|---|---|
| `EventRecordID 12049` (chunk-rel. record offset 512) | 17 (`<Event>`, `<System>`, `<UserData>`, and 14 `<System>` children incl. `<Provider>`, `<EventID>`, `<TimeCreated>`, `<Security>`, ...) | 0, 1, 2 | **17/17** |
| `EventRecordID 12050` (chunk-rel. record offset 2688) | 16 (same shape, all names back-referenced instead of inline) | 0, 1, 2 | **16/16** |

Sample rows (record 12049; full table in the task report):

| Element | `element_start` | `data_size` | `element_start+7+data_size` | Structural end (data_size-blind) | Match |
|---|---|---|---|---|---|
| `<Provider>` | 783 | 217 | 1007 | 1007 | yes |
| `<System>` | 749 | 1158 | 1914 | 1914 | yes |
| `<Event>` | 578 | 1373 | 1958 | 1958 | yes |

**Zero exceptions across 33 elements.** The task brief's formula —
`data_size = end_of_closing_tag − (element_start + 7)` — held exactly, matching
both `testdata/system.evtx` and the brief's independently-cited MS-EVEN6
worked example (`<Event>` at `0x1E`, `data_size 0x4E3`,
`0x1E + 7 + 0x4E3 = 0x508`). The real file did not contradict the formula in
the plan; it confirmed it, so the formula was implemented as given.

**Incidental finding, out of scope, not fixed.** While writing the
data_size-blind parser, real `<Event>`'s `OpenStartElementTag` (with attrs)
turned out to place the inline `NameNode` immediately after `name_offset`,
with `attr_list_size` coming *after* the `NameNode`, right before the
attribute list — not `name_offset` → `attr_list_size` → `NameNode`, the order
`writeOpenElement` has always written. Confirmed directly against the real
`<Event>` element (`name_offset=589`, pointing immediately past the 11-byte
fixed header; the plausible `attr_list_size` value, 135/`0x87`, sits at 609,
right after the 20-byte "Event" `NameNode` ends). This does not affect
`data_size` and was left untouched — Task 7e's scope is the `data_size`
field only — but it is a real, measured divergence a future task should
pick up.

**Implementation.** `writeOpenElement` now returns the chunk-body-local
position of the token byte it wrote. `buildTemplateBody` keeps a LIFO stack
of those positions (`pushOpenElement` pushes); every point that used to write
a bare `EndElementTag` now calls `writeEndElement`, which pops the matching
position and records a `(pos, size)` patch. `bytes.Buffer` has no in-place
mutation, so patches are applied to the finished `[]byte` in one pass, just
before `buildTemplateBody` returns — no caller ever observes an unpatched
body. Every element go-evtx writes closes via `EndElementTag` (never
`CloseEmptyElementTag`, per the existing S2 finding, out of this task's
scope), so one patch mechanism covers all 20 elements; nesting is handled
entirely by stack order, and `TestWriteOpenElement_DataSizeNesting`
(`datasize_test.go`) independently confirms every inner element's span ends
at or before its enclosing element's, guarding the LIFO pairing itself.

**Knock-on fix, required for the test gate, not itself part of F10.**
`dependency_test.go`'s byte-scan (Task 7c) re-examined bytes inside an
already-recognized element's own fixed header on the next several loop
iterations, relying on a weak "does the following u32 look like a plausible
size" guard to avoid misreading them as a second element. That guard was
harmless while `data_size` was always `0`, but a real `data_size`'s own
bytes can equal `0x01`/`0x41` partway through — `<System>`'s `data_size`
`0x0133` stores `0x01` at its second byte — and get misread as a bogus
nested header, producing `TestWriteOpenElement_DependencyIDIsUnset: offset
78: OpenStartElement dependency_id = 0x0000, want 0xffff`. Fixed by skipping
past a recognized element's own fixed header once found, rather than
re-scanning it; confirmed the false positive reproduces without the fix and
disappears with it.

**Golden file: length unchanged, as predicted.** `testdata/binxml-golden.bin`
was 1811 bytes before this change and 1811 bytes after — only 4 bytes'
*value* per `OpenStartElementTag` change (20 of them), no bytes added or
removed.

Commit `9b8e974` ("fix: write a real data_size on every OpenStartElementTag
(F10)"), pushed to `feat/v0.7.0-format-correctness`.

**Run selection, by head SHA:**

```console
$ git rev-parse HEAD
9b8e9742037c31f8d7e0b54fd99ee743d5811b51
$ gh api repos/fjacquet/go-evtx/actions/runs/31275896296 --jq '.head_sha'
9b8e9742037c31f8d7e0b54fd99ee743d5811b51
```

**Fixture identity, confirmed from the `generate` job log:**

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31642 runes)
```

**Byte-identical to rows 6-7** (`31642` runes, same 403 records, same 21
chunks) — exactly as predicted, since this task changes 4 bytes' *value*
per element (`data_size`), not any length, so `cmd/gen-fixture`'s
`largestAccepted()` probe settles on the identical ceiling it found for
rows 6-7. The comparison below is therefore fully valid.

Job log (`generate`):
<https://github.com/fjacquet/go-evtx/actions/runs/31275896296/job/93149235633>

python-evtx differential: FAIL, unchanged —

```text
FAIL
  - ObjectName count: got 0, want 403
```

Expected: python-evtx's own source never reads `data_size`
(`# TODO: use this size() field`), so it cannot be sensitive to this fix
either way.

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31275896296/job/93149323499>

**`get-winevent` — verbatim, the load-bearing result of this task:**

```text
STAGE1 OPEN: ok
STAGE2 READ: FAILED after 0 records - System.Management.Automation.MethodInvocationException: Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
ParentContainsErrorRecordException: D:\a\_temp\0d8c7f97-8048-4c90-9be8-54e28c1ceaf2.ps1:27
Line |
  27 |          $rec = $reader.ReadEvent()
     |          ~~~~~~~~~~~~~~~~~~~~~~~~~~
     | Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31275896296/job/93149323486>

### Reading this result, plainly, without adjusting anything to chase a greener outcome

**STAGE2 READ: FAILED after 0 records — no breakthrough.** Stage 1 still
opens cleanly; stage 2 still throws on the very first `ReadEvent()`, same
exception type, same exact wording, same record count (0), as rows 5-7,
against a fixture byte-identical to rows 6-7. The `data_size` fix — this
release's strongest candidate by its own framing, the only one so far
verified by exact arithmetic against Microsoft's own normative spec text
rather than only by parity with one vendored file — did not change the
observable `Get-WinEvent` outcome at all.

This is a **null result and is reported as such, without softening.** F10
was real and rigorously confirmed (33/33 elements across two differently
structured real records, at three nesting depths, using a decoder that
never itself reads `data_size` — plus exact agreement with MS-EVEN6's own
worked example), and fixing a length field that lied about its own content
was, on every piece of documented BinXML/parser-design reasoning available
to this investigation, the single most likely candidate for a hard abort.
It was not what blocks `EventLogReader.ReadEvent()` on record 0. Seven
single-field tasks and this eighth, higher-confidence one have now each
independently changed a real, measured divergence from the real file and
none has moved `STAGE2 READ` off zero. What differs about record 0's content
and blocks the .NET reader remains open — F8 (missing `xmlns` on `<Event>`),
the sparse `<System>` block (5 of the real file's 14 elements), and S5
(go-evtx never emits `OptionalSubstitution`, per the tokendiff report) are
the remaining named candidates, none of which this task touched.

## Task 7f: F11 (`attr_list_size` misplaced, and zero)

**A different class of defect than every task before it.** F3 through F10
were each a wrong *value* in a correctly-placed field — a parser could read
past one and keep going. F11 is a field-ordering defect: `attr_list_size`
sat before the inline `NameNode` in go-evtx's output and after it in real
files. A parser reading go-evtx's stream took the NameNode's `next_offset`
(always 0) as `attr_list_size`, concluded the element had no attributes, and
then looked for the next token at the NameNode's hash bytes — a hard
desynchronisation on the first element of every record, immediately, not a
value it could shrug off. Task 7e had already found and flagged this exact
divergence as out-of-scope while building its `data_size`-blind parser; this
task picks it up.

**Step 1: measured fresh, before any code changed.** A throwaway probe
(`scratchpad/attrlist_probe.py`, this session's scratchpad, not committed)
parsed chunk 0 of `testdata/system.evtx` directly (no `python-evtx`
dependency) and, for each of the three `0x41` elements the brief named,
decoded `name_offset`, the NameNode it points at, and the four bytes
immediately following the NameNode's end:

| Element | token pos | `name_offset` | `token+11` | NameNode ends | bytes there | `attr_list_size` |
|---|---|---|---|---|---|---|
| `<Event>` | 578 | 589 | 589 (match) | 609 | `87 00 00 00 06 6a 02 00` | 135 |
| `<Provider>` | 783 | 794 | 794 (match) | 820 | `b6 00 00 00 46 3d 03 00` | 182 |
| `<TimeCreated>` | 1286 | 1297 | 1297 (match) | 1329 | `27 00 00 00 06 3a 05 00` | 39 |

`name_offset == token_pos + 11` held for all three (the brief's claim,
independently reconfirmed), and a NameNode decoded correctly at each. This
matches the fixed 11-byte header (`token+dep_id+data_size+name_offset`) — the
**same** size the without-attributes form already used; real Windows does
not grow the fixed header for the with-attributes case, it moves
`attr_list_size` out of it instead.

**The value rule, derived by arithmetic, not guessed.** The brief asked what
`attr_list_size` actually counts. Using Task 7e's already-confirmed
`data_size` formula (`element_start + 7 + data_size` = structural end) as an
independent cross-check:

| Element | `attr_region_start` (NameNode end + 4) | `attr_list_size` | `attr_region_start + attr_list_size` | byte there | structural end (`start+7+data_size`) |
|---|---|---|---|---|---|
| `<Event>` | 613 | 135 | 748 | `0x02` (CloseStartElementTag — `<Event>` has children) | 1958 |
| `<Provider>` | 824 | 182 | 1006 | `0x03` (CloseEmptyElementTag — self-closing) | 1007 |
| `<TimeCreated>` | 1333 | 39 | 1372 | `0x03` (CloseEmptyElementTag — self-closing) | 1373 |

In every case, `attr_region_start + attr_list_size` landed **exactly** on
the `Close(Start|Empty)ElementTag` byte that follows the attribute list —
not on `data_size`'s structural end (`<Event>`'s 748 vs. 1958 makes the
distinction unambiguous: `attr_list_size` is emphatically not a second copy
of `data_size`). **`attr_list_size` counts only the attribute list itself —
from immediately after its own 4 bytes up to, but not including, the
Close(Start|Empty)ElementTag** — not the element's children, not its own
`EndElementTag`; those are already covered by `data_size`, which spans the
whole element. The file did not contradict the brief on either the position
or the "size disagreeing with its content" framing of the value; both were
confirmed exactly, with zero exceptions across the three elements measured.

**Step 2: the failing test**, `TestWriteOpenElement_AttrListSizeAfterNameNode`
(new file, `attrlist_test.go`), asserted `name_offset == tokenPos+11`, a
NameNode decoding there, and a non-zero `attr_list_size` landing on a
`CloseStartElementTag` (`0x02` — go-evtx never emits the self-closing
`0x03` form; every element it writes closes via `0x02` and a later, separate
`EndElementTag`). Run against the pre-fix encoder, all 14 attribute-bearing
elements failed on the first assertion:

```text
offset 108: name_offset (payload-relative) = 123, want 119 (token+11)
... (14 total, one per attrs element)
no OpenElementAttrs (0x41) tokens examined — the scan is wrong
```

**Step 3: reorder, and compute the size.** `writeOpenElement` now writes the
NameNode immediately after `name_offset` (`headerSize` is `11` for both
branches — the `if hasAttrs { headerSize = 15 }` branch is gone, since the
NameNode sits at the same fixed offset either way) and, only for
attribute-bearing elements, reserves `attr_list_size`'s 4 bytes right after
the NameNode, before returning to the caller to write the attributes.

**Back-patching reused, not reinvented**, per the brief's explicit
instruction. `dataSizePatch` (Task 7e) is generalized to `fieldPatch`: `pos`
now means the exact buffer offset of the 4-byte field to patch, not a token
position with an implicit `+3` applied at write time — `writeEndElement`
now stores `pos+3` itself (the `data_size` field's own offset) instead of
the bare token position, and the single apply loop at the end of
`buildTemplateBody` writes `buf[p.pos:]` uniformly for both fields, with no
per-field-type branching. A new `closeAttrList` helper queues an
`attr_list_size` patch once the caller has written that element's
attributes but before writing the `CloseElement` byte — `pushOpenElement`
gained a sibling, `pushOpenElementAttrs`, which is the only new call-site
shape needed (3 source lines touched: `<Provider>`, `<TimeCreated>`, and the
12-iteration `<Data>` loop); the 6 attribute-free elements (`<Event>`,
`<System>`, `<EventID>`, `<Level>`, `<Computer>`, `<EventData>`) are
untouched, still calling the original `pushOpenElement`.

**Step 4: node offsets re-verified, run deliberately.** Moving the NameNode
four bytes earlier for attribute-bearing elements changes every offset
`writeNameNode` reports for those 14 elements (it records
`binXMLBase + b.Len()` at call time). Ran, not merely assumed unaffected:

```text
=== RUN   TestBuildBinXML_ReportsNameOffsets
--- PASS: TestBuildBinXML_ReportsNameOffsets (0.00s)
=== RUN   TestBuildBinXML_TemplateSelfPointer
--- PASS: TestBuildBinXML_TemplateSelfPointer (0.00s)
=== RUN   TestWrittenFile_ChunkTablesArePopulated
    hashtable_integration_test.go:66: 11 names reachable through the table
--- PASS: TestWrittenFile_ChunkTablesArePopulated (0.02s)
=== RUN   TestWrittenFile_ChunkHeaderCRCCoversTables
--- PASS: TestWrittenFile_ChunkHeaderCRCCoversTables (0.01s)
```

`TestWrittenFile_ChunkTablesArePopulated` decodes bytes at each reported
bucket offset and recomputes `sdbmHash` on the decoded name, so a wrong
offset — 4 bytes off, landing mid-NameNode instead of at its start — would
have produced a hash mismatch, not merely a wrong string. It passed clean.

**Knock-on: `dependency_test.go`'s skip distance.** Its byte-scan skip past a
recognized element's own header, added in Task 7e to dodge a false-positive
inside `data_size`'s own bytes, still hardcoded the old `11`/`15` split by
`hasAttrs`. The 15-byte branch is now wrong (it would skip 4 bytes into the
NameNode instead of stopping exactly at its start) even though the test
happened to still pass — the NameNode's leading `next_offset=0` bytes did
not coincidentally trigger the guard it was protecting against. Fixed to a
flat `11` for both branches, matching `writeOpenElement`, per the brief's
"check every use" instruction; confirmed with `go test -race ./... -count=1`
afterward.

**Golden file: length unchanged, exactly as predicted.**
`testdata/binxml-golden.bin` was 1811 bytes before this change and 1811
bytes after — the same fields, reordered and correctly valued, no bytes
added or removed. Captured via the frozen-timestamp procedure
(`goldenFields()`, a throwaway `TestCaptureGolden` removed after use).

**Verification, all four gates:**

```console
$ go build ./...
$ GOOS=windows go build ./...
$ go test -race ./... -count=1
ok  	github.com/fjacquet/go-evtx	14.926s
?   	github.com/fjacquet/go-evtx/cmd/gen-fixture	[no test files]
$ golangci-lint run
golangci-lint: No issues found
```

```text
=== RUN   TestWriteOpenElement_AttrListSizeAfterNameNode
    attrlist_test.go:119: 14 attribute-bearing elements carry a correctly-placed, non-zero attr_list_size
--- PASS: TestWriteOpenElement_AttrListSizeAfterNameNode (0.00s)
```

Commit `7631f93` ("fix: move attr_list_size after the inline NameNode, give
it a real value (F11)"), pushed to `feat/v0.7.0-format-correctness`.

**Run selection, by head SHA, not recency:**

```console
$ git rev-parse HEAD
7631f93cd7c9e81c0f3d02fd4c92f0c6a518f92e
$ gh api repos/fjacquet/go-evtx/actions/runs/31276703107 --jq '.head_sha'
7631f93cd7c9e81c0f3d02fd4c92f0c6a518f92e
$ gh api repos/fjacquet/go-evtx/actions/runs/31276703263 --jq '.head_sha'
7631f93cd7c9e81c0f3d02fd4c92f0c6a518f92e
```

Both `Format Verify` (`31276703107`) and the standard `CI` workflow
(`31276703263`, build/test/lint on push) confirmed at this exact commit.
`CI` completed with `success`.

**Fixture identity, confirmed from the `generate` job log:**

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31642 runes)
```

**Byte-identical to rows 6-8** (`31642` runes, same 403 records, same 21
chunks) — exactly as predicted, since this task reorders and revalues 4
bytes per attribute-bearing element without changing any element's total
length, so `cmd/gen-fixture`'s `largestAccepted()` probe settles on the
identical ceiling it found for rows 6-8.

Job log (`generate`):
<https://github.com/fjacquet/go-evtx/actions/runs/31276703107/job/93151332956>

python-evtx differential: FAIL, unchanged —

```text
FAIL
  - ObjectName count: got 0, want 403
```

Expected: `python-evtx`'s own decoder walks the token stream by following
`data_size`/offsets structurally in its own way and was never shown to be
sensitive to `attr_list_size`'s position either.

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31276703107/job/93151400077>

**`get-winevent` — verbatim, the load-bearing result of this task:**

```text
STAGE1 OPEN: ok
STAGE2 READ: FAILED after 0 records - System.Management.Automation.MethodInvocationException: Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31276703107/job/93151400094>

### Reading this result, plainly, without adjusting anything to chase a greener outcome

**STAGE2 READ: FAILED after 0 records — still zero. No breakthrough.** Stage
1 still opens cleanly; stage 2 still throws on the very first `ReadEvent()`,
identical exception type, identical wording, identical record count (0), as
rows 5-8, against a fixture byte-identical to rows 6-8.

This is reported as a **null result, without softening**, same as every task
before it in this release. F11 was, by the framing in this task's own brief,
qualitatively different from F3-F10: not a wrong value a tolerant parser
might skip past, but a field-ordering defect that desynchronises the token
stream on the very first element of every record — the strongest
*a priori* case yet for a hard, immediate `.NET` `EventLogReader` abort.
Measured directly against the real file (not inferred), fixed exactly as
measured, confirmed not to move any downstream offset incorrectly (Step 4),
and it still did not change `STAGE2 READ` at all. Nine single-field or
single-structural tasks in this release have now each independently changed
a real, measured divergence from the real file, and none has moved
`STAGE2 READ` off zero. What differs about record 0's content and blocks the
.NET reader remains open — F8 (missing `xmlns` on `<Event>`), the sparse
`<System>` block (5 of the real file's 14 elements), and S5 (go-evtx never
emits `OptionalSubstitution`) are the remaining named candidates, none
touched by this task.

**New, out-of-scope finding, flagged for a future task.** While measuring
`attr_list_size`'s value (the second table above), the `<Provider>`
element's attribute token byte was found to be `0x46`, not the `0x06`
go-evtx always writes — while the *second* attribute in the same element
(`<Provider>`'s `Guid`) is `0x06`, matching go-evtx exactly. This looks like
the same "high bit signals more follows" pattern already confirmed for
`OpenStartElement` (`0x01` → `0x41` when attributes are present): `0x46`
plausibly marks a non-last attribute in a multi-attribute list, `0x06` the
last one. go-evtx's own template never writes more than one attribute per
element, so every `writeAttributeSub` call it makes is, structurally, always
the "last" one — meaning `0x06` may already be correct for every attribute
go-evtx currently emits, and this would only matter if a future template
adds a multi-attribute element. Not confirmed rigorously (only one
element's two attributes checked) and not acted on — flagging it, in the
same spirit Task 7e flagged this task's own defect, rather than letting it
sit unrecorded.

## Task 8: F8 (missing `xmlns` on the `<Event>` root)

**The last candidate that is semantic, not structural.** F3 through F11 each
corrected how bytes are laid out — a wrong value, a misplaced field, a
missing header. F8 is different: without
`xmlns="http://schemas.microsoft.com/win/2004/08/events/event"` on the root
element, go-evtx's `<Event>` is in no XML namespace at all. A namespace-aware
consumer that queries with a namespaced XPath — PowerShell's `.ToXml()`,
.NET's `EventLogRecord`, python-evtx, Event Viewer's own XML view — finds no
elements to match, regardless of whether the underlying bytes decode
correctly. `scripts/verify_python_evtx.py` queries exactly this way —
`ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}` then
`root.iterfind(".//e:Data", ns)` — which is precisely why every row above
shows `ObjectName 0/403`: not because the fields weren't there, but because
nothing in the document matched the namespaced query.

**Measured directly against `testdata/system.evtx`, not assumed.** The
brief's premise — 45 occurrences of the schema URI, once per template — was
independently reconfirmed by scanning the fixture's UTF-16LE encoding
directly: **45** occurrences of the URI, first at absolute file offset 4738.
Working outward from there (chunk 0's first `<Event>`, at chunk-relative
offset 578, absolute 4674) to decode the whole attribute byte-for-byte:

| Field | Absolute offset | Bytes | Decoded |
|---|---|---|---|
| `<Event>` token | 4674 | `41` | `OpenElementAttrs` |
| `dependency_id` | 4675 | `ff ff` | not set |
| `data_size` | 4677 | `5d 05 00 00` | 1373 |
| `name_offset` | 4681 | `4d 02 00 00` | 589 (chunk-relative) = `token_pos+11` |
| NameNode | 4685 | `00000000 bc0f 0500 "Event" 0000` | hash `0x0cba`, "Event" |
| `attr_list_size` | 4705 | `87 00 00 00` | **135** |
| Attribute token | 4709 | `06` | `AttributeToken` |
| `name_offset` | 4710 | `6a 02 00 00` | 618 (chunk-relative) — points at 4714, immediately following |
| NameNode | 4714 | `00000000 bc0f 0500 "xmlns" 0000` | hash `0x0fbc`, "xmlns" |
| ValueText token | 4734 | `05` | literal value |
| value type | 4735 | `01` | STRING |
| `char_count` | 4736 | `35 00` | **53** (no null terminator) |
| chars | 4738 | 106 bytes UTF-16LE | `http://schemas.microsoft.com/win/2004/08/events/event` |
| next byte | 4844 | `02` | `CloseStartElementTag` — confirms `attr_list_size` |

Summed, the attribute's own bytes (`06` + `name_offset`(4) + NameNode(20) +
ValueText(1+1+2+106)) total exactly **135** — the same number the file
stores in `attr_list_size` — and `attr_region_start(4709) + 135 = 4844`
lands exactly on the `CloseStartElementTag` byte. Three independent facts
(the attribute's own byte sum, the stored `attr_list_size`, and the
structural close-tag position) agree, which is what "measured, not assumed"
means in this series: this is not an inference from the spec, it is arithmetic
against the real file's own bytes, done before any code changed.

Two things this table confirms beyond the brief's own two traps:

- **`ValueText` (token `0x05`, type `0x01`) carries no null terminator** —
  53 UTF-16LE code units, exactly `len("http://schemas.microsoft.com/win/2004/08/events/event")`,
  with nothing after the last character. This is the opposite convention
  from `NameNode` and substitution string values, both of which do carry a
  trailing `00 00`. Missing this would have produced a payload 2 bytes too
  long and an `attr_list_size` off by 2.
- **`xmlns`'s own `NameNode` is inline**, immediately after the Attribute
  token's 4-byte `name_offset` field — the same "self-referencing" layout
  `writeAttributeSub` already uses, not a shared/back-referenced entry in the
  chunk's common-string table.

**Implementation: one new writer, no substitution slot.** `binxml.go` gained
`writeAttributeLiteral` (Attribute token + inline NameNode + `writeValueText`)
alongside the existing `writeAttributeSub` (Attribute token + inline NameNode
+ `NormalSubstitution`) — same shape, different tail, so the two attribute
kinds share `writeNameNode` and nothing else needs to change. `xmlns`'s value
is fixed in every record, so it is written inline rather than occupying a
30th substitution slot, which would have shifted the index map `CLAUDE.md`
documents and every index `binxml_reader.go` reads by. `<Event>` moves from
`pushOpenElement(..., false, ...)` (token `0x01`) to `pushOpenElementAttrs`
(token `0x41`), gaining an `attr_list_size` computed by `closeAttrList` —
the exact mechanism Task 7f (F11) built for `<Provider>`/`<TimeCreated>`/
`<Data>`, reused rather than duplicated. `attrListPos`'s declaration moved
up one block so `<Event>` could use it too; no second back-patch path was
added.

**Knock-on, found and fixed in this task: `dependency_test.go`'s byte
scanner had a latent false-positive class.** The scanner treats any
`0x01`/`0x41` byte followed by a "plausible" (small) 4-byte field as an
`OpenStartElement` header. `<Event>`'s new 135 bytes shift every later
offset in the payload; after the shift, the `<Provider>` element's own
`Name` attribute happened to get `name_offset = 0x0601` — low byte `0x01` —
immediately followed by its `NameNode`'s `next_offset` field, which
`writeNameNode` always writes as `0`, i.e. a "plausible" zero-size element
span. `go test -race ./... -count=1` caught this immediately (one `Errorf`,
`found` still correctly counting all 20 real elements). Rather than patch
around this one collision, the scanner now recognizes `0x06` (`Attribute`)
tokens and skips their structure — but only after confirming the field
really is a `name_offset`, by checking it holds the *exact* absolute address
its `NameNode` sits at (`base+i+5`). An unguarded byte-value check alone is
not enough: `0x06` is a common byte in ordinary text and substitution value
data (an early version of the fix, matching on the byte value alone,
mis-skipped past two real elements — `found` dropped to 18 instead of 20 —
because it occasionally matched inside unrelated data and computed a bogus
skip length from a decoded "char_count" that happened to be large). The
exact-address check eliminates that: 15 genuine Attribute tokens detected
(14 pre-existing + `xmlns`), zero false positives, `found` back to the
correct 20.

**Reader: confirmed unaffected, not assumed.** `binxml_reader.go` decodes
`data_length` from the fixed `TemplateNode` header offset (`payload[34:38]`)
and jumps straight to the substitution array — it never walks element or
attribute tokens, so an attribute added to the template body changes nothing
about how records are read; `data_length` simply reflects the longer body
automatically. Confirmed by running the round-trip tests
(`TestReadRecord_RoundTrip`, `TestReadRecord_MultipleRecords`) rather than
inferring it from the code, per the brief's "confirm rather than assume"
instruction.

**Node-offset re-verification, run deliberately** (the hash-table
integration test decodes bytes at every reported `NameNode` offset and
recomputes the hash, so a wrong offset — 4 bytes off, landing mid-`NameNode`
— produces a hash mismatch, not merely a wrong string):

```text
=== RUN   TestBuildBinXML_ReportsNameOffsets
--- PASS: TestBuildBinXML_ReportsNameOffsets (0.00s)
=== RUN   TestBuildBinXML_TemplateSelfPointer
--- PASS: TestBuildBinXML_TemplateSelfPointer (0.00s)
=== RUN   TestWrittenFile_ChunkTablesArePopulated
    hashtable_integration_test.go:66: 12 names reachable through the table
--- PASS: TestWrittenFile_ChunkTablesArePopulated (0.02s)
=== RUN   TestWrittenFile_ChunkHeaderCRCCoversTables
--- PASS: TestWrittenFile_ChunkHeaderCRCCoversTables (0.01s)
=== RUN   TestWriteOpenElement_AttrListSizeAfterNameNode
    attrlist_test.go:119: 15 attribute-bearing elements carry a correctly-placed, non-zero attr_list_size
--- PASS: TestWriteOpenElement_AttrListSizeAfterNameNode (0.00s)
=== RUN   TestWriteOpenElement_DependencyIDIsUnset
    dependency_test.go:110: 20 OpenStartElement tokens carry the 0xffff sentinel
--- PASS: TestWriteOpenElement_DependencyIDIsUnset (0.00s)
```

12 reachable names, not 11 (Task 7f's count): `xmlns` is the one new unique
name added to the chunk's string table (`Event`, `System`, `Provider`,
`Name`, `EventID`, `Level`, `TimeCreated`, `SystemTime`, `Computer`,
`EventData`, `Data`, `xmlns` = 12); 15 attribute-bearing elements, not 14
(the pre-existing 14 plus `<Event>` itself).

**Golden file: length changed, exactly as predicted — unlike the last three
tasks.** `testdata/binxml-golden.bin` went from 1811 to **1950 bytes**, +139:
the attribute's own 135 bytes (`06` + `name_offset`(4) + NameNode(20) +
ValueText(1+1+2+106)) plus the 4 new bytes of `<Event>`'s own
`attr_list_size` field (which did not exist at all when `<Event>` had no
attributes). Captured via the documented procedure — a throwaway
`TestCaptureGolden` (written, run once to overwrite
`testdata/binxml-golden.bin` via `goldenFields()`'s frozen timestamp, then
removed; never committed).

**Verification, all four gates:**

```console
$ go build ./...
$ GOOS=windows go build ./...
$ go test -race ./... -count=1
ok  	github.com/fjacquet/go-evtx	15.141s
?   	github.com/fjacquet/go-evtx/cmd/gen-fixture	[no test files]
$ go vet ./...
$ golangci-lint run
0 issues.
```

Commit `3b3f575` ("fix: declare the event schema namespace on the Event root
(F8)"), pushed to `feat/v0.7.0-format-correctness`.

**Run selection, by head SHA, not recency:**

```console
$ git rev-parse HEAD
3b3f575449baabe1032c67518c76399039c4608d
$ gh api repos/fjacquet/go-evtx/actions/runs/31277415872 --jq '.head_sha'
3b3f575449baabe1032c67518c76399039c4608d
$ gh api repos/fjacquet/go-evtx/actions/runs/31277416044 --jq '.head_sha'
3b3f575449baabe1032c67518c76399039c4608d
```

Both `Format Verify` (`31277415872`) and the standard `CI` workflow
(`31277416044`, build/test/lint on push) confirmed at this exact commit.
`CI` completed with `success` (`ci / ci` and `security / security` both
succeeded). `Format Verify`'s overall conclusion is `failure` — but that
conclusion is the `get-winevent` job alone; its other two jobs
(`generate`, `python-evtx-differential`) both succeeded, per-job:

```console
$ gh run view 31277415872 --json jobs --jq '.jobs[] | {name, conclusion}'
{"name":"generate","conclusion":"success"}
{"name":"python-evtx-differential","conclusion":"success"}
{"name":"get-winevent","conclusion":"failure"}
```

**Fixture is NOT byte-identical to rows 6-9**, exactly as this section's
change predicts. From the `generate` job log:

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31573 runes)
...
go_evtx_chunk_flushed path=artifacts/generated.evtx chunk=21 total_chunks=22
```

31573 runes (down from 31642) and **22 chunks (up from 21)**: F8 adds 139
bytes to every record's encoded BinXML payload, so `largestAccepted()`'s
binary search against the real writer settles on a shorter maximum
`ObjectName`, and the two chunk-fill boundary records (each already sized to
~55% of the *old* maximum) now push one additional chunk boundary. Per the
brief and every prior task in this series, this makes any record-count or
message comparison to rows 2-9 invalid on its own — only the open/read stage
split, and now the python-evtx result, stay interpretable across this
boundary.

Job log (`generate`):
<https://github.com/fjacquet/go-evtx/actions/runs/31277415872/job/93153166636>

### python-evtx differential: PASS — the breakthrough this task's brief named

```text
OK: 403 records, all chunk checksums verify
```

**The `ObjectName` count that has been `got 0, want 403` since the very
first baseline (row 1, before this release even started counting rows) is
now correct.** `scripts/verify_python_evtx.py` queries
`root.iterfind(".//e:Data", {"e": "http://schemas.microsoft.com/win/2004/08/events/event"})`
— a namespaced XPath that matched nothing against every prior row's
namespace-less `<Event>`, regardless of whether the underlying `Data`
elements and their content were otherwise correct (they were: F1-F11 had
already fixed every structural divergence this differential could see,
which is exactly why it had been silently masking a defect the checker
itself could not observe until its own query started matching). Declaring
`xmlns` did not change a single byte of `<Data>`'s own encoding — it changed
whether `ET.fromstring`'s namespace-aware `iterfind` can see `<Data>` at
all.

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31277415872/job/93153230092>

**`get-winevent` — verbatim:**

```text
STAGE1 OPEN: ok
STAGE2 READ: FAILED after 0 records - System.Management.Automation.MethodInvocationException: Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31277415872/job/93153230098>

### Reading this result, plainly, without adjusting anything to chase a greener outcome

**Two numbers, and they move in opposite directions. Both are reported in
full, neither softened.**

**`STAGE2 READ`: still zero.** Stage 1 still opens cleanly; stage 2 still
throws on the very first `ReadEvent()`, identical exception type, identical
wording, identical record count (0), as every row since row 5. F8 was, by
this task's own framing, the strongest remaining *a priori* case for a hard
`.NET` `EventLogReader` abort — the one candidate that changes what the
document *is* rather than how its bytes are laid out — and it still did not
move `STAGE2 READ` off zero. Twelve single-defect or single-structural tasks
in this release (F1/F3-F11, B1-B3, F8) have now each independently corrected
a real, measured divergence from the real file, and none has changed
`Get-WinEvent`'s record-1 rejection.

**python-evtx `ObjectName`: `got 0, want 403` → `PASS`, unchanged since the
very first baseline until this exact task.** This is not a null result and
is not presented as one: it is a real, reportable outcome, predicted by the
brief before the fix was written, and confirmed against an independent
parser implementation (not go-evtx reading its own output). It proves the
namespace declaration is now correct and that a real, independent,
namespace-aware XML consumer can extract field values from go-evtx's output
for the first time in this release.

**Together, these two results say something Windows-only or python-evtx-only
measurements could not say alone: whatever blocks `Get-WinEvent` is not the
missing namespace, and is not upstream of `<EventData>`'s own content
either** — python-evtx parses the full document, including every `<Data>`
element deep inside `<EventData>`, without error. The defect `.NET`'s
`EventLogReader` throws on remains open. The brief's own remaining named
candidates — the sparse `<System>` block (5 of the real file's 14 elements)
and S5 (go-evtx never emits `OptionalSubstitution`) — are untouched by this
task and, after F8's elimination, are what remain.

## Task 8b: F12 (`<System>`, value types, `OptionalSubstitution` — batched)

**Batched deliberately**, per the task's own brief: F12a (value types), F12b
(the sparse `<System>` block) and F12c (`OptionalSubstitution`) are three
facets of one thing — the record didn't describe an event the way Windows
describes an event — so they were fixed together against one Step 1
measurement rather than three separate single-defect tasks.

### Step 1: decoding `<System>` from `testdata/system.evtx`, before any code changed

Chunk 0, record 0 (`EventRecordID 12049`, provider
`Microsoft-Windows-Eventlog`), absolute file offsets. `<System>` itself opens
at 749 (token `0x01`, no attributes, `dependency_id` `0xffff`, `data_size`
1158) and closes (its own `EndElementTag`) at 1913. Every child, in the
real file's own order:

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

Cross-checked against a second record in the same chunk (`EventRecordID
12050`, offset 2688, same template resident at a different `TemplateInstance`
occurrence) and against Task 7e/7f's own independently-measured
`data_size`/`attr_list_size` numbers for `<Provider>` (783, `data_size`
217) and `<System>` (749, `data_size` 1158) — identical. Full walk (all 20
tokens, all 20 substitution-array entries) in
`scratchpad/tokendiff/real_decoded.txt` (generated by a from-scratch BinXML
walker, `scratchpad/tokendiff/decode.py`, re-run fresh against
`testdata/system.evtx` for this task rather than trusted from the prior
task's cached output).

**This table corrects the brief's own prose in one place.** F12c's text
frames `0x0E` as needed "for any element added in F12b whose value can be
absent." The measured table shows real Windows uses `0x0E` for **every**
`<System>` child whose sole content is one substitution value — including
`EventID` and `Level`, which already existed and whose value go-evtx always
supplies (never absent). The brief's own text anticipates and permits this
reading ("elements that are genuinely always present may legitimately stay
`0x0D`"), so `EventID`/`Level` were deliberately left `0x0D`/`0xffff` — but
the table, not the prose summary, is what a future task should extend from
if it revisits this.

### F12a confirmed exactly as suspected

`Level`'s value type is `UNSIGNED_BYTE` (`0x04`) in the real file, not
`UNSIGNED_WORD` (`0x06`) as go-evtx wrote through every prior release.
Fixed: `collectSubstitutionsFromFields`'s substitution 2 now writes a
1-byte `binXMLTypeUint8` entry, and `buildTemplateBody`'s own
`writeSubstitution(b, 2, ...)` call matches.

### F12b: nine children added, in the real file's own order

`Version`, `Task`, `Opcode`, `Keywords`, `EventRecordID`, `Correlation`
(`ActivityID`/`RelatedActivityID`), `Execution` (`ProcessID`/`ThreadID`),
`Channel`, `Security` (`UserID`) — bringing `<System>` from 5 to 14
children, in the measured order: `Provider`, `EventID`, `Version`, `Level`,
`Task`, `Opcode`, `Keywords`, `TimeCreated`, `EventRecordID`,
`Correlation`, `Execution`, `Channel`, `Computer`, `Security`. `Version`
now sits between `EventID` and `Level` — a real reordering, not just an
insertion, since Task 8's release wrote `Level` immediately after `EventID`.

`EventRecordID` carries the writer's real record ID (`w.recordID`, already
tracked). `Version`/`Task`/`Opcode`/`Keywords` have no caller-supplied
source, so each carries a typed zero rather than invented data — matching
`Version`'s own real value (`0`) in the sampled record.
`Correlation`/`Execution`/`Security`'s five attributes
(`ActivityID`/`RelatedActivityID`/`ProcessID`/`ThreadID`/`UserID`) have no
source either; each is written NULL (value-spec size 0, type `0x00`) —
reproducing exactly how the real file itself encodes these fields for an
event that doesn't populate them (`Correlation`'s own `ActivityID` in the
sampled record is itself NULL), not inventing forensic data go-evtx was
never given.

Substitution indices 29-39 are appended after the existing 0-28 — the 12
caller-facing data fields (`dataFieldNames`, indices 5-28) keep their exact
original indices and semantics; nothing calling `WriteRecord` needs to
change.

### F12c: `OptionalSubstitution` (`0x0E`) added

`writeOptionalSubstitution`/`writeAttributeOptional` (new, mirroring the
existing `writeSubstitution`/`writeAttributeSub`) emit token `0x0E`.
`writeOpenElement`/`pushOpenElement`/`pushOpenElementAttrs` gained a real
`depID` parameter: `Version`/`Task`/`Opcode`/`Keywords`/`EventRecordID`'s
own `OpenStartElementTag` now carries that substitution's own index as
`dependency_id`, matching the real file's convention exactly.
`Correlation`/`Execution`/`Security` stay `dependency_id` `0xffff` (element
itself always present, matching the real file) with their individual
attribute values `0x0E`-wrapped.

`Provider`'s `Name` attribute gained a `moreAttrs`-capable `writeAttributeSub`
(token `0x46`, "more attributes follow") because `Correlation` and
`Execution` each need two attributes in one list — a token go-evtx had never
emitted before this task.

### Round trip and the hash-table integration test, run deliberately

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
`Channel`, `Security`, `UserID`) — exactly `12 + 14 = 26`, offsets moved
substantially and re-verified clean.

`binxml_reader.go` needed one real change (`Level` decodes as a 1-byte
value now, not 2 — a new `getUint8` helper; the old `getUint16` would have
silently returned `0` for every record's `Level`), confirmed by
`TestReadRecord_RoundTrip` and the new `system_test.go` regression tests
(`TestCollectSubstitutions_LevelIsUint8`,
`TestBuildTemplateBody_NewSystemChildrenPresent` — both confirmed to fail
against the pre-fix encoder: `Level`'s type was `binXMLTypeUint16` and none
of the fourteen new names appeared anywhere in `binxml.go` at all).

`dependency_test.go`'s generic byte scanner needed two changes: it now
bounds its scan to the template body (`preambleSize` through
`preambleSize+data_length`) rather than the whole payload — Task 8b's own
new bytes (a NULL entry's absence of data, `EventRecordID`'s small
`uint64`) produced one genuine coincidental false-positive header match in
the substitution array/value data region, which was never in scope for
this scanner — and it recognises the five legitimate new dependency IDs
instead of flagging them as corruption.

### Golden file: +649 bytes

`testdata/binxml-golden.bin` grew from **1950 to 2599 bytes (+649)** —
the eleven new substitution slots' value-spec entries plus the nine new
elements' full token structure (open tags, attribute lists, NameNodes,
substitution/value tokens, end tags). Regenerated via the documented
procedure: a throwaway `TestCaptureGolden`, run once, removed before commit.

### Verification: all four gates

```console
$ go build ./...
$ GOOS=windows go build ./...
$ go test -race ./... -count=1
ok  	github.com/fjacquet/go-evtx	16.259s
$ go vet ./...
$ golangci-lint run
0 issues.
```

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

**Fixture is NOT byte-identical to row 10**, as expected: eleven new
substitution slots and nine new elements add real bytes to every record.
From the `generate` job log:

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31248 runes)
...
go_evtx_chunk_flushed path=artifacts/generated.evtx chunk=25 total_chunks=26
```

31248 runes (down from 31573) and **26 chunks (up from 22)**: the larger
per-record payload settles `largestAccepted()`'s binary search lower and
pushes more chunk-fill boundaries, exactly the same mechanism Task 8's own
139-byte growth produced, just larger (this task adds far more than 139
bytes per record).

Job log (`generate`):
<https://github.com/fjacquet/go-evtx/actions/runs/31278789309/job/93156614017>

### python-evtx differential — stayed GREEN, the regression guard held

```text
OK: 403 records, all chunk checksums verify
```

Unchanged from row 10. This is the number the brief named as the more
important of the two to check first: a regression here would have meant
this task broke what Task 8 fixed. It did not — python-evtx still parses
every record, every `<Data>` element, and every chunk checksum cleanly,
including all nine new `<System>` children and the `0x0E` tokens
python-evtx's own parser does not specially validate.

Job log:
<https://github.com/fjacquet/go-evtx/actions/runs/31278789309/job/93156675064>

### `get-winevent` — verbatim

```text
STAGE1 OPEN: ok
STAGE2 READ: FAILED after 0 records - System.Management.Automation.MethodInvocationException: Exception calling "ReadEvent" with "0" argument(s): "The data is invalid."
```

Identical exception type, wording, and record count to every row since row
5 — including row 10, whose fixture and payload shape were both very
different. No breakthrough.

Job log:
<https://github.com/fjacquet/go-evtx/actions/runs/31278789309/job/93156675052>

### Reading this result, plainly

**`STAGE2 READ`: still zero.** Thirteen tasks (F1/F3-F11, B1-B3, F8, F12)
have now each independently corrected a real, measured divergence from the
real file — including, this task, all three of the brief's own named
"facets of one thing": the value-type mismatch, the sparse `<System>`
block, and the complete absence of `OptionalSubstitution`. None has moved
`Get-WinEvent`'s record-1 rejection off zero, and this was the release's
strongest remaining candidate by the brief's own framing (an event that
finally describes itself the way Windows describes an event, batched
rather than measured one field at a time). The defect `.NET`'s
`EventLogReader` throws on remains open, and no further candidate from this
release's own investigation (tokendiff-report.md, the escalation report)
remains untried.

**python-evtx: PASS, unchanged.** The regression guard held — this task did
not break what Task 8 fixed. A null result on `Get-WinEvent` with
python-evtx still green is, per the brief's own framing, a real outcome
here: it says whatever `.NET`'s `EventLogReader` requires is not fully
captured by any divergence this release's investigation (byte-level
comparison against two real records, cross-checked against MS-EVEN6's own
worked example) found — or that it requires several of these fixed
divergences in combination with something not yet identified, rather than
any single one of them.

## Task 8c: F13 (exhaust the named list — batched, this is the breakthrough)

**This row is the first non-zero `STAGE2 READ` in this entire table.** Read
that sentence again before reading anything else below it: fourteen tasks
(F1/F3-F11, B1-B3, F8, F12) each independently corrected a real, measured
divergence from `testdata/system.evtx` and none moved `STAGE2 READ` off
zero. This task's fixes did. Full detail is in
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-8c-report.md`,
written after the fact from the commit and CI logs (the report was not
written at the time because the agent that implemented this task stalled
waiting on CI rather than writing up what was already measured); the
essential facts are repeated here so this document stays self-contained.

**Change, batched deliberately per the task brief** (the same reasoning
Task 8b used for F12a/b/c): three named divergences from
`testdata/system.evtx`'s `<System>` block, all previously measured and
deliberately deferred by earlier tasks, fixed together against one
Step-1-derived table rather than as three single-field tasks.

- **F13a**: `EventID` and `Level` reclassified from `NormalSubstitution`
  (`0x0D`) to `OptionalSubstitution` (`0x0E`), with `dependency_id` set to
  the element's own content substitution index (`subEventID = 1`,
  `subLevel = 2`) — not the index of any attribute the element also
  carries. Task 8b had left both at `0x0D`/`0xffff` as an explicit,
  permitted scope decision; this closes it out to match the real file
  exactly.
- **F13b**: `Provider` gains a second attribute, `Guid` (new substitution
  index 40, STRING, from `fields["ProviderGuid"]`) — the first
  multi-attribute element go-evtx has ever emitted. `Name`'s own attribute
  token switches from `0x06` to `0x46` ("more attributes follow"); `Guid`
  (last) stays `0x06`.
- **F13c**: `EventID` gains a `Qualifiers` attribute (new substitution
  index 41), go-evtx's first NULL-valued `OptionalSubstitution` whose
  declared type is the field's own real type (`UNSIGNED_WORD`) rather than
  a generic null-type marker — matching `testdata/system.evtx`'s own
  encoding and MS-EVEN6's worked example.

Substitution index map extended from 40 to **42** total slots. A
`dependency_test.go` scanner gap exposed by F13a's reuse of small
substitution indices as dependency IDs was fixed alongside (strengthened to
verify `name_offset` exactly, the same check `attrlist_test.go` already
used, rather than the size heuristic it replaced).

Commit `2e86005` ("fix: exhaust the named list — EventID/Level
OptionalSubstitution, Provider/@Guid, EventID/@Qualifiers (F13)"), pushed to
`feat/v0.7.0-format-correctness`.

**Run selection, by head SHA:**

```console
$ git rev-parse HEAD
2e860058cb78c1aae14bb31b7d6ed74a14a4a810
$ gh api repos/fjacquet/go-evtx/actions/runs/31285813636 --jq '.head_sha'
2e860058cb78c1aae14bb31b7d6ed74a14a4a810
$ gh api repos/fjacquet/go-evtx/actions/runs/31285813757 --jq '.head_sha'
2e860058cb78c1aae14bb31b7d6ed74a14a4a810
```

Both `Format Verify` (`31285813636`) and the standard `CI` workflow
(`31285813757`, build/test/lint on push) confirmed at this exact commit.
`CI` completed with `success`. `Format Verify`'s overall conclusion is
`failure` — per-job:

```console
$ gh api repos/fjacquet/go-evtx/actions/runs/31285813636/jobs --jq '.jobs[] | {name,conclusion}'
{"name":"generate","conclusion":"success"}
{"name":"get-winevent","conclusion":"failure"}
{"name":"python-evtx-differential","conclusion":"success"}
```

**Fixture is NOT byte-identical to row 11**, as expected — F13b/F13c add
real bytes to every record. From the `generate` job log:

```text
wrote artifacts/generated.evtx (403 records, max ObjectName 31208 runes)
...
go_evtx_chunk_flushed path=artifacts/generated.evtx chunk=26 total_chunks=27
```

31208 runes (down from 31248) and **27 chunks (up from 26)** — the same
mechanism (larger per-record payload settles `largestAccepted()`'s binary
search lower, pushing one more chunk-fill boundary) every prior growing
task in this series has produced.

Job log (`generate`):
<https://github.com/fjacquet/go-evtx/actions/runs/31285813636/job/93174296078>

### python-evtx differential — stayed GREEN

```text
OK: 403 records, all chunk checksums verify
```

Unchanged from row 11. The regression guard held.

Job log:
<https://github.com/fjacquet/go-evtx/actions/runs/31285813636/job/93174342754>

### `get-winevent` — verbatim, the load-bearing result of this task

```text
STAGE1 OPEN: ok
STAGE2 READ: ok, 403 records
```

**Fourteen prior tasks each moved zero. This is the first non-zero
`STAGE2 READ` in this document's history.** .NET's `EventLogReader`,
reading forward one record at a time via `ReadEvent()`, decodes all 403
records without throwing.

The workflow step does not stop there — the pre-existing, unmodified
assertion block further down the same step still runs
`$events = @(Get-WinEvent -Path artifacts/generated.evtx -ErrorAction Stop)`,
and this throws:

```text
Get-WinEvent: D:\a\_temp\dae63c47-4ecf-44d3-99ee-98126b65f182.ps1:40
Line |
  40 |  $events = @(Get-WinEvent -Path artifacts/generated.evtx -ErrorAction …
     |             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | The data is invalid.
```

Job log:
<https://github.com/fjacquet/go-evtx/actions/runs/31285813636/job/93174342750>

`Format Verify`'s overall conclusion is `failure` because of this second,
still-failing assertion — not because `STAGE2 READ` regressed. Two
different Windows APIs (`EventLogReader.ReadEvent()`, forward iteration;
`Get-WinEvent`, newest-first by default) reading the identical bytes give
two different verdicts. That gap — and whether it is ordering-dependent —
is the subject of Task 8d, documented in
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-8d-report.md`,
not repeated here.

### Reading this result

**Do not guess which of F13a/F13b/F13c moved it.** This task's own brief
batched all three against one Step 1 measurement, the same way Task 8b
batched F12a/b/c — a single pass/fail CI signal over the whole file, with
no run that applied only one of the three. python-evtx was already green
before this task and stayed green after, so it gives no discriminating
signal either. Attributing the breakthrough to one specific fix here would
be an inference dressed as a measurement, exactly the discipline this
document's own opening caveat exists to prevent. What is established: the
combination of all three, applied on top of the fourteen prior fixes, is
what produced the first non-zero `STAGE2 READ` in this release. Isolating
which sub-fix (or combination) is load-bearing would require a splice
experiment this task did not run.

## Task 8d: `-Oldest` experiment, and where `Get-WinEvent` actually fails

Full detail is in
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-8d-report.md`;
the essential facts are repeated here so this document stays
self-contained, per the same convention row 12/"Task 8c" above follows.

**Change.** `.github/workflows/format-verify.yml`'s `get-winevent` job,
which already established (row 12) that `Get-WinEvent`'s own assertion
still throws even though `EventLogReader.ReadEvent()` reads all 403
records forward, gained two rounds of diagnostics, in two commits:

- `bdc3ec1`: splits the existing `Get-WinEvent` assertion into two
  independent orderings — default (newest-first) and `-Oldest` — each
  reported on its own `GETWINEVENT` line, testing the leading hypothesis
  that reverse-iteration metadata
  (`LastEventRecordNumber`/`LastEventRecordDataOffset`/`LastChunkNumber`/
  `NextRecordIdentifier`) was the defect.
- `72f63a0`: adds two more non-fatal probes to the same job — `LOGINFO`
  (`EventLogSession.GetLogInformation()`, log-header-level metadata
  `EvtNext`/`ReadEvent()` never touches) and `PROP` (touches each of
  `Id`/`Level`/`ProviderName`/`TimeCreated`/`RecordId`/`MachineName`/
  `ToXml()` individually on the same record object `STAGE2` already
  captured).

Neither commit touches Go code, `go.mod`, or `cmd/gen-fixture/main.go` —
confirmed by `git diff 2e86005 72f63a0 -- '*.go' go.mod
cmd/gen-fixture/main.go` being empty — so both are directly comparable to
row 12's fixture.

**Run selection, by head SHA:**

```console
$ gh api repos/fjacquet/go-evtx/actions/runs/31286108697 --jq '.head_sha'   # Format Verify, bdc3ec1
bdc3ec1811478c6bf1b3dfa5f97bc6c9bb964428
$ gh api repos/fjacquet/go-evtx/actions/runs/31286256103 --jq '.head_sha'   # Format Verify, 72f63a0
72f63a05efadab09d1ea33e629b0aa91ee08b060
```

**Fixture identity, confirmed from the `generate` job log at both
heads:** `wrote artifacts/generated.evtx (403 records, max ObjectName
31208 runes)`, 27 chunks — byte-identical to row 12.

python-evtx differential — unchanged, still green:

```text
OK: 403 records, all chunk checksums verify
```

**`get-winevent` — verbatim, from run `31286256103` (head `72f63a0`)::**

```text
STAGE1 OPEN: ok
STAGE2 READ: ok, 403 records
LOGINFO: ok - records=403 oldest=1 full=False
PROP Id ok: 
PROP Level ok: 
PROP ProviderName ok: 
PROP TimeCreated ok: 
PROP RecordId ok: 
PROP MachineName ok: 
PROP ToXml FAILED - Exception calling "ToXml" with "0" argument(s): "The data is invalid."
GETWINEVENT default: FAILED - The data is invalid.
GETWINEVENT -Oldest: FAILED - The data is invalid.
```

Reproduced identically (same wording, same fixture) at run `31286108697`
(head `bdc3ec1`) for the `GETWINEVENT` lines, before the `LOGINFO`/`PROP`
probes existed.

### Reading this result

**The `-Oldest` hypothesis is closed, not just deprioritized.** Both
orderings produce the byte-identical exception type and message on the
byte-identical file — reverse-iteration metadata was never the variable
that mattered. This eliminates ordering direction as a candidate outright.

**The extended `LOGINFO`/`PROP` probes narrow the defect further, past
where row 12 left it.** Three facts, each measured directly, not inferred:

1. `EventLogSession.GetLogInformation()` succeeds and reports the correct
   record count — file-header-level metadata is not what throws.
2. Six typed properties on the very `EventRecord` object `ReadEvent()`
   already returned all read without throwing, but every one is **empty**
   — including `ProviderName`, which the fixture's `<System><Provider
   Name="...">` gives a real, non-empty value. Reported as observed, not
   explained: consistent with (but not proof of) the property getters
   silently swallowing an internal failure.
3. **`EventRecord.ToXml()`, called directly on the same record object,
   throws the identical `"The data is invalid."` string both
   `Get-WinEvent` orderings throw.**

**What this narrows.** `STAGE2 READ: ok, 403 records` proves only that the
low-level record-fetch path (`EvtNext`) succeeds. It does not prove any
record's content can be rendered. `ToXml()` throwing the exact string
`Get-WinEvent` throws places the defect specifically in **XML rendering of
a record's content** — BinXML template-to-XML resolution via the
substitution array — not in enumeration and not in file-level metadata.
This does not by itself identify which substitution-array content
triggers the render failure; see "F14" below for the investigation that
followed from this lead.

## Task 8e (F14): a substitution-array probe, two false starts, net zero

Full detail — including the complete substitution-array table, the
byte-for-byte real-file cross-check, and the string null-termination
lead found but not acted on — is in
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-8e-report.md`.
Summarized here per this document's own convention.

**Starting point.** Task 8d's `ToXml()` lead pointed at XML rendering of a
record's content. A probe of go-evtx's own record 0's substitution array,
cross-checked against `task-8b-report.md`'s Step 1 table (a real-file
decode from an earlier task), found the table claims four NULL-valued
positions declare their field's own real type (`GUID`, `SID`,
`UNSIGNED_WORD`) rather than a generic `0x00` marker.

**Attempt 1 (`eecb372`) — regression, caught immediately.** Reclassified
five NULL fields (`Correlation/@ActivityID`/`@RelatedActivityID`,
`Execution/@ProcessID`/`@ThreadID`, `Security/@UserID`) from
`binXMLTypeNull` to `GUID`/`SID`/`UINT32`, trusting that table. Broke
`python-evtx-differential` outright — its own parser rejects a fixed-width
type (`GUID` = 16 bytes) declared at a size more than 4 bytes short, and a
NULL value's size (0) fails that check for any 16-byte type.

**Re-verification, three independent ways**, done in direct response to
the break: a byte-for-byte raw re-parse of `testdata/system.evtx`'s own
record 0 (the exact record the Step 1 table cites) found the real bytes at
all four disputed positions are declared type `0x00`, not
`GUID`/`SID`/`UNSIGNED_WORD` — the table was wrong there, confirmed by
`python-evtx`'s own successful real-file parse (impossible if `ActivityID`
were really `GUID`-typed at size 0) and by `UnsignedWordTypeNode`'s
narrower 2-byte tolerance explaining why the table's `Qualifiers` error
never broke anything on its own.

**Attempt 2 (`e1f8aca`) — a second, different regression.** Reverted all
six NULL fields (the five above, plus `EventID/@Qualifiers`, which F13c
had declared `UNSIGNED_WORD`) to `binXMLTypeNull`, matching the
byte-for-byte finding. Fixed `python-evtx`. **Broke `Get-WinEvent`'s
`STAGE2 READ`** — Task 8c's own breakthrough — from reading all 403
records to failing on record 0.

**Isolation and final correction (`ab6ae57`).** A third data point
(`eecb372`'s own `get-winevent` job, checked retroactively: `STAGE2 READ`
failed after 384 records, a third distinct mode) isolated it to
`Qualifiers` specifically — of three combinations tried, Windows fully
accepts only the original F12b/F13c one (five fields `NULL`, `Qualifiers`
`UNSIGNED_WORD`). Reverted `Qualifiers` back to `UNSIGNED_WORD`, restoring
`binxml.go`'s emitted bytes to MD5-identical parity with row 13
(`72f63a0`). Row 14's measurement (above) confirms this: every field
`get-winevent` prints for `ab6ae57` matches row 13's exactly.

### Reading this result

**Net functional code change: none, and that is the whole point.** Three
pushes, three CI round-trips, and the release ends exactly where Task 8d
left it — but with a real, confirmed divergence documented
(`task-8b-report.md`'s Step 1 table is wrong at four positions, corrected
in place with its own note) and a real, confirmed non-fix ruled out with
evidence rather than left as an untested guess for a future task to
re-attempt. `Correlation`/`Execution`/`Security`'s five fields' reversion
to `binXMLTypeNull` is solid, independent of the `Qualifiers` question
(the `python-evtx` crash is type-identity-driven, not tied to which named
field the type is nominally attached to). `Qualifiers`'s own case is
**left open, not resolved**: real Windows' file shows `0x00` at the
position identified as `Qualifiers`; go-evtx's own record needs `0x06`
there for Windows to read it. The task-8e-report.md "Concerns" section
names the likeliest reconciliation (the Step 1 table's *index*
assignments, not just some of its *type* claims, may themselves be
unreliable) as unchecked, not ruled out.

**A new, unimplemented lead for the next task.** Every `String`-typed
substitution-array value real Windows writes (28/28 samples checked) has
**no trailing null terminator** — declared size is exactly character
count × 2. go-evtx's `encodeSubString` always appends one. This touches
`ProviderName` directly, plausibly relevant to the still-open "empty
scalar properties" half of the original symptom — flagged, not
implemented, per this task's own hard-won caution about unmeasured
byte-level fixes.

## Task 8f: F15 (substitution-value string null terminator) — backfilled

**Paperwork gap, not a missing measurement.** This row was never written:
the implementing task pushed the fix, CI ran and completed, and the task
was interrupted before its report and this row were committed — consistent
with the pattern named in task-9a's own brief ("Four agents have now burned
their budgets waiting on CI and had to be killed"). The commit
(`b41ac76`, "fix: encodeSubString drops the substitution-value null
terminator (F15)") and the CI run it produced (`31287980079`) both already
existed and are unchanged by this backfill — only the documentation was
missing. Recorded here by Task 9a before adding its own rows, so the table
has no unexplained gap and so Task 9a's own fixture-length delta (see
below) has a documented cause rather than looking like an unexplained
discrepancy.

**The fix.** `encodeSubString` (binxml.go) stopped appending a trailing
UTF-16 null pair to String-typed substitution-array *values* — confirmed
against `testdata/system.evtx` by decoding the substitution arrays of 45
records using a "full" (inline, non-cached) template instance: 28/28
non-empty String entries have a declared size of exactly `char_count*2`,
none carry a trailing null. `NameNode` strings are unaffected (real Windows
does null-terminate those, and `writeNameNode` was never touched).

**Measurement, verbatim, from run [`31287980079`](https://github.com/fjacquet/go-evtx/actions/runs/31287980079) (head `b41ac76`):**

```console
$ gh api repos/fjacquet/go-evtx/actions/runs/31287980079 --jq '.head_sha'
b41ac7643fed78390148d84e23154360dd40858c
```

`generate` job: `wrote artifacts/generated.evtx (403 records, max ObjectName
31236 runes)` — independently reproduced locally by re-running
`cmd/gen-fixture` unmodified against this same commit, confirming the
binary search is deterministic and the CI number is not a fluke.

`python-evtx-differential`: `OK: 403 records, all chunk checksums verify` —
stayed green.

`get-winevent`:

```text
STAGE1 OPEN: ok
STAGE2 READ: ok, 403 records
PROP ToXml FAILED - Exception calling "ToXml" with "0" argument(s): "The data is invalid."
GETWINEVENT default: FAILED - The data is invalid.
GETWINEVENT -Oldest: FAILED - The data is invalid.
```

### Reading this result

**NULL RESULT, held cleanly.** `STAGE2 READ: ok, 403 records` — the
release's hard-won win — was not put at risk by this fix, and
`python-evtx` stayed green. But `ToXml`/`Get-WinEvent` fail with the exact
same exception type and message as row 14, on a fixture that is not
byte-identical (the near-maximum ObjectName ceiling moved by 28 runes as an
arithmetic side effect of shrinking every String value by 2 bytes) —
consistent with this baseline's own standing rule that Windows' rejection
message is content-dependent and a repeated message alone is not by itself
proof that nothing changed structurally, only that whatever *did* change
was not the defect `ToXml` hits. The null-terminator lead is closed, not
open: it was a real, independently-confirmed divergence from the real
file's own bytes, worth fixing on its own merits, but it was not (or was
not sufficient on its own to be) the cause of `ToXml`'s failure.

## Task 9a: Experiment A (minimal fixture) and Experiment B (splice)

Full detail in
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9a-report.md`.
Both experiments were run beside the existing fixture/jobs, which are
untouched — `cmd/gen-fixture/main.go`'s output stays byte-identical to row
15 (row 16 confirms this: no regression, see the table above).

Two experiments neither guesses at another field, each answering a question
seventeen prior field-level fixes could not: does the defect need the big
fixture's scale/variety, and is go-evtx's own file/chunk container sound
independent of its BinXML encoding?

**Experiment A — new `cmd/gen-fixture-minimal` (public API only:
`New`/`WriteRecord`/`Close`), one record, one chunk, pure ASCII, fixed
timestamp — run through new `generate-minimal`/`get-winevent-minimal` jobs:**

```text
MINIMAL STAGE1 OPEN: ok
MINIMAL STAGE2 READ: ok, 1 records
MINIMAL PROP ToXml FAILED - Exception calling "ToXml" with "0" argument(s): "The data is invalid."
MINIMAL GETWINEVENT default: FAILED - The data is invalid.
MINIMAL GETWINEVENT -Oldest: FAILED - The data is invalid.
```

**Fails identically to the 403-record fixture** — same exception type, same
message, on the simplest record this library can produce. 403 records, 21+
chunks, non-BMP strings, and a 31,236-rune record are eliminated from the
variable set: the defect reproduces on one ordinary ASCII record in one
chunk.

**Experiment B — new `cmd/gen-splice-fixture`: extracts `testdata/system.evtx`
chunk 0 record 0's real BinXML (2148 bytes) via `Reader.ReadRaw()`, writes it
into a fresh go-evtx file via `Writer.WriteRaw()`.** Chosen deliberately
(option 1 of the brief's own preference order — a self-relative record, not
rewritten offsets): it is the first record ever written into that chunk, so
by construction every name/template it references is introduced inline,
within its own bytes — verified, not assumed, by a throwaway structural walk
(not committed) that found 27 `name_offset` references and 1
`template_offset`, all 28 resolving inside the record's own `[536, 536+2148)`
byte range. `WriteRaw`'s first call on a fresh `Writer` places its record at
that identical chunk-relative offset (512-byte header + 24-byte record
header = 536), so the bytes needed **zero rewriting**. Run through new
`generate-splice`/`get-winevent-splice` jobs:

```text
SPLICE STAGE1 OPEN: ok
SPLICE STAGE2 READ: ok, 1 records
SPLICE PROP ToXml ok
SPLICE GETWINEVENT default: ok, 1 records
SPLICE GETWINEVENT -Oldest: ok, 1 records
```

**Succeeds completely.** `ToXml()` — the exact call that throws on every
go-evtx-generated record tested, including Experiment A's minimal one —
succeeds on a real record's BinXML wrapped in nothing but go-evtx's own
writer code (file header, chunk header with all-zero hash tables, record
wrapper, CRC32s).

CI run [`31288541480`](https://github.com/fjacquet/go-evtx/actions/runs/31288541480)
(`Format Verify`, head `07f81f0`), jobs: `generate`/`generate-minimal`/
`generate-splice`/`python-evtx-differential`/`get-winevent-splice` all
**success**; `get-winevent`/`get-winevent-minimal` **failure** (expected,
per above — not a regression). `CI` run
[`31288541677`](https://github.com/fjacquet/go-evtx/actions/runs/31288541677)
(build/vet/test/lint/security): **success**.

### Reading this result

**The two experiments localise the defect completely, in the same
direction.** Experiment B proves go-evtx's file/chunk *container* is sound —
real BinXML renders under both Windows APIs wrapped in nothing but go-evtx's
own writer code. Experiment A proves the defect needs none of the big
fixture's scale or variety — it reproduces on the single simplest record
go-evtx's encoder can produce. Together: **the defect is entirely inside
`buildBinXML`/`buildTemplateBody`'s own encoding** (`binxml.go`) — the half
seventeen prior fixes targeted, but evidently not at the right byte(s) yet —
and not in the file header, chunk header, hash tables, record wrapper, or
CRC computation.

This does not identify which byte(s) differ. It does hand the next task a
much cheaper tool than a hex dump: two BinXML payloads already proven by CI
to sit on opposite sides of the same pass/fail line, in the identical
container — one Windows accepts (the spliced real record, 20 substitutions)
and one it rejects (go-evtx's own minimal record). A structural diff between
them is a far smaller search space than the 42-substitution template this
release has been debugging by inspection, and the minimal fixture is now the
natural target to diff against, not the 403-record one.

## Task 9b: bisect by construction — three offset-correct hybrids

Full detail in
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9b-report.md`.
Row 17 above is this task's regression check (main fixture, unchanged — no
code in `binxml.go`/`evtx.go` touched); this section covers three new hybrid
fixtures built from task 9a's own two CI-proven payloads (the real
`testdata/system.evtx` chunk 0 record 0 BinXML that Windows accepts, and
go-evtx's own minimal-fixture BinXML that it rejects), each with one
structural region swapped and every position-dependent offset explicitly
recomputed — not another hex-dump hypothesis.

**Ground truth, gathered before building anything** (a throwaway structural
walker, deleted before this task's first commit, same discipline as task
9a's own): real record 0's `<System>` block has the **same 14 children, same
order, same declared substitution types** as go-evtx's own — diverging in
exactly one measured place: 5 attribute-only, zero-content children
(Provider, TimeCreated, Correlation, Execution, Security) close via
`CloseEmptyElementTag` (`0x03`) in the real file, vs. `CloseStartElementTag`
(`0x02`) + a separate `EndElementTag` in go-evtx's own output — a fact
`attrlist_test.go`'s own comment already named but no prior task tested for
effect. Also found: real record 0 uses `<UserData>` (20 total substitutions)
where go-evtx uses `<EventData>`/12 `Data` fields (42 substitutions) —
record 0 is a *different event/template* than the one go-evtx's scheme was
built from (task-8b's EventRecordID 12049), which rules out directly
byte-grafting the substitution array or the `<EventData>`/`<UserData>`
structure (cut points 2 and 4) — an index/count-mismatched graft would fail
for a reason unrelated to any byte-level defect, not a measurement. Reported
as not attempted, not forced.

**Hybrid 1 (`cmd/gen-hybrid-preamble-ours`), cut point 1 (fixed preamble),
real→ours direction:** real record 0's BinXML verbatim except
`template_id`/GUID replaced by go-evtx's own trivial values. No offset
rewriting needed (pure identity metadata, referenced by nothing else;
`WriteRaw` never populates hash tables either). 2148 bytes, unchanged length.

**Hybrid 2 (`cmd/gen-hybrid-preamble-real`), cut point 1, mirror direction:**
go-evtx's own minimal-fixture BinXML verbatim except `template_id`/GUID
replaced by the real file's own values. Same offset-safety argument. 2637
bytes, unchanged length.

**Hybrid 3 (`cmd/gen-hybrid-selfclose`), cut point 3 (individual `<System>`
children):** go-evtx's own minimal-fixture BinXML with only the 5 identified
elements' closing bytes rewritten `0x02`+`0x04` → `0x03`. This is where the
offset problem is real: analysed the *original, valid* payload first (its
own correct `data_size`/`attr_list_size`/`name_offset` fields locate every
element/attribute/name reference via one flat linear scan — no nesting stack
needed, since every field is already self-describing), then recomputed every
position-dependent field (the 5 edited elements' own `data_size`; every
ancestor's `data_size`; every `attr_list_size` whose region-end is an edited
close-tag position; every `name_offset`'s absolute value; the outer
`data_length`) via one position-remap function, derived from that analysis,
never patched by assumption. Self-validated twice before ever reaching a
file: an embedded re-parser, and independently a second, separately-coded
throwaway walker before push. 2637 → 2632 bytes (−5, exactly the 5
deletions).

CI run [`31289444649`](https://github.com/fjacquet/go-evtx/actions/runs/31289444649)
(`Format Verify`, head `92b5a3f`), jobs: `generate`/`generate-minimal`/
`generate-splice`/`generate-hybrid-preamble-ours`/`generate-hybrid-preamble-real`/
`generate-hybrid-selfclose`/`python-evtx-differential`/`get-winevent-splice`/
**`get-winevent-hybrid-preamble-ours`** all **success**;
`get-winevent`/`get-winevent-minimal` **failure** (expected, no regression —
row 17 above); `get-winevent-hybrid-preamble-real`/`get-winevent-hybrid-selfclose`
**failure**. `CI` run
[`31289444818`](https://github.com/fjacquet/go-evtx/actions/runs/31289444818):
**success**.

| Hybrid | Direction | Cut point | Content | Result |
|---|---|---|---|---|
| H1 preamble-ours | real → graft ours | 1 (fixed preamble) | real body+subs, our template_id/GUID | **PASS** |
| H2 preamble-real | ours → graft real | 1 (fixed preamble) | our body+subs, real template_id/GUID | **FAIL** — `"The data is invalid."`, identical to every other go-evtx-generated record tested |
| H3 selfclose | ours → graft real | 3 (`<System>` children) | our body+subs, 5 elements' close-tag rewritten | **FAIL** — same message |

### Reading this result

**Cut point 1 (fixed preamble) is eliminated in both directions.** H1 shows
go-evtx's own trivial `template_id`/GUID do not break an otherwise real,
passing record; H2 shows the reverse doesn't fix anything either. Combined
with Experiment B (task 9a, real preamble unmodified), every value in the
outer preamble has now been tested and eliminated.

**Cut point 3's one measured, previously-unmeasured structural divergence —
the self-closing-tag convention for 5 `<System>` children — is eliminated.**
This was the strongest lead this task started with (an exact match between
real record 0's own self-closing elements and go-evtx's own zero-content
elements, already named in `attrlist_test.go`'s comment but never tested).
Correcting it, with every downstream offset rigorously recomputed and
doubly self-validated, produces the exact same exception on the exact same
call. NULL RESULT, held cleanly, same discipline as row 15's.

**Narrowest region this task can honestly report:** somewhere in go-evtx's
own template body or substitution array (per task 9a's own conclusion),
excluding the outer preamble's identity fields (eliminated both directions)
and excluding the 5-element self-closing-tag convention within `<System>`
(eliminated). The rest of `<System>` already matches the real file's own
structure/order/types exactly (established by the ground-truth walk, not
grafted because it already provably matches). What remains untested and is
not byte-graftable against record 0, due to the template mismatch: the
`<EventData>`/`Data` element structure, and the substitution array's actual
value encoding for go-evtx's own 42 substitutions (cut points 2 and 4).

### Concerns

1. Cut points 2 and 4 remain genuinely untested, not merely deprioritised —
   a next task wanting to close them needs either a real record whose
   template structurally matches go-evtx's own 42-substitution scheme and
   sits at some chunk's own record-0 position (self-contained, offset-safe
   by task 9a's own argument — not located this task), or real
   offset-rewriting against EventRecordID 12049 itself (option 2 from task
   9a's own preference order, not attempted this task).
2. The structural ground-truth walker was, again, throwaway — written, run
   locally, deleted before this task's first commit. Its findings are
   reproduced in this report, `task-9b-report.md`, and
   `cmd/gen-hybrid-selfclose/main.go`'s own doc comment.
3. This task made no code change to `binxml.go` or `evtx.go`. Every hybrid
   lives in a new, independent `cmd/gen-hybrid-*` package;
   `cmd/gen-fixture/main.go`'s output is confirmed byte-identical (empty
   `git diff --stat`). The release's only hard-won win (`STAGE2 READ: ok,
   403 records`) was not put at risk and did not regress.

## Task 9c: shrink our own record until it renders (no grafting)

Full detail in
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9c-report.md`.
Row 18 above is this task's regression check (main fixture, unchanged — no
code in `binxml.go`/`evtx.go`/`binformat.go`/`binxml_reader.go`/
`chunkhash.go`/`errors.go` touched, confirmed by both an empty `git diff
--stat` and a matching fixture SHA-256 hash before/after). Task 9b's cut
points 2 (full template-body structure) and 4 (substitution array) were
left genuinely untested because the only self-contained real record
available uses a different, 20-substitution `<UserData>` template than
go-evtx's own 42-substitution `<EventData>` scheme — grafting between them
would fail on an index/count mismatch, not a format defect. This task
closes that gap **without grafting**: it shrinks go-evtx's own template
through its own encoder instead.

**Method.** New file `binxml_variants.go` adds `BuildVariantBinXML`, which
calls the exact same low-level token writers `buildTemplateBody` itself
calls (`pushOpenElement`/`pushOpenElementAttrs`, `writeAttributeSub`/
`writeAttributeOptional`/`writeAttributeLiteral`, `writeSubstitution`/
`writeOptionalSubstitution`, `writeNameNode`, `closeAttrList`,
`writeEndElement`, `writeSubstitutionArray`), assembled into three smaller
or altered shapes rather than production's one fixed shape — so a variant's
Windows verdict measures go-evtx's own encoder, not a parallel
reimplementation. `buildBinXML`/`buildTemplateBody`/
`collectSubstitutionsFromFields` are neither called nor modified — a
disjoint call graph, confirmed (not assumed) via an empty `git diff --stat`
on every production file and a byte-identical `cmd/gen-fixture` output hash
(`2795b91654ef441eafcaf2f364847837d131f76c25c866c5e50a1d5b7a03e888`) before
and after, checked by regenerating the fixture against a `git stash`-ed
tree.

**Four ladder rungs**, each self-validated (container round-trip via
`WriteRaw`/`ReadRaw`; independent re-derivation of every `data_size`/
`attr_list_size`/`name_offset`/substitution-array-bounds field from the
payload's own bytes, the same genuineness-checked scan
`datasize_test.go`/`attrlist_test.go` use against production's own output)
before relying on any of them for a CI probe:

1. **`cmd/gen-ladder-system-only`** (new job pair
   `generate-ladder-system-only`/`get-winevent-ladder-system-only`):
   `<Event><System>...</System></Event>` — no `<EventData>` element at
   all, 18 substitutions.
2. **`cmd/gen-ladder-one-data-pair`** (new job pair
   `generate-ladder-one-data-pair`/`get-winevent-ladder-one-data-pair`):
   `<System>` plus `<EventData>` with exactly one `Data` pair
   (Name+Value both substituted, production's own per-pair convention), 20
   substitutions.
3. **Control — the existing `generate-minimal`/`get-winevent-minimal` job
   pair (task 9a), unmodified, run in this same workflow at this same head
   SHA**: `<System>` plus `<EventData>` with all 12 `Data` pairs — today's
   real production output via `WriteRecord`, not a new fixture. Not
   duplicated as a new job; reused for a same-run, same-commit comparison.
4. **`cmd/gen-ladder-literal-dataname`** (new job pair
   `generate-ladder-literal-dataname`/`get-winevent-ladder-literal-dataname`):
   `<System>` plus `<EventData>` with all 12 `Data` pairs **at the
   control's own scale**, but each `Data/@Name` written as a literal
   `ValueText` (F8's `xmlns` convention) instead of a substitution — only
   `Value` is substituted, 30 substitutions. Tests the hypothesis that a
   BinXML template's element/attribute *names* are the template's own fixed
   shape and only *values* vary, as one controlled rung next to rung 3
   rather than a standalone fix.

Commit `69ca68a` ("test(format): shrink our own record ladder — task 9c (no
grafting)"), pushed to `feat/v0.7.0-format-correctness`.

**Run selection, by head SHA:**

```console
$ git rev-parse HEAD
69ca68a389d1f1bc27c68e99ce92171bc1bea0e9
```

`Format Verify` run [`31290241031`](https://github.com/fjacquet/go-evtx/actions/runs/31290241031),
`CI` run [`31290241162`](https://github.com/fjacquet/go-evtx/actions/runs/31290241162).

`Format Verify` run [`31290241031`](https://github.com/fjacquet/go-evtx/actions/runs/31290241031)
overall: **failure** (expected — the four `get-winevent-ladder-*`/
`get-winevent-minimal` jobs fail by design, see below; not a regression).
`CI` run [`31290241162`](https://github.com/fjacquet/go-evtx/actions/runs/31290241162):
**success**.

### Result: every rung fails, including `<System>` alone — no boundary exists

```text
LADDER1-SYSTEMONLY STAGE1 OPEN: ok
LADDER1-SYSTEMONLY STAGE2 READ: ok, 1 records
LADDER1-SYSTEMONLY PROP ToXml FAILED - Exception calling "ToXml" with "0" argument(s): "The data is invalid."
LADDER1-SYSTEMONLY GETWINEVENT default: FAILED - The data is invalid.
LADDER1-SYSTEMONLY GETWINEVENT -Oldest: FAILED - The data is invalid.

LADDER2-ONEDATAPAIR STAGE1 OPEN: ok
LADDER2-ONEDATAPAIR STAGE2 READ: ok, 1 records
LADDER2-ONEDATAPAIR PROP ToXml FAILED - Exception calling "ToXml" with "0" argument(s): "The data is invalid."
LADDER2-ONEDATAPAIR GETWINEVENT default: FAILED - The data is invalid.
LADDER2-ONEDATAPAIR GETWINEVENT -Oldest: FAILED - The data is invalid.

MINIMAL STAGE1 OPEN: ok
MINIMAL STAGE2 READ: ok, 1 records
MINIMAL PROP ToXml FAILED - Exception calling "ToXml" with "0" argument(s): "The data is invalid."
MINIMAL GETWINEVENT default: FAILED - The data is invalid.
MINIMAL GETWINEVENT -Oldest: FAILED - The data is invalid.

LADDER4-LITERALNAME STAGE1 OPEN: ok
LADDER4-LITERALNAME STAGE2 READ: ok, 1 records
LADDER4-LITERALNAME PROP ToXml FAILED - Exception calling "ToXml" with "0" argument(s): "The data is invalid."
LADDER4-LITERALNAME GETWINEVENT default: FAILED - The data is invalid.
LADDER4-LITERALNAME GETWINEVENT -Oldest: FAILED - The data is invalid.
```

**Stated prominently, per this task's own instruction: there is no
pass/fail boundary.** Rung 1 — `<Event><System>...</System></Event>`, no
`<EventData>` at all, 18 substitutions, the smallest event record go-evtx's
encoder can produce — fails with the exact same exception, on the exact
same call (`ToXml()`), with the exact same message, as the largest rung
measured (the control, 12 Data pairs). All four rungs, spanning 18 to 42
implied substitutions and 0 to 12 `Data` elements, fail identically.

**Reading this result.** The defect is **not** in `<EventData>`'s
structure or the substitution array's count/shape — rung 2 (one pair) and
rung 4 (literal names, refuting that hypothesis cleanly — see below) both
isolate those variables and both still fail exactly like the 12-pair
control. It is somewhere in what **every rung shares**: `<System>`'s own
content, `<Event>`'s `xmlns` attribute, or the outer preamble. Task 9b
already eliminated the outer preamble (both directions) and one specific
`<System>` divergence (the self-closing-tag convention); this task's own
rung 1 adds a new, stronger data point in the same direction — go-evtx's
own trivial preamble, paired with go-evtx's own `<System>`-only body (no
`<EventData>` at all), still fails. The remaining, now-narrower suspect is
something about `<System>`'s *content* not yet tested — most likely a
substitution *value* encoding (a type/byte-width mismatch, or the
`OptionalSubstitution`/`dependency_id` mechanism itself) for one or more of
its 18 fields, since `<System>`'s *structure* (children, order, element
shapes) was already confirmed to match `testdata/system.evtx` byte-for-byte
and this task shows that structural match alone is not sufficient.

**Rung 4's hypothesis — that `Data/@Name` must be a template-fixed literal,
not a substitution — is refuted, not confirmed.** Making the change
produced the identical exception and message as the control (rung 3), with
every other variable held constant (same 12-pair scale, same field
content). This closes the hypothesis out cleanly as a null result.

**No regression.** `generate`: `wrote artifacts/generated.evtx (403
records, max ObjectName 31236 runes)` — byte-identical to row 17.
`python-evtx-differential`: `OK: 403 records, all chunk checksums verify` —
stayed green. `get-winevent`: `STAGE1 OPEN: ok` / `STAGE2 READ: ok, 403
records` (the release's hard-won win, held) / `PROP ToXml FAILED` / both
`GETWINEVENT` orderings `FAILED` — `"The data is invalid."` — identical in
every respect to row 17.

Full verbatim job output, method detail, and concerns (including F8's
`xmlns` and the outer preamble being held fixed rather than re-varied by
this task) are in
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/task-9c-report.md`.
