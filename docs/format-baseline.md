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

CI runs: [`31263194648`](https://github.com/fjacquet/go-evtx/actions/runs/31263194648) (row 1), [`31267775745`](https://github.com/fjacquet/go-evtx/actions/runs/31267775745) (row 2, re-confirmed stable via `gh run rerun --failed` reusing the identical uploaded artifact — see "Message stability" below), [`31268668199`](https://github.com/fjacquet/go-evtx/actions/runs/31268668199) (row 3, head `173fcf2`, after Task 3's F3/F4/F5 header fixes — see "After Task 3" below; independently re-confirmed by [`31268734614`](https://github.com/fjacquet/go-evtx/actions/runs/31268734614), head `c13b724`, the very next push), [`31270735835`](https://github.com/fjacquet/go-evtx/actions/runs/31270735835) (row 4, head `3c9e825`, after Task 6's F1 hash-table fix — see "After Task 6" below), [`31272448023`](https://github.com/fjacquet/go-evtx/actions/runs/31272448023) (row 5, head `ff33b7e`, harness stage split only — see "Task 7 Part A" below), [`31272639129`](https://github.com/fjacquet/go-evtx/actions/runs/31272639129) (row 6, head `62de633`, after Task 7 Part B's B1/B2/B3 fixes — see "Task 7 Part B" below), [`31273985286`](https://github.com/fjacquet/go-evtx/actions/runs/31273985286) (row 7, head `4510103`, after Task 7c's dependency_id sentinel fix — see "Task 7c" below), [`31275896296`](https://github.com/fjacquet/go-evtx/actions/runs/31275896296) (row 8, head `9b8e974`, after Task 7e's data_size fix — see "Task 7e" below), [`31276703107`](https://github.com/fjacquet/go-evtx/actions/runs/31276703107) (row 9, head `7631f93`, after Task 7f's attr_list_size reordering fix — see "Task 7f" below), [`31277415872`](https://github.com/fjacquet/go-evtx/actions/runs/31277415872) (row 10, head `3b3f575`, after Task 8's xmlns namespace fix — see "Task 8" below).

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
