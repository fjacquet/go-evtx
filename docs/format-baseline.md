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

CI runs: [`31263194648`](https://github.com/fjacquet/go-evtx/actions/runs/31263194648) (row 1), [`31267775745`](https://github.com/fjacquet/go-evtx/actions/runs/31267775745) (row 2, re-confirmed stable via `gh run rerun --failed` reusing the identical uploaded artifact — see "Message stability" below), [`31268668199`](https://github.com/fjacquet/go-evtx/actions/runs/31268668199) (row 3, head `173fcf2`, after Task 3's F3/F4/F5 header fixes — see "After Task 3" below; independently re-confirmed by [`31268734614`](https://github.com/fjacquet/go-evtx/actions/runs/31268734614), head `c13b724`, the very next push).

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

```
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

```
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

```
FAIL
  - ObjectName count: got 0, want 403
```

Job log: <https://github.com/fjacquet/go-evtx/actions/runs/31268668199/job/93130919628>

No chunk-checksum failure line appeared — CRCs remain clean, consistent with
every prior measurement.

Get-WinEvent: FAIL

```
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
