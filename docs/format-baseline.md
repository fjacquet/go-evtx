# Format verification baseline

Measured at commit `35392ac7733cc7b9fcb1cb468df4161a233c80d8`, before any
v0.7.0 format fix. CI run:
<https://github.com/fjacquet/go-evtx/actions/runs/31263194648>. Recorded so
every later task has a signal that moves: a fix that changes the failure mode
is progress, and a fix that changes nothing is aimed at the wrong defect.

The workflow has three jobs. `generate` builds `generated.evtx` (400 records,
`WriteRecord`-only, non-ASCII and non-BMP `ObjectName` values, spanning 18
chunks) and uploads it once; `python-evtx-differential` and `get-winevent`
both depend only on `generate`, not on each other, so a failure in one cannot
skip the other. In this run `generate` succeeded; both verifier jobs failed.

## python-evtx differential (Linux)

Result: **FAIL**

```
FAIL
  - ObjectName count: got 0, want 400
```

Job log:
<https://github.com/fjacquet/go-evtx/actions/runs/31263194648/job/93117113460>

The `record_count` check passed (`python-evtx` enumerated exactly 400
records) and the chunk-checksum block that runs unconditionally afterward
reported no failures — both chunk header and data CRC32 values verify. Only
the `ObjectName` extraction failed, and it failed for *all* 400 records, not
some.

**Root cause, confirmed by inspection, not guessed.** The checker's XPath
(`.//e:Data` under namespace
`http://schemas.microsoft.com/win/2004/08/events/event`) found nothing
because go-evtx's generated `<Event>` root carries no `xmlns` attribute at
all:

```
<Event><System><Provider Name=""></Provider>
...
```

A real Windows-generated file (`testdata/system.evtx`, vendored in a prior
task) always declares it:

```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>...
```

Confirmed directly with `python-evtx` against both files locally. This is a
**format defect** — the checker parsed the file successfully and found real
content missing an attribute real Windows output always has — not a checker
bug. `binxml.go`'s `writeOpenElement("Event", false, baseOffset)` call
(`binxml.go:149`) never writes the namespace attribute on the root element.
grepping the spec (`docs/superpowers/specs/2026-08-08-durability-and-format-correctness-design.md`)
confirms this is **not** F1–F7 — it is a sixth, previously undocumented
defect this harness surfaced. Not fixed here per this task's scope; flagged
for whoever picks up the writer changes.

## Get-WinEvent (windows-latest)

Result: **FAIL**

```
Get-WinEvent: D:\a\_temp\ddbb1226-1f91-4e83-bd2f-806ed10d4590.ps1:6
Line |
   6 |  $events = @(Get-WinEvent -Path artifacts/generated.evtx -ErrorAction  …
     |              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | The event log file is corrupted.
```

Job log:
<https://github.com/fjacquet/go-evtx/actions/runs/31263194648/job/93117113464>

`Get-WinEvent -Path` throws on the call itself — it never returns an event
array, so the record-count and `ObjectName` assertions in the script never
execute. This is the definition-of-done job for the release: `Get-WinEvent`
uses the same parsing stack as Event Viewer, so today the answer to "does
this open in Event Viewer" is no, with a specific, reproducible error.

### Reading the symptom against the task table

| Symptom | Likely cause |
|---|---|
| "The data is invalid" on open | Chunk header checksum, or the zero hash tables (Task 5) |
| Opens, zero records | `LastEventRecordDataOffset` or `FreeSpaceOffset` (Task 7) |
| Opens, wrong record count | 8-byte alignment (Task 6) |
| Records present, fields empty | Template resolution through the template table (Tasks 4, 5) |

"The event log file is corrupted" is not verbatim any row's example text —
the closest documented example, "The data is invalid," is explicitly called
out as *an* example wording for the first row, not the only one. What matters
for classifying it is *where* the exception fires: `Get-WinEvent` never
returns anything — no scalar, no empty array — meaning the failure happens
during the Windows Event Log service's own structural validation of the file,
before a single record is handed back. That places it in the **first row's
bucket** (an open-time rejection), not rows 2–4, which all presuppose the
file opened and enumeration proceeded at least far enough to produce a
(possibly wrong) record count.

Within that bucket, the python-evtx differential above already narrows it:
`python-evtx` independently recomputed both the chunk header and chunk data
CRC32 values and found them correct, so a checksum mismatch is ruled out as
the cause. That leaves the chunk string/template hash tables — `buildChunkHeader`
(`evtx.go:523-533`) leaves bytes `[128:384]` and `[384:512]` entirely zero on
every chunk — as the strongest remaining candidate, consistent with the
spec's own assessment in F1: "This is the single most likely reason Event
Viewer rejects the files." **This is a hypothesis to be confirmed by the
signal changing** once Task 5 (renamed per the reorder — see
`.superpowers/sdd/2026-08-08-v0.7.0-format-correctness/progress.md`)
populates those tables, not a diagnosis.

## Harness bugs found and fixed while building this baseline

Two infrastructure failures had to be fixed before either job produced a
result that says anything about the `.evtx` content. Neither is a format
finding; both are recorded here because the task's instructions require
telling the two kinds of failure apart explicitly.

1. **`astral-sh/setup-uv@v8` does not resolve.** The action stopped
   publishing a floating major-version tag as of its own `v8.0.0` ("immutable
   releases and secure tags"); only fully-qualified tags exist from `v8.0.0`
   onward. The Linux job failed in `Set up job`, before the checkout step
   ran — `##[error]Unable to resolve action` `astral-sh/setup-uv@v8`,
   `unable to find version` `v8`. Zero relation to `.evtx` content. Fixed by
   pinning to the commit SHA `c771a70e6277c0a99b617c7a806ffedaca235ff9`
   (verified against the upstream `v9.0.0` tag ref), matching this repo's
   fleet convention of SHA-pinning third-party actions with a trailing
   `# vX.Y.Z` comment. All other third-party actions in the workflow
   (`actions/checkout`, `actions/setup-go`, `actions/upload-artifact`,
   `actions/download-artifact`) were pinned the same way at the same time,
   each SHA verified against its own tag ref before use.

2. **`get-winevent: needs: python-evtx-differential` skipped the Windows job
   entirely** the first time both jobs ran for real. GitHub Actions' default
   `needs` semantics only run a dependent job if everything it depends on
   succeeded; since `python-evtx-differential` is *expected* to fail in this
   task, `get-winevent` — the one measurement the whole release exists to
   take — never executed at all (job conclusion `skipped`, not `failure`).
   Restructured into three jobs: `generate` builds and uploads the fixture
   once, and `python-evtx-differential` / `get-winevent` both depend only on
   `generate`, not on each other, so neither verifier's outcome can skip the
   other.

Both were caught and fixed in this task, before any number in this document
was recorded — confirmed by the fact that the run this document cites
(`31263194648`) shows `generate` succeeding and *both* verifier jobs actually
executing and failing on real content, not being skipped.

## What this baseline does and does not prove

- **Does not** prove any specific one of F1–F5 is the sole cause — `Get-WinEvent`
  gives one terminating error for the whole file, not a defect-by-defect
  breakdown.
- **Does** prove the harness itself works end to end: fixture generation,
  cross-job artifact handoff, an independent Python parser, and a real
  Windows Event Log stack all ran against unmodified output and produced
  real, reproducible, content-based errors.
- **Does** surface one defect (missing `xmlns` on the `Event` root) that was
  not in the spec's F1–F7 list before this task.

Per the task's own exit criteria: do **not** add `continue-on-error`, weaken
an assertion, or delete a job to turn this green. A red `Format Verify` is
the correct state of this branch until the fixes land in later tasks, and
Task 8 (re-run and settle, per the reorder) is where it is expected to turn
green.
