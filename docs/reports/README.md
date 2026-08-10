# Investigation reports

Three working reports from the v0.7.0 format investigation, tracked verbatim
because the code cites them as evidence.

| Report | What it holds |
|---|---|
| [`task-8b-report.md`](task-8b-report.md) | The Step 1 table: a field-by-field decode of a real Windows record's `<System>` block, used to add the nine children go-evtx was missing |
| [`task-8c-report.md`](task-8c-report.md) | `Provider/@Guid` and `EventID/@Qualifiers`, and the `0x46`/`0x06` attribute-token rule |
| [`task-8e-report.md`](task-8e-report.md) | F14: two false starts on the substitution declared types, three independent verifications, and the reversal |

## Why these are tracked and other process artefacts are not

They are cited from `binxml.go`, `binxml_template.go`, `binxml_tokens.go`,
`system_test.go`, `CLAUDE.md`, `docs/evtx-format-notes.md` and
`docs/format-baseline.md` — twenty-five times — as the evidence behind specific
encoding decisions. Until 2026-08-10 they lived only in a git-ignored scratch
directory on one machine, so every one of those citations pointed at a file no
clone contained, and a `git clean -fdx` would have destroyed the lot.

**They are kept verbatim rather than summarised on purpose.** `task-8b-report.md`'s
Step 1 table is *wrong at four positions*, and `task-8c-report.md` and
`task-8e-report.md` are the corrections. That disagreement is the point: it is
what lets a reader check why `EventID/@Qualifiers` was reverted to
`UNSIGNED_WORD` rather than take it on trust. Rewriting them into a clean
narrative would remove the very thing being cited.

## How to read them

They are working documents, not documentation. They record what was believed at
the time they were written, including claims later shown to be false.

- The durable, corrected record of the format is
  [`docs/evtx-format-notes.md`](../evtx-format-notes.md), which marks every
  claim as measured or read-from-source.
- The append-only measurement log is
  [`docs/format-baseline.md`](../format-baseline.md).
- F15 later superseded F14's conclusion — an `OptionalSubstitution`'s *token*
  declares the field's own type while its *substitution-array entry* declares
  `NULL`. F14's measurements stand; its conclusion does not. `CLAUDE.md` carries
  the resolution.

Do not treat a statement in these reports as current unless one of the two
documents above confirms it.
