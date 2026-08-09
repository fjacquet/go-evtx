# ToXml invariant diff — implementation plan (phases 0–2)

> **STATUS: complete.** Phases 0-2 shipped; the diff returned one entry and
> F15 fixed it (`docs/format-baseline.md` row 22, CI run 31331139326). Task 3
> was dropped by decision, and `decodedFloor` — referenced below as a smoke
> gate — no longer exists: `testdata/system.evtx` was removed from the
> repository, so nothing pins a count against it. Read the rest as the record
> of what was planned, not as instructions.
>
> **Execution:** inline, in the main session. Not subagent-driven — the work
> depends on measurement context that does not survive a fresh dispatch. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Goal:** produce the list of every structural shape go-evtx emits that no real
record in the derivation corpus emits.

**Architecture:** finish the strict decoder so it can walk the whole corpus
(phase 0), add a shape hook to the existing parser and census the corpus
through it (phase 1–2), then profile go-evtx's own output the same way and diff.

**Spec:** `docs/superpowers/specs/2026-08-09-toxml-invariant-diff-design.md`

## Global Constraints

- Zero external dependencies. Standard library only.
- `go test -race ./... -count=1` passes; `go vet ./...` and
  `GOOS=windows go build ./...` clean; `golangci-lint run` clean.
- No string values are ever written to a corpus output file. Names, types,
  sizes, offsets, counts only.
- **`testdata/system.evtx` is excluded from everything except crash
  regression.** Not merely held out of derivation — excluded as evidence. See
  "Why system.evtx is out" below.
- `decodedFloor` in `corpus_scan_test.go` stays as a smoke gate: it proves the
  decoder does not regress into crashing or refusing records it used to read.
  It is **not** a conformance target and no task is judged by moving it.
- `AnsiString` stays unimplemented: the format carries no codepage.
- Every task ends with a commit.

## Why system.evtx is out

Every format rule this project mined, it mined from `testdata/system.evtx` —
1601 records. The `<System>` block's fourteen children, `OptionalSubstitution`
against `NormalSubstitution` per element, the `dependency_id` rule,
`EventID/@Qualifiers`'s `UNSIGNED_WORD` declared type, the `0x46`/`0x06`
attribute-token rule: tasks 8b and 8c took all of them from that one file. The
encoder was built to imitate it. `ToXml` rejects what the encoder produces.

Measured 2026-08-09: **55 of its records carry a `Null`-typed substitution with
data. That construct appears zero times in the other 320 398 records of the
local corpus.** One file does something nothing else does.

Against that: Task 9a's splice showed `system.evtx`'s own record 0 renders
completely on the VM. So it is not uniformly atypical — which sharpens the
hypothesis rather than weakening it. We may have copied the atypical parts.

Phase 1–2 answers this without changing method: censusing shapes across 320 k
records re-derives every rule previously taken from 1601.

## Measured baseline (2026-08-09)

Local corpus, 322 k records, **73.8 % decoded**.

| Cause | Records | Concentration |
|---|---|---|
| type disagreement, `SizeT`→`HexInt64` / `HexInt32` / `UInt8`→`UInt16` | 61 843 | `security.evtx` is 100 % this |
| array type `0x81` (array of UTF-16 strings) | 22 036 | all four `testdata` files, 11 samples |
| `Null`-typed substitution carrying data | 55 | `system.evtx` **only** — excluded, see above |
| `AnsiString` | 16 | out of scope |
| `SysTime` | 8 | samples |

Derivation corpus — everything above **except** `system.evtx` — is 320 398
records. Phase 0 targets ≥ 99.99 % of those: everything but `AnsiString`'s 16.

## File structure

| File | Change |
|---|---|
| `value.go` | array `0x81`, `Null`-with-data, `SysTime`; array-guard message corrected |
| `value_test.go` | unit tests for the three above |
| `binxml_decode.go` | type-disagreement rule; `onShape` hook on `binxmlParser` |
| `corpus_scan_test.go` | `decodedFloor` raised per task |
| `corpus_shape_test.go` | new — the profiler, the census, the held-out check, the diff |
| `testdata/shape-census.json` | new — derived, non-identifying, committed |

---

### Task 1: array of UTF-16 strings (`0x81`)

**Files:** `value.go`, `value_test.go`, `corpus_scan_test.go`

**Produces:** `Value.Strings() ([]string, bool)`; `decodeValue` accepts
`ValString|valArrayFlag`; `MarshalJSON` emits a JSON array for it.

- [ ] Test first: `TestDecodeValue_StringArray` — `["AB","CD"]` from two
      NUL-terminated runs; `["AB","CD"]` when the last run is unterminated;
      `["AB","","CD"]` for an empty middle element; empty data is absent.
- [ ] Run it, watch it fail on the array guard.
- [ ] Implement `decodeStringArray`; add `strs []string` to `Value`; add
      `ValString|valArrayFlag` to `valueTypeNames` as `"StringArray"`; keep
      rejecting every other array type, with the message corrected — the
      current "measured zero occurrences" is false.
- [ ] Green. Then re-scan the corpus and record the delta.
- [ ] Update `decodedFloor` to whatever `system.evtx` now reads — to keep the
      smoke gate accurate, not because reaching a number is the goal.
- [ ] Commit.

**Exit criterion:** `app.evtx` goes from 43.85 % to ~100 %.

---

### Task 2: the template/array type disagreement — the array wins

**Files:** `binxml_decode.go`, `corpus_scan_test.go`

- [ ] Confirm against [MS-EVEN6] and libyal before changing anything, and
      record what they say — including if they are silent.
- [ ] `parseSubstitutionRef` stops comparing the template's declared type with
      the array's and returns the array's value unchanged. Comment carries the
      mechanism: `SizeT` is a pointer width and the array is what says which.
- [ ] Sanity-check the values, not just the count: the 61 344 `security.evtx`
      records must decode to plausible `HexInt64` values, not garbage.
- [ ] Re-scan; update `decodedFloor` only to keep the smoke gate accurate.
- [ ] Commit.

**Exit criterion:** `security.evtx` from 66.65 % to ~100 %.

---

### Task 3: `Null`-typed substitution carrying data — **DROPPED**

Kept in the plan as a record of the decision, not as work.

The construct occurs in 55 records of `testdata/system.evtx` and in **zero** of
the other 320 398. Implementing it would teach the decoder a rule sourced from
the one file this plan has excluded as evidence — the exact mistake the
exclusion exists to prevent. The decoder keeps rejecting it, and the rejection
is itself a measurement: it is how the census will flag the construct when
Task 8 profiles that file's idiosyncrasies.

Revisit only if the construct turns up outside `system.evtx`.

---

### Task 4: `SysTime`

**Files:** `value.go`, `value_test.go`

- [ ] Test with a known 16-byte `SYSTEMTIME` (8 × `uint16` LE: year, month,
      day-of-week, day, hour, minute, second, milliseconds).
- [ ] Implement; render to RFC3339Nano in `str`; reject any length but 16.
- [ ] Green. Commit.

**Exit criterion:** the 8 sample records decode; local corpus ≥ 99.99 %
(everything but `AnsiString`'s 16).

---

### Task 5: the shape hook

**Files:** `binxml_decode.go`

**Produces:** `binxmlParser.onShape func(shapeEvent)`, nil by default.

- [ ] Define `shapeEvent` — token, and the shape fields only: element
      has-attributes / `dependency_id` set / `data_size` zero; attribute token
      `0x06` vs `0x46` and position; substitution normal vs optional, template's
      declared type and the array's; value type; fragment header present,
      definition inline. No content, ever.
- [ ] Call the hook from `parseFragment`, `parseElement`, `parseAttribute`,
      `parseSubstitutionRef`, `parseLiteralValue`.
- [ ] Test: a hook over one `system.evtx` record receives the expected event
      sequence; and the existing suite still passes with the hook nil.
- [ ] Commit.

**Exit criterion:** 208 existing tests unchanged; nil hook is a no-op.

---

### Task 6: census over the derivation corpus

**Files:** `corpus_shape_test.go`, `testdata/shape-census.json`

- [ ] Walk the derivation corpus — the 278 samples plus untracked
      `security.evtx`, `system2.evtx`, `app.evtx`. **Never `system.evtx`.**
- [ ] Aggregate shape → count; write `testdata/shape-census.json`.
- [ ] Frozen-counter test on `system.evtx` — the only tracked file, so the only
      one CI can run the profiler against. It asserts the *instrument* works;
      it asserts nothing about the format.
- [ ] Commit the census.

**Exit criterion:** census written over 320 398 records, `system.evtx`
contributing none of them.

---

### Task 7: profile go-evtx's own output, produce the list

**Files:** `corpus_shape_test.go`

- [ ] Generate `gen-fixture-minimal` and `gen-fixture` output to a temp dir.
- [ ] Profile both through the same hook.
- [ ] Report every shape with census count zero, then the low-count tail.
- [ ] Write the list to `docs/format-baseline.md` as a new appended row, and
      the analysis to `docs/evtx-format-notes.md`.
- [ ] Commit.

**Exit criterion:** the candidate list exists.

---

### Task 8: what we copied from system.evtx that nobody else does

The encoder was built to imitate one file. This task measures how far that went.

- [ ] Profile `testdata/system.evtx` through the same hook and diff it against
      the census: every shape it emits that the other 320 398 records never do.
- [ ] Cross-reference each hit against `binxml.go`: does the encoder reproduce
      it? The `Null`-with-data construct (55 records) is the known member of
      this set; tasks 8b and 8c's `<System>` decisions are the ones to check.
- [ ] Anything the encoder copied and the corpus contradicts joins Task 7's
      candidate list, ranked above the rest — it is a rule we adopted from a
      sample of one.
- [ ] Write the finding to `docs/evtx-format-notes.md`. Commit.

**Exit criterion:** every encoder choice traceable to `system.evtx` is either
confirmed by 320 398 records or on the candidate list.

Phase 3 — fix, reprofile, and the single VM run when the list is empty — is
driven inline and is not part of this plan.
