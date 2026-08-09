# ToXml invariant diff — implementation plan (phases 0–2)

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
- Invariant **derivation** never reads `testdata/system.evtx`. It is the
  held-out validation set and the only CI-assertable file. (Counting the
  decoder's own failures on it is not derivation — the floor is defined on it.)
- `decodedFloor` in `corpus_scan_test.go` is a minimum, never an equality, and
  rises in the same commit as any fix that changes it.
- `AnsiString` stays unimplemented: the format carries no codepage.
- Every task ends with a commit.

## Measured baseline (2026-08-09)

Local corpus, 322 k records, **73.8 % decoded**.

| Cause | Records | Concentration |
|---|---|---|
| type disagreement, `SizeT`→`HexInt64` / `HexInt32` / `UInt8`→`UInt16` | 61 843 | `security.evtx` is 100 % this |
| array type `0x81` (array of UTF-16 strings) | 22 036 | all four `testdata` files, 11 samples |
| `Null`-typed substitution carrying data | 55 | `system.evtx` |
| `AnsiString` | 16 | out of scope |
| `SysTime` | 8 | samples |

`testdata/system.evtx`: 1496 / 1601 today; 1546 after Task 1; **1601 after Task 3**.

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
- [ ] Raise `decodedFloor` to the measured `system.evtx` count (expected 1546).
- [ ] Commit.

**Exit criterion:** `app.evtx` goes from 43.85 % to ~100 %; `system.evtx` 1546.

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
- [ ] Re-scan; raise `decodedFloor` if it moves.
- [ ] Commit.

**Exit criterion:** `security.evtx` from 66.65 % to ~100 %.

---

### Task 3: `Null`-typed substitution carrying data

**Files:** `value.go`, `value_test.go`, `corpus_scan_test.go`

- [ ] Measure first: what is in those 55 payloads — length distribution, and
      whether the bytes look like a value of some other type.
- [ ] Decide the rule from that evidence and write it in the comment. Default
      if the bytes carry no signal: `Null` with data is absent, data ignored.
- [ ] Test, implement, green.
- [ ] Raise `decodedFloor` to 1601 and change the comment: the floor is no
      longer below the record count.
- [ ] Commit.

**Exit criterion:** `testdata/system.evtx` decodes 1601 / 1601.

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
- [ ] Held-out check: every shape the census records as unseen must also be
      unseen in `system.evtx`. A hit invalidates the rule and gets reported.
- [ ] Frozen-counter test on `system.evtx` — asserts the instrument works, not
      what it learned.
- [ ] Commit the census.

**Exit criterion:** census written; held-out check clean or its misses named.

---

### Task 7: profile go-evtx's own output, produce the list

**Files:** `corpus_shape_test.go`

- [ ] Generate `gen-fixture-minimal` and `gen-fixture` output to a temp dir.
- [ ] Profile both through the same hook.
- [ ] Report every shape with census count zero, then the low-count tail.
- [ ] Write the list to `docs/format-baseline.md` as a new appended row, and
      the analysis to `docs/evtx-format-notes.md`.
- [ ] Commit.

**Exit criterion:** the candidate list exists. Phase 3 — fix, reprofile, and
the single VM run when the list is empty — is driven inline and is not part of
this plan.
