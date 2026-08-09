# ToXml: invariant diff against the real-file corpus — design

**Date:** 2026-08-09
**Status:** approved
**Supersedes as the active method:** the `gen-ladder-*` / `gen-hybrid-*`
bisection harness (kept in the tree, no longer extended)

## The problem, stated only as far as it is established

`.NET`'s `EventLogReader.ReadEvent()` reads all 403 records of go-evtx's own
fixture without throwing. `EventLogRecord.ToXml()` — and `Get-WinEvent`, which
calls it — throws `"The data is invalid."` on every go-evtx record ever
measured, down to the simplest single ASCII record the encoder can produce.
python-evtx renders the same records successfully.

One thing bounds the defect and nothing else does: Task 9a's splice. A real
record's own BinXML, extracted with `Reader.ReadRaw()` and written back through
`Writer.WriteRaw()` into an otherwise ordinary go-evtx file, renders completely
under both APIs. **The defect is entirely inside what `binxml.go` generates.**

### What this design explicitly does not claim

The 2026-08-09 corpus scan found that real Windows declares a template
definition inline once per chunk and points every later instance backward at
it, while go-evtx re-declares a fresh inline copy in every record. That is a
real and universal deviation (36 819 backward references, zero forward, across
37 364 records) and it is the leading explanation for a *different* symptom —
why adding any byte to the payload flips `STAGE2 READ` from 403 records to
failing on record 0. **It is not evidence about `ToXml`,** which fails on the
unmodified fixture that reads all 403 records fine. The two are separate
defects and this design does not conflate them.

Four EOF/alignment combinations have already been probed on the VM. None fixes
`ToXml`.

## Goal

Produce a **list** of every structural shape go-evtx emits that no real record
in the derivation corpus ever emits. Not a fix — the fixes are whatever the
list turns out to contain, and pretending to know them now is the error this
method exists to stop.

## Non-goals

- Encoder fixes. They follow from the list, in a separate plan.
- The template-sharing model (#38/#39). Blocked behind its own confirmation
  experiment, unrelated to `ToXml`.
- Deleting the `gen-ladder-*` harness. `CLAUDE.md` releases it when the defect
  is found, not before.

## Stop criterion

Written here, in advance, because without one this hunt resumes for another
seventeen tasks.

1. List exhausted and `ToXml` still fails → escalate to approach B (register a
   minimal ETW provider on the VM, have Windows write the event, diff its token
   stream against ours). An empty list is itself a strong result: it means the
   missing rule is not observable from files.
2. B infeasible or inconclusive → ship v0.7.0 with the limitation documented:
   `EventLogReader` reads every record, python-evtx renders the XML, native
   Windows rendering does not.

## Corpus policy

Three roles, and a file may hold only one.

| Role | Files | Use |
|---|---|---|
| **Derivation** | the 278 `EVTX-ATTACK-SAMPLES` files, plus local untracked `security.evtx` (1985 chunks, 3.2), `system2.evtx`, `app.evtx` | mine invariants; never asserted on |
| **Held-out validation** | `testdata/system.evtx` | a shape absent from the derivation corpus must also be absent here; if it appears, the rule is false |
| **CI** | `testdata/system.evtx` | the only tracked file, so the only assertable one |

Deriving from the same file CI asserts on makes the assertion circular — it
could no longer detect that the derivation was wrong. Holding `system.evtx`
out costs nothing and buys an independent check.

No string values leave the corpus. Real logs carry account names, SIDs,
machine names and IP addresses, and this output is quoted in `docs/`.

## Phase 0 — decoder completeness

The profiler can only profile what it can walk. Today 1151 of 37 364 records
(3.1 %) fail to decode, and each failure **truncates that record's shape
profile at the point of failure** — so the census would be blind exactly where
the format is unusual. This phase is a prerequisite, not an addition.

Measured causes, from the 2026-08-09 scan:

| Records | Files | Cause | Action |
|---|---|---|---|
| 745 | 38 | template's declared type disagrees with the substitution array's: `UInt8`→`UInt16` (415), `SizeT`→`HexInt32` (176), `SizeT`→`HexInt64` (154) | resolve in favour of the array (below) |
| 396 | 11 | value type `0x81` — array of UTF-16 strings — inside nested fragments | implement `0x81`, and only `0x81` |
| 8 | 1 | `SysTime` not implemented | implement (16-byte `SYSTEMTIME`) |
| 2 | 1 | `AnsiString` | out of scope, see below |

**The type-disagreement rule.** The substitution array's declared type wins.
This is not a preference, it is a mechanism the data itself shows: `SizeT` is a
pointer width — 4 or 8 bytes depending on the emitting process — and the two
`SizeT` rows are precisely the array telling the reader which. The template
declares a slot's shape; the array declares the value actually present. The
implementer must confirm this against [MS-EVEN6] and check that all 745 records
then decode to sane values, and must report a disagreement rather than
silently adopting the rule.

**`0x81` only.** One array type occurs in the whole corpus. Other array types
keep being rejected, but the guard's comment — currently claiming "measured
zero occurrences" — is false and must be rewritten to say what is true: not
observed in the derivation corpus.

**`AnsiString` stays unimplemented.** The format carries no codepage, so any
decoding would be invention. 2 records of 37 364. The error message stays; only
its wording is checked for accuracy.

**Exit criterion.** Derivation-corpus decode rises from 96.9 % to ≥ 99.9 %, and
`corpus_scan_test.go`'s `decodedFloor` is raised **in the same commit** as the
fix — a floor left stale is a CI gate that lies.

## Phase 1 — the shape profiler

For each record, walk the BinXML token stream and emit tuples describing
*shape*, never content:

- token type
- `OpenStartElement`: has-attributes, `dependency_id` set or `0xffff`,
  `data_size` zero or non-zero
- attribute: token `0x06` vs `0x46`, and position in its list (first / middle /
  last / only)
- substitution: normal (`0x0D`) vs optional (`0x0E`), declared type
- value: type
- fragment: header present or absent, definition inline or referenced

**Where it lives, and the one real trade-off.** The walk must tolerate errors,
which the strict decoder does not. Either a second walker in the test file, or
a nullable `func` field on `binxmlParser`, called from each of its parse
methods (`parseFragment`, `parseElement`, `parseAttribute`,
`parseSubstitutionRef`, `parseLiteralValue`).

**Take the hook.** Two walkers that drift apart produce a measurement that is
wrong while looking right — the exact failure class this repository keeps
hitting (see `docs/evtx-format-notes.md`, the template-bucket rule). A hook
guarantees the profile matches what the decoder actually sees. Cost is one
field and four call sites, all no-ops when nil. A record that fails mid-walk
still yields the shapes emitted before the failure, which is the correct
behaviour.

## Phase 2 — census and held-out validation

Run the profiler across the derivation corpus; aggregate shape → count; write a
derived, non-identifying JSON file. It is committed: it becomes the reference
any future encoder change is measured against.

Then check `testdata/system.evtx`: every shape the census records as unseen
must also be unseen there. A shape that appears invalidates the rule, and
learning that costs nothing.

## Phase 3 — the diff, and the loop

Profile the output of `gen-fixture-minimal` and `gen-fixture`. Report every
shape whose corpus count is **zero**, then those with counts low enough to be
suspicious. Zero-count shapes are the candidate list.

Then: fix a candidate, reprofile, rediff. **The VM is touched once, when the
list is empty.** If `ToXml` passes, done. If the list is empty and `ToXml`
still fails, the stop criterion's branch 1 fires.

## Testing

- The profiler gets frozen counters on `testdata/system.evtx` — the only file
  CI sees. These assert that the *instrument* works, not what it learned; the
  distinction is what keeps the held-out role intact.
- The nil hook must change nothing: the existing 208 tests are that guarantee.
- Phase 0 raises `decodedFloor`; the floor is asserted as a minimum, never an
  equality, so the number can only go up.

## Risks

- **The list may be empty.** Then our BinXML honours everything the corpus can
  express and the missing rule is invisible from files. Handled by the stop
  criterion; an empty list is a result, not a failure.
- **The list may be long and mostly benign.** Legitimate encoder choices
  (go-evtx has one template, real files have thousands) will show up as unseen
  shapes. Mitigation: rank by how universal the violated pattern is, and treat
  a shape as a candidate only when the corpus shows a *consistent alternative*,
  not merely a different distribution.
- **Phase 0 could change decode results in a way that hides a defect.** The
  type-disagreement rule is the risk: adopting the array's type makes 745
  records decode, but decoding is not the same as decoding *correctly*. The
  implementer must sanity-check the resulting values, not just the record
  count.
