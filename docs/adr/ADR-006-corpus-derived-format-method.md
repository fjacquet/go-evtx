# ADR-006: Derive format rules from a corpus, not from one sample

**Date:** 2026-08-10
**Status:** Accepted

## Context

This format was implemented against another parser's behaviour before it was
implemented against its specification, and then validated against the single
file it had been derived from. Seventeen tasks went by with
`EventLogRecord.ToXml()` rejecting every file go-evtx wrote.

Two failure modes caused that, and neither is visible from inside the loop that
produces them:

- **Deriving a rule from one sample and asserting against that same sample.**
  The assertion cannot fail when the derivation is wrong.
- **A one-bit oracle.** "Does Windows accept this file?" cannot distinguish a
  wrong hypothesis from a right hypothesis aimed at the wrong field. F14 spent
  a whole task on that and concluded "unresolved"; F16 repeated it.

## Decision

Format rules are derived from a corpus of hundreds of real files, named
against a normative specification, confirmed on a Windows VM, and recorded by
CI. In that order.

- **The corpus derives.** `corpus_scan_test.go` and `corpus_shape_test.go`
  emit structural facts — counts, offsets, types, never string values — over
  every record, including the ones the decoder rejects. A rule is a claim about
  a distribution, quoted with its count.
- **The specification names.** [MS-EVEN6] and libyal/libevtx give the field its
  real name and meaning. `docs/evtx-format-notes.md` marks every claim as
  measured or read-from-source and keeps that distinction.
- **The VM confirms.** A Windows runner is the arbiter of acceptance, never of
  derivation.
- **CI records.** `docs/format-baseline.md` is append-only; a run is selected
  by `head_sha`, never by recency.

`isExcludedFixture` enforces the first rule mechanically: the corpus scan
refuses any file named `system.evtx`, the sample this project originally
derived everything from.

## Consequences

**Positive:**

- **Rules carry their evidence.** "An `OptionalSubstitution` declares its
  field's own type while its array entry declares NULL" is backed by 27 million
  shape observations across 320 398 records, against zero occurrences of the
  shape go-evtx used to write. That is what F15 was, and it is what finally
  made `ToXml` render.
- **A permissive parser passing proves nothing.** python-evtx's own source
  says `TODO: use this size() field` for a field Windows enforces. An encoding
  choice is never justified by what a reader tolerates.
- **Facts are recorded for records the decoder rejects.** Measuring only what
  already decodes is the round-trip blindness that hid every v0.6.0 defect.
- **No string values leave the corpus.** Real logs carry account names, SIDs,
  machine names and IP addresses, and this output gets quoted in `docs/`.

**Negative:**

- **A corpus is a developer's local directory.** These tests skip unless
  `EVTX_CORPUS` is set, so CI never runs them and no `.evtx` beyond the two
  tracked fixtures enters the repository.

## Alternatives Considered

**Keep iterating against the Windows VM alone.** It is the fastest loop to set
up and the one that produced seventeen failed tasks. Rejected on that record.

**Trust the project's own written specification.** It claimed templates bucket
by `template_id % 32`. Measured against two real Windows files that scored 10
of 386 entries; the correct rule scores 386 of 386. Nobody had checked before
writing it down.
