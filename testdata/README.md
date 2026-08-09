# Test fixtures

## No real `.evtx` is tracked here

`.gitignore` excludes `testdata/*.evtx` with no exception. Two reasons, and the
second is the one that cost this project time.

**Privacy and size.** Real logs — `Security` above all — carry account names,
SIDs, machine names and often IP addresses, and this repository is public. A
real `Security` log also runs past GitHub's 100 MB per-file limit.

**A sample of one is not ground truth.** The repository used to track
`system.evtx`, a 1601-record Windows log borrowed from python-evtx's corpus.
Every format rule go-evtx encodes was derived from it — the `<System>` block's
children, the per-element `OptionalSubstitution` choice, the `dependency_id`
rule, `EventID/@Qualifiers`'s declared type, the `0x46`/`0x06` attribute-token
rule — and the same file was then used to assert those rules were right. An
assertion against the file the rule came from cannot fail when the rule is
wrong. It did not fail, and the rules were wrong.

The fix was not a better sample. It was measuring 320 398 records across 281
files: the census in `corpus_shape_test.go` returned 68 distinct structural
shapes, and diffing go-evtx's own output against it produced a list of exactly
one entry — the defect that had survived seventeen tasks.

For the record, `system.evtx` was not itself defective. Profiled against the
census it emits no shape the corpus does not contain. It was a normal file
asked to carry more evidentiary weight than one file can.

## Running the tests that need a real file

A few tests measure hash-table rules against real Windows output. They skip
unless given a file:

```
EVTX_FIXTURE=/path/to/real.evtx go test ./...
```

The corpus tools take one or more directories, and never read a file named
`system.evtx` — `isExcludedFixture` enforces that:

```
EVTX_CORPUS=/dir/one:/dir/two go test -run TestCorpusScan -v .
EVTX_CORPUS=/dir/one:/dir/two go test -run TestCorpusShapeCensus -v .
EVTX_SHAPE_TARGET=/path/to/generated.evtx go test -run TestShapeDiffTarget -v .
```

**Consequence, stated rather than hidden:** with no tracked real file, CI does
not check these rules at all. Restoring that coverage needs a small real log
generated on a Windows machine we control and licensed to us — not another
borrowed sample.

## What may be committed

Only derived, non-identifying results: bucket-rule scores, shape counts,
template shapes, field layouts. `shape-census.json` is exactly that — 68 rows
of structural shapes and their frequencies, no names and no values.

**Name-collision hazard.** When citing a measurement, name the format version
and the chunk count, not just the filename. A `security.evtx` from python-evtx's
corpus (33 chunks, 3.1) and a `Security` log exported from a live machine
(1985 chunks, 3.2) will both land at `testdata/security.evtx`.

## `binxml-golden.bin`

go-evtx's own encoder output for a frozen record, 2623 bytes. Not a fixture —
a regression pin, regenerated deliberately whenever the encoding changes, in
the same commit, with the reason in the commit message.
