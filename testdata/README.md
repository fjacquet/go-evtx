# Test fixtures

## `win2025-system.evtx` — the one tracked log

A System log exported from a disposable Windows Server 2025 instance this
project runs in a throwaway VPC. Format **3.2**, 11 chunks, 1818 records,
1 118 208 bytes, md5 `87b255e5b3e1729e9ddb41ee2f211679`. The strict decoder
reads 1813 of the 1818; the 5 it refuses carry `AnsiString`, which stays
deliberately unimplemented.

`win2025-system-expected.xml` beside it is Windows' own
`EventLogRecord.ToXml()` rendering of the first four records, captured on the
machine that produced the file. That is what `event_test.go` and
`binxml_decode_test.go` assert against — Windows' rendering, never this
library's own decode of the same bytes, because a decoder checked against
itself agrees with itself.

**It is a CI fixture, not a source of format rules.** Rules come from the
corpus census over hundreds of files (`corpus_shape_test.go`). Keeping those
two roles apart is the whole lesson of the section below.

**What it contains, audited before it was committed** — three machine names
(`EC2AMAZ-LNQ713N`, `EC2AMAZ-ETN574G`, `WIN-UK9M20OS250`), two machine SIDs
each with RID 500, `Administrator` as a subject name, and link-local addresses
(`169.254.169.123`, the AWS time service). No user accounts beyond the
built-in, no third-party providers, no routable addresses. The instance and
its VPC exist only for these tests.

Scrubbing was considered and rejected: anonymising an `.evtx` means rewriting
records, which changes the very bytes the fixture exists to be ground truth
for.

## Why no *other* real `.evtx` is tracked

`.gitignore` excludes `testdata/*.evtx` with that single exception. Two
reasons, and the second is the one that cost this project time.

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

They use `win2025-system.evtx` by default. Point `EVTX_FIXTURE` at a **3.1**
file to also exercise the template GUID bucket rule, which is 3.1-only and
therefore skips on the tracked 3.2 fixture:

```
EVTX_FIXTURE=/path/to/real-3.1.evtx go test ./...
```

The corpus tools take one or more directories, and never read a file named
`system.evtx` — `isExcludedFixture` enforces that:

```
EVTX_CORPUS=/dir/one:/dir/two go test -run TestCorpusScan -v .
EVTX_CORPUS=/dir/one:/dir/two go test -run TestCorpusShapeCensus -v .
EVTX_SHAPE_TARGET=/path/to/generated.evtx go test -run TestShapeDiffTarget -v .
```

**What CI does and does not check.** With `win2025-system.evtx` tracked, CI
verifies the name hash-table rule against real Windows output again. It still
does not verify the **template** bucket rule: that rule holds only on format
3.1, and the tracked fixture is 3.2. The 3.2 rule is unknown.

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
