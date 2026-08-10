# `evtx` CLI and the documentation set — design

**Date:** 2026-08-10
**Status:** proposed, awaiting review
**Target release:** v0.8.0

## Why

Two questions started this, and the answer to the first shapes the second.

**"Is go-evtx at full reader and writer conformance?"** Measured today: the
reader is there, the writer is correct but narrow. The numbers are below. That
asymmetry is not currently written down anywhere a user would look — `docs/PRD.md`
still says version 0.2.0, dated 2026-03-05, and its "known limitations" table is
wrong in both directions: it lists gaps that were closed in v0.3–v0.7, and it
omits the one limitation that actually bites.

**"Can we work on CLI tools that show our usage?"** The library has no
executable demonstration of itself. `cmd/` holds two fixture generators that
exist to feed CI, neither shipped. A colleague evaluating go-evtx has the README
and godoc, and no way to point the thing at a file and see what comes out.

One release serves both: a shipped `evtx` binary that is a working tool *and* a
faithful demonstration of the API, plus the documentation that tells the truth
about what the library does and does not do.

## What was measured

All figures from 2026-08-10, against the local corpus
(`EVTX-ATTACK-SAMPLES` plus `testdata/`), `system.evtx` excluded by
`isExcludedFixture` as it always is.

| Measurement | Value |
|---|---|
| Files | 285 |
| Records | 333 100 |
| `decodeRecordBinXML` succeeds | 333 074 — 99.992% |
| `Reader.ReadEvent()` succeeds | 332 894 — 99.938% |
| Events with an empty `Provider` | 1 |
| Files carrying at least one `ReadEvent` failure | 178 of 285 |
| Whole-corpus scan wall time | 10.6 s |

The 206 `ReadEvent` failures have exactly two causes, not a long tail:

| Count | Files | Cause |
|---|---|---|
| 180 | 174 to 178 | `FILETIME 0 is out of range for a 100ns Unix offset` |
| 26 | 4 | `AnsiString is not supported: the format carries no codepage` |

The per-cause file counts were not measured separately; 178 files carry at
least one failure of either kind and 4 carry an `AnsiString`, so the FILETIME
range is what those two facts bound it to.

The first of those is a defect in this library, not a property of the corpus,
and it is in scope for this work — see "The FILETIME 0 fix" below.

For scale, on 2026-08-09 the decoder returned **0** non-empty `Provider` and
**0** non-zero `EventID` across 37 534 real records, and reported no error while
doing it.

The writer is a different story. What it writes is accepted by Windows —
`ToXml` renders, both `Get-WinEvent` orderings enumerate, `EventLogReader` reads
every record, python-evtx agrees, and all of that is a merge gate. But it can
express exactly one event shape: one template, twelve fixed `<Data>` names,
`EventID` as `uint16`, `Level`/`Task`/`Opcode`/`Keywords` pinned to zero, no
`UserData`, no `Binary`, no typed values. **Conformance of what it writes:
reached. Coverage of what it can write: not.**

## Goals

1. Ship an `evtx` binary with two read-side subcommands: `dump` and `info`.
2. Make that binary a faithful demonstration of the library API — no parallel
   serialisation layer that can drift from it.
3. Fix `fromFILETIME` so a zero timestamp decodes instead of erroring.
4. Replace the documentation set with one that states the measured position,
   including the writer limitation.

## Non-goals

- **No write subcommand.** Decided during design. `dump | write` would not
  reproduce its input, because of the writer coverage gap above. Exposing that
  through a shipped CLI before the gap is closed would ship a tool whose most
  obvious use is broken.
- **No filtering or query.** No selection by EventID, provider or time range.
  `jq` consumes the NDJSON.
- **No XML rendering.** Unchanged from the decoder design: structure, not
  presentation.
- **No changes to the writer.** Its coverage gap is a separate project.

## Decisions taken during design

| Question | Decision |
|---|---|
| CLI role | A shipped binary **and** non-shipped examples, kept separate |
| Scope of the shipped binary | Read-side only for v1 |
| JSON shape | Both a faithful shape and a flat shape, behind a flag |
| Behaviour on undecodable records | Skip, report, exit non-zero |
| Module layout | `cmd/evtx/` inside the existing module |
| Input and output | Explicit `--in` / `--out` flags |
| Documents in this batch | PRD, ADR-005, ADR-006, user guide |
| `FILETIME 0` | Fixed in this batch, not deferred |

**On the two JSON shapes.** A flat shape was raised as carrying a cost: field
names from `EventData` can collide with `System` names, and Windows produces
unnamed positional `<Data>` elements — `Data.Name` is documented as empty for
those in `event.go`. The decision was to build both anyway. This design
therefore fixes explicit rules for collision and for unnamed entries rather
than leaving them to be discovered; see `--shape=flat` below.

**On non-shipped examples.** They go in `example_test.go` as godoc `Example`
functions, not as new `cmd/` programs. A godoc example is compiled and executed
by `go test`, its output is verified against its `// Output:` comment, and it
renders on pkg.go.dev beside the function it illustrates. A `cmd/` program that
is neither shipped nor executed rots unobserved — `cmd/gen-fixture` was removed
on 2026-08-10 for exactly that.

## The FILETIME 0 fix

This entered scope because measuring the exit-code policy exposed it: 178 of
285 real files carry at least one record `ReadEvent` refuses, so the CLI would
exit 2 on nearly two files in three at first contact.

The cause is this library's arithmetic, not the corpus and not Windows, which
emits zero timestamps routinely:

```go
// binformat.go, before
delta := int64(ft) - filetimeEpochDelta
const maxDelta = math.MaxInt64 / 100
const minDelta = math.MinInt64 / 100
if delta > maxDelta || delta < minDelta {
    return time.Time{}, fmt.Errorf("go_evtx: FILETIME %d is out of range for a 100ns Unix offset", ft)
}
return time.Unix(0, delta*100).UTC(), nil
```

`time.Unix(0, ns)` routes the whole offset through nanoseconds, and an `int64`
of nanoseconds spans only 1678–2262. FILETIME 0 is the year 1601, so it
overflows — even though `time.Time` represents 1601 without difficulty. The
range check is enforcing a limit of our own construction.

```go
// after
sec := delta / 10_000_000
nsec := (delta % 10_000_000) * 100
return time.Unix(sec, nsec).UTC(), nil
```

Seconds cannot overflow across the whole FILETIME domain (1601 to roughly
30828), so the `minDelta`/`maxDelta` check goes away with the `ft > MaxInt64`
guard retained — a FILETIME above `MaxInt64` is not a time, and rejecting it
stays correct.

Expected effect, to be confirmed by re-measuring after the change: `ReadEvent`
failures fall from 206 to 26, and affected files from 178 to 4. The CLI then
exits 0 on 281 of 285 corpus files instead of 107.

**`toFILETIME` has the same defect and must move with it.** It computes
`t.UTC().UnixNano()/100 + filetimeEpochDelta`, and `UnixNano` is undefined
outside 1678–2262 — so the 1601 round trip this fix is meant to enable would
fail on the encode side. It becomes
`u.Unix()*10_000_000 + int64(u.Nanosecond())/100 + filetimeEpochDelta`.

**One existing test asserts the wrong belief and must be rewritten, not
deleted.** `TestFromFILETIME_OutOfRangeIsError` in `binformat_test.go` states
that `fromFILETIME(0)` must error, with a comment explaining it as a corruption
guard. It becomes a test that 0 decodes to 1601-01-01T00:00:00Z, carrying a
comment that says what replaced the old belief and why.

Tests: `fromFILETIME(0)` yields 1601-01-01T00:00:00Z; a round trip through
`toFILETIME` returns the input for 1601, for the Unix epoch, and for a present
day value; `ft > MaxInt64` still errors. A reader-level test asserts a
zero-timestamp record now decodes rather than failing.

## Architecture

```
cmd/evtx/main.go     subcommand dispatch, exit codes, --version
cmd/evtx/dump.go     evtx dump
cmd/evtx/info.go     evtx info
cmd/evtx/flat.go     flat projection and its collision rules
cmd/evtx/*_test.go   tests
```

All `package main`. Argument parsing is `flag` from the standard library, one
`flag.FlagSet` per subcommand, dispatched on `os.Args[1]`. No CLI framework:
ADR-001 stands and `go.mod` keeps its empty require block.

`cmd/evtx/` lives in the existing module, so
`go install github.com/fjacquet/go-evtx/cmd/evtx@latest` works with no extra
setup and the binary's version is the library's version. A library consumer also
fetches the `cmd/` sources; with no dependencies these are inert Go files.

**The flat projection stays in the CLI, not the library.** It is a presentation
format carrying arguable trade-offs; in `package evtx` it would become a public
contract to keep forever. Downstream consumers already have `Event`, which is
faithful and typed.

### Library addition: `Reader.FileInfo`

`evtx info` needs facts the public API does not expose. `Reader` keeps only
`numChunks`; the format version at `hdr[36:40]` is read during `Open` and
discarded. Format 3.1 versus 3.2 is exactly what belongs at the top of an
`info` report.

```go
// FileInfo describes the container, not its contents.
type FileInfo struct {
    Major, Minor uint16 // format version; Windows writes 3.1 and 3.2
    Chunks       int
    Dirty, Full  bool   // file header flags
}

// FileInfo returns the container facts read from the file header.
func (r *Reader) FileInfo() FileInfo
```

Four fields already read, or trivially readable, in `Open`. This is a new public
surface on a `v0.x` library and is intentional: "what format version am I
holding" is a legitimate question for any consumer, not only for a display.

Everything else `info` reports — record count and decode failures — comes from
walking the file with `ReadEvent`, so it needs no further API.

## `evtx dump`

```
evtx dump [--in FILE] [--out FILE] [--shape=event|flat] [--allow-errors] [FILE]
```

`--in` and the positional argument are equivalent; supplying both is a usage
error. Without `--out`, NDJSON goes to stdout. Diagnostics and the summary
always go to stderr, so `evtx dump f.evtx > out.ndjson` never mixes them.

One record per line. No pretty-printing, no trailing array.

### `--shape=event` (default)

Literally `json.Marshal(ev)` on the library's `Event`. `Event` already carries
its JSON tags, and `Value.MarshalJSON` already does the type-aware work: a SID
renders as `S-1-5-18`, a FILETIME as RFC 3339, binary as base64, a string array
as a JSON array, and integers at or beyond 2^53 are quoted so `Keywords` is not
silently rounded.

The CLI adds no serialisation code of its own. That is what makes it an honest
demonstration rather than a parallel layer that drifts.

```json
{"record_id":4211,"timestamp":"2026-08-10T06:02:35.412Z","system":{"provider":{"name":"Microsoft-Windows-Security-Auditing","guid":"{54849625-5478-4994-a5ba-3e3b0328c30d}"},"event_id":4663,"level":0,"time_created":"2026-08-10T06:02:35.412Z","event_record_id":4211,"channel":"Security","computer":"WIN-SRV25"},"event_data":[{"name":"ObjectName","value":"C:\\logs\\a.txt"}]}
```

### `--shape=flat`

One level. `System` fields at the root, `EventData` entries lifted beside them.
Three cases need a rule, and one rule covers all three:

> An `EventData` entry takes its own name as its root key when that name is
> non-empty, collides with no `System` key, and has not already been used.
> Otherwise its key is `data_<i>`, where `i` is the entry's absolute index in
> `EventData`, followed by `_<Name>` when a name exists.

So `ObjectName` stays `ObjectName`; a `<Data Name="Computer">` becomes
`data_7_Computer` and cannot overwrite `System`'s `Computer`; an unnamed
`<Data>` at index 3 becomes `data_3`. Deterministic, traceable back to the
originating index, and lossless.

The count of relocated keys goes in the stderr summary. A silent arbitration is
one that gets discovered six months later.

The reserved `System` key set is fixed by the `System` struct's JSON tags plus
`record_id`, `timestamp`, `binary` and `user_data`. It is computed from those
tags rather than hand-listed, so adding a `System` field cannot silently open a
collision.

**`user_data` stays nested, including in flat shape.** It is an arbitrary XML
tree; flattening it would mean inventing a path convention. Stated exception:
"flat" describes `EventData`, not the whole record.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Every record decoded, or `--allow-errors` was given |
| 1 | Usage error, or the input cannot be read: missing file, invalid magic |
| 2 | At least one record was skipped |

A skipped record produces one stderr line carrying its chunk, its record index
and the cause, and is followed at end of stream by a summary line. `--allow-errors`
turns the 2 into a 0 and changes nothing else.

With the FILETIME fix in, this yields 2 on the 4 corpus files carrying an
`AnsiString` record and 0 on the other 281. Without it, it would yield 2 on 178
of 285 — which is what put that fix in scope.

## `evtx info`

```
evtx info [--in FILE] [FILE]
```

Human-readable, not NDJSON: `dump` is the machine path.

```
file       win2025-system.evtx
format     3.2
chunks     11
flags      dirty=false full=true
records    1818
decode     1818/1818 records, 0 failures
```

**Correction, made while planning.** An earlier draft of this section also
printed a distinct-template count. It is not reachable: template offsets live
in unexported structures, `cmd/evtx` is a separate package, and the only ways
to print it would be to export chunk internals or to reimplement the decoder in
the CLI. Dropped rather than paid for.

When records fail, causes are **grouped and normalised**, never listed one per
record:

```
decode     183999/184002 records, 3 failures
             3  AnsiString is not supported
```

Normalisation strips digits from the message so that per-record positions do not
fragment the grouping — the same reduction used to produce the two-line failure
table in "What was measured".

`info` always performs a full decode pass, with no flag to skip it. The whole
corpus scans in 10.6 s; a 200 000-record file therefore costs a few seconds, and
a `--deep` flag would be documentation weight against a saving nobody notices.

**`info` exits 0** unless the file cannot be read or its magic is invalid, which
give 1. Deliberate divergence from `dump`: `dump` produces data a pipeline
consumes, so a partial decode must reach the exit code; `info` produces a
report, and a report that says "3 failures" has done its job.

## Testing

Each subcommand is a function, not a `main` that must be spawned:

```go
func runDump(args []string, stdout, stderr io.Writer) int
func runInfo(args []string, stdout, stderr io.Writer) int
```

`main` calls one and passes its return to `os.Exit`. Exit codes become return
values to assert, with no process spawn and no built binary needed before tests.

1. **`dump --shape=event` against a library-written file.** Every line
   unmarshals, the line count equals the number of records written, and the
   values read back equal those passed to `WriteRecord`.

2. **The flat rules, unit-tested on the projection function**, against
   synthetic `Event` values — plain name, collision with a `System` key, unnamed
   entry, repeated name. This is deliberate, not a shortcut: the writer cannot
   produce any of the contentious cases, since its twelve names are fixed, all
   named, and none collides with `System`. An end-to-end test would never
   construct a collision and would pass while testing nothing — the failure mode
   this repository has hit three times.

3. **Exit codes:** 0 on a clean file, 2 on a file with undecodable records, 0
   with `--allow-errors`, 1 on a missing file and on invalid magic.

4. **`info` against a library-written file:** format 3.1, chunk count, record
   count, `0 failures`.

5. **`fromFILETIME` bounds**, as listed in "The FILETIME 0 fix": zero, the
   epoch, a present-day round trip, and the retained `MaxInt64` rejection.

6. **Corpus test, skipped without `EVTX_CORPUS`:** dump every corpus file,
   assert each line is valid NDJSON and that every reported failure cause is
   non-empty. No assertion on exact counts — the corpus is local and will
   change; asserting "26" would be false on another machine.

## Documentation deliverables

| Document | Content |
|---|---|
| `docs/adr/ADR-005-ship-cli-binaries.md` | The posture reversal. Context: `.goreleaser.yaml` sets `builds: [{skip: true}]` and zero release assets is currently the correct outcome. Consequences: a build matrix, checksums, the CLI surface becomes a compatibility promise, and the binary is versioned with the library |
| `docs/adr/ADR-006-corpus-derived-format-method.md` | The corpus derives, the specification names, the VM confirms, CI records. With what it replaced: seventeen tasks spent imitating a single sample, and a one-bit oracle that cannot distinguish a wrong hypothesis from a right one aimed at the wrong field. The rule currently lives only in `CLAUDE.md`, which is agent instructions, not a traced decision |
| `docs/PRD.md` | Rewritten at 0.8.0. Delivered/planned tables refreshed through v0.7, plus this release. Known limitations replaced with the measured ones: writer expressiveness, `AnsiString`, the 3.2 template bucket rule. Plus CLI requirements |
| `docs/user-guide.md` | New. Install both library and CLI, read a file, write records, rotation, both subcommands, what the library cannot do, and the two errors a caller actually meets: `ErrMissingProviderName`, `ErrRecordTooLarge` |
| `docs/index.md`, `README.md` | Links and a CLI section |

### Release

**v0.8.0.** Minor, not patch: `Reader.FileInfo` is a public API addition and a
binary appears where there was none. The FILETIME fix rides with it as a
`Fixed` entry — records that previously failed to decode now decode, which is
a behaviour change worth its own CHANGELOG line. `.goreleaser.yaml` gains a build matrix for
`cmd/evtx` across linux/darwin/windows on amd64 and arm64, with checksums.

## Deliberately out of scope

- **ADR-003 and ADR-004 are not rewritten.** An ADR is a journal; the past is
  not edited. Neither of the four existing ADRs covers rotation, the sticky
  error, or the generic decoder. Tracing those is two further ADRs, in their
  own batch.
- **`AnsiString` stays unsupported.** It is a deliberate refusal: the format
  carries no codepage, so any decoding would be a guess. 26 records across 4
  corpus files. Named in the PRD's limitations table by this work; supporting it
  would need a codepage policy and is separate.
- **The writer coverage gap is not addressed.** It is the largest remaining
  piece of work on this library and deserves its own design.
