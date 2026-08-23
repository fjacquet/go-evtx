# ADR-009: The `WriteRecords` Batch API (v0.11.0)

**Date:** 2026-08-23
**Status:** Accepted

## Context

`WriteRecord` takes `w.mu`, runs `checkStateLocked`, checks size-based
rotation, validates the fields map, encodes, and releases the lock — once per
event. A caller with a slice of events in hand pays that fixed overhead N
times and, more importantly, has no way to ask "write all of these or none of
them".

The second half is the real motivation. A caller assembling a batch from an
upstream source generally wants to know *before* anything reaches the file
whether the batch is well-formed, because a partial write leaves them holding
a slice with no clean way to determine where to resume. `WriteRecord` can
only answer that question one record at a time, after the earlier ones are
already committed.

## Decision

### 1. `WriteRecords(recs []RecordInput) error`

```go
type RecordInput struct {
    EventID int
    Fields  map[string]string
}

func (w *Writer) WriteRecords(recs []RecordInput) error
```

`RecordInput` is exactly `WriteRecord`'s two arguments in a struct, so a
caller can move between the two APIs without reshaping their data. A nil or
empty slice is a no-op returning nil.

One `w.mu` acquisition and one `checkStateLocked` cover the whole slice.

### 2. All-or-nothing validation, and its exact scope

Every record is validated before any record is encoded:

```go
for i, rec := range recs {
    if rec.Fields["ProviderName"] == "" { return ...record i... }
    if err := validateSystemFields(rec.Fields); err != nil { return ...record i... }
    if est := estimateMaxPayload(...); est > maxRecordPayload { return ...record i... }
}
```

Nothing below that loop can reject a record. That is what makes the guarantee
true rather than merely likely. Errors name the offending index —
`go_evtx: record 3: …` — so a caller can fix or drop the specific record.

**The guarantee is against validation failures, not against the disk.** This
distinction is stated in the doc comment and repeated here because it is the
thing a caller will misread. A batch larger than one chunk seals chunks as it
goes; that is normal, not an error. If a *write* fails partway through — a
full filesystem, a failing device — the records already committed to earlier
chunks stay written, and the error says which record was reached.
`WriteRecords` is not a transaction. Making it one would mean buffering an
arbitrarily large batch in memory and writing it as a unit, which the format's
64 KiB chunk granularity does not support and which would introduce an
unbounded memory cost to solve a problem nobody stated.

### 3. Size checking needs an analytic bound, not encode-and-rollback

`ErrRecordTooLarge` is the one validation failure that is not a property of
the fields map alone — it is a property of the *encoded* payload, which is
only knowable after encoding. Two ways to get it into the pre-pass were
available.

**Encode-and-rollback** — encode every record into a staging buffer, check
each size, then commit. Rejected on three counts. It buffers the whole batch
in memory, so a large batch's memory cost is unbounded. It makes the encode
happen twice or forces the commit path to consume staged bytes, which is a
second write path and therefore a second place for the byte layout to drift.
And rollback is not actually free here: `appendRecordLocked` may *flush a
chunk* mid-record when the pending chunk fills, and a flushed chunk is on
disk. There is nothing to roll back to.

**An analytic upper bound** — compute a number that is provably at least as
large as what the encoder would produce, without encoding. Chosen.

```go
func estimateMaxPayload(eventID int, recordID uint64, fields map[string]string) int {
    subs := collectSubstitutionsFromFields(eventID, recordID, fields)
    arraySize := 4 + 4*len(subs)
    for _, s := range subs {
        arraySize += len(s.data)
    }
    return preambleSize + templateBodySize() + arraySize + 8
}
```

The direction of the inequality is the safety property and it only has one
safe side: an **over**-estimate rejects a record that would in fact have fit,
which is a usability cost; an **under**-estimate lets an oversized record
reach the chunk buffer, which is the corruption `ErrRecordTooLarge` exists to
prevent. The bound is therefore deliberately loose — the trailing `+ 8`
covers the fragment EOF token plus up to 7 bytes of 8-alignment padding, and
the inline-template case is used because it is the larger of the two
encodings, so bounding it bounds both.

`estimate_test.go` pins both directions: `TestEstimateMaxPayload_IsUpperBound`
asserts it never falls below the real encoded size, and
`TestEstimateMaxPayload_IsNotAbsurdlyLoose` asserts it does not drift into
uselessness.

**One consequence worth naming.** `WriteRecords`'s size check is *stricter*
than `WriteRecord`'s. `WriteRecord` sizes the reference encoding it will
actually attempt first — which is roughly 2 KB smaller, since it points at a
template definition already in the chunk instead of inlining one.
`estimateMaxPayload` bounds the inline case. So a record whose reference
encoding lands in approximately the top 2 KB of `maxRecordPayload` is
accepted by `WriteRecord` and rejected by `WriteRecords`. That divergence is
deliberate and safe in the only direction that matters: validating a whole
batch before encoding any of it requires a bound that holds regardless of
which chunk state a given record happens to land in, and no such bound can be
tighter than the worst case.

### 4. The bound is derived from the encoder, not written down as constants

`templateBodySize` is not a literal. It is computed from `buildTemplateBody`
itself, once, via `sync.OnceValue`:

```go
var templateBodySize = sync.OnceValue(func() int {
    var names []chunkRef
    return len(buildTemplateBody(evtxRecordsStart+evtxRecordHeaderSize+preambleSize, &names))
})
```

Likewise the substitution array size comes from
`collectSubstitutionsFromFields` — the real collector, producing the real
entries the real encode would produce — not from a formula like "2 × UTF-16
length of each field value" written alongside it.

This is the decision this repo's history most directly demands. The template
body has changed in nearly every release since v0.7.0 (F12b added nine
`<System>` children, F13b/F13c added attributes, F15 changed five declared
types, F19 changed how the definition is referenced), and each of those
changes moved its encoded length. A constant would have been correct on the
day it was written and silently wrong afterwards — and "silently" is the
operative word, because a stale under-estimate does not fail loudly; it lets
an oversized record through, and the CRCs are then computed over the corrupt
bytes and verify. The same class of checksum-invisible damage that
`ErrRecordTooLarge` exists to prevent.

Deriving from the encoder's own structures makes the bound *unable* to drift:
a template change updates the estimate in the same compilation.

### 5. `WriteRecord` and `WriteRecords` share `appendRecordLocked`

Both entry points do their own validation and then call one unexported
helper:

```go
func (w *Writer) appendRecordLocked(eventID int, fields map[string]string) error
```

`appendRecordLocked` owns everything from the encode through the
chunk-capacity flush-and-rebuild to the append into `w.records`. Neither
caller reimplements any of it.

The point is that the byte-identity between the two APIs is **structural, not
tested-and-hoped**. `TestWriteRecords_EquivalentToIndividualWrites` asserts
that N `WriteRecord` calls and one `WriteRecords(N)` produce identical files,
and that test is worth having — but a test can only ever demonstrate identity
for the inputs it happens to try. Sharing the single append path means there
is no second implementation that *could* diverge, for any input, which is a
stronger statement than any test provides.

This matters more here than it would in most code because of what
`appendRecordLocked` contains. The flush-and-rebuild branch — where a record
does not fit the pending chunk, the chunk is flushed, and the record is
re-encoded with an inline template against the fresh chunk's offsets —
carries a non-obvious second size check on the *rebuilt* payload. Before F19
both builds were byte-identical in length, so one check covered both; since
F19 the first build may reference a template definition already in the chunk
while the rebuild must inline it, roughly 2 KB larger, so a record that
fitted as a reference can exceed the limit as an inline copy. Without the
second check it would be appended anyway, with the CRCs computed over it. A
duplicated version of that logic in `WriteRecords` would have been a second
place to get that wrong.

`WriteRecord`'s own external behaviour is unchanged; it is not reimplemented
in terms of `WriteRecords`.

`WriteRecords` also repeats the size-based rotation check **per record**
rather than once for the batch. An earlier version hoisted it, and a single
large batch then grew the active file arbitrarily far past `MaxFileSizeMB` —
`w.currentSize` only advances inside `flushChunkLocked`, so nothing
re-triggers rotation mid-batch without the per-record check. That broke both
`MaxFileCount` retention and the byte-identity guarantee.
`TestWriteRecords_RotatesLikeIndividualWrites` pins it.

## Consequences

### `WriteRecords` is measurably *slower* per record. Do not adopt it for speed.

From `docs/perf-baseline.md`, commit `717e122`, `darwin/arm64 M1 Pro, APFS,
go1.27.0`, both rows measured under the identical `SyncOnTick` policy so the
fsync cost is not a confound:

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `WriteRecordSyncOnTick` (single-record loop) | 2 770 | 5 025 | 5 |
| `WriteRecordsBatch (100)` (per record) | 3 934 | 8 997 | 8 |
| `EstimateMaxPayload` | 1 128 | 3 968 | 3 |

**`WriteRecords` at a batch size of 100 is roughly 1.4x slower per record
than 100 sequential `WriteRecord` calls.** This is not a caveat buried in a
footnote; it is the headline result for this API and a caller must read it
before choosing.

The cause is identified, not guessed. The validation pre-pass calls
`estimateMaxPayload`, which calls `collectSubstitutionsFromFields` for every
record — and then `appendRecordLocked` calls it *again* during the real
encode. Every substitution value is built twice. The allocation delta is the
confirmation: 8 997 − 5 025 = 3 972 B and 8 − 5 = 3 allocs per record, against
`EstimateMaxPayload`'s own measured 3 968 B / 3 allocs. Those numbers match to
4 bytes. The double collection is the entire difference.

**What `WriteRecords` actually buys** is the all-or-nothing validation
guarantee and one lock acquisition per batch instead of N. That is the whole
value proposition. The benchmark cannot show the lock saving at all, because
it runs in a single uncontended goroutine and never contends `w.mu`; whether
the trade lands differently under concurrent callers, or at a batch size
small enough for per-call fixed overhead to dominate, is **not established by
anything measured here** and should not be assumed.

**The obvious future optimisation** is to collect once. `estimateMaxPayload`
already produces exactly the `[]substitutionEntry` the encoder needs; threading
that slice from the pre-pass into `appendRecordLocked` would remove the second
collection and, by the arithmetic above, close most or all of the 1.4x gap.
It was not done in this release because it changes `appendRecordLocked`'s
signature — the one function whose sharing between the two entry points is
the structural guarantee in Decision 5 — and doing that while also introducing
the API it serves would have put the byte-identity property at risk in the
same commit that established it. It is a clean follow-up, not a design flaw.

### Each `Writer` now retains roughly 64-128 KiB for its lifetime

The allocation-reuse work in this release (which has no separate ADR; it is
recorded here because it is the same measurement) replaced per-call
allocations with `Writer`-owned scratch:

- `w.chunkScratch` — a **64 KiB** (`evtxChunkSize`) buffer, allocated on the
  first flush and retained until the `Writer` is garbage-collected. It is
  cleared before each use rather than reallocated: `flushChunkLocked` writes
  the chunk's padding tail too, and a reused buffer still holding the previous
  chunk's records would both leak data into the file and break byte-identity
  with v0.10.0, whose fresh buffers were zero-filled.
- `w.encodeScratch` — a `bytes.Buffer` grown to the **largest record encoded
  so far** and never shrunk. Typically a few KiB; bounded above by
  `maxRecordPayload` (64 996 bytes) plus the buffer's growth slack.

So a `Writer`'s steady-state floor is about **64 KiB**, rising toward **128
KiB** for a writer that has encoded a near-chunk-sized record. That is the
point of the work — `WriteRecord` fell from **49.0 to 5.0** allocations per
call by `testing.AllocsPerRun`, and from 60 to 5 allocs/op with 6 822 → 5 033
B/op in the benchmark rows — but it is a real change in resident memory and a
caller holding many concurrent `Writer`s (one per channel, one per tenant)
should size for it. It was previously near zero between calls.

The substitution arena inside `collectSubstitutionsFromFields` is **not**
retained: it is allocated per call at 1 KiB capacity and dropped. Only the two
buffers above live on the `Writer`.

`TestWriteRecord_AllocationCeiling` fails the build if per-record allocation
regresses past 8, so this does not quietly slide back.

### The aliasing hazard

`buildBinXMLInto` writes into `w.encodeScratch` and `res.payload` points into
it, so the payload is invalidated by the next encode. `appendRecordLocked`
consumes it synchronously — `wrapEventRecord` builds the 24-byte header, the
payload and the trailing size copy into one fresh slice, which
`append(w.records, rec...)` then copies into the pending chunk.

**The mechanism is `w.records`' append, not `wrapEventRecord`'s copy.** An
earlier draft of this ADR said the copy in `wrapEventRecord` was "the only
thing the writer retains", and that is wrong: rewriting `wrapEventRecord` to
build into a reused package-level buffer passes the entire test suite, because
the pending chunk owns its bytes either way. The writer is safe here
structurally — `res.payload` has no reachable path to outliving the next
encode — which is also why no test can guard the copy directly.

What is tested is the decoded output.
`TestWriteRecord_EarlierRecordSurvivesNextEncode` writes two records with
distinct field values and reads both back; every other multi-record test in
the package writes identical fields and so cannot see one record's payload in
another. `TestBuildBinXML_PayloadSurvivesNextEncode` covers only
`buildBinXML`'s own contract — it allocates a fresh buffer per call, so its
result is safe to retain — and is not a guard on the writer path. The failure
mode being guarded is silent data corruption, not a panic: both chunk CRCs are
computed over whatever bytes are present and verify.

## Alternatives Considered

**Reimplement `WriteRecord` as `WriteRecords([]RecordInput{{id, fields}})`.**
Rejected. It would put every existing caller on the stricter
`estimateMaxPayload` size check, changing which records `WriteRecord` accepts
in a minor release, and it would make the single-record path pay the double
collection described above.

**Return a `[]error`, one per record, instead of failing the batch.**
Rejected: it is the opposite of the guarantee this API exists to provide. A
caller who wants per-record outcomes already has `WriteRecord` in a loop.

**Buffer the whole batch and write it as one transaction.** Rejected —
unbounded memory, and the format's chunk granularity means the "transaction"
would still be committed in 64 KiB pieces. See Decision 2.

**Relying on the table-driven bound test alone.** Rejected. The design spec
proposed a fuzz target against the real encoder and it **shipped**:
`estimate_test.go` carries both `TestEstimateMaxPayload_IsUpperBound` (the
table of cases the encoder actually distinguishes, which also asserts the
bound is not absurdly loose) and `FuzzEstimateMaxPayload_IsUpperBound`, which
seeds ASCII, non-BMP runes, empty strings and oversize values and then asserts
`est >= len(buildBinXML(...).payload)` for both `shared = 0` (inline template)
and `shared = 512` (backward reference). The property is the one the
all-or-nothing contract rests on, and a table of hand-picked cases is exactly
the kind of evidence this repository has learned not to trust on its own — an
under-estimate is checksum-invisible, so the guard has to explore inputs
nobody thought of. The one thing not done is running the fuzz target as a
long-running corpus job in CI; it runs its seeds on every `go test`.
