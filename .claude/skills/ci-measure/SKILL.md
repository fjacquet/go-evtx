---
name: ci-measure
description: Resolve the Format Verify CI run for a commit by head_sha, wait with a hard ceiling, and print the measurement lines. Use after pushing a change whose effect on the Windows verdict needs measuring.
disable-model-invocation: true
---

# ci-measure

Prints the Windows and python-evtx measurements for a given commit.

```bash
.claude/skills/ci-measure/scripts/ci-measure.sh            # HEAD
.claude/skills/ci-measure/scripts/ci-measure.sh <sha>      # a specific commit
.claude/skills/ci-measure/scripts/ci-measure.sh <sha> 900  # raise the ceiling
```

## Why this exists rather than `gh run list | head`

Two failure modes dominated the v0.7.0 format investigation, and both are structural rather than careless:

**Unbounded waiting.** Six separate agents burned their entire budget polling CI and had to be killed. This script has a hard ceiling and always exits — on timeout it prints the run ID and tells you to report it as pending rather than loop.

**Selecting a run by recency.** A measurement was once recorded against a run whose `head_sha` was two commits behind the fix. Its result was byte-identical to the previous row, which looked like a meaningful null and was in fact mechanically guaranteed. This script matches `head_sha` exactly and refuses to guess.

## Reading the output

| Line | Meaning |
|---|---|
| `STAGE1 OPEN: ok` | `EventLogReader`'s constructor accepted the file |
| `STAGE2 READ: ok, N records` | Windows parsed N records. **This is the release's hard-won win — if it drops to 0, revert whatever caused it before doing anything else.** |
| `PROP ToXml` | BinXML→XML rendering. The currently unsolved defect |
| `GETWINEVENT default` / `-Oldest` | The cmdlet, both iteration orders |
| `OK: N records, all chunk checksums verify` | python-evtx differential — green since the `xmlns` fix, and it must stay green |
| `wrote artifacts/… (N records, max ObjectName M runes)` | The fixture's identity. **Compare it before comparing anything else** — Windows' rejection message is content-dependent, so a message comparison across differing fixtures is meaningless |

## After measuring

Append a row to `docs/format-baseline.md`. Never edit an existing row: earlier rows are the evidence later comparisons rest on. See the measurement-discipline section in `CLAUDE.md`.
