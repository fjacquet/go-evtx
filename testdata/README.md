# Test fixtures

## system.evtx

A real Windows-generated Event Log, used as ground truth for the chunk hash
table layout. go-evtx cannot validate its own format assumptions against files
it produced itself — that is the round-trip blindness that hid every v0.6.0
defect.

- md5: `182de19fe6a25b928a34ad59af0bbf1e`
- Obtained from: https://github.com/williballenthin/python-evtx `tests/data/system.evtx`
- python-evtx is licensed Apache-2.0. Its own provenance note records the
  original source as the plaso project's `test_data` directory:
  https://github.com/log2timeline/plaso/tree/1e2fa282efa2f839e1f179a3e98dbf922b5dbbc7/test_data
- Used unmodified, for testing only. Not linked into the library.
- Format version **3.1**. This is the only tracked fixture, and the only 3.1
  file the project has. Every automated test measures against it.

## Local-only corpus (not committed)

`.gitignore` excludes `testdata/*.evtx` with an exception for `system.evtx`.
Developers may keep additional real logs here for manual verification; they
are deliberately not tracked, for two reasons:

- **Privacy.** Real logs — `Security` above all — carry account names, SIDs,
  machine names and often IP addresses. This repository is public.
- **Size.** A real `Security` log runs past GitHub's 100 MB per-file limit.

Only derived, non-identifying results belong in the repo: bucket-rule scores,
template shapes, field layouts. Never the files.

**Name-collision hazard.** `docs/evtx-format-notes.md` cites a `security.evtx`
of 33 chunks / 240 template entries, obtained from python-evtx's corpus. That
is *not* the same file as a `Security` log exported from a live machine, which
will also land at `testdata/security.evtx` and silently replace it. When
citing a measurement, name the format version and the chunk count, not just
the filename — as of 2026-08-09 the local `security.evtx` is a 1985-chunk 3.2
file and the cited 3.1 fixture is gone. `system.evtx` is unaffected: its md5
is pinned above and still matches.
