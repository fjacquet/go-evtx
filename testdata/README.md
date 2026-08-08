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
