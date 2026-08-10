# ADR-005: Ship CLI binaries

**Date:** 2026-08-10
**Status:** Accepted

## Context

go-evtx has been a library since v0.1.0. `.goreleaser.yaml` sets
`builds: [{skip: true}]`, and a release with zero attached assets is the
correct outcome under that decision: consumers reach the code through
`go get` and the module proxy.

Two subcommands now exist that are useful outside a Go program — `evtx dump`
and `evtx info` — and the library has no executable demonstration of itself.
Someone evaluating go-evtx has the README, the godoc, and no way to point the
thing at a file.

## Decision

Ship one binary, `evtx`, built from `cmd/evtx` in this module, for
linux/darwin/windows on amd64 and arm64, with a checksums file.

`cmd/evtx` stays inside the existing module rather than taking its own
`go.mod` or its own repository. `go install github.com/fjacquet/go-evtx/cmd/evtx@latest`
then works with no extra setup, and the binary's version is the library's
version — `evtx version` reporting v0.8.0 means something.

## Consequences

- **The CLI surface becomes a compatibility promise.** Flag names, the shape
  of the NDJSON, and the exit codes are now things consumers script against.
  Breaking any of them needs a major or minor bump and a CHANGELOG entry, the
  same as an exported Go symbol.
- **Zero release assets stops being the expected state.** A release that
  attaches nothing is now a failed build, not a correct library release. Anyone
  reading an old release page should know assets were absent by design until
  v0.8.0.
- **A library consumer also fetches the `cmd/` sources.** With no dependencies
  these are inert Go files; the empty require block in `go.mod` is unaffected.
- **The two fixture generators stay unshipped.** `builds[].main` names
  `./cmd/evtx` explicitly, so `gen-fixture-system` and `gen-fixture-minimal`
  remain CI-only tools.

## Alternatives Considered

**A separate module under `cmd/evtx/go.mod`.** Would isolate CLI dependencies
if the CLI ever wanted cobra or coloured output. Rejected: it costs `replace`
directives during development, two tags per release and a doubled CI matrix,
paid today for a freedom two subcommands do not need.

**A separate `go-evtx-cli` repository.** Total isolation, no discoverability,
and two release processes for one binary with one upstream consumer. Rejected.
