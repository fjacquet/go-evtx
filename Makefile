# Canonical Go Makefile — fjacquet/ci standard interface (do not rename targets)
.DEFAULT_GOAL := all
DIST  ?= dist
COVER ?= coverage.out
# Go-1.24-compatible tool pins (go.mod is go 1.24; defaults need Go 1.25).
GOLANGCI_VERSION ?= v2.8.0
GORELEASER_VERSION ?= v2.7.0
# govulncheck @latest (v1.4.0) needs Go >= 1.25; the CI runner pins
# GOTOOLCHAIN=local at go 1.24, so pin the last Go-1.24-safe release.
GOVULNCHECK_VERSION ?= v1.1.4
# cyclonedx-gomod @latest (v1.10.0) also needs Go >= 1.25; pin Go-1.24-safe.
CYCLONEDX_GOMOD_VERSION ?= v1.9.0

.PHONY: all clean install tools lint format test build vuln sbom security docs coverage-upload release ci

all: clean lint test build

clean:
	rm -rf $(DIST) site $(COVER) *.sarif

install:
	go mod download

tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)

lint:
	golangci-lint run --timeout=5m

format:
	golangci-lint fmt

test:
	go test -race -coverprofile=$(COVER) -covermode=atomic ./...

# go-evtx is a library (no binary); build verifies all packages compile.
build:
	go build -v ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

sbom:
	mkdir -p $(DIST)
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION) mod -json -output $(DIST)/sbom.cdx.json

security:  # advisory: reports findings but never blocks the build (CodeQL/osv are the blocking gates)
	uvx semgrep scan --config auto --skip-unknown-extensions || true

docs:
	uvx --with mkdocs-material --with pymdown-extensions mkdocs build --strict --site-dir site

coverage-upload:
	uvx --from codecov-cli codecov upload-process --file $(COVER) || true

release:
	goreleaser release --clean

ci: lint test build vuln
