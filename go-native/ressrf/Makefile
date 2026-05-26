# Makefile for ressrf-go.
#
# CI (.github/workflows/{ci,fuzz}.yml) calls these targets so the local
# `make test` / `make lint` / `make fuzz` invocations and the CI invocations
# stay in lockstep. Override behaviour at the command line, e.g.
#   make test GO=/opt/homebrew/bin/go
#   make fuzz FUZZ_TARGET=FuzzValidateURL FUZZ_DURATION=30s

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
LINT_TIMEOUT  ?= 5m

# Fuzz overrides. Default to FuzzValidateURL because it has the richest seed
# corpus; CI passes FUZZ_TARGET per matrix entry.
FUZZ_TARGET   ?= FuzzValidateURL
FUZZ_DURATION ?= 30s
FUZZ_PKG      ?= ./internal/engine/

# Differential-fuzz duration. The oracle WASM is the sibling wazero
# binding's checked-in artifact at ../../go/ressrf/core.wasm, picked
# up automatically by internal/diff/oracle.go — no clone, no cargo
# step from this Makefile.
FUZZ_RUST_DURATION ?= 5m

.DEFAULT_GOAL := help

.PHONY: help
help: ## List available targets
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: build
build: ## Compile all packages
	$(GO) build ./...

.PHONY: test
test: ## Run unit + conformance tests with the race detector
	$(GO) test -count=1 -race ./...

.PHONY: test-fast
test-fast: ## Run tests without -race (faster local iteration)
	$(GO) test -count=1 ./...

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run --timeout $(LINT_TIMEOUT)

.PHONY: fmt
fmt: ## Format every Go file in the repo
	$(GO) fmt ./...

.PHONY: generate
generate: ## Regenerate internal/engine/*_generated.go from ./config
	$(GO) generate ./...

.PHONY: check-generated
check-generated: generate ## Fail if generated files are stale (used by CI drift check)
	@if ! git diff --exit-code internal/engine/ip_ranges_generated.go internal/engine/cloud_generated.go; then \
	  echo ""; \
	  echo "ERROR: generated files are stale. Run 'make generate' and commit the diff."; \
	  exit 1; \
	fi

.PHONY: fuzz
fuzz: ## Run a single fuzz target (override FUZZ_TARGET, FUZZ_DURATION)
	$(GO) test -run='^$$' -fuzz='^$(FUZZ_TARGET)$$' -fuzztime=$(FUZZ_DURATION) $(FUZZ_PKG)

.PHONY: fuzz-rust
fuzz-rust: ## Fuzz this Go engine against the sibling wazero binding's WASM oracle
	$(GO) test -tags diffuzz -run='^$$' -fuzz='^FuzzPolicyDiff$$' -fuzztime=$(FUZZ_RUST_DURATION) ./internal/diff/

.PHONY: fuzz-rust-regress
fuzz-rust-regress: ## Deterministic replay of the persisted divergence corpus (used by CI)
	$(GO) test -tags diffuzz -run='^FuzzPolicyDiff$$' ./internal/diff/

.PHONY: bench
bench: ## Run benchmarks (root package only by default)
	$(GO) test -bench=. -benchmem -benchtime=2s -run=NONE .

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: ci
ci: lint check-generated test ## Run the full CI suite locally (lint includes govet)

.PHONY: clean
clean: ## Remove build / test cache artefacts
	$(GO) clean -cache -testcache
