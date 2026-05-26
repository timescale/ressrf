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

# Differential-fuzz-against-Rust overrides. Upstream Rust repo location and
# the WASM target. The .wasm artifact is not committed; it is rebuilt on
# every `make fuzz-rust` run from the upstream HEAD.
RESSRF_RUST_REPO          ?= https://github.com/timescale/ressrf
RESSRF_RUST_DIR           ?= /tmp/ressrf
RESSRF_WASM_TARGET        ?= wasm32-wasip1
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

# _oracle (underscore-prefixed, no help docstring -> hidden from `make help`)
# always refreshes the upstream clone and rebuilds the WASM. ~2-3s when
# nothing changed, ~10-30s when upstream advances. Both fuzz-rust
# targets depend on it so a stale oracle can never silently coexist with
# the harness.
#
# Three states the directory can be in when this target runs:
#   1. doesn't exist           -> needs fresh clone
#   2. exists with .git/       -> already cloned, pull --ff-only
#   3. exists without .git/    -> populated by actions/cache restoring
#                                 RESSRF_RUST_DIR/target/, but missing
#                                 the repo itself
# State 3 used to fail because `git clone` refuses a non-empty destination.
# Clone into a tempdir and move only .git/ into place so the cache-restored
# target/ (gitignored upstream) survives.
.PHONY: _oracle
_oracle:
	@if [ -d $(RESSRF_RUST_DIR)/.git ]; then \
	  git -C $(RESSRF_RUST_DIR) pull --ff-only; \
	else \
	  tmpclone=$$(mktemp -d); \
	  trap "rm -rf $$tmpclone" EXIT; \
	  git clone --depth 1 $(RESSRF_RUST_REPO) $$tmpclone/oracle && \
	  mkdir -p $(RESSRF_RUST_DIR) && \
	  rm -rf $(RESSRF_RUST_DIR)/.git && \
	  mv $$tmpclone/oracle/.git $(RESSRF_RUST_DIR)/.git && \
	  git -C $(RESSRF_RUST_DIR) checkout -- .; \
	fi
	cd $(RESSRF_RUST_DIR) && cargo build -p ressrf-wasm --target $(RESSRF_WASM_TARGET) --release
	mkdir -p internal/diff/testdata
	cp $(RESSRF_RUST_DIR)/target/$(RESSRF_WASM_TARGET)/release/ressrf_wasm.wasm internal/diff/testdata/

.PHONY: fuzz-rust
fuzz-rust: _oracle ## Fuzz this Go engine against the upstream Rust WASM oracle (auto-refreshes oracle)
	$(GO) test -tags diffuzz -run='^$$' -fuzz='^FuzzPolicyDiff$$' -fuzztime=$(FUZZ_RUST_DURATION) ./internal/diff/

.PHONY: fuzz-rust-regress
fuzz-rust-regress: _oracle ## Deterministic replay of the persisted divergence corpus (used by CI)
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
