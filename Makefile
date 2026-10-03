# ash-log Makefile
# Common development and publishing tasks for the ash-log crate.

# CI pins `dtolnay/rust-toolchain@stable`, and clippy's lint set differs between
# stable and nightly. Running the gates on whatever `cargo` happens to resolve
# to lets local checks pass while CI fails, which is exactly what happened once.
# Override with `make CARGO="cargo +nightly" lint` when that is what you want.
CARGO ?= cargo +stable

.PHONY: help build test doc lint fmt fmt-check clean publish publish-dry \
	coverage coverage-html coverage-check bench bench-quick fuzz fuzz-one fuzz-list

# Default target
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the crate (debug)
	$(CARGO) build

build-release: ## Build the crate (release)
	$(CARGO) build --release

test: ## Run all tests (all features)
	$(CARGO) test --all-features

test-verbose: ## Run all tests with output
	$(CARGO) test --all-features -- --nocapture

test-matrix: ## Test each feature combination, as CI does
	$(CARGO) test
	$(CARGO) test --features hmac-chain
	$(CARGO) test --features hlc
	$(CARGO) test --features ocsf
	$(CARGO) test --features tracing
	$(CARGO) test --all-features

# Build-time code generation is excluded: `codegen_shared.rs` and the
# `ocsf_codegen` binary run during development, not in anything shipped, and
# counting them understates coverage of the library by ~7 points.
COVERAGE_EXCLUDE = '(codegen_shared|bin/ocsf_codegen)'

coverage: ## Report line coverage for shipped library code
	cargo llvm-cov --all-features --summary-only \
		--ignore-filename-regex $(COVERAGE_EXCLUDE)

coverage-html: ## Write an annotated HTML coverage report and open it
	cargo llvm-cov --all-features --open \
		--ignore-filename-regex $(COVERAGE_EXCLUDE)

coverage-check: ## Fail if coverage drops below the recorded floor
	cargo llvm-cov --all-features --summary-only \
		--ignore-filename-regex $(COVERAGE_EXCLUDE) \
		--fail-under-lines 95

bench: ## Run benchmarks
	$(CARGO) bench --features hmac-chain

bench-quick: ## Run benchmarks with reduced sampling, for a fast signal
	$(CARGO) bench --features hmac-chain -- --quick

# Fuzzing needs a nightly toolchain for libFuzzer. Each target runs for
# FUZZ_TIME seconds; override it for a longer soak.
FUZZ_TIME ?= 60
FUZZ_TARGETS = verify_chain event_roundtrip filter_directives severity_parse redaction

fuzz: ## Fuzz every target for FUZZ_TIME seconds each (default 60)
	@for t in $(FUZZ_TARGETS); do \
		echo "=== fuzzing $$t for $(FUZZ_TIME)s ==="; \
		cargo +nightly fuzz run $$t -- -max_total_time=$(FUZZ_TIME) || exit 1; \
	done
	@echo "All fuzz targets clean."

fuzz-one: ## Fuzz a single target: make fuzz-one TARGET=verify_chain
	cargo +nightly fuzz run $(TARGET) -- -max_total_time=$(FUZZ_TIME)

fuzz-list: ## List available fuzz targets
	@cargo +nightly fuzz list

doc: ## Build documentation and open in browser
	$(CARGO) doc --no-deps --all-features --open

doc-build: ## Build documentation without opening
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --all-features

lint: ## Run Clippy linter
	$(CARGO) clippy --all-features --all-targets -- -D warnings

fmt: ## Format source code
	$(CARGO) fmt --all

fmt-check: ## Check formatting without applying changes
	$(CARGO) fmt --all -- --check

check: ## Run cargo check
	$(CARGO) check --all-features

clean: ## Remove build artifacts
	cargo clean

# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------

publish-dry: ## Dry-run publish to crates.io (checks metadata & packaging)
	$(CARGO) publish --dry-run

publish: ## Publish the crate to crates.io
	@echo "Publishing ash-log to crates.io..."
	cargo publish

# ---------------------------------------------------------------------------
# Quality gates (run all checks before publishing)
# ---------------------------------------------------------------------------

ci: fmt-check lint test-matrix doc-build ## Run all CI checks (format, lint, tests, docs)
	@echo "All checks passed."
