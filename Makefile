.PHONY: install test lint fix bump-version clean

# Build the crate and its dev dependencies
install:
	cargo build --all-features

# Run the test suite (wiremock integration tests; Redis-backed tests run
# against localhost:6379 and are included with --include-ignored)
test:
	cargo test

# Lint: format check + clippy with warnings denied (mirrors CI)
lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

# Auto-fix formatting and clippy suggestions where possible
fix:
	cargo fmt --all
	cargo clippy --all-targets --all-features --fix --allow-dirty

# Bump the crate version and scaffold the changelog:
#   make bump-version VERSION=3.0.3
bump-version:
ifndef VERSION
	$(error VERSION is required. Usage: make bump-version VERSION=x.y.z)
endif
	python3 .github/scripts/bump_version.py $(VERSION)

# Clean build artifacts
clean:
	cargo clean
