.PHONY: all fmt lint check doc test

# Run all checks
all: fmt lint check doc

# Format code
fmt:
	cargo +1.63.0 fmt

# Run clippy linting
lint:
	cargo clippy -- -A clippy::erasing_op -A clippy::never_loop -A clippy::if_same_then_else

# Check compilation
check:
	cargo check
	cd fuzz && RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz" cargo check --features=stdin_fuzz
	cd ../lightning && cargo check --no-default-features
	cd .. && RUSTC_BOOTSTRAP=1 RUSTFLAGS="--cfg=c_bindings" cargo check -Z avoid-dev-deps

# Build documentation
doc:
	cargo doc
	cargo doc --document-private-items

# Run tests (optional, for completeness)
test:
	cargo test