#!/usr/bin/env bash
# PoC runner for rust-lightning security-audit finding #1:
#   "Release-mode panic (crash loop) in blocks_disconnected reorg resurrection
#    of mixed-CLTV HTLC timeout packages" (lightning/src/chain/onchaintx.rs:1183)
#
# The vulnerable APIs (OnchainTxHandler, PackageTemplate, ...) are
# pub(crate)/pub(super), so no external crate can reach them. This script
# therefore TEMPORARILY injects the PoC test (poc/onchaintx_poc_test.rs) into
# `mod tests` of lightning/src/chain/onchaintx.rs, runs it with cargo, and
# restores the original file byte-for-byte afterwards (guaranteed via trap,
# even on failure/Ctrl-C). The repository is left untouched.
#
# Usage:
#   ./run.sh              # debug build
#   ./run.sh --release    # release build (the panic is NOT debug-only)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="$REPO_ROOT/lightning/src/chain/onchaintx.rs"
PAYLOAD="$SCRIPT_DIR/onchaintx_poc_test.rs"
BACKUP="$TARGET.poc-backup"
LOG="$SCRIPT_DIR/last_run.log"
TEST_NAME="chain::onchaintx::tests::test_blocks_disconnected_mixed_cltv_resurrection_panic"
PANIC_MSG="assertion failed: request.merge_package(package, new_best_height + 1).is_ok()"

CARGO_ARGS=()
if [ "${1:-}" = "--release" ]; then
	CARGO_ARGS+=(--release)
fi

# Locate cargo (install Rust via https://rustup.rs if missing).
if ! command -v cargo >/dev/null 2>&1; then
	if [ -x "$HOME/.cargo/bin/cargo" ]; then
		export PATH="$HOME/.cargo/bin:$PATH"
	else
		echo "[poc] error: cargo not found; install Rust first (https://rustup.rs)" >&2
		exit 1
	fi
fi

# Self-heal: restore a backup left behind by an interrupted previous run.
if [ -f "$BACKUP" ]; then
	cp "$BACKUP" "$TARGET"
	rm -f "$BACKUP"
fi

restore() {
	if [ -f "$BACKUP" ]; then
		cp "$BACKUP" "$TARGET"
		rm -f "$BACKUP"
		echo "[poc] restored original lightning/src/chain/onchaintx.rs"
	fi
}
trap restore EXIT

cp "$TARGET" "$BACKUP"

# Insert the PoC test just before the final closing brace of `mod tests`
# (the last line of onchaintx.rs).
{
	head -n -1 "$TARGET"
	cat "$PAYLOAD"
	printf '}\n'
} > "$TARGET.poc-tmp"
mv "$TARGET.poc-tmp" "$TARGET"

echo "[poc] injected PoC test (temporary; restored on exit)"
echo "[poc] running: cargo test -p lightning ${CARGO_ARGS[*]:-} $TEST_NAME"
set +e
(cd "$REPO_ROOT" && cargo test -p lightning "${CARGO_ARGS[@]}" "$TEST_NAME" -- --nocapture) 2>&1 | tee "$LOG"
STATUS=${PIPESTATUS[0]}
set -e
echo

if grep -qF "$PANIC_MSG" "$LOG" && grep -q "test result: ok" "$LOG"; then
	echo "[poc] SUCCESS: vulnerability reproduced."
	echo "[poc]   - panicked at lightning/src/chain/onchaintx.rs:1183 on reorg resurrection"
	echo "[poc]   - identical panic on scenario replay => restart crash loop confirmed"
	echo "[poc]   ('test result: ok' because the PoC test EXPECTS the panic)"
	exit 0
else
	echo "[poc] UNEXPECTED RESULT (cargo exit $STATUS) — inspect $LOG" >&2
	exit 1
fi
