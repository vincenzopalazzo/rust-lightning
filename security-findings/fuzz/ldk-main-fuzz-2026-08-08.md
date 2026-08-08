# LDK (rust-lightning) findings recheck + fuzz on recent main

**Date:** 2026-08-08  
**Tree:** `/Users/vincenzopalazzo/github/work/btc/rust-lightning-main-sync`  
**Upstream HEAD:** `384e0d61305b24f5c6cdebe59c2c8f89b015d7b0`  
(`Merge PR 'Fix unused warning on do_test_splice_revalidation_at_quiescence' (#4863)`)  
**Remote:** `lightningdevkit/rust-lightning` `main`  
**Engine:** libFuzzer via `cargo +nightly fuzz` (`fuzz-fake-hashes`, `-D` dev profile)  
**Host:** macOS aarch64  

## 1. Existing BSC findings inventory (`found/rust-lightning`)

### High / Critical

| Finding | Severity | Status on `384e0d613` |
|---------|----------|------------------------|
| `2026-08-05-…-onchaintx-reorg-merge-assert-panic` — `assert!(merge_package(…).is_ok())` in `OnchainTxHandler::blocks_disconnected` with mixed-CLTV aggregate | **High** (node crash / crash-loop on reorg) | **FIXED in practice** |

Evidence:

- Upstream regression test present and **PASSING**:
  - `ln::reorg_tests::test_reorg_resurrect_split_htlc_package_with_future_locktime`
  - Command: `cargo test -p lightning --features _test_utils --lib -- ln::reorg_tests::test_reorg_resurrect_split_htlc_package_with_future_locktime`
  - Result: `ok` in 0.03s (full crate build ~1m20s cold).
- Current code path (`lightning/src/chain/onchaintx.rs:1181–1191`):
  - Still contains `assert!(request.merge_package(package, new_best_height + 1).is_ok())`
  - But only after `request.can_merge_with(&package, new_best_height + 1)`
  - When not mergeable, falls through to `locktimed_packages` (no assert, package preserved)
- Test documents the original failure mode (split HTLC after partial preimage claim + deep reorg) and asserts independent claim broadcast after reconnect.

**Call:** Do **not** re-file. Optionally note in the finding that the hard assert remains as a belt-and-suspenders check behind `can_merge_with`; the crash path is covered by upstream test. Consider a follow-up hygiene PR only if maintainers want `debug_assert!` + explicit `Err` handling instead of `assert!` in release.

### Low / Medium (still open on HEAD — spot check)

| Finding | Sev | HEAD note |
|---------|-----|-----------|
| PrintableString U+2028/U+2029 | Med/Low | Duplicate entries in store; still a string-filter class issue if unfixed |
| LSPS5 `LSPSUrl::parse` only requires `https` (no loopback/private block) | Medium | **Still open** — `lightning-liquidity/src/lsps5/url_utils.rs` accepts any `https` URL |
| LSPS5 webhook validator weak replay window | Medium | **Still open** — `MAX_RECENT_SIGNATURES = 5` in-memory deque; **no timestamp freshness check in `validate()`** despite service docs mentioning ±10 min |
| LSPS5 webhook arbitrarily old timestamps | Medium | **Still open** — validator verifies LN sig + replay cache only (`validator.rs`); no max-age on `timestamp` |
| OffersMessage `read_to_limit(..., u64::MAX)` | Medium | **Still open** — `lightning/src/onion_message/offers.rs:188` |
| Counterparty `tx_signatures` never verified before broadcast | Low | Not re-audited this pass |
| CI codecov floating binary | Low | Process/CI, not runtime LN |
| ExpandedKey Debug / preimage trace logs / no zeroize / rust-bitcoin 0.32 track | Info | Hygiene |

`found/ldk-node` only has a `low-medium` bucket (not expanded this pass).

## 2. Sync to recent main

Previous local tip (`origin` fork) was **313 commits behind** upstream `main`.

```text
before: 2ad0fc75e  (fork main)
after:  384e0d613  (upstream/main)  ← fuzz + recheck baseline
```

## 3. Fuzz campaign (recent main)

### Setup

```bash
cd fuzz
export RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz"
cargo +nightly fuzz run --fuzz-dir fuzz-fake-hashes --features libfuzzer_fuzz -D <target> -- \
  -max_total_time=<secs> -rss_limit_mb=2048|3072 -timeout=10|15
```

- `cargo-fuzz 0.13.2` installed; nightly + `rust-src`.
- `write-seeds` currently **fails to compile** on this tip (`DecodedOnionErrorPacket` private / related privacy errors in msg targets). Did **not** block libFuzzer runs (targets build via `lightning-fuzz` lib path used by cargo-fuzz).
- Artifacts dir: empty after both passes (no crash-/leak-/timeout- files).

### Pass 1 — 10 targets × ~120s

| Target | Execs | exec/s | cov → ft | corp | Result |
|--------|------:|-------:|----------|------|--------|
| `msg_ping_target` | 1.46M | ~12k | 99 / 131 | 8 | OK |
| `peer_crypt_target` | 1.28M | ~10.5k | 465 / 791 | 27 | OK |
| `onion_message_target` | 1.20M | ~10k | 704 / 761 | 27 | OK |
| `process_network_graph_target` | 83k | ~688 | 231 / 233 | 2 | OK (thin corpus growth) |
| `msg_update_add_htlc_target` | 1.45M | ~12k | 137 / 139 | 16 | OK |
| `msg_commitment_signed_target` | 1.38M | ~11.4k | 402 / 768 | 92 | OK |
| `chanmon_deser_target` | 1.40M | ~11.6k | 834 / 1352 | 167 | OK |
| `offer_deser_target` | 1.41M | ~11.7k | 1767 / 2934 | 297 | OK |
| `lsps_message_target` | 89k | ~735 | 2329 / 2983 | 348 | OK |
| `full_stack_target` | 1.46M | ~12k | 385 / 484 | 92 | OK |

**Crashes: 0**

### Pass 2 — richest surfaces × ~300s

| Target | Execs | exec/s | cov / ft | corp | Result |
|--------|------:|-------:|----------|------|--------|
| `offer_deser_target` | 3.30M | ~11.0k | 1861 / 3247 | 328 | OK |
| `chanmon_deser_target` | 3.38M | ~11.2k | 858 / 1426 | 162 | OK |
| `lsps_message_target` | 204k | ~679 | 2575 / 4486 | 625 | OK |
| `msg_commitment_signed_target` | 3.52M | ~11.7k | 402 / 805 | 81 | OK |
| `full_stack_target` | 3.69M | ~12.2k | 470 / 621 | 121 | OK |
| `onion_message_target` | 3.23M | ~10.7k | 2070 / 2780 | 135 | OK |

**Crashes: 0**  
Logs: `/tmp/ldk-fuzz-runs/logs/` (`summary.log`, `summary2.log`, per-target logs).

Rough total: **~24M+ execs** across high-value surfaces on `384e0d613`, no new panic/ASan findings in this window.

## 4. Interpretation

1. **High-crit reorg merge assert:** treated as **upstream-fixed** for filing purposes; regression test is the source of truth. The remaining `assert!` is only on the `can_merge_with == true` path.
2. **Fuzz:** no new memory-safety / panic signal in the time-boxed libFuzzer pass. This is a **smoke + coverage** pass, not a substitute for multi-hour honggfuzz/ClusterFuzz or Nyx/smite campaigns.
3. **Still-worth-tracking Mediums on HEAD:**
   - LSPS5 URL SSRF footgun (https-only)
   - LSPS5 webhook **no timestamp max-age** in client validator (docs promise ±10 min; code does not enforce)
   - LSPS5 replay cache size 5 / process-local
   - OffersMessage unbounded `read_to_limit(..., u64::MAX)`
4. **Tooling debt:** `fuzz/write-seeds` + some msg_target privacy breakage on current main — fix or skip before CI-style `ci-fuzz.sh` locally.

## 5. Recommended next steps

1. **Do not refile** the onchaintx reorg High; annotate BSC finding as fixed-by-upstream + test name + HEAD SHA.
2. **Prioritize static validation / small PoCs** for LSPS5 validator freshness (easy unit test: old timestamp + valid sig should fail once max-age is specified) and OffersMessage read bound.
3. **Extend fuzz:**
   - Multi-hour runs on `offer_deser`, `chanmon_deser`, `lsps_message`, `full_stack`, `onion_message`
   - Add `chanmon_consistency_target` under `fuzz-real-hashes` (only real-hash target)
   - Seed `process_network_graph` (corpus stayed at 2 inputs — needs write-seeds or manual corpus)
4. **Optional smite path:** once checkout + smite local-mode are wired, run LDK noise/init scenarios against this same SHA and feed crashes through `smite-harness`.
5. Fix or pin around `write-seeds` compile errors before relying on full_stack corpus bootstrap.

## 6. Commands cheat-sheet

```bash
# Sync
cd /Users/vincenzopalazzo/github/work/btc/rust-lightning-main-sync
git fetch upstream main && git checkout -B main upstream/main

# High-crit regression
cargo test -p lightning --features _test_utils --lib -- \
  ln::reorg_tests::test_reorg_resurrect_split_htlc_package_with_future_locktime -- --nocapture

# Fuzz one target ~5 min
cd fuzz
RUSTFLAGS="--cfg=fuzzing --cfg=secp256k1_fuzz --cfg=hashes_fuzz" \
  cargo +nightly fuzz run --fuzz-dir fuzz-fake-hashes --features libfuzzer_fuzz -D offer_deser_target -- \
  -max_total_time=300 -rss_limit_mb=3072
```

## 7. Bottom line

| Question | Answer |
|----------|--------|
| Did we check existing LDK fuzz/finding results? | Yes — 1 High + ~14 low/med/info in BSC store |
| Is the High still live on recent main? | **No** — regression test green; safe merge path + fallback |
| Did we fuzz recent main? | **Yes** — `384e0d613`, ~24M execs, **0 crashes** |
| Anything new to file from this fuzz window? | **No** |
| What still looks real on HEAD? | LSPS5 URL/replay/timestamp Mediums; OffersMessage unbounded read |
