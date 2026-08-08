# Panic in `blocks_disconnected` reorg resurrection: `assert!(merge_package(...).is_ok())` reachable with mixed-CLTV aggregated timeout claims

- Project: rust-lightning
- Commit/version: unknown (scanned 2026-08-04; the fallible `merge_package` was introduced in commit `bbf1d93ef`)
- Category: vulnerability / dos
- Severity: High — deterministic release-mode panic (node crash) during reorg processing; recurs on restart (crash loop) while time-sensitive HTLC claims are outstanding. Not Critical: triggering needs a controllable-but-narrow chain setup plus a ≥2-block reorg in an attacker-influenced window.
- Reproduction: static — code trace only (triage risk score 54)
- Confirmed: code-review
- Attacker model: channel counterparty (routes HTLCs to itself through the victim to control CLTV expiries and owns the preimages) + miner assistance or a lucky natural reorg; victim is stock rust-lightning
- Default config affected: yes
- Reported upstream: no

Component: `lightning/src/chain/onchaintx.rs`.

## Summary

`OnchainTxHandler::blocks_disconnected` assumes a package split out of an
aggregated claim request can always be merged back, and enforces it with
`assert!(request.merge_package(package, new_best_height + 1).is_ok())`
(onchaintx.rs:1183). `can_merge_with`'s locktime-compatibility check is
height-dependent (`max(cur_height, cltv)`), so two counterparty-HTLC timeout
packages with different CLTVs merge at a high confirmation height but fail to
re-merge at the lower resurrection height. A channel counterparty who controls
the CLTV expiries, combined with a ≥2-block reorg in the right window, turns
this into a deterministic release-build panic that recurs on restart — a crash
loop while time-sensitive HTLC claims are outstanding (availability loss with
indirect fund-loss exposure).

## Attacker model

Channel counterparty (routes HTLCs to itself through the victim to control
CLTV expiries and owns the preimages) + miner assistance or a lucky natural
reorg; easiest against an offline/async victim (no early holder force-close),
but also possible against an online victim with a small CLTV gap
(`cltv2 = cltv1 + 2`).

## Exploit chain

1. Victim and attacker share a channel on whose counterparty (attacker) commitment sit ≥2 outbound HTLCs ("received" by the counterparty) with different CLTV expiries `cltv1 < cltv2`. On commitment confirmation the monitor builds `PackageSolvingData::CounterpartyReceivedHTLCOutput` claims for each (lightning/src/chain/channelmonitor.rs:5080-5095), whose `minimum_locktime()` is `cltv_expiry` (lightning/src/chain/package.rs:1009-1014) and whose `signed_locktime()` is `None` (package.rs:1017-1027).
2. Attacker gets their commitment confirmed at height C ≥ `cltv2` (both HTLCs expired; for an online victim this requires `cltv2 ≤ cltv1+3`, since the victim force-closes at `cltv_expiry + LATENCY_GRACE_PERIOD_BLOCKS` = `cltv1+3`, channelmonitor.rs:297,6175). In `update_claims_view_from_requests` both packages have `package_locktime(C) = max(C, cltv) = C`, so `can_merge_with` accepts (package.rs:1224-1227, 1347-1356) and they are aggregated into one pending claim request X = {htlc1(cltv1), htlc2(cltv2)} (lightning/src/chain/onchaintx.rs:833-845).
3. Attacker claims htlc1 with the preimage (HTLC-success, valid at any height), confirmed at height S ≥ C. `update_claims_view_from_matched_txn` sees the tx spend a proper subset of X's outpoints, splits htlc1 off (request becomes {htlc2}) and registers `OnchainEvent::ContentiousOutpoint { package: {htlc1} }` at height S (onchaintx.rs:966-1022, 1040-1049).
4. A reorg is processed (via `Listen::blocks_disconnected`, chainmonitor.rs:1476) with fork height F ∈ [`cltv1`, `cltv2`−2], before the event matures (within `ANTI_REORG_DELAY − 1` = 5 blocks of S; channelmonitor.rs:309). Note C ≥ `cltv2` > F, so the commitment itself is also disconnected — but the resurrection logic runs *before* the stale-claim cleanup (onchaintx.rs:1168-1195 vs 1230-1238).
5. In `OnchainTxHandler::blocks_disconnected`, the ContentiousOutpoint package has `package_locktime(0) = cltv1 ≤ F`, so it is not re-locked; `claimable_outpoints[htlc1]` still maps to X, and `pending_claim_requests.get_mut(X)` yields {htlc2}. The code executes `assert!(request.merge_package(package, new_best_height + 1).is_ok())` (onchaintx.rs:1183).
6. `merge_package` → `can_merge_with(&{htlc1}, F+1)`: `package_locktime(F+1)` for the remaining request {htlc2} = `max(F+1, cltv2) = cltv2` (since F+1 ≤ cltv2−1), but for the resurrected package {htlc1} = `max(F+1, cltv1) = F+1` (since F ≥ cltv1). `cltv2 ≠ F+1` → `can_merge_with` returns false (package.rs:1225) → `merge_package` returns `Err` → **the `assert!` panics**.

## Root cause

`can_merge_with`'s locktime-compatibility check is height-dependent (`max(cur_height, cltv)`), but `blocks_disconnected` assumes a package split out of a request can always be merged back at any height. Two packages with different CLTVs merge when `cur_height` ≥ both CLTVs (both locktimes saturate to `cur_height`), then fail to re-merge at the lower resurrection height where the locktimes diverge again. The fallible `merge_package` (introduced in commit `bbf1d93ef`) is handled gracefully at its other call site (onchaintx.rs:837-840, re-inserts the rejected package) but asserted infallible at onchaintx.rs:1183.

## Why defenses fail

The only guard is `package_locktime(0) > new_best_height` re-locking (onchaintx.rs:1175-1179), which keeps the package timelocked only when F < `cltv1` — the exact opposite branch. The end-of-function cleanup that would drop claims whose outpoints were reorged out (onchaintx.rs:1230-1238, creation height C > F) is never reached because the assert fires first. `update_claims_view_from_requests`' dedup and `cancel_prev_commitment_claims`/`abandon_claim` do not run in this path. `transaction_unconfirmed` cannot trigger it (it steps back only to S−1 ≥ `cltv2`−1, where the merge still succeeds, onchaintx.rs:1153-1157); only a real ≥2-block `blocks_disconnected` fork lands in the panic window.

## Impact

Deterministic panic in release builds during reorg handling inside `ChainMonitor::blocks_disconnected`, before `best_block` is updated (channelmonitor.rs:6021) and before monitor persistence; on restart the block source re-delivers the same reorg and the node crashes again (crash loop). While down, the node cannot fee-bump or broadcast the surviving {htlc2} timeout claim nor any other channel's claims, exposing in-flight HTLC value to timeout/preimage races. With a miner counterparty the setup is fully deterministic; without a miner it requires a natural ≥2-block reorg inside a (potentially ~2000-block-wide for offline victims) window within 5 blocks of the success confirmation.

## Suggested fix

Replace the `assert!` at onchaintx.rs:1183 with graceful handling mirroring onchaintx.rs:837-840 — on `Err(rejected)`, re-insert the package into `locktimed_packages` at its `package_locktime(0)` (or drop it if its creation height exceeds `new_best_height`), and skip adding to `bump_candidates`. Additionally, consider moving the stale-claim cleanup (creation height > new best) before the resurrection loop so resurrection never merges into requests whose funding outpoints were disconnected.

## Confidence

High (static trace verified end-to-end: merge condition at package.rs:1224-1227, split at onchaintx.rs:996-1006, resurrection assert at onchaintx.rs:1183; no intermediate defense found). No dynamic reproduction yet.

## Suspicions (secondary, lower confidence)

- Uncapped exponential ForceBump for self-funded malleable claims: `feerate_bump`'s `ForceBump` arm bumps `previous_feerate * 1.25` with no cap relative to the fee estimate (package.rs:1722-1729), bounded only by the dust check (package.rs:1755-1758). The external-funding path (`compute_package_feerate`, package.rs:1556-1563) explicitly caps the same 25% bump at 5× the estimate. With timer = `HIGH_FREQUENCY_BUMP_INTERVAL` (1 block, package.rs:1502-1503 / pinnable within 12 blocks) and a stale-low estimator, a mempool-pinned claim (e.g., counterparty's competing preimage claim) doubles its fee every ~3 blocks, burning up to nearly the full claim value in fees over ~30 blocks. Likely a deliberate design trade-off, but the asymmetry with the capped path suggests it may be unintended.
- `fee_sat = input_amount_sats - tx.output.sum()` subtraction (onchaintx.rs:700): if a legacy (pre-0.2) deserialized `HolderFundingOutput` lacks `funding_amount_sats`, the fallback is the deprecated `channel_value_satoshis` (onchaintx.rs:693-698), which can be 0/stale for upgraded monitors, giving a u64 underflow panic (debug) or a huge `commitment_tx_fee_satoshis` in a `BumpCommitment` event (release). Legacy-upgrade edge only.
- `locktimed_packages` are never purged in `OnchainTxHandler::blocks_disconnected` (onchaintx.rs:1161-1239) when the commitment tx creating their outpoints is reorged out; they are only cleaned if a *different* commitment later confirms (`cancel_prev_commitment_claims` → `abandon_claim`, channelmonitor.rs:5314, onchaintx.rs:770-778) or become valid again if the same commitment re-confirms. If the funding output is never re-spent, the stale locktimed package eventually fires, broadcasting a transaction spending a nonexistent outpoint and leaving a permanent `pending_claim_requests` entry that is re-bumped/rebroadcast forever (resource leak; `has_pending_claims` stuck true).
- `get_htlc_descriptor` `.find(...).unwrap()` on `nondust_htlcs` (package.rs:514-517): reachable only for pre-0.2 deserialized `HolderHTLCOutput`s without a stored descriptor; panics if the outpoint's vout isn't found in the current/prev holder commitment. Legacy edge.
- `transaction_unconfirmed` computes `height - 1` (onchaintx.rs:1155); a `OnchainEventEntry` with height 0 would underflow. Not reachable for real channel transactions (cannot confirm in genesis).

## Coverage note

Traced `update_claims_view_from_requests` (dedup, merge, locktimed split), `update_claims_view_from_matched_txn` (subset check, split/ContentiousOutpoint, maturation ordering), `generate_claim` (all package types, external-funding events), `rebroadcast_pending_claims`, `blocks_disconnected`/`transaction_unconfirmed` (resurrection + cleanup), plus package.rs fee/locktime/merge helpers and channelmonitor.rs claim generation/cancellation. Verified defenses: claim/event maturation ordering is consistent (ContentiousOutpoint always matures before a Claim of the same request), mixed-creation-height packages cannot form in one call, `cancel_prev_commitment_claims` covers commitment replacement, dropped `Claim` events on reorg resume via pending request timers, and `BumpTransactionEvent` loss on restart is bounded by timer-based regeneration (pending_claim_events intentionally not serialized). Assert/unwrap sites audited; only onchaintx.rs:1183 found attacker-reachable.
