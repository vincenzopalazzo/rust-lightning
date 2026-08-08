# PoC — Finding #1: release-mode panic (crash loop) in `blocks_disconnected` reorg resurrection

Reproducer for **finding #1** of the security audit
(`security-audit/findings/lightning/src/chain/onchaintx.rs.md`, FINDING-1, Severity: High):

> A reorg that resurrects an HTLC timeout claim previously split out of a mixed-CLTV
> aggregated package hits
> `assert!(request.merge_package(package, new_best_height + 1).is_ok())`
> at `lightning/src/chain/onchaintx.rs:1183` and **panics in all build profiles**.
> Because the panic fires before state is persisted, the same disconnection is
> re-delivered on restart → **crash loop** while time-sensitive HTLC claims are outstanding.

## Contents

| File | Purpose |
|------|---------|
| `run.sh` | Executable runner. Injects the PoC test temporarily, runs it, restores the source file. |
| `onchaintx_poc_test.rs` | The PoC test payload (injected into `mod tests` of `onchaintx.rs`). |
| `last_run.log` | Output of the most recent run (created by `run.sh`). |

## Usage

```bash
./run.sh              # debug build
./run.sh --release    # release build — the panic is NOT debug-only
```

Requires a Rust toolchain (`cargo`); if not on `PATH`, `~/.cargo/bin` is tried.
Expected result:

```
thread '…test_blocks_disconnected_mixed_cltv_resurrection_panic' panicked at lightning/src/chain/onchaintx.rs:1183:33:
assertion failed: request.merge_package(package, new_best_height + 1).is_ok()
test chain::onchaintx::tests::test_blocks_disconnected_mixed_cltv_resurrection_panic ... ok
[poc] SUCCESS: vulnerability reproduced.
```

The test **expects** the panic, so `test result: ok` means the exploit chain executed
deterministically — twice (see "crash loop" below).

## Why the injection approach?

`OnchainTxHandler`, `PackageTemplate`, and `CounterpartyReceivedHTLCOutput::build` are
`pub(crate)`/`pub(super)` — no external crate can reach them, so the PoC cannot be a normal
dependent crate. `run.sh` instead copies `lightning/src/chain/onchaintx.rs` to a backup,
inserts the payload just before the final closing brace of its `mod tests`, runs
`cargo test`, and **restores the original file byte-for-byte on exit** (via `trap`,
including on failure or Ctrl-C; a stale backup from an interrupted run is self-healed on
the next invocation). After a run, `git status` shows no modification to the codebase.

## Attack chain executed by the PoC

Attacker model: a channel counterparty who routes HTLCs to themselves through the victim
(controls the CLTV expiries, owns the preimages), plus a ≥2-block reorg with the fork in an
attacker-influenced window (deterministic with miner collaboration; opportunistic with a
natural reorg — trivially wide against an offline victim).

Concrete heights used: `cltv1 = 100`, `cltv2 = 110`, commitment confirmed at `C = 110`,
fork at `F = 105` ∈ `[cltv1, cltv2 − 2]`.

1. **Merge** — commitment confirms at height 110 (≥ cltv2) with two HTLCs (CLTV 100/110);
   both timeout claims have `package_locktime(110) = 110`, so they aggregate into one
   pending claim request (`update_claims_view_from_requests`).
2. **Split** — the attacker's preimage tx spends only HTLC-1's outpoint at height 110;
   LDK splits {htlc1} off the request and parks it as a `ContentiousOutpoint` event
   awaiting `ANTI_REORG_DELAY` (`update_claims_view_from_matched_txn`).
3. **Reorg** — `blocks_disconnected(105)` resurrects the split package and asserts an
   infallible re-merge. But `package_locktime` is height-relative
   (`max(cur_height, cltv)`): the surviving request {htlc2} evaluates to `max(106, 110) = 110`
   while the resurrected {htlc1} evaluates to `max(106, 100) = 106` → `can_merge_with`
   returns false → `merge_package` returns `Err` → the `assert!` fires.
4. **Crash loop** — the whole scenario runs a second time on a freshly constructed
   handler, modeling a node that restarted from pre-reorg persisted state (the panic fires
   before persistence) and received the same disconnection again. The test asserts the two
   panics are byte-identical.

## Impact if triggered in production

- Deterministic crash of the embedding node process in **release** builds (plain `assert!`).
- Persistent crash loop on restart (no state persisted before the panic).
- While down: the surviving {htlc2} timeout claim cannot be broadcast/fee-bumped, and no
  other channel's claims are processed → in-flight HTLC value exposed to timeout/preimage
  races and missed justice windows (indirect fund-loss exposure).

## Fix pointers

- Replace the `assert!` at `onchaintx.rs:1183` with graceful handling mirroring
  `onchaintx.rs:837-840`: on `Err(rejected)`, re-insert the package into
  `locktimed_packages` at its `package_locktime(0)` (or drop it if its creation height
  exceeds `new_best_height`), and skip adding it to `bump_candidates`.
- Move the stale-claim cleanup (`onchaintx.rs:1230-1238`) **before** the resurrection loop
  so resurrection never merges into requests whose funding outpoints were disconnected.
- The same fix covers finding #14 (same assert via the pinnability reclassification path).
- After fixing, convert the payload into a regression test asserting the rejected package
  is re-locked instead of panicking.
