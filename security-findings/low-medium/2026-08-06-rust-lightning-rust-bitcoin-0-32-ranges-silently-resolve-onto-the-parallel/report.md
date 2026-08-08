# rust-bitcoin ^0.32 ranges silently resolve onto the parallel '0.32.10x' release track (resolved 0.32.102 > 0.32.11), risking missed security backports on crypto-critical signing/amount paths

- Project: rust-lightning
- Commit/version: (see source finding record)
- Category: dependency
- Severity: Info
- Reproduction: static — see source finding for evidence
- Confirmed: code-review
- Attacker model: Bluetooth/BLE attacker in radio range
- Default config affected: unknown
- Reported upstream: no

## Summary

rust-bitcoin maintains two parallel 0.32 release lines: the classic 0.32.x line (latest 0.32.11, 2026-07-22) which upstream says is reserved for security backports, and the 0.32.10x line (latest 0.32.102, 2026-07-15) which carries an MSRV bump and new consensus_encoding features. Because cargo caret resolution selects the numerically greatest semver-compatible version, every LDK manifest asking for "0.32.x" silently lands on the 10x track — a different maintenance branch than the one designated for security releases. The same pattern applies to bitcoin_hashes 0.14.101 (Cargo.lock:209-ish, newe...

## Exploit chain

1. Entry point at `lightning/Cargo.toml:42`
2. rust-bitcoin maintains two parallel 0.32 release lines: the classic 0.32.x line (latest 0.32.11, 2026-07-22) which upstream says is reserved for security backports, and the 0.32.10x line (latest 0.32.102, 2026-07-15) which carries an MSRV bump and new consensus_encoding features. Because cargo caret

## Root cause

The manifest uses Cargo's default caret requirement for bitcoin version "0.32.4", which permits any >=0.32.4 and <0.33.0, so a numerically higher 0.32.10x release will be selected over 0.32.11. However, this is dependency-resolution drift rather than a present vulnerability: no vulnerable rust-bitcoin version or missing security fix is identified, and exploitation depends on a future security backport being published only to the lower-numbered track. The PoC supports the resolution behavior but...

## Impact

Not directly exploitable. Scenario of concern: a future secp256k1/bitcoin consensus or sighash bug is patched as bitcoin 0.32.12 only; LDK-derived wallets float on 0.32.102 and never see the fix, while cargo-audit may not flag it either if the advisory's affected-range metadata lists '< 0.32.12' semantics that 0.32.102 technically satisfies or misses.

## Source

- Harness: redteam
- Finding ID: DEP-002
- Repo: lightningdevkit/rust-lightning
- File: lightning/Cargo.toml:42
- Confidence: high
