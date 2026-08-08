# cargo-audit clean; summary of remaining triage — dev-only atty warnings, duplicate crate versions, and C-compiling build scripts (secp256k1-sys on signing path, aws-lc-sys/ring on TLS path)

- Project: rust-lightning
- Commit/version: (see source finding record)
- Category: dependency
- Severity: Info
- Reproduction: static — see source finding for evidence
- Confirmed: code-review
- Attacker model: See the finding record.
- Default config affected: unknown
- Reported upstream: no

## Summary

Summary finding for the remaining dependency triage, per audit method (at most one summary info finding). (1) cargo-audit against the generated lockfile (RustSec advisory-db fetched 2026-08-05, 1189 advisories) reports 0 vulnerabilities and exactly 2 allowed warnings, both on dev-only atty 0.2.14 via criterion — no action needed. (2) Duplicate versions in the graph: hashbrown 0.12.3+0.13.2, getrandom 0.2.17+0.4.3, syn 2.0.119+3.0.3 (proc-macro only), electrum-client 0.24.1+0.25.0, windows-sys 0.48/0.52/0.61 — all duplicates are confined to dev/build-time edges; the crypto-relevant crates (secp...

## Exploit chain

1. Entry point at `Cargo.lock:48`
2. Summary finding for the remaining dependency triage, per audit method (at most one summary info finding). (1) cargo-audit against the generated lockfile (RustSec advisory-db fetched 2026-08-05, 1189 advisories) reports 0 vulnerabilities and exactly 2 allowed warnings, both on dev-only atty 0.2.14 vi

## Root cause

The finding does not describe an exploitable code bug; it is an informational dependency-triage summary stating cargo-audit is clean and residual issues are dev/build-time or inherent supply-chain trust concerns. Dev-only atty warnings and duplicate build/dev dependencies do not create a runtime attack path, and vendored C build scripts are a normal dependency trust boundary rather than a demonstrated vulnerability.

## Impact

None — summary/tracking finding only. The residual risk concentration is the crates.io publishing credentials of secp256k1-sys, bitcoin, chacha20-poly1305 and dnssec-prover maintainers (a poisoned release there lands on signing paths), which is inherent to any non-vendored dependency model.

## Source

- Harness: redteam
- Finding ID: DEP-003
- Repo: lightningdevkit/rust-lightning
- File: Cargo.lock:48
- Confidence: high
