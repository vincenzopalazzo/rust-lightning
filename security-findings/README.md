# Sentinel / BSC findings for rust-lightning

Personal tracking branch on the `vincenzopalazzo/rust-lightning` fork.
**Not** an upstream LDK branch. Do not merge into `lightningdevkit/rust-lightning`.

**Baseline HEAD:** `384e0d613` (upstream main as of 2026-08-08)  
**Source store:** bitcoin-security-council/findings `found/rust-lightning`  
**Fuzz report:** [fuzz/ldk-main-fuzz-2026-08-08.md](./fuzz/ldk-main-fuzz-2026-08-08.md)

## High / Critical

| Finding | Status on 384e0d613 |
|---------|---------------------|
| [onchaintx reorg merge assert panic](./high-crit/2026-08-05-rust-lightning-onchaintx-reorg-merge-assert-panic/) | **Fixed in practice** — upstream regression test green. See STATUS-2026-08-08.md |

## Low / Medium (still of interest on HEAD)

| Finding | Sev | Notes |
|---------|-----|-------|
| [LSPS5 URL https-only / loopback](./low-medium/2026-08-06-rust-lightning-lsps5-https-url-allows-loopback-private-hosts/) | Medium | Still open — `url_utils.rs` |
| [LSPS5 webhook old timestamps](./low-medium/2026-08-06-rust-lightning-lsps5-webhook-validator-accepts-arbitrarily-old-timestamps/) | Medium | Still open — no max-age in `validate()` |
| [LSPS5 weak replay window](./low-medium/2026-08-06-rust-lightning-lsps5-webhook-validator-weak-replay-window/) | Medium | Still open — `MAX_RECENT_SIGNATURES = 5` |
| [OffersMessage unbounded read](./low-medium/2026-08-06-rust-lightning-offersmessage-read-unbounded-buffer/) | Medium | Still open — `read_to_limit(..., u64::MAX)` |
| [PrintableString Zl/Zp](./low-medium/2026-08-04-printablestring-line-paragraph-separators/) | Med/Low | Fix branch exists: `2026-08-04-printablestring-zl-zp` |
| [PrintableString duplicate](./low-medium/2026-08-06-rust-lightning-printablestring-passes-u-2028-u-2029-line-separators/) | Low | Duplicate of above |
| [tx_signatures not verified](./low-medium/2026-08-06-rust-lightning-counterparty-tx-signatures-incl-splice-shared-input/) | Low | Not re-audited 2026-08-08 |
| [codecov floating binary](./low-medium/2026-08-06-rust-lightning-ci-coverage-job-downloads-and-executes-the-codecov-binary/) | Low | CI process |
| Info / hygiene | Info | ExpandedKey Debug, preimage logs, zeroize, rust-bitcoin 0.32 track, cargo-audit summary |
| [Triage rejected](./low-medium/2026-08-06-rust-lightning-triage-rejected-ai-slop/) | — | Rejected AI noise |
| [Loupe triage notes](./low-medium/2026-08-04-loupe-triage-notes/) | — | Non-findings ledger |

## Fuzz (2026-08-08)

- Engine: libFuzzer / `cargo-fuzz` on `fuzz-fake-hashes`
- ~24M+ execs across peer_crypt, onion_message, chanmon_deser, offer_deser, lsps_message, full_stack, commitment/HTLC msgs, …
- **0 crashes**
- Details: [fuzz/ldk-main-fuzz-2026-08-08.md](./fuzz/ldk-main-fuzz-2026-08-08.md)

## Related fix branches on this fork

- `2026-08-04-printablestring-zl-zp` — PrintableString Zl/Zp filter
