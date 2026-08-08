# Loupe triage notes for rust-lightning / related (non-findings)

- Triage severity: INFO
- Verdict: NOT A FINDING (ledger of reviewed-and-rejected candidates)
- Scanned: 2026-08-04
- Target: lightningdevkit/rust-lightning (Forgejo) + cross-repo Loupe false positives

This is a **dedup / negative-results** record so future scans do not re-escalate the same items.

## Rejected: LSPS5 "missing timestamp freshness" (Loupe #9)

- Claim: `LSPS5Validator::validate` never compares timestamp to local time; 5-entry signature cache allows indefinite replay after eviction.
- Code claim is factually true on HEAD.
- **Not a vulnerability:** timestamp validation was **intentionally removed** in Forgejo PR #3961 ("Simplify LSPS5/validator: drop time checks & custom signature storage", merged 2025-07-30), tracked under issue #3944 checklist item "avoid timestamp validation on validator". Maintainer discussion (PR #3662): HTTPS is the replay mitigation; robust time/cache complexity was deliberately dropped. Current bLIP-55 likewise relies on HTTPS, not a ±10 minute MUST.
- Residual: `service.rs` docs still mention clients should validate ±10 min — docs drift only, not filed as security.

## Rejected cross-repo clones of the same LSPS5 text

- Loupe #11 on marmot-protocol/mdk — identical text/paths to LDK LSPS5; mdk has **zero** LSPS5 code → misattribution.
- Loupe #12 on vincenzopalazzo/carl — same misattribution.

## Already upstream (do not re-file)

- Loupe #14 mdk unbounded `extra_profile_fields` ≡ open upstream issue https://github.com/marmot-protocol/mdk/issues/867 (still unfixed on HEAD at review time).

## Novel finding filed separately

- `../2026-08-04-printablestring-line-paragraph-separators/report.md` — residual Zl/Zp gap after PR #4593/#4605.
