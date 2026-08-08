# LSPS5 webhook validator uses small in-memory signature cache without strong freshness guarantees

- Project: rust-lightning
- Commit/version: `4347eb85277d19bd06660228a7bed4b8a5b3c514`
- Category: authn / replay
- Severity: Medium — bounded recent signature deque; replays possible after eviction/restart
- Reproduction: static
- Confirmed: code-review
- Attacker model: network observer replaying captured LSP webhooks
- Default config affected: consumers using stock WebhookValidator
- Reported upstream: no
- Source: sentinel, 2026-08-06

## Suggested fix
Enforce max skew on timestamp; persist nonces.

## References
- lightning-liquidity/src/lsps5/validator.rs
