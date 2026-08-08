# LSPS5 webhook validator accepts arbitrarily old timestamps, enabling indefinite replay of captured notifications

- Project: rust-lightning
- Commit/version: (see source finding record)
- Category: vulnerability
- Severity: Medium
- Reproduction: static — see source finding for evidence
- Confirmed: code-review
- Attacker model: See the finding record.
- Default config affected: unknown
- Reported upstream: no

## Summary

LSPS5Validator::validate (lines 71-90) binds the timestamp into the signed message and verifies the LN signature, then delegates replay protection to check_for_replay_attack (lines 92-105). However, validate never compares the supplied timestamp against local time, and the replay cache is a bounded VecDeque of only MAX_RECENT_SIGNATURES (5) entries. As a result, a captured (timestamp, signature, notification) triple is valid forever: an attacker who can observe a single webhook POST (e.g. via logging, a proxy, or network capture) can replay it indefinitely. Immediate replay is rejected only wh...

## Root cause

The described validator verifies that the timestamp is signed but does not enforce any freshness bound, and the only replay state is a small in-memory cache of the last 5 signatures. A captured valid webhook can therefore be replayed after cache eviction or restart, although the attacker must first obtain a legitimate signed notification, typically despite HTTPS. Impact appears limited to replaying prior notifications and causing duplicate client behavior or DoS, not key recovery or funds theft.

## Impact

See the source finding record for impact assessment.

## Source

- Harness: loupe
- Finding ID: 9
- Repo: lightningdevkit/rust-lightning
- Confidence: medium
