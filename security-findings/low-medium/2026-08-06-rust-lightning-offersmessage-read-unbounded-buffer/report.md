# OffersMessage::read uses read_to_limit(..., u64::MAX) before parse

- Project: rust-lightning
- Commit/version: `4347eb85277d19bd06660228a7bed4b8a5b3c514`
- Category: dos / resource consumption
- Severity: Medium
- Reproduction: static
- Confirmed: code-review
- Attacker model: peer sending oversized onion message offers TLV
- Default config affected: nodes processing offers onion messages
- Reported upstream: no
- Source: sentinel, 2026-08-06

## Suggested fix
Cap read size to protocol max encoded offer size.

## References
- lightning/src/onion_message/offers.rs ~187-190
