# PrintableString passes U+2028/U+2029 line separators enabling log injection

- Project: rust-lightning
- Commit/version: (see source finding record)
- Category: vulnerability
- Severity: Low
- Reproduction: static — see source finding for evidence
- Confirmed: code-review
- Attacker model: network peer
- Default config affected: unknown
- Reported upstream: no

## Summary

PrintableString (and its wrapper UntrustedString) is the documented defensive sanitiser for displaying peer-controlled, untrusted strings to operators. Its explicit threat model, stated in lightning/src/events/mod.rs for the peer_msg / msg fields it wraps, is that "a well-crafted message could exploit a security vulnerability in the terminal emulator or the logging subsystem", and developers are told to rely on Display of UntrustedString to be safe. The same PrintableString is also used for node aliases (lightning/src/routing/gossip.rs) and Bolt 12 offer/invoice description/issuer/payer_note f...

## Exploit chain

1. Entry point at `lightning-types/src/string.rs:32`
2. PrintableString (and its wrapper UntrustedString) is the documented defensive sanitiser for displaying peer-controlled, untrusted strings to operators. Its explicit threat model, stated in lightning/src/events/mod.rs for the peer_msg / msg fields it wraps, is that "a well-crafted message could explo

## Root cause

The Display implementation only replaces char::is_control(), Unicode Other, and Unassigned characters; U+2028 and U+2029 are Zl/Zp separators and will be written verbatim. If attacker-controlled values using this wrapper are viewed in Unicode-aware log or UI renderers, they may visually forge additional lines, but the PoC only proves pass-through and many common log pipelines split records only on LF/CR, limiting impact.

## Impact

See the source finding record for impact assessment.

## Source

- Harness: loupe
- Finding ID: 13
- Repo: lightningdevkit/rust-lightning
- File: lightning-types/src/string.rs:32
- Confidence: medium
