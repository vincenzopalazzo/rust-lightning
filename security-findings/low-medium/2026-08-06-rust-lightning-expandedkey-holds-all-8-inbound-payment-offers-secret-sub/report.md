# ExpandedKey (holds all 8 inbound-payment/offers secret sub-keys) derives Debug — latent secret-printing hazard

- Project: rust-lightning
- Commit/version: (see source finding record)
- Category: key-storage
- Severity: Info
- Reproduction: static — see source finding for evidence
- Confirmed: code-review
- Attacker model: network peer
- Default config affected: unknown
- Reported upstream: no

## Summary

`ExpandedKey` is the root secret for all stateless inbound-payment authentication and BOLT12 offers: knowledge of it lets an attacker recompute every LDK-issued payment preimage (preimage = HMAC(ldk_pmt_hash_key, iv||info||metadata), where iv/info are public in the payment secret) — i.e. claim any not-yet-claimed inbound HTLC whose invoice the node issued — forge payment-secret authentication, decrypt offer metadata/payment ids, and authenticate blinded-path contexts. The struct derives `Debug`, so a single stray `{:?}`/`dbg!` in downstream code (or a future LDK log line) prints all 256 bits o...

## Exploit chain

1. Entry point at `lightning/src/ln/inbound_payment.rs:40`
2. `ExpandedKey` is the root secret for all stateless inbound-payment authentication and BOLT12 offers: knowledge of it lets an attacker recompute every LDK-issued payment preimage (preimage = HMAC(ldk_pmt_hash_key, iv||info||metadata), where iv/info are public in the payment secret) — i.e. claim any n

## Root cause

ExpandedKey does derive Debug while holding eight 32-byte secret subkeys, and a derived Debug implementation will print the raw byte arrays if formatted. However, the shown code has no active logging/formatting sink; exploitation requires downstream code to accidentally log it and an attacker to gain log access. The impact of an actual leak could be serious, but this is a latent exposure hazard, not an attacker-triggerable vulnerability in this code.

## Impact

Any LDK-based application (or a debugging session by an operator) formats the ExpandedKey obtained from node_signer.get_expanded_key() with {:?} — e.g. inside a custom error path or tracing instrumentation. The log/metrics pipeline (often less protected than the key store, shipped to third-party log aggregators) now contains ldk_pmt_hash_key. An attacker reading the logs recomputes the preimage for any unpaid invoice the node previously issued (payment_secret travels in cleartext in the onion) a...

## Source

- Harness: redteam
- Finding ID: KEY-002
- Repo: lightningdevkit/rust-lightning
- File: lightning/src/ln/inbound_payment.rs:40
- Confidence: high
