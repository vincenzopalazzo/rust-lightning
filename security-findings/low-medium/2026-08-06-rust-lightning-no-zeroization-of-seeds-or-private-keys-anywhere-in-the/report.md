# No zeroization of seeds or private keys anywhere in the workspace; secret copies multiplied via Clone (memory-hygiene gap)

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

The entire workspace contains no use of the `zeroize` crate or any Drop-time erasure for key material (verified by workspace-wide grep: zero matches for `zeroize` outside vendored dev-dependency crates; zeroize 1.9.0 appears in Cargo.lock only as a transitive dev-dependency). rust-secp256k1 0.29.1's `SecretKey` does not erase itself on drop (only a manual, best-effort `non_secure_erase()` exists and is never called by LDK). Consequences: (1) `KeysManager` keeps the master 32-byte wallet seed, the BIP32 master/channel/static-payment Xprivs, node secret, peer-storage key and receive-auth key in...

## Exploit chain

1. Entry point at `lightning/src/sign/mod.rs:1983`
2. The entire workspace contains no use of the `zeroize` crate or any Drop-time erasure for key material (verified by workspace-wide grep: zero matches for `zeroize` outside vendored dev-dependency crates; zeroize 1.9.0 appears in Cargo.lock only as a transitive dev-dependency). rust-secp256k1 0.29.1's

## Root cause

The shown KeysManager stores SecretKey, Xprivs, peer/auth keys, entropy state, and the raw 32-byte seed in ordinary fields, with no evidence of Drop-time erasure or zeroizing wrappers. Rust will not clear these bytes automatically, so dropped or cloned secret material may remain in allocator memory. However, an attacker needs an independent memory-disclosure capability, core/swap/hibernation access, or similar privileged positioning; this is a hardening gap rather than a directly triggerable vul...

## Impact

Attacker obtains a memory image of the running LDK process (core dump left by a crash handler, swap partition, VM hibernation/snapshot file, or a separate memory-disclosure bug). They carve the image for 32-byte sequences that are valid secp256k1 scalars whose public keys match the victim's public node_id, funding pubkeys, or basepoints visible on-chain/gossip. Recovery of the KeysManager `seed` alone yields every past and future channel key (derivation is fully deterministic, see KEY-003), the...

## Source

- Harness: redteam
- Finding ID: KEY-001
- Repo: lightningdevkit/rust-lightning
- File: lightning/src/sign/mod.rs:1983
- Confidence: high
