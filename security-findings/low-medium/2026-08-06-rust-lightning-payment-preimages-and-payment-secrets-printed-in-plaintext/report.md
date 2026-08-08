# Payment preimages and payment secrets printed in plaintext into trace logs via ChannelManager event Debug logging

- Project: rust-lightning
- Commit/version: (see source finding record)
- Category: key-storage
- Severity: Info
- Reproduction: static — see source finding for evidence
- Confirmed: code-review
- Attacker model: Bluetooth/BLE attacker in radio range
- Default config affected: unknown
- Reported upstream: no

## Summary

Every `Event` handled by ChannelManager is written to the trace log in full Debug form. `PaymentSent` carries the 32-byte payment preimage; `PaymentClaimed` carries a `PaymentPurpose` that (for BOLT11 payments) carries both the payer-supplied preimage and the receiver's `payment_secret`. Both types implement hex Display/Debug via `impl_fmt_traits!`. Log files — typically far less protected than key stores, shipped to aggregators, retained in backups — thus accumulate live payment secrets. Impact is bounded: at the point these events fire, the preimage has normally already been revealed on the...

## Exploit chain

1. Entry point at `lightning/src/ln/channelmanager.rs:3677`
2. Every `Event` handled by ChannelManager is written to the trace log in full Debug form. `PaymentSent` carries the 32-byte payment preimage; `PaymentClaimed` carries a `PaymentPurpose` that (for BOLT11 payments) carries both the payer-supplied preimage and the receiver's `payment_secret`. Both types

## Root cause

The code logs every pending Event with full Debug formatting at trace level, and the cited Event variants carry PaymentPreimage/PaymentSecret values that will be included rather than redacted. Exploitation requires access to trace logs or log aggregation output, and the strongest theft scenarios are narrow because preimages are normally revealed as part of settlement and arbitrary third parties generally cannot spend channel HTLCs without being a relevant party. The realistic impact is sensitive...

## Impact

Attacker obtains the node's log archive (shared log collector, support bundle, backup). For any invoice the node paid whose counterpart HTLC is still claimable on-chain (e.g. a duplicate-hash payment in flight, or a PaymentClaimed whose inbound HTLC is not yet irrevocably resolved), the attacker extracts the preimage from the trace line 'Handling event PaymentSent { payment_preimage: ... }' and broadcasts/races a claim transaction spending the corresponding HTLC output before the victim's own cl...

## Source

- Harness: redteam
- Finding ID: KEY-004
- Repo: lightningdevkit/rust-lightning
- File: lightning/src/ln/channelmanager.rs:3677
- Confidence: high
