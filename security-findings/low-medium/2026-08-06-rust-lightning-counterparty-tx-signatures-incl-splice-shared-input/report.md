# Counterparty tx_signatures (incl. splice shared-input signature) never verified before finalizing and broadcasting the interactive funding transaction

- Project: rust-lightning
- Commit/version: (see source finding record)
- Category: other
- Severity: Low
- Reproduction: static — see source finding for evidence
- Confirmed: code-review
- Attacker model: See the finding record.
- Default config affected: unknown
- Reported upstream: no

## Summary

In the interactive transaction construction protocol (dual-funded opens and splices), after tx_complete both sides exchange tx_signatures carrying per-input witnesses plus, for splices, the 2-of-2 shared funding input signature. LDK verifies its OWN contributed witnesses (verify_interactive_tx_signatures) but never verifies the counterparty's witnesses nor the counterparty's shared-input ECDSA signature against the sighash of the negotiated transaction. received_tx_signatures() only checks: witness count == remote input count, shared-input signature presence/absence, and (in channel.rs) txid m...

## Exploit chain

1. Entry point at `lightning/src/ln/interactivetxs.rs:623`
2. In the interactive transaction construction protocol (dual-funded opens and splices), after tx_complete both sides exchange tx_signatures carrying per-input witnesses plus, for splices, the 2-of-2 shared funding input signature. LDK verifies its OWN contributed witnesses (verify_interactive_tx_signa

## Root cause

The shown received_tx_signatures path only checks duplicate receipt, witness count, and shared-signature presence/absence before storing counterparty signatures and potentially returning a finalized signed_tx; there is no cryptographic verification in this code. A malicious negotiation peer can therefore provide syntactically acceptable but invalid witnesses/signatures and cause LDK to assemble/broadcast a transaction that will not confirm. Impact appears limited to peer-triggered griefing/DoS o...

## Impact

1. Attacker opens/splices with the victim using the interactive tx protocol and drives negotiation to tx_complete. 2. Attacker sends tx_signatures with syntactically well-formed but cryptographically invalid witnesses (e.g., random 71-byte ECDSA-looking blobs) and, for a splice, a garbage shared_input_signature. 3. Victim's received_tx_signatures accepts them (count/presence checks pass). 4. Victim finalizes the funding tx, transitions state (AwaitingChannelReady for V2 open; negotiated splice c...

## Source

- Harness: redteam
- Finding ID: SIG-001
- Repo: lightningdevkit/rust-lightning
- File: lightning/src/ln/interactivetxs.rs:623
- Confidence: medium
