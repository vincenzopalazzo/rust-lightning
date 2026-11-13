# bLIP 56 findings from the LDK implementation

Against the draft at
https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md.
Each finding says where it surfaced and what the implementation does about it.
Line numbers refer to that draft.

Severity:

- **Blocking**: two implementations cannot interoperate, or the text is wrong.
- **Should fix**: the text misleads, or leaves a decision to implementers that
  changes behaviour.
- **Wording**: clarity, duplication or numbers.

## Blocking

### F-1. `Enc` and `sealed_order` are unspecified

Lines 433-466 name `Enc` and the three fields but no algorithm, key derivation,
layout or TLV types, so a merchant and a PoS from different vendors cannot
interoperate and no test vector can exist.

The implementation (`offers/payment_token.rs`) uses ECDH between a fresh
ephemeral key and `offer_issuer_id`, `k = HMAC-SHA256("blip56_payment_token",
ss)`, and RFC 8439 ChaCha20-Poly1305 with a zero nonce and the ephemeral key as
associated data. `sealed_order` is a TLV stream: 0 amount (tu64), 2 description
(utf8), 4 order_metadata (at least 16 bytes); unknown odd types are ignored.

**Proposed**: adopt this construction. The vector in
`reference/payment_token_ref.py` reproduces LDK's output independently.

### F-2. Number collisions

Found by the readiness review and confirmed in code:

- bLIP number 56 is lightning/blips PR #56 (Pluggable Channel Factories).
- Onion message types 65540-65546 are lightning/blips PR #66 (Static Invoice
  Server).
- Feature bit 264/265 is lightning/blips PR #73 (Path Queries).
- Offer TLV 1000000001, the first odd experimental type, collided with LDK's own
  tests, which used `EXPERIMENTAL_OFFER_TYPES.start + 1` as an arbitrary unknown
  record. Two tests had to move (commit "offers: Add bLIP 56 per-order offer
  records").

**Proposed**: renumber everything, reserve the numbers in bLIP 2, and pick offer
TLVs away from the bottom of the experimental range.

### F-3. The payer proof reference is stale

bolts#1295 was closed unmerged; payer proofs are in BOLT 12 master through
bolts#1346. The implementation builds on LDK's BOLT 12 master payer proofs and
needed one addition: a way to disclose and read back the experimental
`payment_token` record (`PayerProofBuilder::include_payment_token`,
`PayerProof::payment_token`).

**Proposed**: cite BOLT 12 "Payer Proofs".

### F-4. `notification_ack` and `notification_nack` encoding

Lines 836-848 give them as bare data, not TLV streams, with no length rule. LDK's
onion message decoder silently drops trailing bytes of a custom record, so the
reader here requires exactly 32 and 33 bytes (`onion_message/pos_notification.rs`).
Either way, the messages cannot be extended.

**Proposed**: make them TLV streams like `payment_notification`, or state the
exact lengths.

## Should fix

### F-5. Who the PoS peers with

The draft never says. Both sides of the implementation assume the PoS is
connected to its merchant: the PoS uses the merchant as the introduction node of
its notification paths (`PosConfig::notification_path_intro_node`), and the
merchant roots its reply paths at itself. That is the only setup in which line
897's "root the reply path at the notification path's introduction node" is
straightforward. A PoS without that peer has to be its own introduction node,
which puts its node id in every offer.

**Proposed**: one normative paragraph: the PoS peers with its merchant, which
introduces its notification paths and roots the merchant's reply paths.

### F-6. Banning `offer_chains` makes the protocol mainnet-only (deviation)

Lines 251, 306 and 559-562 forbid `offer_chains`, so no conformant test-network
run is possible. Deviation implemented on both sides: a template may name
exactly one chain, which must be the PoS's (and the merchant's), per-order offers
inherit it, and the invoice request must be for it.

**Proposed**: allow exactly one chain and require `invreq_chain` to match.

### F-7. Rate limiting has no unit, and conflicts with a MUST

Line 929 says SHOULD rate-limit signature verification, not per what. A global
limit lets one customer starve every order at the till. The implementation limits
failed signature checks per order (8 a minute, `pos_terminal.rs`), shared with
payment proofs, whose parsing also verifies two signatures. Even per order, a
customer flooding their own order makes the PoS drop the genuine notification
until the window ends, which collides with line 925's "MUST NOT suppress its
first response" for a passing notification. The merchant's backoff retry gets
through afterwards (`pos_terminal::limits_failed_signature_checks_per_order`).

**Proposed**: say per order, and carve the budget out of line 925, relying on the
merchant's retries.

### F-8. Onion message payloads are decoded before the path is authenticated

In LDK, and plausibly elsewhere, the messenger decodes a payload before it knows
whether the message arrived over one of our paths. Decoding a payer proof verifies
two signatures, so an unauthenticated sender could make the PoS verify signatures
for messages it is about to drop. The implementation carries `payment_proof`
unparsed and parses it only after the path check.

**Proposed**: a rationale line telling implementers to authenticate the path
before parsing a proof.

### F-9. PoS-private `sealed_order` records

Line 458 allows them but does not say they must be odd. The reader here ignores
unknown odd types and rejects unknown even ones, so an even private record makes
the merchant reject the request.

**Proposed**: private records MUST use odd types.

### F-10. The bare template paid directly

Nothing says what a merchant does with an invoice request for the template itself
(no token, no notification path). It is a valid amountless offer. The
implementation rejects such requests, since the template is for the PoS only.

**Proposed**: say so, or say templates may also be paid directly.

### F-11. Only one notification path fits through a stateless merchant

Line 570 lets the merchant keep all notification paths if it wants to retry over
different ones. A stateless merchant carries them back with the payment, inside
the invoice's blinded payment paths and so inside the payer's onion. The
implementation keeps one path (one encoded path plus 48 bytes of
`payment_metadata`). Several large paths would make the merchant's invoice harder
to pay, which the draft does not mention.

**Proposed**: a rationale note, and a SHOULD for at most one path per transport.

## Wording

### F-12. The claimed amount exceeds the invoiced amount

Sender-paid fees for the merchant's blinded-path dummy hops land at the
merchant, so the notification reports slightly more than the order total
(5,000,010 against 5,000,000 msat in `notifies_point_of_sale_of_settled_payment`).
Line 689 already requires the claimed amount; a note would save implementers
from treating the difference as an error.

### F-13. The QR size concern, measured

With one notification path, the per-order records add 371 bytes to the template,
about 593 bech32 characters (`pos_terminal::per_order_offer_size`). 10 of those
bytes are the two 5-byte experimental record types.

### F-14. The diagram has seven steps, the prose five

Lines 83-112 against 114-140.

### F-15. Repetition

The same argument appears in several places, which is most of why the draft is
8369 words against bLIP 42's 1878:

- the self-sealed token: lines 197-212, 407-414, 578-587, 771-791, 877-884,
  1087-1099;
- "that order's key": lines 153-158, 723-728, 755-769, 1030-1036;
- path verification: lines 170-187, 392-396, 717-720, 961-972.

The requirement matrix (`requirements-matrix.md`) gives each requirement one
home.

### F-16. A selective-disclosure contradiction

Line 713 forbids selectively disclosing a notification's records; lines 793-798
justify `notification_metadata` by selective disclosure.

## Confirmed by implementation, no change needed

- **The cross-order replay defence works.** A genuine notification for one order
  replayed on a same-priced order's path is refused with `order_mismatch`
  (`pos_terminal::refuses_notifications_failing_checks`).
- **The self-sealed token attack plays out as the security model says.** A
  customer who re-seals the description passes every merchant check and pays,
  and the PoS refuses the notification
  (`pos_notification_tests::point_of_sale_terminal_refuses_resealed_offer`).
- **Signing with the template key works for co-tenant merchants.** A second
  merchant's signature is ignored for the first merchant's order
  (`pos_terminal::ignores_notifications_not_signed_by_the_orders_merchant`).
- **A stateless merchant is workable.** Nothing is stored per invoice request;
  per-notification state starts at settlement and survives restarts
  (`pos_notification_tests::keeps_payment_notification_across_restart`).
- **The payer proof fallback works**, including the later notification being
  re-acked as already paid
  (`pos_notification_tests::point_of_sale_terminal_accepts_payment_proof`).
