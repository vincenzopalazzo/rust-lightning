# bLIP-56 in LDK: PR plan, split by actor

Date: 2026-11-13 (revised the same day: re-cut by actor after discussion with Jeff)
Companion to: `2026-11-13-blip56-ldk-implementation-spec-dogfood.md`
Spec revision: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md

## Phases

| Phase | What | Where | Exit condition |
|-------|------|-------|----------------|
| 0 | Pin base, confirm the defaults below | local | defaults confirmed |
| 1a | Shared wire formats | private fork | both actors can be built against it |
| 1b | PoS track and Merchant track, independently | private fork | each track green against fixtures of the other side |
| 1c | "Then see": join the tracks, customer proof, conformance | private fork | steps 1-7 pass end to end |
| 2 | Revisit the spec: findings, patches, slim rewrite in the shape of bLIP-42 | drafts, not posted | slim draft + vectors + matrix ready |
| 3 | Review with Jeff | fork PRs, Jeff's blips branch | comments resolved |
| 4 | Go public | LDK PR(s) on Forgejo, bLIP PR on lightning/blips | opened |

Nothing goes upstream (LDK or lightning/blips) before phase 3 is done.

## Why split by actor

- The spec is already written per actor ("The merchant:", "The PoS:"), so each
  PR lines up with one column of the requirement matrix.
- The PoS has no channels. It can be a standalone type that only needs keys, an
  entropy source, a message router and an `OnionMessenger`. LDK already
  supports a node like that (`IgnoringMessageHandler` for offers,
  `ErroringMessageHandler` for channels in `ln/peer_handler.rs`). The June
  branch put both roles behind `ChannelManager`; this drops that for the PoS.
- The merchant does need `ChannelManager` and `OffersMessageFlow`: it issues
  invoices and learns about settlement there.
- Each track is tested against a fixture of the other side built from the
  shared wire layer, so the tracks do not block each other and can be reviewed
  (or written) by different people.

Cost: nothing runs end to end until phase 1c, so a disagreement between the
two sides shows up late. The shared test vectors are what limit that.

## Code shape

| Piece | Where | Owns |
|-------|-------|------|
| Wire formats | `offers/payment_token.rs`, `offers/offer.rs`, `onion_message/pos_notification.rs` | encodings, seal / unseal, sign / verify. No policy, no state |
| PoS actor | new standalone type (name to settle, for example `PosTerminal`) | template validation, per-order offers and paths, persisted order book, reader checks, response policy, proof verification |
| Merchant actor | `offers/flow.rs` plus hooks in `ln/channelmanager.rs` | template creation and key, invoice request checks, notify on settlement, reply paths, retry queue |
| Customer | `offers/payer_proof.rs` plus one send API | building and sending the proof |

One handler trait on `OnionMessenger` covers the four message types. The PoS
type implements the half it receives (`payment_notification`, `payment_proof`),
the merchant implements the other half (ack, nack).

## Defaults assumed

1. **PoS order store**: owned and persisted by the PoS actor itself, not by
   `ChannelManager`. Spec-literal stateful PoS.
2. **`Enc`**: the June construction (ephemeral secp256k1 ECDH,
   ChaCha20-Poly1305, `sealed_order` records 0 / 2 / 4), proposed to the spec in
   phase 2.
3. **Spec deliverables**: `docs/blip-0056/` in one droppable commit at the top.
4. **Granularity** (decided 2026-11-13): three PRs, one per group, with the
   units below as separate commits inside each PR. PR 1 is the shared wire
   (commits F1-F4), PR 2 is the PoS (commits P1-P2), PR 3 is the merchant
   (commits M1-M3). The "then see" work becomes a fourth PR later. Each commit
   still compiles and passes tests on its own, so a PR can be reviewed commit
   by commit.

## Branch layout

```
blip56-v2-base  (upstream main, pinned)
  └─ blip56-v2/wire        PR 1: commits F1, F2, F3, F4
       ├─ blip56-v2/pos        PR 2: commits P1, P2        (targets wire)
       └─ blip56-v2/merchant   PR 3: commits M1, M2, M3    (targets wire)
            blip56-v2/joined   PR 4, later: commits J1, J2, J3
```

- PR 2 and PR 3 both target `blip56-v2/wire` and do not touch each other's
  files, so they can be written and reviewed in parallel.
- `joined` is a merge of the PoS and merchant tips, created only when both are
  green.
- The ids below (F1, P1, M1, ...) are commits, not PRs.
- Every commit compiles, passes `cargo +1.75.0 test` for the crates it touches
  and is `cargo +1.75.0 fmt --all` clean on its own.
- "Salvage" means code taken file by file from the June branch
  `blip56-pos-notifications`, not a rebase of it.

Sizes are rough estimates of changed lines including tests.

## Phase 1a: shared wire

### F1 `wire-offer` (about 300 lines)
- Spec: Offer Template (feature table), Per-Order Offers (TLV table).
- Feature bit 265 in `lightning-types/src/features.rs`.
- `notification_path` (1000000001) and `payment_token` (1000000003) in
  `ExperimentalOfferTlvStream`, with accessors, carried byte for byte through
  invoice request and invoice.
- A policy-free way to rebuild an offer from another one with amount,
  description, expiry and the two records set. Both tracks' fixtures use it.
- Salvage: June cac9f4802 and the TLV parts of 70efd4e92.

### F2 `wire-token` (about 300 lines)
- Spec: Payment Token.
- `offers/payment_token.rs`: `sealed_order` records, seal to a public key,
  unseal with the secret key, SHA256 of the ciphertext.
- Tests: round trip, tamper and truncation, short `order_metadata`, vector.
- Salvage: ECIES skeleton from June b281ec27e.

### F3 `wire-messages` (about 400 lines)
- Spec: Onion Message Types, `payment_notification` stream and Signature
  Calculation, ack / nack.
- `onion_message/pos_notification.rs`: signed stream (0 / 2 / 4 / 6 / 8 / 240)
  with its own merkle tag, sign and verify, ack / nack with echoed hash, reason
  codes, proof wrapper, types 65540 / 42 / 44 / 46.
- Tests: TLV ordering, unknown even ignored, unknown odd hashed, exactly one
  signature record, signature vector.

### F4 `messenger-handler` (about 250 lines, many files)
- Handler trait and generic parameter on `OnionMessenger`, threaded through
  `ln/peer_handler.rs`, `lightning-background-processor`,
  `lightning-dns-resolver`, test utilities and doc examples; `MessageContext`
  variant. Mechanical; isolated so the actor PRs stay readable.

## Phase 1b: PoS track

Fixture for tests: a "merchant" that is just a key pair producing a template
(F1) and signed notifications (F3). No merchant code.

### P1 `pos-orders` (about 450 lines)
- Spec: Offer Template (PoS requirements), Per-Order Offers, Notification Path,
  Payment Token (PoS requirements), Retained state.
- The PoS type: accepts or refuses a template (the MUST NOT use list), creates
  a per-order offer with fresh `order_metadata`, one sealed token and per-order
  notification path(s), and records the order.
- Persisted order book: ciphertext, expected amount, expiry, issuer id, settled
  payment hash; retention after settlement or expiry.
- Tests: each refused template shape; one token per order across transports;
  order survives restart; measured offer size with one path.

### P2 `pos-notification-reader` (about 450 lines)
- Spec: `payment_notification` (reader), Reply Path (PoS half), ack / nack
  (writer).
- Arrival path identifies the order. Checks as a pure function returning ack,
  nack with reason, or ignore: signature against that order's issuer key,
  preimage, already paid, expiry with grace, token hash, amount.
- Response policy: silent on bad signature, `unknown_order` once per path,
  per-path budget for signature verification, reply only over the supplied
  reply path. Event on acceptance.
- Tests: one per reason code and per silent case, duplicate and double payment,
  notification over a path the PoS did not build, flood on one order does not
  affect another.

## Phase 1b: Merchant track

Fixture for tests: a "PoS" that is a test helper building a per-order offer
from F1 and F2. No PoS code.

### M1 `merchant-template` (about 200 lines)
- Spec: Offer Template (merchant requirements).
- Template creation in `offers/flow.rs` and a template-scoped signing key in
  `offers/signer.rs` that still resolves after the offer has been edited.
- Salvage: `derive_keys_for_delegation` from June 70efd4e92.

### M2 `merchant-invreq-checks` (about 400 lines)
- Spec: Invoice Requests, Stateless merchants, Payment Token (merchant
  requirements, non-disclosure).
- The check list as a pure function over a parsed `InvoiceRequest`; wired into
  `verify_invoice_request` and the invoice builders; order data (issuer nonce,
  notification paths, token hash) carried in the payment context so nothing is
  stored before settlement; errors that cannot contain sealed plaintext.
- Tests: one negative test per check; an unmodified payer pays a fixture
  per-order offer.

### M3 `merchant-notify` (about 500 lines)
- Spec: `payment_notification` (writer), Reply Path (merchant half),
  ack / nack (reader).
- On settlement in `ln/channelmanager.rs`: recover the order data, sign with
  the template key, send over a path from the request. Fresh pubkey-form reply
  path per notification, persisted retry queue with backoff, ack clears, nack
  escalates through an event, responses accepted only over a reply path built
  for a pending notification with a matching hash.
- Salvage: retry queue and claim hook from June 1f6a19e10. Known gotcha:
  taking the persistence guard in the claim hook deadlocks.
- Tests: notification captured at a fixture PoS verifies with F3; lost ack,
  forged ack, retries exhausted.

## Phase 1c: then see

Decided once both tracks are up. Current proposal:

### J1 `end-to-end` (tests only)
- Three real nodes (customer, merchant with channels, channel-less PoS running
  only the PoS type), steps 1-6. First time the two tracks meet.

### J2 `payment-proof` (about 400 lines)
- Spec: `payment_proof`.
- Customer: accessor for a disclosed experimental offer record in
  `offers/payer_proof.rs`, helper that keeps `payment_token` and
  `invoice_amount`, send API.
- PoS: verification (valid proof, arrival path, issuer binding, token
  equality, amount), marks the order paid.
- Kept out of the two tracks because it adds a third actor and depends on the
  BOLT 12 payer proof code rather than on the notification path logic. It could
  move into the PoS track as P3 if you want the PoS side complete on its own.

### J3 `conformance` (tests plus docs)
- Remaining matrix rows, a test that emits all vectors, and `docs/blip-0056/`
  (`findings.md`, `requirements-matrix.md`, `vectors.json`) in its own commit.

## Readiness review of the current draft (2026-11-13)

An independent read concluded the draft is **not ready for public review**.
Six blockers; three land in code and need a provisional answer.

| # | Blocker | Checked | Lands in | Provisional handling |
|---|---------|---------|----------|----------------------|
| 1 | `Enc` and `sealed_order` layout undefined | yes, spec text | F2 | Implement the June ECIES construction, propose it as the spec's scheme |
| 2 | Open question 3 (authenticating the request to the merchant) is really a wire-format decision and could replace public-key `Enc` | judgment | F2, M2 | Not implemented; keep the token module small enough to swap |
| 3 | Number collisions with open lightning/blips PRs: bLIP number 56 (#56), onion message types 65540-46 (#66), feature bit 264/265 (#73) | yes, on GitHub | F1, F3 | All numbers as named constants in one place; renumbering is the authors' call |
| 4 | Payer proof reference is stale: bolts#1295 closed unmerged, bolts#1346 merged, payer proofs are in BOLT 12 master | yes, on GitHub | J2 | Build against BOLT 12 master via `offers/payer_proof.rs` |
| 5 | Who the PoS peers with is never stated, so reply delivery is underspecified | yes, spec text | P1, M3 | Assume the PoS peers with the merchant, which is the introduction node and the reply path root |
| 6 | Banning `offer_chains` makes the protocol mainnet-only; LDK's builders set the chain on test networks, so no conformant test run is possible | yes, spec text and `offers/flow.rs` | P1, M2 | Allow exactly one chain and require `invreq_chain` to match; a deliberate deviation and a proposed patch |

Row 6 is the one place the code cannot follow the draft literally.

Non-blocking items from the same review go into `findings.md` in J3: ack / nack
encoding, offer TLV element encodings, the 7-step diagram against 5-step prose,
a selective-disclosure contradiction, missing bLIP-1 sections, and the three
most duplicated arguments.

## Phase 2: spec revisit

1. Triage findings into blocking, wording, and cut.
2. One home per requirement, using the matrix (already grouped by actor) to
   find duplicates.
3. Add what the implementation had to invent: concrete `Enc`, `sealed_order`
   record numbers, ack / nack encoding, test vectors.
4. Cut or downgrade requirements no test could observe.
5. Rewrite to the bLIP-42 skeleton: definitions, Requirements, short Rationale,
   Test vectors, Reference implementation.

## Phase 3 and 4

- Jeff reviews the fork PRs against the slim draft; fixes land in the PR that
  owns the requirement.
- For upstream LDK the natural grouping is the same one: wire, PoS, merchant,
  proof. Decide with Jeff.
- The bLIP PR carries the slim draft, the vectors and a link to the LDK PR, and
  reserves the numbers in bLIP 2.

## Open items

- Name and home of the PoS type.
- Which fork hosts the PRs: GitHub `origin` (where PR #88 lives) or the Forgejo
  fork. Plan assumes GitHub `origin`.
- Fork PR #88 and `blip56-pos-notifications`: untouched until the new PRs cover
  them, then close.
- Whether to send blockers 3 and 4 to Jeff now; they need no implementation.
