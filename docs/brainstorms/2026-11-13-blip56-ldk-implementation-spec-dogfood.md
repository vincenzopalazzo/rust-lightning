# bLIP-56 in LDK, and using it to dogfood the spec

Date: 2026-11-13
Spec revision: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md
Slimness reference: https://github.com/jkczyz/blips/blob/master/blip-0042.md

## Clarified Problem Statement

**Goal:** Implement the current bLIP-56 revision end to end in LDK (customer,
merchant, PoS; steps 1-7 including verified `payment_proof`), and use that
implementation to produce spec feedback: a findings doc, test vectors, a
requirement-to-test matrix, drafted spec patches, and a slimmed proposal
modelled on bLIP-42.

**Decisions taken (2026-11-13):**

- Scope is the full protocol, including real `payment_proof` verification on
  the PoS. `lightning/src/offers/payer_proof.rs` is on main now, so this is no
  longer opaque plumbing.
- Implement the spec as written. That includes the stateful PoS: per-order
  retained state (sealed ciphertext, expected amount, expiry, template
  `offer_issuer_id`, settled `payment_hash`). The June stateless design is
  dropped. (My reading of "implement the current version specified inside the
  docs"; see Open questions for what that leaves undecided.)
- Dogfooding deliverables: all four (findings, vectors, matrix, patches) plus
  the slim rewrite.

**Constraints:**

- Numbers come from the spec, not from the June branch: feature bit 265, offer
  TLVs 1000000001 / 1000000003, onion message TLVs 65540 / 65542 / 65544 /
  65546.
- An unmodified BOLT 12 wallet must be able to pay a per-order offer.
- The merchant never discloses the sealed plaintext, including through
  `invoice_error` fields.
- Fork only (`origin`, github.com/vincenzopalazzo/rust-lightning). No upstream
  PR. Nothing gets posted to the blips repo by Claude; patches are drafts.
- Repo rules: no new dependencies, `cargo +1.75.0 test` and
  `cargo +1.75.0 fmt --all` before each commit, license header on new files,
  `Co-Authored-By` disclosure.

**Non-goals:**

- Async payments / offline merchant (spec open question 2).
- Implementing the `offer_metadata` MAC from spec open question 3. It can be a
  finding, not code.
- BIP 353 template publishing, currency-denominated offers.
- Lampo or any downstream integration.

**Success criteria:**

- A three-node functional test (customer, merchant, channel-less PoS) passes
  steps 1-7, plus negative tests for every reason code and every
  silent-ignore case.
- Every MUST / MUST NOT (69 of them) is either mapped to a named test or
  listed as untestable with the reason.
- Vectors are emitted by a test with fixed keys and entropy, so they can be
  regenerated.
- The slim draft keeps every requirement that has a test and is measurably
  closer to bLIP-42 in size (see below).

## What changed since the June branch

`blip56-pos-notifications` (6 commits, base c9260ee2a, fork PR #88) is 345
commits behind main and conflicts in `channelmanager.rs`, `offers/flow.rs`,
`offers/mod.rs`, `offers/signer.rs`, `onion_message/messenger.rs`,
`onion_message/functional_tests.rs`.

| Area | June branch | Current spec | Reuse |
|------|-------------|--------------|-------|
| Feature bit 265 | done | same | as is |
| Token payload | `amount`, `description`, `order_id` | `amount`, `description`, `order_metadata`, PoS-private records allowed | ECIES skeleton reusable, payload changes |
| Offer TLVs | 1_000_005_601 / 03 | 1000000001 / 03 | renumber |
| Template + per-order offer, delegation key derivation | done | same shape, more template checks | mostly as is |
| `payment_notification` | plain fields, relays `order_id` | signed TLV stream (types 0/2/4/6/8/240), BOLT 12 merkle with its own tag, commits to SHA256(token ciphertext) | rewrite |
| ack / nack | empty ack, reason-only nack | both echo `payment_hash` | rewrite |
| PoS | stateless, order data in path context | stateful order record, order found only from arrival path, signature checked against that order's issuer key | rewrite |
| Merchant request checks | token decrypt + amount | six-part check list, raw-octet comparison, no plaintext in errors | extend |
| Reply path | LDK default | pubkey form, fresh per notification, rooted where the PoS can reach | new |
| `payment_proof` | opaque bytes | payer proof verified: issuer key binding, token equality, amount | new |
| OM TLV numbers | 65560-66 | 65540-46 | renumber |
| Handler generic through `OnionMessenger` / `peer_handler` / BP | done | same | mechanical, but in the conflict files |

## Approaches Considered

### Approach A: Rebase and patch

- Sketch: Rebase the six June commits onto main, resolve the six conflict
  files, then add delta commits for each spec change.
- Affected files: everything in the June diffstat (25 files).
- Tradeoffs: Fastest route to a compiling tree. But the conflicts are in the
  files that get rewritten anyway (`flow.rs`, `channelmanager.rs`,
  `messenger.rs`), so the resolution work is thrown away. History reads as "old
  protocol, then undo it". Worst for dogfooding: the code starts from the old
  design's assumptions (stateless PoS, shared-secret relay) and the spec gets
  read as a diff rather than as a spec.
- Effort: M

### Approach B: Greenfield on main, commits in spec-section order

- Sketch: Start from this branch (main 7c937aff7). One commit per spec
  section, each carrying that section's requirement tests: feature bit;
  `payment_token`; offer TLVs + template + per-order offer + delegation keys;
  signed `payment_notification` stream + ack/nack + `payment_proof` messages;
  merchant request checks and settlement-time notification with retries; PoS
  order store, reader checks and response policy; `payment_proof` verification;
  functional tests and vectors. Salvage unchanged code from the June branch
  file by file with `git show`. The matrix and findings docs grow with each
  commit.
- Affected files: `lightning-types/src/features.rs`,
  `lightning/src/offers/{payment_token.rs (new), offer.rs, invoice_request.rs, invoice.rs, signer.rs, flow.rs, payer_proof.rs, merkle.rs}`,
  `lightning/src/onion_message/{pos_notification.rs (new), messenger.rs, packet.rs}`,
  `lightning/src/blinded_path/message.rs`, `lightning/src/events/mod.rs`,
  `lightning/src/ln/{channelmanager.rs, peer_handler.rs, pos_notification_tests.rs (new)}`,
  `lightning-background-processor`, `lightning-dns-resolver`.
- Tradeoffs: History is reviewable against the spec one section at a time, and
  every requirement is read fresh, which is the point of dogfooding. Costs
  redoing the handler-generic threading. Spec output arrives gradually rather
  than up front.
- Effort: L

### Approach C: Conformance core first, integration second

- Sketch: Build the wire formats and both rule sets (merchant request checker
  and notifier, PoS verifier and order book) as I/O-free modules with unit
  tests and vectors first. Ship findings, vectors, matrix and the slim draft
  from that. Only then wire into `OffersMessageFlow`, `ChannelManager` and
  `OnionMessenger`.
- Affected files: phase 1 stays inside `lightning/src/offers/` and
  `lightning/src/onion_message/pos_notification.rs`; phase 2 touches the same
  integration files as B.
- Tradeoffs: Spec feedback reaches Jeff earliest and is immune to
  `channelmanager.rs` churn; the PoS verifier is usable by a PoS app that does
  not run a `ChannelManager`. But the requirements most likely to be wrong in
  practice are operational ones (notify on settled not claimable, retry and
  correlation, reply path reachability, state surviving restart), and those
  only get exercised in phase 2. Risk of declaring the spec fine before the
  hard part.
- Effort: L, front-loaded on spec output

## Recommendation

**B**, borrowing one thing from C: keep the PoS reader checks and the merchant
request checks as pure functions over parsed messages plus an order record, so
vectors and the matrix come out of unit tests and only delivery, retries and
persistence need three-node functional tests. I am not fully sure where the
PoS order store should persist (see Open questions); that is the main design
risk in B and should be settled in the plan before the PoS commit.

## Findings already visible from reading the spec

These are pre-implementation and need confirming in code. They seed the
findings doc.

1. **`Enc` and `sealed_order` are not specified.** No concrete scheme, no TLV
   type numbers for `amount` / `description` / `order_metadata`. A PoS and a
   merchant from different vendors cannot interoperate, and no test vector can
   exist. bLIP-42 pins its derivation and ships a vector. LDK will have to
   choose (June branch: ephemeral secp256k1 ECDH + ChaCha20-Poly1305, records
   0/2/4) and that choice is a candidate patch.
2. **ack / nack encoding is ambiguous.** `payment_notification` is given as a
   `tlv_stream`; ack and nack are given as bare `data:` lists. Raw 32 (+1)
   bytes or a TLV stream? Extensibility differs.
3. **Reply path rooting is hard for the merchant in general.** "SHOULD root
   the path at the introduction node of the `notification_path`" needs the
   merchant to build a blinded path from a third-party node back to itself.
   Trivial when the PoS's only peer is the merchant, unclear otherwise. The
   spec never says who the PoS peers with.
4. **Issuer key lookup.** "`offer_issuer_id` is one of the merchant's own
   issuer keys" assumes a key table. LDK derives per-offer keys from the offer
   contents, which the PoS changes, so the template needs its own derivation
   and the merchant needs to recover it again at settlement to sign.
5. **Payer proof over an experimental-range TLV.** `PayerProofBuilder::include_type`
   accepts 1000000003, but `PayerProof` parsing discards the experimental
   offer stream and has no accessor for it. Disclosing a 1e9-range record also
   walks straight into the known 239 -> 1e9 marker-jump problem in bolts#1295.
6. **Possibly redundant requirement.** "amount the merchant would invoice is
   at least the token's `amount`" on top of `offer_amount` == token `amount`
   and BOLT 12's own `invreq_amount` >= `offer_amount`. Slim candidate.
7. **QR size is asserted, not measured.** "noticeably larger" should become a
   number: bytes of a one-path per-order offer from LDK.
8. **TLV numbers 1000000001 / 03** are the very bottom of the experimental
   range, the likeliest place for a collision with another experiment.

## Slimming toward bLIP-42

| | bLIP-42 | bLIP-56 now |
|---|---|---|
| Lines | 295 | 1105 |
| Words | 1878 | 8369 |
| Headings | 13 | 69 |
| MUST / MUST NOT | 17 | 69 |
| SHOULD / MAY | 7 | 26 |
| Test vector | yes | none |

bLIP-42's shape: TLV definitions, one Requirements block, one short Rationale,
a deterministic construction, a test vector. Method for 56, driven by the
matrix rather than by taste:

- One home per requirement. Today the same rule appears in Payment Flow,
  Security Model, Notification Path, the `payment_notification` reader list
  and Reply Path.
- Security Model (about 90 lines of prose) collapses to the two checks and the
  trust statement; the attack narratives move to a rationale line each, kept
  only where a negative test demonstrates the attack.
- Requirements that no test can observe get cut or downgraded, with the matrix
  as evidence.
- Add what 42 has and 56 lacks: a concrete `Enc`, and vectors.

## Open questions

- **PoS order store location.** Spec-literal stateful PoS in LDK means a
  persisted per-order table. Inside `OffersMessageFlow` / `ChannelManager`
  serialization (as the June retry queue was), or behind a small trait the PoS
  app implements? Decide in the plan.
- **`Enc` choice.** Keep the June ECIES construction and propose it as the
  spec's scheme?
- **Where spec deliverables live.** Proposed: `docs/blip-0056/` on this branch
  in a separate droppable commit (`findings.md`, `requirements-matrix.md`,
  `vectors.json`, `blip-0056-slim.md`). Or a local clone of the blips repo if
  you have one.
- **Fork PR #88.** New branch and new fork PR, closing #88 once the new one
  covers it? Not touched until you say so.
