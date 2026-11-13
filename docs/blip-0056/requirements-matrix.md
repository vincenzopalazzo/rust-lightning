# bLIP 56 requirement-to-test matrix

Every normative bullet (MUST, MUST NOT, SHOULD, MAY) of the draft at
https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md,
by line number, against the LDK implementation on the `blip56-v2/*` branches.

Status:

- **Tested**: a test fails if the requirement is broken.
- **Construction**: the code cannot do otherwise, but no test targets it.
- **Partial**: some of the requirement is tested or built, the rest is not.
- **Deviation**: deliberately not followed; see `findings.md`.
- **Open**: not implemented.

Test names are relative to `lightning/src`: `pos_terminal::` is
`offers::pos_terminal::tests`, `pos_notification_tests::` is
`ln::pos_notification_tests`, `om::` is `onion_message::functional_tests`.

Counts: 62 bullets. Tested 42, Construction 9, Partial 8, Deviation 2,
Open 1. The Open one is a MAY.

## Offer Template

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 250 | Merchant | MUST include `offer_issuer_id` | Tested | `pos_notification_tests::creates_pos_offer_template` |
| 251 | Merchant | MUST NOT set chains, currency, quantity_max | Deviation | Currency and quantity: Construction. Chains: one chain off mainnet (finding F-6) |
| 253 | Merchant | MAY refresh the template | Partial | `create_pos_offer_template` can be called again; no rotation helper |
| 254 | Merchant | MAY publish via BIP 353 | Open | |
| 259 | PoS | MUST NOT use an unusable template | Tested | `pos_terminal::rejects_unusable_templates` (chains per F-6) |

## Per-Order Offers

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 306 | PoS | MUST NOT set currency, quantity_max, chains | Deviation | `pos_terminal::creates_order_offer`; chains inherited per F-6 |
| 311 | PoS | Exactly one token per order, same ciphertext on every transport | Partial | One seal per `create_order`; no API yet to present one order over several transports |
| 314 | PoS | SHOULD use one notification path for QR | Tested | `pos_terminal::per_order_offer_size` |
| 316 | PoS | MUST retain token, amount, expiry, issuer id, payment hash | Tested | `pos_terminal::persists_orders`, `keeps_payments_across_restarts` |
| 320 | PoS | MUST retain state and path recognition for a period | Tested | `pos_terminal::prunes_finished_orders`; paths stay recognizable through the node's receive key |
| 323 | PoS | SHOULD retain the signed notification | Tested | `pos_terminal::accepts_and_records_valid_notification` |

## Notification Path

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 388 | PoS | Per order, never in the template | Construction | Built in `create_order` |
| 390 | PoS | Only for this order's notifications and proofs | Construction | The context names one order; acks and nacks on it are ignored |
| 392 | PoS | MUST ignore messages over paths it did not build | Tested | `om::drops_pos_notification_messages_not_sent_over_own_paths` |

## Payment Token

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 454 | PoS | MUST encrypt to the template's `offer_issuer_id` | Tested | `pos_terminal::creates_order_offer` |
| 455 | PoS | Fresh unpredictable `order_metadata` of at least 16 bytes | Partial | 32 entropy bytes; `pos_terminal::creates_distinct_orders_for_identical_items`. "Never reused across restarts and terminals" rests on the entropy source |
| 458 | PoS | MUST TLV encode; MAY add private records | Partial | Reading: `payment_token::unseals_order_with_unknown_odd_records`. No API to write private records (F-9) |
| 465 | Enc | MUST be authenticated | Tested | `payment_token::fails_unsealing_tampered_token` |
| 466 | Enc | MUST conceal the plaintext | Construction | ECDH to the issuer key; vector reproduced independently |
| 470 | Merchant | MUST decrypt with the issuer key | Tested | `pos_notification_tests::rejects_invalid_per_order_invoice_requests` (foreign token) |
| 471 | Merchant | MUST NOT disclose the sealed order | Tested | Rejected requests get no answer at all: `rejects_invalid_per_order_invoice_requests` |

## Invoice Requests

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 549 | Merchant | Reject `notification_path` without token | Partial | Template paths: tested (bare template). Other offers: rejected by metadata authentication, not tested |
| 551 | Merchant | The check list | Partial | Amount, description, token, path, overpay: `rejects_invalid_per_order_invoice_requests`. Currency, quantity, chain: Construction in `check_pos_invoice_request` |
| 568 | Merchant | Copy token byte for byte | Tested | `invoice::carries_per_order_offer_records_into_invoice`, `pay_and_claim` |
| 570 | Merchant | Determine issuer, path, token hash at settlement | Tested | `pos_notification_tests::pays_for_per_order_offer` |

## `payment_notification`, writer

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 680 | Merchant | Not for rejected requests | Construction | No invoice, so no payment to notify |
| 681 | Merchant | Not before settlement | Tested | Sent from the `PaymentClaimed` path only; `notifies_point_of_sale_of_settled_payment` |
| 682 | Merchant | Fresh unpredictable `notification_metadata` | Construction | 32 entropy bytes |
| 684 | Merchant | Token hash over the value only | Tested | `notifies_point_of_sale_of_settled_payment` |
| 687 | Merchant | Payment hash and preimage of the settled payment | Tested | same |
| 689 | Merchant | Amount claimed, not invoiced | Tested | same (claimed exceeds invoiced, F-12) |
| 691 | Merchant | Exactly one signature record | Tested | `payment_notification::fails_parsing_malformed_notification` |
| 693 | Merchant | Only over the request's notification path | Construction | The path comes from the payment's own context |
| 698 | Merchant | MUST include a reply path | Tested | `notifies_point_of_sale_of_settled_payment` |
| 700 | Merchant | SHOULD retry with backoff, escalate | Tested | `retries_payment_notification_until_answered`, `gives_up_on_payment_notification` |

## `payment_notification`, reader

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 710 | PoS | BOLT 1 parsing; ignore unknown even | Tested | `payment_notification::fails_parsing_malformed_notification` |
| 713 | PoS | Complete stream; reject missing records | Tested | same |
| 717 | PoS | Ignore foreign paths; order from the arrival path; `unknown_order` | Tested | `om::drops_...`, `pos_terminal::answers_unknown_order_once_per_path` |
| 721 | PoS | Merkle root over unknown records too | Tested | `payment_notification::verifies_notification_with_unknown_odd_records` |
| 723 | PoS | Verify against that order's key only | Tested | `pos_terminal::ignores_notifications_not_signed_by_the_orders_merchant` |
| 729 | PoS | `preimage_mismatch` | Tested | `pos_terminal::refuses_notifications_failing_checks` |
| 733 | PoS | Re-ack when already paid; flag double payment | Tested | `pos_terminal::applies_expiry_with_grace_period`, `flags_additional_payment` |
| 740 | PoS | `order_expired`, SHOULD use a grace period | Tested | `pos_terminal::applies_expiry_with_grace_period` |
| 744 | PoS | Token hash, else `order_mismatch` | Tested | `pos_terminal::refuses_notifications_failing_checks`, `point_of_sale_terminal_refuses_resealed_offer` |
| 747 | PoS | Amount, else `amount_insufficient` | Tested | `pos_terminal::refuses_notifications_failing_checks` |
| 749 | PoS | Not paid on any failure | Tested | same |

## Acknowledgements

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 865 | PoS | Echo the payment hash | Tested | `pos_notification::round_trips_ack_and_nack`, end-to-end tests |
| 870 | Merchant | SHOULD report a nack, not retry | Tested | `retries_payment_notification_until_answered` |
| 872 | Merchant | MAY retry on `unknown_order` | Tested | `gives_up_on_payment_notification` |

## Reply Path

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 897 | Merchant | Pubkey form; SHOULD root at the notification path's intro | Partial | Pubkey form: Construction. Rooted at the merchant, which matches only when the PoS peers with it (F-5) |
| 903 | Merchant | Fresh per notification | Construction | Built in `enqueue_payment_notification` |
| 905 | Merchant | No reuse across notifications or `offer_paths` | Construction | The context binds the payment hash |
| 910 | Merchant | Accept answers only over its reply path, matching hash | Tested | `retries_payment_notification_until_answered` |
| 917 | PoS | Answer only over the reply path | Construction | Responses go through the messenger's responder |
| 920 | PoS | SHOULD process notifications without a reply path | Tested | `pos_terminal::handles_notifications_through_the_handler` |
| 922 | PoS | SHOULD answer verified, never unverified | Tested | `pos_terminal::ignores_notifications_not_signed_by_the_orders_merchant` |
| 925 | PoS | MUST NOT suppress the first passing response | Tested | Conflicts with line 929: `pos_terminal::limits_failed_signature_checks_per_order` shows the drop (F-7) |
| 928 | PoS | SHOULD answer `unknown_order` once per path | Tested | `pos_terminal::answers_unknown_order_once_per_path` |
| 929 | PoS | SHOULD rate-limit signature verification | Tested | `pos_terminal::limits_failed_signature_checks_per_order` |

## `payment_proof`

| Line | Who | Requirement | Status | Evidence |
|------|-----|-------------|--------|----------|
| 991 | Customer | MUST NOT redact token or amount | Tested | `send_pos_payment_proof` refuses: `point_of_sale_terminal_ignores_proof_for_another_order` |
| 998 | PoS | Accept only valid, own-path, issuer-bound, amount-sufficient proofs | Partial | Valid and own path: tested. Issuer binding: Construction in `check_payment_proof`, no co-tenant test |
| 1005 | PoS | Token disclosed and byte-identical | Tested | `point_of_sale_terminal_ignores_proof_for_another_order` |
