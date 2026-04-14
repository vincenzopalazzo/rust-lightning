# PoS-Delegated BOLT 12 Offers Implementation Status

## Overview

This document captures the implementation status of the PoS-delegated BOLT 12 offer creation proposal for rust-lightning. The implementation allows:

1. A merchant to create a "template offer" with their node info
2. A PoS device to modify the template with order-specific data (notification paths, encrypted payment token)
3. The merchant to notify the PoS when payment is received via onion messages

## Branch

```
macros/pos-bolt12-delegation
```

## Commits (8 total, all complete)

```
0f820cdd2 offers: Add PosDelegationConfig for merchant-side PoS management
9f5227ef3 offers: Add PoS notification queueing to OffersMessageFlow
735248d93 blinded_path: Add DelegatedBolt12OfferContext for PoS payments
6cb5aa54e peer_handler: Add PosNotificationHandler impl for IgnoringMessageHandler
3298eca3c onion_message: Add PoS notification message types
f42f57a82 offers: Add payment token encryption utilities for PoS delegation
47fedb033 offers: Add OfferModifier for PoS template offer modification
b861cf06a offers: Add PoS delegation fields to Offer (experimental TLV range)
```

## Implementation Parts

### Part 1: PoS Delegation Fields (COMPLETE)
**File:** `lightning/src/offers/offer.rs`

Added experimental TLV fields to offers:
- `notification_paths: Option<Vec<BlindedMessagePath>>` (TLV 1_000_000_002)
- `encrypted_payment_token: Option<Vec<u8>>` (TLV 1_000_000_004)

Key changes:
- Extended `OfferContentsBase` with new fields
- Added `tlv_stream!` macro for experimental TLV range
- Added accessor methods: `notification_paths()`, `encrypted_payment_token()`
- Added 2 tests for serialization

### Part 2: Offer Modification (COMPLETE)
**File:** `lightning/src/offers/offer.rs`

Added `OfferModifier` struct for PoS template modification:
- `Offer::modify()` method returns `OfferModifier`
- Modification methods for PoS fields: `notification_paths()`, `encrypted_payment_token()`
- Modification methods for common fields: `amount()`, `description()`, `issuer()`, `supported_quantity()`, `absolute_expiry()`
- `build()` method to create modified offer
- Added 3 tests for template modification

### Part 3: Payment Token Encryption (COMPLETE)
**File:** `lightning/src/offers/payment_token.rs` (NEW)

Payment token utilities using ChaCha20Poly1305:
- `PaymentTokenSecret` - 32-byte shared secret wrapper
- `encrypt_payment_token(secret, order_id, entropy)` - Encrypts order ID
- `decrypt_payment_token(secret, encrypted_token)` - Decrypts and verifies
- `PaymentTokenError` enum for error handling
- 12 tests for encryption/decryption

**File:** `lightning/src/offers/mod.rs`
- Added `pub mod payment_token;`

### Part 4: PoS Notification Messages (COMPLETE)
**File:** `lightning/src/onion_message/pos_notification.rs` (NEW)

Onion message types for PoS notifications:
- `PaymentNotification` - Merchant → PoS (TLV 1_000_000_100)
  - `encrypted_payment_token: Vec<u8>`
  - `preimage: PaymentPreimage`
- `PaymentAck` - PoS → Merchant (TLV 1_000_000_102)
  - `encrypted_payment_token: Vec<u8>`
- `PaymentNack` - PoS → Merchant (TLV 1_000_000_104)
  - `encrypted_payment_token: Vec<u8>`
  - `reason: Option<String>`
- `PosNotificationMessage` enum wrapper
- `PosNotificationHandler` trait
- `OnionMessageContents` implementations
- 11 tests for serialization

**File:** `lightning/src/onion_message/mod.rs`
- Added `pub mod pos_notification;`

### Part 5: Handler Implementation (COMPLETE)
**File:** `lightning/src/ln/peer_handler.rs`

Added `impl PosNotificationHandler for IgnoringMessageHandler`:
- `handle_payment_notification()` - Returns None (ignores)
- `handle_payment_ack()` - No-op
- `handle_payment_nack()` - No-op

**Note:** Full OnionMessenger integration would require adding a 10th generic parameter - marked as future work.

### Part 6: Payment Context (COMPLETE)
**File:** `lightning/src/blinded_path/payment.rs`

Added `DelegatedBolt12OfferContext` struct:
```rust
pub struct DelegatedBolt12OfferContext {
    pub offer_id: OfferId,
    pub invoice_request: InvoiceRequestFields,
    pub encrypted_payment_token: Vec<u8>,
    pub notification_paths: Vec<BlindedMessagePath>,
}
```

Added `PaymentContext::DelegatedBolt12Offer` variant (discriminant 4).
- Serialization via `impl_writeable_tlv_based!`
- 2 tests for context serialization

**File:** `lightning/src/events/mod.rs`
- Added match arm for `DelegatedBolt12Offer` in `PaymentPurpose::from_parts()`

### Part 7: Notification Queueing (COMPLETE)
**File:** `lightning/src/offers/flow.rs`

Added to `OffersMessageFlow`:
- `pending_pos_notification_messages: Mutex<Vec<(PosNotificationMessage, MessageSendInstructions)>>`
- `release_pending_pos_notification_messages()` method
- `queue_pos_payment_notification(encrypted_token, preimage, notification_paths)` method

### Part 8: Merchant Configuration (COMPLETE)
**File:** `lightning/src/offers/pos_delegation.rs` (NEW)

Merchant-side PoS management:
- `PosDelegationConfig` - Stores PoS device shared secrets
  - `add_pos_secret(pos_id, secret)`
  - `remove_pos_secret(pos_id)`
  - `get_pos_secret(pos_id)`
  - `try_decrypt_token(encrypted_token)` - Tries all secrets
- `PosDelegationManager` - Processes delegated payments
  - `process_delegated_payment(context, preimage)` → `Option<PosNotificationInfo>`
  - `decrypt_token(encrypted_token)`
- `PosNotificationInfo` - Notification data struct
- Serialization support (`Readable`/`Writeable`)
- 5 tests

**File:** `lightning/src/offers/mod.rs`
- Added `pub mod pos_delegation;`

## Key Technical Details

### TLV Type Allocation
All experimental types use the range 1_000_000_000 - 1_999_999_999:
- Offer fields: 1_000_000_002 (notification_paths), 1_000_000_004 (encrypted_payment_token)
- Messages: 1_000_000_100 (notification), 1_000_000_102 (ack), 1_000_000_104 (nack)

### Template Offer Model
Offers in BOLT 12 are NOT signed, which enables the modification pattern:
1. Merchant creates template offer
2. PoS modifies with order-specific data
3. Customer pays modified offer
4. Merchant receives payment and notifies PoS

### Payment Token Format
```
[12-byte nonce][encrypted data][16-byte auth tag]
```
- Uses ChaCha20Poly1305 AEAD
- Shared secret derived between merchant and PoS during setup

## Future Work

1. **OnionMessenger Integration**: Add `PosNotificationHandler` as a generic parameter to `OnionMessenger` (currently would be 10th parameter - significant change)

2. **ChannelManager Integration**: Wire up payment receipt to automatically trigger PoS notifications when `DelegatedBolt12OfferContext` is present

3. **Full Integration Test**: Create end-to-end test covering:
   - Template offer creation
   - PoS modification
   - Invoice generation
   - Payment receipt
   - Notification delivery
   - Ack/Nack handling

## Test Commands

```bash
# Run all PoS-related tests
cargo test -p lightning --lib offers::pos_delegation
cargo test -p lightning --lib offers::payment_token
cargo test -p lightning --lib onion_message::pos_notification
cargo test -p lightning --lib offers::offer::tests::test_offer_modification

# Run CI checks (when requested)
./ci/check-compiles.sh
./ci/check-lint.sh
rustup run 1.75.0 cargo fmt --check
```

## File Summary

| File | Status | Description |
|------|--------|-------------|
| `lightning/src/offers/offer.rs` | Modified | PoS TLV fields + OfferModifier |
| `lightning/src/offers/payment_token.rs` | New | Token encryption utilities |
| `lightning/src/offers/pos_delegation.rs` | New | Merchant-side config/manager |
| `lightning/src/offers/flow.rs` | Modified | Notification queueing |
| `lightning/src/offers/mod.rs` | Modified | Module exports |
| `lightning/src/onion_message/pos_notification.rs` | New | Message types |
| `lightning/src/onion_message/mod.rs` | Modified | Module export |
| `lightning/src/blinded_path/payment.rs` | Modified | DelegatedBolt12OfferContext |
| `lightning/src/events/mod.rs` | Modified | PaymentPurpose match arm |
| `lightning/src/ln/peer_handler.rs` | Modified | IgnoringMessageHandler impl |

## Resumption Instructions

To continue work on this implementation:

1. Checkout the branch: `git checkout macros/pos-bolt12-delegation`
2. Verify commits: `git log --oneline -10`
3. Run tests: `cargo test -p lightning --lib`
4. Continue with future work items above

Last updated: 2026-01-02
