# PoS-Delegated BOLT 12 - Implementation Plan

This document outlines the implementation strategy for PoS-delegated BOLT 12 offer creation in rust-lightning. The changes are organized into small, reviewable commits that can be discussed with LDK maintainers.

## Overview

The implementation is divided into **8 parts** with approximately **20-25 commits**. Each commit should:
- Compile independently
- Pass all existing tests
- Be reviewable in isolation
- Have a clear, focused purpose

## Dependency Graph

```
Part 1: Offer TLV Extensions
         │
         ▼
Part 2: Offer Modification API ◄──────┐
         │                            │
         ▼                            │
Part 3: Payment Token Utilities ──────┤
         │                            │
         ▼                            │
Part 4: New Onion Message Types       │
         │                            │
         ▼                            │
Part 5: Message Handler Trait         │
         │                            │
         ▼                            │
Part 6: Invoice Integration ──────────┘
         │
         ▼
Part 7: Payment Receipt Flow
         │
         ▼
Part 8: ChannelManager Integration
```

---

## Part 1: Offer TLV Extensions

**Goal**: Add new TLV fields to the Offer structure for PoS delegation.

**Files affected**:
- `lightning/src/offers/offer.rs`
- `lightning/src/offers/mod.rs` (if adding new module)

### Commit 1.1: Add TLV type constants for PoS delegation

Add constants for the new experimental TLV types.

```rust
// In offers/offer.rs or a new offers/pos.rs module

/// TLV type for notification paths to PoS (experimental range)
pub const OFFER_NOTIFICATION_PATHS_TLV_TYPE: u64 = 1_000_000_000;

/// TLV type for encrypted payment token (experimental range)
pub const OFFER_ENCRYPTED_PAYMENT_TOKEN_TLV_TYPE: u64 = 1_000_000_002;
```

**Rationale**: Using experimental TLV range (1000000000-1999999999) per BOLT 12 spec until formal type allocation.

**Tests**: None needed (just constants).

---

### Commit 1.2: Add `notification_paths` field to `OfferContents`

Add the field and basic accessor.

```rust
// In OfferContents
pub(super) struct OfferContents {
    // ... existing fields ...

    /// Blinded paths to the PoS for payment notifications
    notification_paths: Option<Vec<BlindedMessagePath>>,
}

// In Offer impl
impl Offer {
    /// Returns the blinded paths to the PoS for payment notifications, if any.
    pub fn notification_paths(&self) -> Option<&Vec<BlindedMessagePath>> {
        self.contents.notification_paths.as_ref()
    }
}
```

**Tests**:
- Test that `notification_paths()` returns `None` for regular offers
- Test accessor behavior

---

### Commit 1.3: Implement TLV serialization for `notification_paths`

Add read/write support for the new TLV field.

```rust
// In the Writeable/Readable impl for OfferContents

// Writing: encode notification_paths at type 1_000_000_000
// Reading: decode notification_paths from type 1_000_000_000
```

**Tests**:
- Round-trip serialization test
- Test parsing offer with notification_paths
- Test parsing offer without notification_paths (backwards compat)

---

### Commit 1.4: Add `encrypted_payment_token` field to `OfferContents`

Same pattern as notification_paths.

```rust
pub(super) struct OfferContents {
    // ... existing fields ...
    notification_paths: Option<Vec<BlindedMessagePath>>,

    /// Encrypted payment token (order ID) for PoS delegation
    encrypted_payment_token: Option<Vec<u8>>,
}

impl Offer {
    /// Returns the encrypted payment token, if any.
    pub fn encrypted_payment_token(&self) -> Option<&Vec<u8>> {
        self.contents.encrypted_payment_token.as_ref()
    }
}
```

**Tests**: Same pattern as 1.3

---

### Commit 1.5: Implement TLV serialization for `encrypted_payment_token`

Add read/write support.

**Tests**:
- Round-trip serialization
- Offer with both new fields
- Backwards compatibility

---

### Commit 1.6: Add `OfferBuilder` methods for new fields

Allow building offers with the new fields directly.

```rust
impl<'a, M: MetadataStrategy, T: secp256k1::Signing> OfferBuilder<'a, M, T> {
    /// Sets the notification paths to the PoS for payment confirmations.
    pub fn notification_paths(mut self, paths: Vec<BlindedMessagePath>) -> Self {
        self.offer.notification_paths = Some(paths);
        self
    }

    /// Sets the encrypted payment token for order tracking.
    pub fn encrypted_payment_token(mut self, token: Vec<u8>) -> Self {
        self.offer.encrypted_payment_token = Some(token);
        self
    }
}
```

**Tests**:
- Build offer with notification_paths
- Build offer with encrypted_payment_token
- Build offer with both

---

## Part 2: Offer Modification API

**Goal**: Enable the "template offer" model where PoS modifies a merchant-provided template.

**Files affected**:
- `lightning/src/offers/offer.rs`

### Commit 2.1: Add `OfferModifier` struct

Create the basic structure for modifying offers.

```rust
/// A builder for modifying an existing [`Offer`].
///
/// This enables the "template offer" pattern where a merchant provides
/// a base offer and a PoS device modifies it with order-specific data.
pub struct OfferModifier {
    original_bytes: Vec<u8>,
    contents: OfferContents,
}

impl Offer {
    /// Creates a modifier for this offer, allowing fields to be changed.
    ///
    /// Since offers are not signed, modifications produce valid offers
    /// as long as the `issuer_signing_pubkey` is unchanged (so the
    /// merchant can still sign invoices).
    pub fn modify(self) -> OfferModifier {
        OfferModifier {
            original_bytes: self.bytes,
            contents: self.contents,
        }
    }
}
```

**Tests**: Basic creation test

---

### Commit 2.2: Add modification methods for PoS fields

Methods to set the new PoS-specific fields.

```rust
impl OfferModifier {
    /// Sets or replaces the notification paths.
    pub fn notification_paths(mut self, paths: Vec<BlindedMessagePath>) -> Self {
        self.contents.notification_paths = Some(paths);
        self
    }

    /// Clears the notification paths.
    pub fn clear_notification_paths(mut self) -> Self {
        self.contents.notification_paths = None;
        self
    }

    /// Sets or replaces the encrypted payment token.
    pub fn encrypted_payment_token(mut self, token: Vec<u8>) -> Self {
        self.contents.encrypted_payment_token = Some(token);
        self
    }

    /// Clears the encrypted payment token.
    pub fn clear_encrypted_payment_token(mut self) -> Self {
        self.contents.encrypted_payment_token = None;
        self
    }
}
```

**Tests**: Test each modification method

---

### Commit 2.3: Add modification methods for common fields

Allow modifying amount and description for the template model.

```rust
impl OfferModifier {
    /// Sets or replaces the amount.
    pub fn amount_msats(mut self, amount: u64) -> Self {
        self.contents.amount = Some(Amount::Bitcoin { amount_msats: amount });
        self
    }

    /// Sets or replaces the description.
    pub fn description(mut self, description: String) -> Self {
        self.contents.description = Some(description);
        self
    }

    /// Sets or replaces the absolute expiry.
    pub fn absolute_expiry(mut self, expiry: Duration) -> Self {
        self.contents.absolute_expiry = Some(expiry);
        self
    }
}
```

**Tests**: Test each method

---

### Commit 2.4: Implement `OfferModifier::build()`

Finalize modifications and produce a new offer.

```rust
impl OfferModifier {
    /// Builds the modified offer.
    ///
    /// This re-serializes the offer with all modifications applied.
    pub fn build(self) -> Result<Offer, Bolt12SemanticError> {
        // Validate: must have description
        if self.contents.description.is_none() {
            return Err(Bolt12SemanticError::MissingDescription);
        }

        // Validate: must have paths or issuer_signing_pubkey
        if self.contents.paths.is_none() &&
           self.contents.issuer_signing_pubkey.is_none() {
            return Err(Bolt12SemanticError::MissingPaths);
        }

        // Serialize contents to bytes
        let bytes = self.contents.to_bytes();
        let id = OfferId::from_bytes(&bytes);

        Ok(Offer {
            bytes,
            contents: self.contents,
            id,
        })
    }
}
```

**Tests**:
- Modify template and build
- Round-trip: create → modify → build → parse
- Verify issuer_signing_pubkey unchanged after modification
- Error cases (missing required fields)

---

### Commit 2.5: Add integration test for template offer flow

End-to-end test of the template model.

```rust
#[test]
fn test_template_offer_modification() {
    // Merchant creates template
    let merchant_pubkey = ...;
    let merchant_paths = ...;

    let template = OfferBuilder::new(merchant_pubkey)
        .paths(merchant_paths)
        .description("Coffee Shop".to_string())
        .build()
        .unwrap();

    // Simulate sending to PoS (serialize/deserialize)
    let template_bytes = template.to_bytes();
    let received_template = Offer::try_from(template_bytes).unwrap();

    // PoS modifies for specific order
    let pos_notification_paths = ...;
    let encrypted_token = vec![1, 2, 3, 4]; // Encrypted order ID

    let order_offer = received_template
        .modify()
        .notification_paths(pos_notification_paths)
        .encrypted_payment_token(encrypted_token.clone())
        .amount_msats(5000)
        .build()
        .unwrap();

    // Verify modifications applied
    assert_eq!(order_offer.amount(), Some(5000));
    assert!(order_offer.notification_paths().is_some());
    assert_eq!(order_offer.encrypted_payment_token(), Some(&encrypted_token));

    // Verify merchant can still sign (pubkey unchanged)
    assert_eq!(
        order_offer.issuer_signing_pubkey(),
        template.issuer_signing_pubkey()
    );
}
```

---

## Part 3: Payment Token Utilities

**Goal**: Provide encryption/decryption utilities for the payment token.

**Files affected**:
- New file: `lightning/src/offers/payment_token.rs`
- `lightning/src/offers/mod.rs`

### Commit 3.1: Create payment token module with encryption

```rust
// lightning/src/offers/payment_token.rs

//! Utilities for encrypting and decrypting payment tokens in PoS-delegated offers.
//!
//! Payment tokens are encrypted order identifiers that allow the merchant to
//! notify the PoS when a payment is received.

use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;

/// The length of the shared secret for payment token encryption.
pub const SHARED_SECRET_LEN: usize = 32;

/// The length of the nonce for ChaCha20Poly1305.
const NONCE_LEN: usize = 12;

/// The length of the authentication tag.
const TAG_LEN: usize = 16;

/// A shared secret between the PoS and Merchant for payment token encryption.
#[derive(Clone, PartialEq, Eq)]
pub struct PaymentTokenSecret([u8; SHARED_SECRET_LEN]);

impl PaymentTokenSecret {
    /// Creates a new payment token secret from bytes.
    pub fn from_bytes(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the secret as a byte slice.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

/// Encrypts a payment token (order ID) using the shared secret.
///
/// The output format is: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// # Arguments
/// * `secret` - The shared secret between PoS and Merchant
/// * `order_id` - The plaintext order identifier
/// * `entropy` - Random bytes for the nonce (at least 12 bytes)
pub fn encrypt_payment_token(
    secret: &PaymentTokenSecret,
    order_id: &[u8],
    entropy: &[u8],
) -> Vec<u8> {
    assert!(entropy.len() >= NONCE_LEN);

    let nonce: [u8; NONCE_LEN] = entropy[..NONCE_LEN].try_into().unwrap();
    let mut cipher = ChaCha20Poly1305RFC::new(secret.as_bytes(), &nonce, &[]);

    let mut ciphertext = vec![0u8; order_id.len() + TAG_LEN];
    ciphertext[..order_id.len()].copy_from_slice(order_id);

    let mut tag = [0u8; TAG_LEN];
    cipher.encrypt_full_message_in_place(&mut ciphertext[..order_id.len()], &mut tag);
    ciphertext[order_id.len()..].copy_from_slice(&tag);

    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypts a payment token to recover the order ID.
///
/// # Arguments
/// * `secret` - The shared secret between PoS and Merchant
/// * `encrypted_token` - The encrypted token from the offer/payment
///
/// # Returns
/// The decrypted order ID, or an error if decryption fails.
pub fn decrypt_payment_token(
    secret: &PaymentTokenSecret,
    encrypted_token: &[u8],
) -> Result<Vec<u8>, PaymentTokenError> {
    if encrypted_token.len() < NONCE_LEN + TAG_LEN {
        return Err(PaymentTokenError::InvalidLength);
    }

    let nonce: [u8; NONCE_LEN] = encrypted_token[..NONCE_LEN].try_into().unwrap();
    let ciphertext_and_tag = &encrypted_token[NONCE_LEN..];
    let ciphertext_len = ciphertext_and_tag.len() - TAG_LEN;

    let mut cipher = ChaCha20Poly1305RFC::new(secret.as_bytes(), &nonce, &[]);

    let mut plaintext = vec![0u8; ciphertext_len];
    plaintext.copy_from_slice(&ciphertext_and_tag[..ciphertext_len]);

    let tag: [u8; TAG_LEN] = ciphertext_and_tag[ciphertext_len..].try_into().unwrap();

    if !cipher.decrypt_full_message_in_place(&mut plaintext, &tag) {
        return Err(PaymentTokenError::DecryptionFailed);
    }

    Ok(plaintext)
}

/// Errors that can occur when working with payment tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentTokenError {
    /// The encrypted token is too short.
    InvalidLength,
    /// Decryption failed (invalid secret or corrupted data).
    DecryptionFailed,
}
```

**Tests**: See next commit

---

### Commit 3.2: Add tests for payment token encryption

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
        let order_id = b"order:12345";
        let entropy = [1u8; 32];

        let encrypted = encrypt_payment_token(&secret, order_id, &entropy);
        let decrypted = decrypt_payment_token(&secret, &encrypted).unwrap();

        assert_eq!(decrypted, order_id);
    }

    #[test]
    fn test_different_secrets_fail() {
        let secret1 = PaymentTokenSecret::from_bytes([1u8; 32]);
        let secret2 = PaymentTokenSecret::from_bytes([2u8; 32]);
        let order_id = b"order:12345";
        let entropy = [0u8; 32];

        let encrypted = encrypt_payment_token(&secret1, order_id, &entropy);
        let result = decrypt_payment_token(&secret2, &encrypted);

        assert_eq!(result, Err(PaymentTokenError::DecryptionFailed));
    }

    #[test]
    fn test_corrupted_token_fails() {
        let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
        let order_id = b"order:12345";
        let entropy = [0u8; 32];

        let mut encrypted = encrypt_payment_token(&secret, order_id, &entropy);
        encrypted[20] ^= 0xFF; // Corrupt a byte

        let result = decrypt_payment_token(&secret, &encrypted);
        assert_eq!(result, Err(PaymentTokenError::DecryptionFailed));
    }

    #[test]
    fn test_too_short_token() {
        let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
        let short_token = vec![0u8; 10]; // Too short

        let result = decrypt_payment_token(&secret, &short_token);
        assert_eq!(result, Err(PaymentTokenError::InvalidLength));
    }

    #[test]
    fn test_empty_order_id() {
        let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
        let order_id = b"";
        let entropy = [0u8; 32];

        let encrypted = encrypt_payment_token(&secret, order_id, &entropy);
        let decrypted = decrypt_payment_token(&secret, &encrypted).unwrap();

        assert_eq!(decrypted, order_id);
    }

    #[test]
    fn test_large_order_id() {
        let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
        let order_id = vec![0xAB; 1024]; // 1KB order ID
        let entropy = [0u8; 32];

        let encrypted = encrypt_payment_token(&secret, &order_id, &entropy);
        let decrypted = decrypt_payment_token(&secret, &encrypted).unwrap();

        assert_eq!(decrypted, order_id);
    }
}
```

---

## Part 4: New Onion Message Types

**Goal**: Define the message types for PoS notifications.

**Files affected**:
- New file: `lightning/src/onion_message/pos_notification.rs`
- `lightning/src/onion_message/mod.rs`

### Commit 4.1: Add `PaymentTokenMessage` struct

The core notification message from Merchant to PoS.

```rust
// lightning/src/onion_message/pos_notification.rs

//! Messages for PoS payment notifications in delegated BOLT 12 offers.

use crate::io;
use crate::util::ser::{Readable, Writeable, Writer};

/// A message from the Merchant to the PoS indicating a payment was received.
///
/// Sent via onion message using the `notification_paths` from the offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentTokenMessage {
    /// The decrypted payment token (order ID).
    pub payment_token: Vec<u8>,
}

impl Writeable for PaymentTokenMessage {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
        self.payment_token.write(writer)
    }
}

impl Readable for PaymentTokenMessage {
    fn read<R: io::Read>(reader: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
        Ok(Self {
            payment_token: Readable::read(reader)?,
        })
    }
}
```

**Tests**: Serialization round-trip

---

### Commit 4.2: Add `PaymentAckMessage` and `PaymentNackMessage`

Acknowledgment messages from PoS to Merchant.

```rust
/// Acknowledgment that the payment token was recognized.
///
/// Sent from PoS to Merchant after receiving `PaymentTokenMessage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAckMessage {
    /// The payment token being acknowledged.
    pub payment_token: Vec<u8>,
}

/// Negative acknowledgment - the payment token was not recognized.
///
/// Sent from PoS to Merchant if the token doesn't match any known order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentNackMessage {
    /// The payment token that was not recognized.
    pub payment_token: Vec<u8>,
    /// Optional reason for the rejection.
    pub reason: Option<String>,
}

// Implement Writeable/Readable for both...
```

**Tests**: Serialization round-trips

---

### Commit 4.3: Add `PaymentProofMessage` (optional customer → PoS)

For redundancy - customer can prove payment to PoS directly.

```rust
/// A message from the Customer to the PoS proving payment was made.
///
/// This provides redundancy in case the Merchant's notification fails.
/// Sent via onion message using the `notification_paths` from the offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentProofMessage {
    /// The payment preimage proving the payment was made.
    pub preimage: PaymentPreimage,
    /// The invoice that was paid (contains the encrypted payment token).
    pub invoice: Bolt12Invoice,
}

// Implement Writeable/Readable...
```

**Tests**: Serialization round-trip

---

### Commit 4.4: Add `PosNotificationMessage` enum

Wrapper enum for all PoS notification messages.

```rust
/// Messages related to PoS payment notifications.
#[derive(Clone, Debug)]
pub enum PosNotificationMessage {
    /// Payment received notification (Merchant → PoS).
    PaymentToken(PaymentTokenMessage),
    /// Positive acknowledgment (PoS → Merchant).
    PaymentAck(PaymentAckMessage),
    /// Negative acknowledgment (PoS → Merchant).
    PaymentNack(PaymentNackMessage),
    /// Payment proof (Customer → PoS).
    PaymentProof(PaymentProofMessage),
}

// TLV type constants
pub const PAYMENT_TOKEN_TLV_TYPE: u64 = 1_000_000_100;
pub const PAYMENT_ACK_TLV_TYPE: u64 = 1_000_000_102;
pub const PAYMENT_NACK_TLV_TYPE: u64 = 1_000_000_104;
pub const PAYMENT_PROOF_TLV_TYPE: u64 = 1_000_000_106;

impl PosNotificationMessage {
    /// Returns the TLV type for this message.
    pub fn tlv_type(&self) -> u64 {
        match self {
            Self::PaymentToken(_) => PAYMENT_TOKEN_TLV_TYPE,
            Self::PaymentAck(_) => PAYMENT_ACK_TLV_TYPE,
            Self::PaymentNack(_) => PAYMENT_NACK_TLV_TYPE,
            Self::PaymentProof(_) => PAYMENT_PROOF_TLV_TYPE,
        }
    }
}

// Implement Writeable/Readable for the enum...
```

**Tests**: Enum serialization for all variants

---

### Commit 4.5: Implement `OnionMessageContents` for `PosNotificationMessage`

Allow these messages to be sent via onion messages.

```rust
impl OnionMessageContents for PosNotificationMessage {
    fn tlv_type(&self) -> u64 {
        self.tlv_type()
    }

    fn msg_type(&self) -> &'static str {
        match self {
            Self::PaymentToken(_) => "Payment Token",
            Self::PaymentAck(_) => "Payment Ack",
            Self::PaymentNack(_) => "Payment Nack",
            Self::PaymentProof(_) => "Payment Proof",
        }
    }
}
```

**Tests**: Test message can be wrapped in onion message

---

## Part 5: Message Handler Trait

**Goal**: Define the interface for handling PoS notifications.

**Files affected**:
- `lightning/src/onion_message/pos_notification.rs`
- `lightning/src/onion_message/messenger.rs`

### Commit 5.1: Define `PosNotificationHandler` trait

```rust
/// A handler for PoS notification messages.
///
/// Implement this trait to handle payment notifications for delegated offers.
pub trait PosNotificationHandler {
    /// Handles a payment token notification from the Merchant.
    ///
    /// Called at the PoS when a payment has been received by the Merchant.
    /// Should return `PaymentAck` if the token matches a known order,
    /// or `PaymentNack` otherwise.
    ///
    /// # Arguments
    /// * `message` - The payment token message
    /// * `responder` - Used to send the ack/nack response
    fn handle_payment_token(
        &self,
        message: PaymentTokenMessage,
        responder: Option<Responder>,
    ) -> Option<PosNotificationMessage>;

    /// Handles an acknowledgment from the PoS.
    ///
    /// Called at the Merchant when the PoS acknowledges a payment notification.
    fn handle_payment_ack(&self, message: PaymentAckMessage);

    /// Handles a negative acknowledgment from the PoS.
    ///
    /// Called at the Merchant when the PoS doesn't recognize a payment token.
    fn handle_payment_nack(&self, message: PaymentNackMessage);

    /// Handles a payment proof from the Customer.
    ///
    /// Called at the PoS when a customer sends proof of payment.
    /// Should return `PaymentAck` if the proof is valid, `PaymentNack` otherwise.
    fn handle_payment_proof(
        &self,
        message: PaymentProofMessage,
        responder: Option<Responder>,
    ) -> Option<PosNotificationMessage>;
}
```

---

### Commit 5.2: Add no-op `IgnoringPosNotificationHandler`

Default implementation that ignores all messages.

```rust
/// A [`PosNotificationHandler`] that ignores all messages.
///
/// Use this if you don't need PoS notification support.
pub struct IgnoringPosNotificationHandler;

impl PosNotificationHandler for IgnoringPosNotificationHandler {
    fn handle_payment_token(
        &self,
        _message: PaymentTokenMessage,
        _responder: Option<Responder>,
    ) -> Option<PosNotificationMessage> {
        None
    }

    fn handle_payment_ack(&self, _message: PaymentAckMessage) {}

    fn handle_payment_nack(&self, _message: PaymentNackMessage) {}

    fn handle_payment_proof(
        &self,
        _message: PaymentProofMessage,
        _responder: Option<Responder>,
    ) -> Option<PosNotificationMessage> {
        None
    }
}
```

---

### Commit 5.3: Integrate handler into `OnionMessenger`

Add the handler to the OnionMessenger generic parameters.

```rust
// In OnionMessenger definition, add:
pub struct OnionMessenger<ES, NS, L, NL, MR, OMH, APH, CMH, PNH>
where
    // ... existing bounds ...
    PNH: PosNotificationHandler,
{
    // ... existing fields ...
    pos_notification_handler: PNH,
}

// Update message handling to dispatch PosNotificationMessage to the handler
```

This is a larger change that touches OnionMessenger generics.

---

## Part 6: Invoice Integration

**Goal**: Ensure the payment token flows through the invoice correctly.

**Files affected**:
- `lightning/src/offers/invoice.rs`
- `lightning/src/blinded_path/payment.rs`

### Commit 6.1: Extend `PaymentContext` for delegated offers

Add a way to carry the encrypted payment token in the payment path.

```rust
// In blinded_path/payment.rs

/// Context for a payment in a blinded path.
pub enum PaymentContext {
    // ... existing variants ...

    /// Payment for a PoS-delegated BOLT 12 offer.
    DelegatedBolt12Offer(DelegatedBolt12OfferContext),
}

/// Context for a PoS-delegated offer payment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedBolt12OfferContext {
    /// The offer fields (same as Bolt12OfferContext).
    pub offer_id: OfferId,
    pub offer_fields: InvoiceRequestFields,

    /// The encrypted payment token for PoS notification.
    pub encrypted_payment_token: Vec<u8>,

    /// Blinded paths to the PoS for sending notifications.
    pub notification_paths: Vec<BlindedMessagePath>,
}
```

**Tests**: Serialization tests

---

### Commit 6.2: Modify invoice creation for delegated offers

When creating an invoice for a delegated offer, embed the token.

```rust
// In InvoiceBuilder or OffersMessageFlow

impl InvoiceBuilder {
    /// Creates an invoice for a PoS-delegated offer.
    ///
    /// The encrypted payment token and notification paths from the offer
    /// are embedded in the payment context for later extraction.
    pub fn for_delegated_offer(
        invoice_request: &InvoiceRequest,
        payment_paths: Vec<BlindedPaymentPath>,
        payment_hash: PaymentHash,
    ) -> Result<Self, Bolt12SemanticError> {
        // Extract token and notification paths from the offer
        let encrypted_token = invoice_request.offer()
            .encrypted_payment_token()
            .ok_or(Bolt12SemanticError::MissingPaymentToken)?;

        let notification_paths = invoice_request.offer()
            .notification_paths()
            .cloned()
            .unwrap_or_default();

        // Build invoice with DelegatedBolt12OfferContext
        // ...
    }
}
```

---

### Commit 6.3: Add reply path to PoS in invoice

The invoice should include a reply path to the PoS for error handling.

```rust
// When building invoice response, include notification path as reply path
// This allows the customer to send payment_proof directly to PoS
```

---

## Part 7: Payment Receipt Flow

**Goal**: Extract payment token and send notification on payment receipt.

**Files affected**:
- `lightning/src/ln/channelmanager.rs`
- `lightning/src/offers/flow.rs`

### Commit 7.1: Extract payment token on payment receipt

When a payment is received, check if it's for a delegated offer.

```rust
// In payment receipt handling

fn handle_payment_received(&self, payment: &ClaimablePayment) {
    // Check if this is a delegated offer payment
    if let PaymentContext::DelegatedBolt12Offer(context) = &payment.payment_context {
        // We have a delegated offer payment
        let encrypted_token = &context.encrypted_payment_token;
        let notification_paths = &context.notification_paths;

        // Queue notification to PoS
        self.queue_pos_notification(encrypted_token, notification_paths);
    }
}
```

---

### Commit 7.2: Implement notification sending logic

Send the payment_token message to the PoS.

```rust
fn send_pos_notification(
    &self,
    encrypted_token: &[u8],
    notification_paths: &[BlindedMessagePath],
    shared_secret: &PaymentTokenSecret,
) -> Result<(), ()> {
    // Decrypt token
    let order_id = decrypt_payment_token(shared_secret, encrypted_token)?;

    // Create message
    let message = PosNotificationMessage::PaymentToken(PaymentTokenMessage {
        payment_token: order_id,
    });

    // Send via first available notification path
    for path in notification_paths {
        if self.send_onion_message(message.clone(), path.clone()).is_ok() {
            return Ok(());
        }
    }

    Err(())
}
```

---

### Commit 7.3: Implement retry mechanism

Retry notifications until ack/nack received.

```rust
/// Pending PoS notifications awaiting acknowledgment.
struct PendingPosNotification {
    payment_token: Vec<u8>,
    notification_paths: Vec<BlindedMessagePath>,
    attempts: u32,
    last_attempt: Instant,
}

// In timer_tick_occurred or similar:
fn retry_pending_notifications(&self) {
    for notification in &self.pending_pos_notifications {
        if notification.last_attempt.elapsed() > RETRY_INTERVAL {
            if notification.attempts < MAX_ATTEMPTS {
                self.send_pos_notification(&notification);
                notification.attempts += 1;
                notification.last_attempt = Instant::now();
            } else {
                // Give up, log warning
            }
        }
    }
}
```

---

## Part 8: ChannelManager Integration

**Goal**: Wire everything together at the top level.

### Commit 8.1: Add `PosNotificationHandler` to `ChannelManager`

Add the handler as a generic parameter or field.

---

### Commit 8.2: Add shared secret management

How does the Merchant know the shared secret for decryption?

```rust
/// Configuration for PoS delegation.
pub struct PosDelegationConfig {
    /// Shared secrets for each authorized PoS device.
    /// Map from PoS identifier to shared secret.
    pub pos_secrets: HashMap<Vec<u8>, PaymentTokenSecret>,
}
```

---

### Commit 8.3: Wire up payment receipt to notification flow

Connect the dots in ChannelManager.

---

### Commit 8.4: Add integration tests

Full end-to-end tests for the delegated offer flow.

```rust
#[test]
fn test_pos_delegated_offer_full_flow() {
    // 1. Merchant creates template offer
    // 2. PoS modifies with payment token
    // 3. Customer sends invoice request
    // 4. Merchant creates invoice
    // 5. Customer pays
    // 6. Merchant receives payment
    // 7. Merchant sends notification to PoS
    // 8. PoS acknowledges
}
```

---

## Summary: Commit Checklist

| Part | Commit | Description | Est. LOC |
|------|--------|-------------|----------|
| 1 | 1.1 | TLV constants for PoS fields | ~10 |
| 1 | 1.2 | Add notification_paths field | ~50 |
| 1 | 1.3 | TLV serialization for notification_paths | ~80 |
| 1 | 1.4 | Add encrypted_payment_token field | ~50 |
| 1 | 1.5 | TLV serialization for encrypted_payment_token | ~60 |
| 1 | 1.6 | OfferBuilder methods for new fields | ~40 |
| 2 | 2.1 | OfferModifier struct | ~60 |
| 2 | 2.2 | Modification methods for PoS fields | ~50 |
| 2 | 2.3 | Modification methods for common fields | ~60 |
| 2 | 2.4 | OfferModifier::build() | ~80 |
| 2 | 2.5 | Integration test for template flow | ~100 |
| 3 | 3.1 | Payment token encryption module | ~150 |
| 3 | 3.2 | Payment token tests | ~100 |
| 4 | 4.1 | PaymentTokenMessage struct | ~50 |
| 4 | 4.2 | PaymentAck/Nack messages | ~80 |
| 4 | 4.3 | PaymentProofMessage | ~60 |
| 4 | 4.4 | PosNotificationMessage enum | ~80 |
| 4 | 4.5 | OnionMessageContents impl | ~40 |
| 5 | 5.1 | PosNotificationHandler trait | ~60 |
| 5 | 5.2 | IgnoringPosNotificationHandler | ~40 |
| 5 | 5.3 | OnionMessenger integration | ~150 |
| 6 | 6.1 | DelegatedBolt12OfferContext | ~80 |
| 6 | 6.2 | Invoice creation for delegated offers | ~100 |
| 6 | 6.3 | Reply path to PoS | ~50 |
| 7 | 7.1 | Extract token on payment receipt | ~80 |
| 7 | 7.2 | Notification sending logic | ~100 |
| 7 | 7.3 | Retry mechanism | ~120 |
| 8 | 8.1 | ChannelManager handler integration | ~100 |
| 8 | 8.2 | Shared secret management | ~80 |
| 8 | 8.3 | Wire up payment receipt | ~80 |
| 8 | 8.4 | Integration tests | ~200 |

**Total estimated**: ~2,500 lines of code

---

## Review Strategy

### PR 1: Offer Extensions (Part 1)
- Commits 1.1 - 1.6
- Self-contained, just adds fields to Offer
- No behavioral changes to existing code
- **Review focus**: TLV types, field naming, API design

### PR 2: Offer Modification API (Part 2)
- Commits 2.1 - 2.5
- Enables template model
- **Review focus**: API ergonomics, validation

### PR 3: Payment Token Utilities (Part 3)
- Commits 3.1 - 3.2
- Standalone cryptographic utilities
- **Review focus**: Crypto correctness, API safety

### PR 4: New Onion Messages (Parts 4-5)
- Commits 4.1 - 5.3
- New message types and handler trait
- **Review focus**: Message format, handler design

### PR 5: Invoice & Payment Flow (Parts 6-7)
- Commits 6.1 - 7.3
- Core integration
- **Review focus**: Correctness, error handling

### PR 6: Final Integration (Part 8)
- Commits 8.1 - 8.4
- Top-level wiring
- **Review focus**: API completeness, documentation

---

## Open Questions for LDK Maintainers

1. **TLV type allocation**: Should we use experimental range or request formal allocation?

2. **Feature flag**: Should this be behind a feature flag initially?

3. **OnionMessenger generics**: Adding another handler type increases complexity. Is there a better pattern?

4. **PaymentContext variant**: Is adding `DelegatedBolt12OfferContext` the right approach, or should we extend `Bolt12OfferContext`?

5. **Shared secret management**: How should the Merchant manage secrets for multiple PoS devices?

6. **Retry strategy**: What retry parameters make sense for notifications?
