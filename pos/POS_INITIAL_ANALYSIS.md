# PoS-Delegated BOLT 12 Offer Creation - Initial Analysis

## 1. Problem Statement

The proposal addresses a real-world use case where:
- **Merchant** runs an always-online Lightning node with channels (receives payments)
- **Point-of-Sale (PoS)** is a device that needs to display offers and track orders, but has **no channels** (can't receive payments directly)
- **Customer** pays via Lightning

**Goal**: Allow the PoS to create offers that route payments to the merchant, while maintaining order tracking and payment confirmation.

---

## 2. Current BOLT 12 Architecture vs. Proposal

### Current BOLT 12 Flow:
```
Customer → [invreq via offer.paths] → Merchant
Customer ← [invoice via reply_path] ← Merchant
Customer → [payment via invoice_paths] → Merchant
```

### Proposed Delegated Flow:
```
                ┌─────────────────────────────────────────┐
                │                OFFER                     │
                │  - paths: blinded to Merchant            │
                │  - notification_paths: blinded to PoS    │
                │  - node_id: derived(shared_secret)       │
                │  - encrypted_payment_token: Enc(order_id)│
                └─────────────────────────────────────────┘
                              │ (QR Code)
                              ▼
┌──────────┐    invreq     ┌──────────┐
│ Customer │ ────────────► │ Merchant │
└──────────┘               └──────────┘
      │                         │
      │    invoice              │
      │ ◄───────────────────────┤
      │   (reply_path → PoS)    │
      │                         │
      │    payment              │
      │ ────────────────────────►
      │                         │
      │                         │ payment_token (onion msg)
      │                     ┌───────┐
      │                     │  PoS  │
      │                     └───────┘
      │                         │
      │                         │ payment_[n]ack
      │                     ┌──────────┐
      │ ◄─────────────────── │ Merchant │
      │  (optional)          └──────────┘
      │
      │ payment_proof (optional)
      │ ─────────────────────────────────►  PoS
```

---

## 3. New Components Required

### A. New Offer TLV Fields

| Field | Type | Description |
|-------|------|-------------|
| `offer_notification_paths` | `Vec<BlindedMessagePath>` | Blinded paths to the PoS for payment notifications |
| `offer_encrypted_payment_token` | `Vec<u8>` | Payment token (order ID) encrypted with shared secret |

These should use the **experimental TLV range** (1000000000-1999999999) initially:

```rust
// Proposed TLV types (experimental range)
const OFFER_NOTIFICATION_PATHS_TYPE: u64 = 1_000_000_000;
const OFFER_ENCRYPTED_PAYMENT_TOKEN_TYPE: u64 = 1_000_000_002;
```

### B. Shared Secret Key Derivation

The `node_id` (issuer signing pubkey) must be derived such that:
1. PoS can compute it (to put in offer)
2. Merchant knows the private key (to sign invoices)

**Proposed scheme:**
```rust
// Setup: PoS and Merchant share a secret via out-of-band means
shared_secret: [u8; 32] = ...

// Key derivation (both PoS and Merchant compute):
signing_pubkey = derive_pubkey(shared_secret, "bolt12-delegated-signing")

// Only Merchant knows:
signing_privkey = derive_privkey(shared_secret, "bolt12-delegated-signing")
```

Alternatively, using tweaking:
```rust
// Merchant provides base pubkey to PoS
tweak = HMAC-SHA256(shared_secret, order_id)
delegated_pubkey = merchant_base_pubkey + tweak * G
// Merchant can sign with: merchant_base_privkey + tweak
```

### C. New Onion Message Types

```rust
pub enum PosNotificationMessage {
    /// Merchant → PoS: Payment received
    PaymentToken(PaymentTokenMessage),

    /// PoS → Merchant: Acknowledgment
    PaymentAck(PaymentAckMessage),
    PaymentNack(PaymentNackMessage),

    /// Customer → PoS: Optional payment proof
    PaymentProof(PaymentProofMessage),
}

pub struct PaymentTokenMessage {
    payment_token: Vec<u8>,  // Decrypted order ID
}

pub struct PaymentAckMessage {
    payment_token: Vec<u8>,
}

pub struct PaymentNackMessage {
    payment_token: Vec<u8>,
    reason: Option<String>,
}

pub struct PaymentProofMessage {
    preimage: PaymentPreimage,
    invoice: Bolt12Invoice,
}
```

**Proposed TLV types** (in experimental range or new message namespace):
```rust
const PAYMENT_TOKEN_TLV_TYPE: u64 = 72;      // Or experimental range
const PAYMENT_ACK_TLV_TYPE: u64 = 74;
const PAYMENT_NACK_TLV_TYPE: u64 = 76;
const PAYMENT_PROOF_TLV_TYPE: u64 = 78;
```

---

## 4. Mapping to rust-lightning Implementation

### A. Extending `OfferContents`

In `lightning/src/offers/offer.rs`:

```rust
pub(super) struct OfferContents {
    // ... existing fields ...

    // NEW: Notification paths to PoS
    notification_paths: Option<Vec<BlindedMessagePath>>,

    // NEW: Encrypted payment token
    encrypted_payment_token: Option<Vec<u8>>,
}
```

### B. Extending `OfferBuilder`

```rust
impl OfferBuilder {
    /// Sets notification paths to the PoS for payment confirmations
    pub fn notification_paths(mut self, paths: Vec<BlindedMessagePath>) -> Self {
        self.offer.notification_paths = Some(paths);
        self
    }

    /// Sets the encrypted payment token (order ID)
    pub fn encrypted_payment_token(mut self, token: Vec<u8>) -> Self {
        self.offer.encrypted_payment_token = Some(token);
        self
    }
}
```

### C. Invoice Reply Path Modification

The invoice must include a reply path to the PoS (not just the Merchant). In `InvoiceBuilder`:

```rust
// When building invoice for delegated offer:
let invoice = invoice_request
    .respond_with(payment_paths, payment_hash)?
    // Reply path should go to PoS (from notification_paths)
    .build_with_notification_reply_path(pos_notification_path)?;
```

### D. New Message Handler

```rust
pub trait PosNotificationHandler {
    /// Called when merchant receives payment for delegated offer
    fn handle_payment_received(
        &self,
        payment_token: PaymentTokenMessage,
        reply_path: BlindedMessagePath,
    ) -> Result<(), ()>;

    /// Called at PoS when receiving payment confirmation
    fn handle_payment_token(
        &self,
        token: PaymentTokenMessage,
    ) -> Result<PaymentAckMessage, PaymentNackMessage>;

    /// Called at PoS when customer sends proof
    fn handle_payment_proof(
        &self,
        proof: PaymentProofMessage,
    ) -> Result<PaymentAckMessage, PaymentNackMessage>;
}
```

---

## 5. Security Considerations

### A. Payment Token Encryption

The encrypted payment token prevents:
- Customers from forging order IDs
- Third parties from correlating orders

**Encryption scheme:**
```rust
// At PoS (encryption):
nonce = random_bytes(12);
ciphertext = ChaCha20Poly1305.encrypt(
    key = shared_secret,
    nonce = nonce,
    plaintext = order_id,
    aad = offer_id  // Bind to this specific offer
);
encrypted_payment_token = nonce || ciphertext;

// At Merchant (decryption):
(nonce, ciphertext) = split(encrypted_payment_token);
order_id = ChaCha20Poly1305.decrypt(
    key = shared_secret,
    nonce = nonce,
    ciphertext = ciphertext,
    aad = offer_id
);
```

### B. Signing Key Security

The delegated signing key must be:
1. **Deterministic**: Both PoS and Merchant derive the same pubkey
2. **Unique per offer**: Prevents correlation across offers
3. **Only merchant knows privkey**: PoS only has pubkey

```rust
// Deterministic key derivation with per-offer uniqueness:
offer_seed = HMAC-SHA256(shared_secret, "offer" || offer_metadata);
signing_privkey = derive_key(offer_seed);
signing_pubkey = signing_privkey * G;
```

### C. Replay Protection

Payment tokens should include:
- Timestamp or expiry
- Unique nonce per order
- Offer ID binding

---

## 6. Implementation Approach in rust-lightning

### Phase 1: Core Data Structures

1. Add new TLV fields to `OfferContents`
2. Extend TLV serialization/deserialization
3. Update `OfferBuilder` with new methods

### Phase 2: Key Derivation

1. Create `DelegatedKeyManager` trait
2. Implement shared secret-based key derivation
3. Integrate with `ExpandedKey` for key management

### Phase 3: New Onion Messages

1. Define new message types in `onion_message/`
2. Create `PosNotificationHandler` trait
3. Implement message routing through `OffersMessageFlow`

### Phase 4: Flow Integration

1. Extend `ChannelManager` to handle delegated offers
2. Implement notification sending on payment receipt
3. Add retry logic for acknowledgments

---

## 7. Key Technical Challenges

| Challenge | Solution |
|-----------|----------|
| PoS has no channels | Uses onion messages through blinded paths via Merchant or other nodes |
| Merchant needs to sign for PoS-created offers | Shared secret key derivation |
| Order tracking | Encrypted payment token passed through invoice payment paths |
| Reliability | Retry mechanism with ack/nack |
| Privacy | Blinded paths hide PoS identity from customers |

---

## 8. Questions for Spec Clarification

1. **TLV type allocation**: Should notification_paths and encrypted_payment_token use experimental range or get formal type assignments?

2. **Payment token in payment path**: How exactly is the encrypted token embedded in `BlindedPaymentPath`? Via `PaymentContext`?

3. **Reply path construction**: Who constructs the reply path in the invoice - Merchant or derived from offer's notification_paths?

4. **Static vs per-order offers**: Can one offer be reused for multiple orders, or is each order a new offer?

5. **Error handling**: What happens if PoS is offline when payment_token arrives?

---

## 9. References

- [BOLT 12 Specification](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- rust-lightning offers implementation: `lightning/src/offers/`
- rust-lightning blinded paths: `lightning/src/blinded_path/`
- rust-lightning onion messages: `lightning/src/onion_message/`
