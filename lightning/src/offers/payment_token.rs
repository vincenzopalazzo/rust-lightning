// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Cryptographic primitives for the BLIP-0056 PoS-delegated payment token and the merchant's
//! notification signature.
//!
//! BLIP-0056 (BOLT 12 PoS notifications) extends BOLT 12 offers with two experimental TLV
//! records that allow a point-of-sale (PoS) device to extend a merchant's template offer with
//! per-order data:
//!
//! - `notification_paths`: blinded message paths the merchant uses to deliver a payment
//!   notification to the PoS once the customer's payment is claimed.
//! - `payment_token`: opaque bytes used by the merchant to correlate an incoming
//!   `invoice_request` with a PoS-side order.
//!
//! This module defines the **payment token** as a tagged hash of PoS-private order information
//! (an order id, a merchant-known nonce, anything the PoS chooses) and provides the
//! sign/verify primitives that the merchant uses to authenticate a `payment_notification` onion
//! message to the PoS.
//!
//! # Token shape
//!
//! ```text
//! payment_token = tagged_hash("LDK/PoS/order_v1", order_info)
//! ```
//!
//! The 32-byte hash is what the PoS embeds in the offer's experimental `payment_token` TLV.
//! Customers do not interpret it; the merchant verifies it against its own order book.
//!
//! # Notification signature
//!
//! The merchant signs the digest
//!
//! ```text
//! signature = schnorr_sign(
//!     issuer_priv,
//!     tagged_hash("LDK/PoS/notification_v1", order_hash || payment_hash || amount_msat_be),
//! )
//! ```
//!
//! when emitting the `payment_notification`. The PoS verifies the signature against the
//! merchant's offer issuer pubkey, which it already knows from the template offer.
//!
//! Wire-format types and serialization for the notification message live in
//! `crate::onion_message::pos_notification` (added by a later patch in the BLIP-0056 stack).

use crate::types::payment::PaymentHash;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{
	self, Keypair, Message, PublicKey, Secp256k1, Signing, Verification, XOnlyPublicKey,
};

/// Tag used when computing the order hash from PoS-private order information.
const PAYMENT_TOKEN_TAG: &str = "LDK/PoS/order_v1";

/// Tag used when computing the digest signed in a payment notification.
const PAYMENT_NOTIFICATION_TAG: &str = "LDK/PoS/notification_v1";

/// A 32-byte payment token attached to a BLIP-0056 PoS-delegated offer's experimental
/// `payment_token` TLV.
///
/// The token is a tagged SHA-256 hash of arbitrary PoS-private order information, opaque to the
/// customer and to LDK. Its only requirement is that the merchant can recompute (or look up) the
/// hash from its own order book in order to authenticate an incoming `invoice_request`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PaymentToken {
	order_hash: [u8; 32],
}

impl PaymentToken {
	/// Computes a payment token from arbitrary PoS-private order information by domain-separated
	/// tagged hashing.
	///
	/// The PoS must store the same `order_info` (or an equivalent canonicalisation) so the
	/// merchant can re-derive the hash when an `invoice_request` arrives.
	pub fn from_order_info(order_info: &[u8]) -> Self {
		Self { order_hash: tagged_hash(PAYMENT_TOKEN_TAG, &[order_info]).to_byte_array() }
	}

	/// Wraps a previously computed 32-byte order hash. Use this when the merchant looks up an
	/// order hash in its order book without recomputing the underlying tagged hash.
	pub fn from_order_hash(order_hash: [u8; 32]) -> Self {
		Self { order_hash }
	}

	/// Returns the 32-byte order hash that should be embedded in the offer's `payment_token`
	/// TLV.
	pub fn order_hash(&self) -> &[u8; 32] {
		&self.order_hash
	}
}

/// The fields of a BLIP-0056 `payment_notification` that the merchant signs and the PoS
/// verifies.
///
/// The triple `(order_hash, payment_hash, amount_msat)` binds the signature to the specific
/// claim event and prevents a captured signature from being replayed against a different
/// payment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentNotificationDigest {
	order_hash: [u8; 32],
	payment_hash: PaymentHash,
	amount_msat: u64,
}

impl PaymentNotificationDigest {
	/// Constructs the digest from its components.
	pub fn new(order_hash: [u8; 32], payment_hash: PaymentHash, amount_msat: u64) -> Self {
		Self { order_hash, payment_hash, amount_msat }
	}

	/// Returns the order hash component.
	pub fn order_hash(&self) -> &[u8; 32] {
		&self.order_hash
	}

	/// Returns the payment hash component.
	pub fn payment_hash(&self) -> PaymentHash {
		self.payment_hash
	}

	/// Returns the amount component, in millisatoshi.
	pub fn amount_msat(&self) -> u64 {
		self.amount_msat
	}

	/// Computes the 32-byte tagged hash that the merchant signs.
	fn message_hash(&self) -> [u8; 32] {
		tagged_hash(
			PAYMENT_NOTIFICATION_TAG,
			&[&self.order_hash[..], &self.payment_hash.0[..], &self.amount_msat.to_be_bytes()[..]],
		)
		.to_byte_array()
	}

	/// Signs the digest with the merchant's offer issuer keypair.
	pub fn sign<T: Signing>(&self, keypair: &Keypair, secp_ctx: &Secp256k1<T>) -> Signature {
		let message = Message::from_digest(self.message_hash());
		secp_ctx.sign_schnorr_no_aux_rand(&message, keypair)
	}

	/// Verifies a Schnorr `signature` over this digest against the merchant's offer issuer
	/// pubkey.
	pub fn verify<T: Verification>(
		&self, signature: &Signature, pubkey: &PublicKey, secp_ctx: &Secp256k1<T>,
	) -> Result<(), secp256k1::Error> {
		let message = Message::from_digest(self.message_hash());
		let xonly = XOnlyPublicKey::from(*pubkey);
		secp_ctx.verify_schnorr(signature, &message, &xonly)
	}
}

/// Computes a BIP-340-style tagged hash over the concatenation of `chunks`.
fn tagged_hash(tag: &str, chunks: &[&[u8]]) -> sha256::Hash {
	let tag_hash = sha256::Hash::hash(tag.as_bytes());
	let mut engine = sha256::Hash::engine();
	engine.input(tag_hash.as_ref());
	engine.input(tag_hash.as_ref());
	for chunk in chunks {
		engine.input(chunk);
	}
	sha256::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	fn keypair_from(seed: u8) -> Keypair {
		let secp = Secp256k1::new();
		Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
	}

	#[test]
	fn payment_token_is_deterministic() {
		let a = PaymentToken::from_order_info(b"order-42");
		let b = PaymentToken::from_order_info(b"order-42");
		assert_eq!(a, b);

		let c = PaymentToken::from_order_info(b"order-43");
		assert_ne!(a, c);
	}

	#[test]
	fn payment_token_is_domain_separated() {
		// A naive sha256(order_info) would collide with the tagged hash for an attacker who
		// can choose a colliding input; tagged hashing makes that infeasible.
		let token = PaymentToken::from_order_info(b"hello");
		let bare_sha = sha256::Hash::hash(b"hello");
		assert_ne!(token.order_hash(), bare_sha.as_byte_array());
	}

	#[test]
	fn from_order_hash_is_a_passthrough_of_bytes() {
		let raw = [9u8; 32];
		let token = PaymentToken::from_order_hash(raw);
		assert_eq!(token.order_hash(), &raw);
	}

	#[test]
	fn payment_notification_signature_round_trips() {
		let secp = Secp256k1::new();
		let merchant = keypair_from(7);

		let digest = PaymentNotificationDigest::new([42u8; 32], PaymentHash([1u8; 32]), 20_000);

		let signature = digest.sign(&merchant, &secp);
		digest.verify(&signature, &merchant.public_key(), &secp).expect("signature verifies");
	}

	#[test]
	fn payment_notification_signature_does_not_validate_against_wrong_pubkey() {
		let secp = Secp256k1::new();
		let merchant = keypair_from(7);
		let attacker = keypair_from(8);

		let digest = PaymentNotificationDigest::new([42u8; 32], PaymentHash([1u8; 32]), 20_000);
		let signature = digest.sign(&merchant, &secp);

		assert!(digest.verify(&signature, &attacker.public_key(), &secp).is_err());
	}

	#[test]
	fn payment_notification_signature_does_not_validate_against_tampered_fields() {
		let secp = Secp256k1::new();
		let merchant = keypair_from(7);

		let digest = PaymentNotificationDigest::new([42u8; 32], PaymentHash([1u8; 32]), 20_000);
		let signature = digest.sign(&merchant, &secp);

		// Tampering with order_hash invalidates the signature.
		let tampered_order =
			PaymentNotificationDigest::new([43u8; 32], PaymentHash([1u8; 32]), 20_000);
		assert!(tampered_order.verify(&signature, &merchant.public_key(), &secp).is_err());

		// Tampering with payment_hash invalidates the signature.
		let tampered_payment =
			PaymentNotificationDigest::new([42u8; 32], PaymentHash([2u8; 32]), 20_000);
		assert!(tampered_payment.verify(&signature, &merchant.public_key(), &secp).is_err());

		// Tampering with amount_msat invalidates the signature.
		let tampered_amount =
			PaymentNotificationDigest::new([42u8; 32], PaymentHash([1u8; 32]), 20_001);
		assert!(tampered_amount.verify(&signature, &merchant.public_key(), &secp).is_err());
	}

	#[test]
	fn payment_notification_tag_differs_from_token_tag() {
		// Domain separation: signing a digest whose components match an order hash must NOT
		// produce a signature that can be confused with one over the same bytes under a
		// different domain.
		let secp = Secp256k1::new();
		let merchant = keypair_from(7);

		let order_hash = [42u8; 32];
		let digest = PaymentNotificationDigest::new(order_hash, PaymentHash([0u8; 32]), 0);
		let signature = digest.sign(&merchant, &secp);

		// A would-be confused-deputy attempt: someone holding only the order_hash should not
		// be able to forge a notification by signing the order_hash directly under any
		// tagged hash. Verification against the digest computed from those components fails.
		let mut wrong_engine = sha256::Hash::engine();
		wrong_engine.input(b"some-other-tag");
		wrong_engine.input(&order_hash);
		let wrong_message =
			Message::from_digest(sha256::Hash::from_engine(wrong_engine).to_byte_array());
		let xonly = XOnlyPublicKey::from(merchant.public_key());
		assert!(secp.verify_schnorr(&signature, &wrong_message, &xonly).is_err());
	}
}
