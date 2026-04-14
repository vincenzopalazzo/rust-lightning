// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for encrypting and decrypting payment tokens in PoS-delegated offers.
//!
//! Payment tokens are merchant-readable encrypted payloads used for pre-payment
//! validation of delegated offers. Order correlation data lives in the
//! notification path context and is only readable by the PoS.
//!
//! # Overview
//!
//! In the current PoS delegation flow:
//! 1. The merchant shares a delegated offer template with the PoS
//! 2. The PoS adds the final amount, description, and notification path(s)
//! 3. The PoS encrypts a validation payload to the template offer's signing pubkey
//! 4. The encrypted token is placed in the offer's `encrypted_payment_token` field
//! 5. The merchant decrypts the token using the corresponding delegation secret key
//! 6. The merchant uses the decrypted payload to validate the delegated invoice request
//!
//! # Example
//!
//! ```
//! use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::payment_token::{
//!     decrypt_payment_token_payload_with_secret_key, encrypt_payment_token_payload_to_pubkey,
//!     PaymentTokenPayload,
//! };
//!
//! let secp_ctx = Secp256k1::new();
//! let secret_key = SecretKey::from_slice(&[42u8; 32]).unwrap();
//! let public_key = PublicKey::from_secret_key(&secp_ctx, &secret_key);
//!
//! // PoS encrypts the committed delegated-offer fields.
//! let entropy = [1u8; 32]; // Should be random in production
//! let payload = PaymentTokenPayload {
//!     amount_msats: 50_000,
//!     description: "coffee, large".to_string(),
//! };
//! let encrypted_token =
//!     encrypt_payment_token_payload_to_pubkey(&public_key, &payload, &entropy);
//!
//! // Merchant decrypts the token when the delegated invoice request arrives.
//! let decrypted_payload =
//!     decrypt_payment_token_payload_with_secret_key(&secret_key, &encrypted_token).unwrap();
//! assert_eq!(decrypted_payload, payload);
//! ```

use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;
use crate::io;
use crate::prelude::*;
use crate::util::ser::{Readable, Writeable, Writer};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

/// The length of the shared secret for payment token encryption.
pub const SHARED_SECRET_LEN: usize = 32;

/// The length of the nonce for ChaCha20Poly1305.
const NONCE_LEN: usize = 12;

/// The length of the authentication tag.
const TAG_LEN: usize = 16;

/// The length of a compressed secp256k1 public key.
const PUBKEY_LEN: usize = 33;

/// The length of the random bytes used for nonce derivation.
const RANDOM_BYTES_LEN: usize = 32;

/// A shared secret between the PoS and Merchant for payment token encryption.
///
/// This secret should be established out-of-band between the merchant and PoS
/// device, for example during initial PoS setup.
#[derive(Clone, PartialEq, Eq)]
pub struct PaymentTokenSecret([u8; SHARED_SECRET_LEN]);

impl PaymentTokenSecret {
	/// Creates a new payment token secret from bytes.
	pub fn from_bytes(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
		Self(bytes)
	}

	/// Returns the secret as a byte array reference.
	pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
		&self.0
	}
}

impl core::fmt::Debug for PaymentTokenSecret {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		// Don't leak the secret in debug output
		f.debug_struct("PaymentTokenSecret").field("inner", &"[REDACTED]").finish()
	}
}

impl Writeable for PaymentTokenSecret {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.0.write(writer)
	}
}

impl Readable for PaymentTokenSecret {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		let bytes: [u8; SHARED_SECRET_LEN] = Readable::read(reader)?;
		Ok(Self(bytes))
	}
}

/// A structured payment token payload that commits to the delegated-offer fields
/// the merchant must validate before issuing an invoice.
///
/// By encrypting this payload, the PoS can commit to the expected amount and
/// description without revealing them to the customer in a merchant-readable form.
/// The encrypted payload is placed in the offer's `encrypted_payment_token` field.
///
/// # Fields
/// - `amount_msats`: The amount committed in the offer
/// - `description`: The order description committed in the offer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentTokenPayload {
	/// The amount in millisatoshis that the delegated offer should charge.
	///
	/// LDK currently only supports Bitcoin-denominated delegated offers, so the
	/// committed amount is expressed in millisatoshis.
	pub amount_msats: u64,
	/// The delegated offer description committed by the PoS.
	pub description: String,
}

impl_writeable_tlv_based!(PaymentTokenPayload, {
	(0, amount_msats, required),
	(2, description, required),
});

/// Encrypts a [`PaymentTokenPayload`] using the shared secret.
///
/// This is a convenience wrapper that serializes the payload via `Writeable::encode()`
/// and then encrypts the resulting bytes using [`encrypt_payment_token`].
pub fn encrypt_payment_token_payload(
	secret: &PaymentTokenSecret, payload: &PaymentTokenPayload, entropy: &[u8],
) -> Vec<u8> {
	let serialized = payload.encode();
	encrypt_payment_token(secret, &serialized, entropy)
}

/// Decrypts an encrypted token and parses it as a [`PaymentTokenPayload`].
///
/// # Errors
/// Returns [`PaymentTokenError::DecryptionFailed`] if the token cannot be decrypted,
/// or [`PaymentTokenError::InvalidPayload`] if the decrypted bytes cannot be parsed
/// as a valid `PaymentTokenPayload`.
pub fn decrypt_payment_token_payload(
	secret: &PaymentTokenSecret, encrypted_token: &[u8],
) -> Result<PaymentTokenPayload, PaymentTokenError> {
	let plaintext = decrypt_payment_token(secret, encrypted_token)?;
	let mut cursor = io::Cursor::new(&plaintext);
	<PaymentTokenPayload as Readable>::read(&mut cursor)
		.map_err(|_| PaymentTokenError::InvalidPayload)
}

/// Derives a nonce from the secret and random bytes.
///
/// The nonce format is `[0, 0, 0, 0, hmac[0..8]]` to satisfy the ChaCha20Poly1305RFC
/// requirement that the first 4 bytes of the nonce must be zero.
fn derive_nonce(secret: &PaymentTokenSecret, random_bytes: &[u8]) -> [u8; NONCE_LEN] {
	let key_hash = Sha256::hash(secret.as_bytes());
	let mut hmac = HmacEngine::<Sha256>::new(key_hash.as_byte_array());
	hmac.input(random_bytes);

	let mut nonce = [0u8; NONCE_LEN];
	// First 4 bytes must be 0 for ChaCha20Poly1305RFC
	nonce[4..].copy_from_slice(&Hmac::from_engine(hmac).to_byte_array()[0..8]);
	nonce
}

fn derive_ephemeral_secret(entropy: &[u8]) -> SecretKey {
	assert!(entropy.len() >= RANDOM_BYTES_LEN, "entropy must be at least 32 bytes");

	let mut candidate = Sha256::hash(&entropy[..RANDOM_BYTES_LEN]).to_byte_array();
	loop {
		if let Ok(secret_key) = SecretKey::from_slice(&candidate) {
			return secret_key;
		}
		candidate = Sha256::hash(&candidate).to_byte_array();
	}
}

fn derive_nonce_from_key_material(key: &[u8; 32], associated_data: &[u8]) -> [u8; NONCE_LEN] {
	let mut hmac = HmacEngine::<Sha256>::new(key);
	hmac.input(associated_data);

	let mut nonce = [0u8; NONCE_LEN];
	nonce[4..].copy_from_slice(&Hmac::from_engine(hmac).to_byte_array()[0..8]);
	nonce
}

fn derive_cipher_material(
	shared_secret: &SharedSecret, associated_data: &[u8],
) -> ([u8; 32], [u8; NONCE_LEN]) {
	let encryption_key = Sha256::hash(shared_secret.as_ref()).to_byte_array();
	let nonce = derive_nonce_from_key_material(&encryption_key, associated_data);
	(encryption_key, nonce)
}

/// Encrypts a payment token using the merchant's delegated-offer public key.
///
/// The output format is: `ephemeral_pubkey (33 bytes) || ciphertext || tag (16 bytes)`.
pub fn encrypt_payment_token_to_pubkey(
	recipient_pubkey: &PublicKey, plaintext: &[u8], entropy: &[u8],
) -> Vec<u8> {
	let secp_ctx = Secp256k1::new();
	let ephemeral_secret = derive_ephemeral_secret(entropy);
	let ephemeral_pubkey = PublicKey::from_secret_key(&secp_ctx, &ephemeral_secret);
	let shared_secret = SharedSecret::new(recipient_pubkey, &ephemeral_secret);
	let ephemeral_pubkey_bytes = ephemeral_pubkey.serialize();
	let (encryption_key, nonce) = derive_cipher_material(&shared_secret, &ephemeral_pubkey_bytes);

	let mut chacha = ChaCha20Poly1305RFC::new(&encryption_key, &nonce, &[]);
	let mut ciphertext = plaintext.to_vec();
	let mut tag = [0u8; TAG_LEN];
	chacha.encrypt_full_message_in_place(&mut ciphertext, &mut tag);

	let mut result = Vec::with_capacity(PUBKEY_LEN + ciphertext.len() + TAG_LEN);
	result.extend_from_slice(&ephemeral_pubkey_bytes);
	result.extend_from_slice(&ciphertext);
	result.extend_from_slice(&tag);
	result
}

/// Decrypts a payment token encrypted to the merchant's delegated-offer public key.
pub fn decrypt_payment_token_with_secret_key(
	recipient_secret_key: &SecretKey, encrypted_token: &[u8],
) -> Result<Vec<u8>, PaymentTokenError> {
	if encrypted_token.len() < PUBKEY_LEN + TAG_LEN {
		return Err(PaymentTokenError::InvalidLength);
	}

	let ephemeral_pubkey = PublicKey::from_slice(&encrypted_token[..PUBKEY_LEN])
		.map_err(|_| PaymentTokenError::DecryptionFailed)?;
	let ciphertext_and_tag = &encrypted_token[PUBKEY_LEN..];
	let ciphertext_len = ciphertext_and_tag.len() - TAG_LEN;

	let shared_secret = SharedSecret::new(&ephemeral_pubkey, recipient_secret_key);
	let (encryption_key, nonce) =
		derive_cipher_material(&shared_secret, &encrypted_token[..PUBKEY_LEN]);

	let mut chacha = ChaCha20Poly1305RFC::new(&encryption_key, &nonce, &[]);
	let mut plaintext = ciphertext_and_tag[..ciphertext_len].to_vec();
	let tag = &ciphertext_and_tag[ciphertext_len..];

	match chacha.check_decrypt_in_place(&mut plaintext, tag) {
		Ok(()) => Ok(plaintext),
		Err(()) => Err(PaymentTokenError::DecryptionFailed),
	}
}

/// Encrypts a structured [`PaymentTokenPayload`] to the merchant's delegated-offer public key.
pub fn encrypt_payment_token_payload_to_pubkey(
	recipient_pubkey: &PublicKey, payload: &PaymentTokenPayload, entropy: &[u8],
) -> Vec<u8> {
	let serialized = payload.encode();
	encrypt_payment_token_to_pubkey(recipient_pubkey, &serialized, entropy)
}

/// Decrypts an encrypted token using the merchant's delegated-offer secret key and parses it as a
/// [`PaymentTokenPayload`].
pub fn decrypt_payment_token_payload_with_secret_key(
	recipient_secret_key: &SecretKey, encrypted_token: &[u8],
) -> Result<PaymentTokenPayload, PaymentTokenError> {
	let plaintext = decrypt_payment_token_with_secret_key(recipient_secret_key, encrypted_token)?;
	let mut cursor = io::Cursor::new(&plaintext);
	<PaymentTokenPayload as Readable>::read(&mut cursor)
		.map_err(|_| PaymentTokenError::InvalidPayload)
}

/// Encrypts a payment token (order ID) using the shared secret.
///
/// The output format is: `random_bytes (32 bytes) || ciphertext || tag (16 bytes)`
///
/// # Arguments
/// * `secret` - The shared secret between PoS and Merchant
/// * `order_id` - The plaintext order identifier
/// * `entropy` - Random bytes for nonce derivation (at least 32 bytes)
///
/// # Panics
/// Panics if `entropy` is less than 32 bytes.
pub fn encrypt_payment_token(
	secret: &PaymentTokenSecret, order_id: &[u8], entropy: &[u8],
) -> Vec<u8> {
	assert!(entropy.len() >= RANDOM_BYTES_LEN, "entropy must be at least 32 bytes");

	let random_bytes: [u8; RANDOM_BYTES_LEN] = entropy[..RANDOM_BYTES_LEN].try_into().unwrap();
	let nonce = derive_nonce(secret, &random_bytes);

	let mut chacha = ChaCha20Poly1305RFC::new(secret.as_bytes(), &nonce, &[]);

	let mut ciphertext = order_id.to_vec();
	let mut tag = [0u8; TAG_LEN];
	chacha.encrypt_full_message_in_place(&mut ciphertext, &mut tag);

	// Output format: random_bytes || ciphertext || tag
	let mut result = Vec::with_capacity(RANDOM_BYTES_LEN + ciphertext.len() + TAG_LEN);
	result.extend_from_slice(&random_bytes);
	result.extend_from_slice(&ciphertext);
	result.extend_from_slice(&tag);
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
	secret: &PaymentTokenSecret, encrypted_token: &[u8],
) -> Result<Vec<u8>, PaymentTokenError> {
	// Minimum length: random_bytes (32) + tag (16) = 48 bytes
	// (ciphertext can be 0 bytes for empty order IDs, though that's unusual)
	if encrypted_token.len() < RANDOM_BYTES_LEN + TAG_LEN {
		return Err(PaymentTokenError::InvalidLength);
	}

	let random_bytes = &encrypted_token[..RANDOM_BYTES_LEN];
	let ciphertext_and_tag = &encrypted_token[RANDOM_BYTES_LEN..];
	let ciphertext_len = ciphertext_and_tag.len() - TAG_LEN;

	let nonce = derive_nonce(secret, random_bytes);
	let mut chacha = ChaCha20Poly1305RFC::new(secret.as_bytes(), &nonce, &[]);

	let mut plaintext = ciphertext_and_tag[..ciphertext_len].to_vec();
	let tag = &ciphertext_and_tag[ciphertext_len..];

	match chacha.check_decrypt_in_place(&mut plaintext, tag) {
		Ok(()) => Ok(plaintext),
		Err(()) => Err(PaymentTokenError::DecryptionFailed),
	}
}

/// Errors that can occur when working with payment tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentTokenError {
	/// The encrypted token is too short to contain valid data.
	InvalidLength,
	/// Decryption failed due to invalid secret or corrupted data.
	DecryptionFailed,
	/// The decrypted bytes could not be parsed as a valid [`PaymentTokenPayload`].
	InvalidPayload,
}

impl core::fmt::Display for PaymentTokenError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			PaymentTokenError::InvalidLength => {
				write!(f, "encrypted payment token is too short")
			},
			PaymentTokenError::DecryptionFailed => {
				write!(f, "payment token decryption failed")
			},
			PaymentTokenError::InvalidPayload => {
				write!(f, "decrypted payment token is not a valid payload")
			},
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for PaymentTokenError {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encrypt_decrypt_roundtrip() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let order_id = b"order:12345";
		let entropy = [1u8; 32];

		let encrypted = encrypt_payment_token(&secret, order_id, &entropy);
		let decrypted = decrypt_payment_token(&secret, &encrypted).unwrap();

		assert_eq!(decrypted, order_id);
	}

	#[test]
	fn encrypt_decrypt_empty_order_id() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let order_id = b"";
		let entropy = [1u8; 32];

		let encrypted = encrypt_payment_token(&secret, order_id, &entropy);
		let decrypted = decrypt_payment_token(&secret, &encrypted).unwrap();

		assert_eq!(decrypted, order_id);
	}

	#[test]
	fn encrypt_decrypt_long_order_id() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let order_id = b"this-is-a-very-long-order-id-with-lots-of-data-1234567890";
		let entropy = [1u8; 32];

		let encrypted = encrypt_payment_token(&secret, order_id, &entropy);
		let decrypted = decrypt_payment_token(&secret, &encrypted).unwrap();

		assert_eq!(decrypted, order_id);
	}

	#[test]
	fn different_entropy_produces_different_ciphertext() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let order_id = b"order:12345";

		let encrypted1 = encrypt_payment_token(&secret, order_id, &[1u8; 32]);
		let encrypted2 = encrypt_payment_token(&secret, order_id, &[2u8; 32]);

		// Different entropy should produce different ciphertext
		assert_ne!(encrypted1, encrypted2);

		// But both should decrypt to the same plaintext
		assert_eq!(
			decrypt_payment_token(&secret, &encrypted1).unwrap(),
			decrypt_payment_token(&secret, &encrypted2).unwrap()
		);
	}

	#[test]
	fn different_secrets_fail() {
		let secret1 = PaymentTokenSecret::from_bytes([1u8; 32]);
		let secret2 = PaymentTokenSecret::from_bytes([2u8; 32]);
		let order_id = b"order:12345";
		let entropy = [0u8; 32];

		let encrypted = encrypt_payment_token(&secret1, order_id, &entropy);
		let result = decrypt_payment_token(&secret2, &encrypted);

		assert_eq!(result, Err(PaymentTokenError::DecryptionFailed));
	}

	#[test]
	fn encrypt_decrypt_roundtrip_with_pubkey() {
		let secp_ctx = Secp256k1::new();
		let recipient_secret_key = SecretKey::from_slice(&[3u8; 32]).unwrap();
		let recipient_pubkey = PublicKey::from_secret_key(&secp_ctx, &recipient_secret_key);
		let order_id = b"order:pubkey";
		let entropy = [9u8; 32];

		let encrypted = encrypt_payment_token_to_pubkey(&recipient_pubkey, order_id, &entropy);
		let decrypted =
			decrypt_payment_token_with_secret_key(&recipient_secret_key, &encrypted).unwrap();

		assert_eq!(decrypted, order_id);
	}

	#[test]
	fn pubkey_encryption_fails_with_wrong_secret_key() {
		let secp_ctx = Secp256k1::new();
		let recipient_secret_key = SecretKey::from_slice(&[4u8; 32]).unwrap();
		let wrong_secret_key = SecretKey::from_slice(&[5u8; 32]).unwrap();
		let recipient_pubkey = PublicKey::from_secret_key(&secp_ctx, &recipient_secret_key);

		let encrypted =
			encrypt_payment_token_to_pubkey(&recipient_pubkey, b"order:pubkey", &[7u8; 32]);
		let result = decrypt_payment_token_with_secret_key(&wrong_secret_key, &encrypted);

		assert_eq!(result, Err(PaymentTokenError::DecryptionFailed));
	}

	#[test]
	fn corrupted_ciphertext_fails() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let order_id = b"order:12345";
		let entropy = [0u8; 32];

		let mut encrypted = encrypt_payment_token(&secret, order_id, &entropy);
		// Corrupt a byte in the ciphertext (after random_bytes)
		encrypted[RANDOM_BYTES_LEN + 5] ^= 0xFF;

		let result = decrypt_payment_token(&secret, &encrypted);
		assert_eq!(result, Err(PaymentTokenError::DecryptionFailed));
	}

	#[test]
	fn corrupted_tag_fails() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let order_id = b"order:12345";
		let entropy = [0u8; 32];

		let mut encrypted = encrypt_payment_token(&secret, order_id, &entropy);
		// Corrupt the last byte (part of the tag)
		let last_idx = encrypted.len() - 1;
		encrypted[last_idx] ^= 0xFF;

		let result = decrypt_payment_token(&secret, &encrypted);
		assert_eq!(result, Err(PaymentTokenError::DecryptionFailed));
	}

	#[test]
	fn corrupted_random_bytes_fails() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let order_id = b"order:12345";
		let entropy = [0u8; 32];

		let mut encrypted = encrypt_payment_token(&secret, order_id, &entropy);
		// Corrupt a byte in the random_bytes section
		encrypted[5] ^= 0xFF;

		let result = decrypt_payment_token(&secret, &encrypted);
		assert_eq!(result, Err(PaymentTokenError::DecryptionFailed));
	}

	#[test]
	fn too_short_token_fails() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);

		// Token shorter than minimum (random_bytes + tag = 48 bytes)
		let short_token = vec![0u8; 47];
		let result = decrypt_payment_token(&secret, &short_token);
		assert_eq!(result, Err(PaymentTokenError::InvalidLength));

		// Empty token
		let result = decrypt_payment_token(&secret, &[]);
		assert_eq!(result, Err(PaymentTokenError::InvalidLength));
	}

	#[test]
	fn minimum_length_token_works() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let order_id = b""; // Empty order ID
		let entropy = [1u8; 32];

		let encrypted = encrypt_payment_token(&secret, order_id, &entropy);
		// Should be exactly random_bytes (32) + tag (16) = 48 bytes
		assert_eq!(encrypted.len(), RANDOM_BYTES_LEN + TAG_LEN);

		let decrypted = decrypt_payment_token(&secret, &encrypted).unwrap();
		assert_eq!(decrypted, order_id);
	}

	#[test]
	fn secret_debug_does_not_leak() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let debug_str = format!("{:?}", secret);
		assert!(debug_str.contains("REDACTED"));
		assert!(!debug_str.contains("42"));
	}

	#[test]
	fn secret_serialization_roundtrip() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);

		let mut serialized = Vec::new();
		secret.write(&mut serialized).unwrap();

		let mut reader = io::Cursor::new(&serialized);
		let deserialized = PaymentTokenSecret::read(&mut reader).unwrap();

		assert_eq!(secret, deserialized);
	}

	#[test]
	fn payload_encrypt_decrypt_roundtrip() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let entropy = [1u8; 32];

		let payload =
			PaymentTokenPayload { amount_msats: 50_000, description: "coffee, large".to_string() };

		let encrypted = encrypt_payment_token_payload(&secret, &payload, &entropy);
		let decrypted = decrypt_payment_token_payload(&secret, &encrypted).unwrap();

		assert_eq!(decrypted, payload);
	}

	#[test]
	fn payload_tamper_detection() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let entropy = [1u8; 32];

		let payload =
			PaymentTokenPayload { amount_msats: 50_000, description: "coffee, large".to_string() };

		let mut encrypted = encrypt_payment_token_payload(&secret, &payload, &entropy);
		// Corrupt a byte in the ciphertext
		encrypted[RANDOM_BYTES_LEN + 2] ^= 0xFF;

		let result = decrypt_payment_token_payload(&secret, &encrypted);
		assert_eq!(result, Err(PaymentTokenError::DecryptionFailed));
	}

	#[test]
	fn payload_encrypt_decrypt_roundtrip_with_pubkey() {
		let secp_ctx = Secp256k1::new();
		let recipient_secret_key = SecretKey::from_slice(&[6u8; 32]).unwrap();
		let recipient_pubkey = PublicKey::from_secret_key(&secp_ctx, &recipient_secret_key);
		let payload = PaymentTokenPayload {
			amount_msats: 75_000,
			description: "single origin espresso".to_string(),
		};

		let encrypted =
			encrypt_payment_token_payload_to_pubkey(&recipient_pubkey, &payload, &[8u8; 32]);
		let decrypted =
			decrypt_payment_token_payload_with_secret_key(&recipient_secret_key, &encrypted)
				.unwrap();

		assert_eq!(decrypted, payload);
	}

	#[test]
	fn raw_token_fails_as_payload() {
		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let entropy = [1u8; 32];

		// Encrypt raw bytes (not a valid PaymentTokenPayload)
		let raw_order_id = b"order:12345";
		let encrypted = encrypt_payment_token(&secret, raw_order_id, &entropy);

		// Attempting to decrypt as a payload should fail
		let result = decrypt_payment_token_payload(&secret, &encrypted);
		assert_eq!(result, Err(PaymentTokenError::InvalidPayload));
	}
}
