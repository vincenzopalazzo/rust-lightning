// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The `payment_token` of a point-of-sale per-order offer, as defined by [bLIP 56].
//!
//! A point-of-sale device builds a per-order offer from a merchant's offer template and seals the
//! order's amount, description and a fresh, unpredictable `order_metadata` to the template's
//! `offer_issuer_id`. Only the merchant can open the token. The merchant checks the sealed fields
//! against the cleartext offer fields of the `invoice_request`, and the payment notification it
//! later signs commits to the SHA256 of the token ciphertext, which binds the notification to the
//! one order whose token it is.
//!
//! # Construction
//!
//! The draft leaves the encryption scheme open. This module uses:
//!
//! - `e`: a fresh secret key per token, and `E = e*G` in compressed form (33 bytes)
//! - `ss = SHA256(compressed(e*P))`, where `P` is the `offer_issuer_id` (secp256k1 ECDH)
//! - `k = HMAC-SHA256(key = "blip56_payment_token", msg = ss)`
//! - `c || tag = ChaCha20-Poly1305(key = k, nonce = 0^96, aad = E, plaintext = sealed_order)`,
//!   as specified in RFC 8439
//! - `payment_token = E || c || tag`
//!
//! The key is unique per token since `e` is, which is what makes the all-zero nonce safe.
//!
//! `sealed_order` is a TLV stream:
//!
//! 1. type: 0 (`amount`), data: \[`tu64`:`msat`\]
//! 2. type: 2 (`description`), data: \[`...*utf8`:`description`\]
//! 3. type: 4 (`order_metadata`), data: \[`...*byte`:`order_metadata`\], at least 16 bytes
//!
//! A reader rejects a `sealed_order` missing any of these or carrying an unknown even type, and
//! ignores unknown odd types, which the point-of-sale device may use for records of its own.
//!
//! [bLIP 56]: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::prelude::*;
use crate::sign::EntropySource;
use crate::util::ser::{HighZeroBytesDroppedBigSize, Readable, WithoutLength, Writeable, Writer};

/// The minimum length in bytes of [`SealedOrder::order_metadata`].
pub const MIN_ORDER_METADATA_LEN: usize = 16;

/// The length of the ephemeral public key a payment token starts with.
const EPHEMERAL_PUBKEY_LEN: usize = 33;

/// The length of the authentication tag a payment token ends with.
const TAG_LEN: usize = 16;

/// The HMAC key used to derive the encryption key from the ECDH shared secret.
const KEY_DERIVATION_TAG: &[u8] = b"blip56_payment_token";

/// The order fields a point-of-sale device seals into a per-order offer's `payment_token`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedOrder {
	/// The per-order offer's amount in millisatoshis.
	pub amount_msats: u64,
	/// The per-order offer's description.
	pub description: String,
	/// An unpredictable value, fresh for this order, that makes the token's ciphertext unique to
	/// the order. Must be at least [`MIN_ORDER_METADATA_LEN`] bytes.
	pub order_metadata: Vec<u8>,
}

impl SealedOrder {
	/// Encrypts the order to `offer_issuer_id`, returning the `payment_token`.
	///
	/// A fresh ephemeral key is drawn from `entropy_source`, so sealing the same order twice yields
	/// different tokens. A point-of-sale device must therefore seal each order once and reuse the
	/// resulting token wherever it presents the order.
	///
	/// Errors if [`Self::order_metadata`] is shorter than [`MIN_ORDER_METADATA_LEN`], or if
	/// `entropy_source` returns bytes that are not a valid secret key.
	pub fn seal<ES: EntropySource, T: secp256k1::Signing>(
		&self, offer_issuer_id: &PublicKey, entropy_source: ES, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<u8>, ()> {
		if self.order_metadata.len() < MIN_ORDER_METADATA_LEN {
			return Err(());
		}

		let ephemeral_secret =
			SecretKey::from_slice(&entropy_source.get_secure_random_bytes()).map_err(|_| ())?;
		let ephemeral_pubkey = PublicKey::from_secret_key(secp_ctx, &ephemeral_secret);
		let ephemeral_pubkey = ephemeral_pubkey.serialize();
		let key = derive_key(&SharedSecret::new(offer_issuer_id, &ephemeral_secret));

		let plaintext_len = self.serialized_length();
		let mut token = Vec::with_capacity(EPHEMERAL_PUBKEY_LEN + plaintext_len + TAG_LEN);
		token.extend_from_slice(&ephemeral_pubkey);
		self.write(&mut token).expect("writing to a Vec never fails");

		let cipher = ChaCha20Poly1305::new(Key::new(key), Nonce::new([0; 12]));
		let tag = cipher.encrypt(&mut token[EPHEMERAL_PUBKEY_LEN..], Some(&ephemeral_pubkey));
		token.extend_from_slice(&tag);

		Ok(token)
	}

	/// Decrypts a `payment_token` with the secret key for the `offer_issuer_id` it was sealed to.
	///
	/// Errors if the token is malformed or fails to authenticate, or if the decrypted order is not
	/// a valid `sealed_order`, including one whose `order_metadata` is too short.
	pub fn unseal(offer_issuer_secret: &SecretKey, payment_token: &[u8]) -> Result<Self, ()> {
		if payment_token.len() < EPHEMERAL_PUBKEY_LEN + TAG_LEN {
			return Err(());
		}

		let (ephemeral_pubkey, rest) = payment_token.split_at(EPHEMERAL_PUBKEY_LEN);
		let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
		let ephemeral = PublicKey::from_slice(ephemeral_pubkey).map_err(|_| ())?;
		let key = derive_key(&SharedSecret::new(&ephemeral, offer_issuer_secret));

		let mut plaintext = ciphertext.to_vec();
		let mut tag_bytes = [0; TAG_LEN];
		tag_bytes.copy_from_slice(tag);
		let cipher = ChaCha20Poly1305::new(Key::new(key), Nonce::new([0; 12]));
		cipher.decrypt(&mut plaintext, tag_bytes, Some(ephemeral_pubkey)).map_err(|_| ())?;

		let mut reader = io::Cursor::new(&plaintext);
		let order: SealedOrder = Readable::read(&mut reader).map_err(|_| ())?;
		if order.order_metadata.len() < MIN_ORDER_METADATA_LEN {
			return Err(());
		}

		Ok(order)
	}
}

/// The SHA256 of a `payment_token` value, which a payment notification commits to.
pub fn payment_token_hash(payment_token: &[u8]) -> Sha256 {
	Sha256::hash(payment_token)
}

fn derive_key(shared_secret: &SharedSecret) -> [u8; 32] {
	let mut hmac = HmacEngine::<Sha256>::new(KEY_DERIVATION_TAG);
	hmac.input(&shared_secret.secret_bytes());
	Hmac::from_engine(hmac).to_byte_array()
}

impl Writeable for SealedOrder {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		encode_tlv_stream!(w, {
			(0, HighZeroBytesDroppedBigSize(self.amount_msats), required),
			(2, WithoutLength(&self.description), required),
			(4, WithoutLength(&self.order_metadata), required),
		});
		Ok(())
	}
}

impl Readable for SealedOrder {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut amount_msats = None;
		let mut description: Option<WithoutLength<String>> = None;
		let mut order_metadata: Option<WithoutLength<Vec<u8>>> = None;
		decode_tlv_stream!(r, {
			(0, amount_msats, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
			(2, description, option),
			(4, order_metadata, option),
		});

		match (amount_msats, description, order_metadata) {
			(Some(amount_msats), Some(description), Some(order_metadata)) => Ok(SealedOrder {
				amount_msats,
				description: description.0,
				order_metadata: order_metadata.0,
			}),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{payment_token_hash, SealedOrder, EPHEMERAL_PUBKEY_LEN, MIN_ORDER_METADATA_LEN};

	use crate::prelude::*;
	use crate::sign::EntropySource;
	use crate::util::ser::{BigSize, Writeable};

	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;
	use bitcoin::hex::DisplayHex;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	use core::cell::Cell;

	/// Returns the given 32-byte values in turn, so tokens are reproducible.
	struct FixedEntropy(Cell<u8>);

	impl EntropySource for FixedEntropy {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			let byte = self.0.get();
			self.0.set(byte + 1);
			[byte; 32]
		}
	}

	fn issuer_keys() -> (SecretKey, PublicKey) {
		let secret = SecretKey::from_slice(&[42; 32]).unwrap();
		(secret, PublicKey::from_secret_key(&Secp256k1::new(), &secret))
	}

	fn order() -> SealedOrder {
		SealedOrder {
			amount_msats: 50_000,
			description: "coffee, large".to_string(),
			order_metadata: vec![7; MIN_ORDER_METADATA_LEN],
		}
	}

	#[test]
	fn seals_and_unseals_order() {
		let (secret, pubkey) = issuer_keys();
		let token = order().seal(&pubkey, &FixedEntropy(Cell::new(1)), &Secp256k1::new()).unwrap();
		assert_eq!(SealedOrder::unseal(&secret, &token), Ok(order()));
	}

	#[test]
	fn sealing_is_randomized() {
		let (_, pubkey) = issuer_keys();
		let entropy = FixedEntropy(Cell::new(1));
		let secp_ctx = Secp256k1::new();
		let token_a = order().seal(&pubkey, &entropy, &secp_ctx).unwrap();
		let token_b = order().seal(&pubkey, &entropy, &secp_ctx).unwrap();
		assert_ne!(token_a, token_b);
		assert_ne!(payment_token_hash(&token_a), payment_token_hash(&token_b));
	}

	#[test]
	fn fails_unsealing_with_wrong_key() {
		let (_, pubkey) = issuer_keys();
		let token = order().seal(&pubkey, &FixedEntropy(Cell::new(1)), &Secp256k1::new()).unwrap();
		let wrong_secret = SecretKey::from_slice(&[43; 32]).unwrap();
		assert!(SealedOrder::unseal(&wrong_secret, &token).is_err());
	}

	#[test]
	fn fails_unsealing_tampered_token() {
		let (secret, pubkey) = issuer_keys();
		let token = order().seal(&pubkey, &FixedEntropy(Cell::new(1)), &Secp256k1::new()).unwrap();

		// Flipping a bit anywhere, including in the ephemeral key bound as associated data, fails
		// authentication.
		for i in [EPHEMERAL_PUBKEY_LEN - 1, EPHEMERAL_PUBKEY_LEN + 3, token.len() - 1] {
			let mut tampered = token.clone();
			tampered[i] ^= 1;
			assert!(SealedOrder::unseal(&secret, &tampered).is_err());
		}
	}

	#[test]
	fn fails_unsealing_truncated_token() {
		let (secret, pubkey) = issuer_keys();
		let token = order().seal(&pubkey, &FixedEntropy(Cell::new(1)), &Secp256k1::new()).unwrap();
		assert!(SealedOrder::unseal(&secret, &token[..token.len() - 1]).is_err());
		assert!(SealedOrder::unseal(&secret, &token[..EPHEMERAL_PUBKEY_LEN + 15]).is_err());
		assert!(SealedOrder::unseal(&secret, &[]).is_err());
	}

	#[test]
	fn fails_sealing_short_order_metadata() {
		let (_, pubkey) = issuer_keys();
		let mut order = order();
		order.order_metadata.pop();
		assert!(order.seal(&pubkey, &FixedEntropy(Cell::new(1)), &Secp256k1::new()).is_err());
	}

	/// Seals arbitrary plaintext with the token construction, bypassing [`SealedOrder::seal`].
	fn seal_raw(plaintext: &[u8], issuer: &PublicKey) -> Vec<u8> {
		use super::derive_key;
		use bitcoin::secp256k1::ecdh::SharedSecret;
		use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

		let ephemeral_secret = SecretKey::from_slice(&[9; 32]).unwrap();
		let ephemeral =
			PublicKey::from_secret_key(&Secp256k1::new(), &ephemeral_secret).serialize();
		let key = derive_key(&SharedSecret::new(issuer, &ephemeral_secret));
		let mut token = ephemeral.to_vec();
		token.extend_from_slice(plaintext);
		let cipher = ChaCha20Poly1305::new(Key::new(key), Nonce::new([0; 12]));
		let tag = cipher.encrypt(&mut token[EPHEMERAL_PUBKEY_LEN..], Some(&ephemeral));
		token.extend_from_slice(&tag);
		token
	}

	fn write_record(bytes: &mut Vec<u8>, r#type: u64, value: &[u8]) {
		BigSize(r#type).write(bytes).unwrap();
		BigSize(value.len() as u64).write(bytes).unwrap();
		bytes.extend_from_slice(value);
	}

	#[test]
	fn unseals_order_with_unknown_odd_records() {
		let (secret, pubkey) = issuer_keys();
		let mut plaintext = order().encode();
		write_record(&mut plaintext, 5, b"till 3");
		let token = seal_raw(&plaintext, &pubkey);
		assert_eq!(SealedOrder::unseal(&secret, &token), Ok(order()));
	}

	#[test]
	fn fails_unsealing_invalid_sealed_order() {
		let (secret, pubkey) = issuer_keys();

		// Unknown even record.
		let mut plaintext = order().encode();
		write_record(&mut plaintext, 6, b"x");
		assert!(SealedOrder::unseal(&secret, &seal_raw(&plaintext, &pubkey)).is_err());

		// Missing records.
		for skipped in [0u64, 2, 4] {
			let mut plaintext = Vec::new();
			let order = order();
			if skipped != 0 {
				write_record(&mut plaintext, 0, &order.amount_msats.to_be_bytes()[5..]);
			}
			if skipped != 2 {
				write_record(&mut plaintext, 2, order.description.as_bytes());
			}
			if skipped != 4 {
				write_record(&mut plaintext, 4, &order.order_metadata);
			}
			assert!(SealedOrder::unseal(&secret, &seal_raw(&plaintext, &pubkey)).is_err());
		}

		// Short order metadata.
		let mut plaintext = Vec::new();
		write_record(&mut plaintext, 0, &[0xc3, 0x50]);
		write_record(&mut plaintext, 2, b"tea");
		write_record(&mut plaintext, 4, &[1; MIN_ORDER_METADATA_LEN - 1]);
		assert!(SealedOrder::unseal(&secret, &seal_raw(&plaintext, &pubkey)).is_err());

		// A non-minimal amount encoding.
		let mut plaintext = Vec::new();
		write_record(&mut plaintext, 0, &[0x00, 0xc3, 0x50]);
		write_record(&mut plaintext, 2, b"tea");
		write_record(&mut plaintext, 4, &[1; MIN_ORDER_METADATA_LEN]);
		assert!(SealedOrder::unseal(&secret, &seal_raw(&plaintext, &pubkey)).is_err());
	}

	/// A test vector for the token construction, with every input fixed.
	#[test]
	fn payment_token_test_vector() {
		let (secret, pubkey) = issuer_keys();
		let order = SealedOrder {
			amount_msats: 50_000,
			description: "coffee, large".to_string(),
			order_metadata: vec![0x11; 16],
		};
		let token = order.seal(&pubkey, &FixedEntropy(Cell::new(0x21)), &Secp256k1::new()).unwrap();

		assert_eq!(
			order.encode().as_hex().to_string(),
			"0002c350020d636f666665652c206c61726765041011111111111111111111111111111111",
		);
		assert_eq!(token.len(), EPHEMERAL_PUBKEY_LEN + order.encode().len() + 16);
		assert_eq!(&token[..EPHEMERAL_PUBKEY_LEN], &{
			let e = SecretKey::from_slice(&[0x21; 32]).unwrap();
			PublicKey::from_secret_key(&Secp256k1::new(), &e).serialize()
		});
		assert_eq!(SealedOrder::unseal(&secret, &token), Ok(order));

		// Reproduced by an independent implementation of the construction.
		assert_eq!(
			pubkey.serialize().as_hex().to_string(),
			"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c",
		);
		assert_eq!(
			token.as_hex().to_string(),
			"028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7d229f121961ae22f3a0e\
			7c0b31ba6d0cf232c04611ea5155cdd13519e5f3c322bc09fedc4d51a434ddb67f6c7101227e17670fedd1",
		);
		assert_eq!(
			payment_token_hash(&token),
			Sha256::from_byte_array([
				0xce, 0x6f, 0x4d, 0xa4, 0x64, 0xdc, 0x7f, 0x32, 0xd9, 0xf1, 0x3d, 0x78, 0x86, 0x67,
				0x8b, 0x32, 0x1f, 0x3b, 0x9c, 0x41, 0xbf, 0x03, 0x45, 0x24, 0x46, 0xe2, 0x3e, 0xe9,
				0x8f, 0xa6, 0xaa, 0x36,
			]),
		);
	}
}
