// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for PoS-delegated BOLT 12 offers.
//!
//! This module provides configuration and helper functions for merchants
//! who want to support PoS-delegated offers. In this flow:
//!
//! 1. The merchant creates a "template offer" with their node info
//! 2. PoS devices modify the template with order-specific data
//! 3. Customers pay using the modified offer
//! 4. The merchant receives payment and notifies the PoS
//!
//! # Example
//!
//! ```ignore
//! use lightning::offers::pos_delegation::{PosDelegationConfig, PosDelegationManager};
//! use lightning::offers::payment_token::PaymentTokenSecret;
//!
//! // Merchant sets up delegation config with PoS shared secrets
//! let mut config = PosDelegationConfig::new();
//! config.add_pos_secret(b"pos-device-1".to_vec(), secret1);
//! config.add_pos_secret(b"pos-device-2".to_vec(), secret2);
//!
//! // When payment is received for a delegated offer...
//! let manager = PosDelegationManager::new(config);
//! if let Some(notification_info) = manager.process_delegated_payment(&context, preimage) {
//!     // Queue the notification for sending to the PoS
//!     offers_flow.queue_pos_payment_notification(
//!         notification_info.encrypted_token,
//!         notification_info.preimage,
//!         &notification_info.notification_paths,
//!     );
//! }
//! ```

use crate::blinded_path::message::BlindedMessagePath;
use crate::blinded_path::payment::DelegatedBolt12OfferContext;
use crate::io;
use crate::offers::payment_token::{
	decrypt_payment_token, decrypt_payment_token_payload, PaymentTokenPayload, PaymentTokenSecret,
};
use crate::prelude::*;
use crate::types::payment::PaymentPreimage;
use crate::util::ser::{Readable, Writeable, Writer};

/// Configuration for PoS delegation on the merchant side.
///
/// This struct holds the shared secrets for each authorized PoS device,
/// allowing the merchant to decrypt payment tokens and identify which
/// PoS device initiated a payment.
#[derive(Clone, Debug, Default)]
pub struct PosDelegationConfig {
	/// Map from PoS identifier to shared secret.
	///
	/// The PoS identifier is typically a unique ID for each PoS device,
	/// established during initial setup.
	pos_secrets: HashMap<Vec<u8>, PaymentTokenSecret>,
}

impl PosDelegationConfig {
	/// Creates a new empty PoS delegation configuration.
	pub fn new() -> Self {
		Self { pos_secrets: new_hash_map() }
	}

	/// Adds a shared secret for a PoS device.
	///
	/// # Arguments
	/// * `pos_id` - Unique identifier for the PoS device
	/// * `secret` - The shared secret established with this PoS
	pub fn add_pos_secret(&mut self, pos_id: Vec<u8>, secret: PaymentTokenSecret) {
		self.pos_secrets.insert(pos_id, secret);
	}

	/// Removes a PoS device's shared secret.
	///
	/// Call this when a PoS device is deauthorized.
	pub fn remove_pos_secret(&mut self, pos_id: &[u8]) -> Option<PaymentTokenSecret> {
		self.pos_secrets.remove(pos_id)
	}

	/// Gets the shared secret for a PoS device.
	pub fn get_pos_secret(&self, pos_id: &[u8]) -> Option<&PaymentTokenSecret> {
		self.pos_secrets.get(pos_id)
	}

	/// Returns the number of configured PoS devices.
	pub fn num_pos_devices(&self) -> usize {
		self.pos_secrets.len()
	}

	/// Returns an iterator over all PoS device IDs.
	pub fn pos_device_ids(&self) -> impl Iterator<Item = &Vec<u8>> {
		self.pos_secrets.keys()
	}

	/// Attempts to decrypt a payment token using any of the configured secrets.
	///
	/// This tries each secret until one successfully decrypts the token.
	/// This is useful when the PoS ID is embedded in the token itself.
	///
	/// Returns the decrypted legacy raw token and the PoS ID that was used, if successful.
	pub fn try_decrypt_token(&self, encrypted_token: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
		for (pos_id, secret) in &self.pos_secrets {
			if let Ok(decrypted) = decrypt_payment_token(secret, encrypted_token) {
				return Some((decrypted, pos_id.clone()));
			}
		}
		None
	}

	/// Attempts to decrypt a structured [`PaymentTokenPayload`] using any of the
	/// configured secrets.
	///
	/// Returns the payload and the PoS ID that was used, if successful.
	/// This is used by the merchant to verify that the token commits to the
	/// correct offer fields (amount and description).
	pub fn try_decrypt_token_payload(
		&self, encrypted_token: &[u8],
	) -> Option<(PaymentTokenPayload, Vec<u8>)> {
		for (pos_id, secret) in &self.pos_secrets {
			if let Ok(payload) = decrypt_payment_token_payload(secret, encrypted_token) {
				return Some((payload, pos_id.clone()));
			}
		}
		None
	}
}

/// Information needed to send a notification to a PoS device.
#[derive(Clone, Debug)]
pub struct PosNotificationInfo {
	/// The encrypted payment token (passed through to the notification).
	pub encrypted_token: Vec<u8>,

	/// The payment preimage proving payment was received.
	pub preimage: PaymentPreimage,

	/// The blinded paths to reach the PoS device.
	pub notification_paths: Vec<BlindedMessagePath>,

	/// The decrypted order ID for legacy raw-token deployments.
	///
	/// Structured BLIP-56 payment tokens no longer carry PoS correlation data, so
	/// this will be `None` when the token uses the structured payload format.
	pub decrypted_order_id: Option<Vec<u8>>,
}

/// Manager for processing PoS-delegated payments.
///
/// This struct combines the configuration with helper methods for
/// processing delegated offer payments and preparing notifications.
#[derive(Clone, Debug)]
pub struct PosDelegationManager {
	config: PosDelegationConfig,
}

impl PosDelegationManager {
	/// Creates a new PoS delegation manager with the given configuration.
	pub fn new(config: PosDelegationConfig) -> Self {
		Self { config }
	}

	/// Creates a new manager with an empty configuration.
	pub fn empty() -> Self {
		Self::new(PosDelegationConfig::new())
	}

	/// Returns a reference to the underlying configuration.
	pub fn config(&self) -> &PosDelegationConfig {
		&self.config
	}

	/// Returns a mutable reference to the underlying configuration.
	pub fn config_mut(&mut self) -> &mut PosDelegationConfig {
		&mut self.config
	}

	/// Processes a delegated offer payment and returns notification info.
	///
	/// Call this when a payment is received with a [`DelegatedBolt12OfferContext`].
	/// If the payment token can be decrypted, returns information needed to
	/// notify the PoS device.
	///
	/// # Arguments
	/// * `context` - The delegated offer context from the payment
	/// * `preimage` - The payment preimage
	///
	/// # Returns
	/// `Some(PosNotificationInfo)` if the payment should trigger a notification,
	/// `None` if the context has no notification paths.
	pub fn process_delegated_payment(
		&self, context: &DelegatedBolt12OfferContext, preimage: PaymentPreimage,
	) -> Option<PosNotificationInfo> {
		// If there are no notification paths, we can't notify anyone
		if context.notification_paths.is_empty() {
			return None;
		}

		// Structured payment tokens only commit to validation fields, not order correlation data.
		// If the token is not structured, fall back to the legacy raw-token format.
		let decrypted_order_id =
			if self.config.try_decrypt_token_payload(&context.encrypted_payment_token).is_some() {
				None
			} else {
				self.config
					.try_decrypt_token(&context.encrypted_payment_token)
					.map(|(order_id, _pos_id)| order_id)
			};

		Some(PosNotificationInfo {
			encrypted_token: context.encrypted_payment_token.clone(),
			preimage,
			notification_paths: context.notification_paths.clone(),
			decrypted_order_id,
		})
	}

	/// Decrypts a payment token and returns the order ID.
	///
	/// This is a convenience method for when you want to decrypt a token
	/// outside of the payment flow.
	pub fn decrypt_token(&self, encrypted_token: &[u8]) -> Option<Vec<u8>> {
		self.config.try_decrypt_token(encrypted_token).map(|(order_id, _)| order_id)
	}
}

impl Writeable for PosDelegationConfig {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		(self.pos_secrets.len() as u32).write(writer)?;
		for (pos_id, secret) in &self.pos_secrets {
			(pos_id.len() as u16).write(writer)?;
			writer.write_all(pos_id)?;
			secret.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for PosDelegationConfig {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, crate::ln::msgs::DecodeError> {
		let count: u32 = Readable::read(reader)?;
		let mut pos_secrets = new_hash_map();

		for _ in 0..count {
			let id_len: u16 = Readable::read(reader)?;
			let mut pos_id = vec![0u8; id_len as usize];
			reader.read_exact(&mut pos_id)?;
			let secret: PaymentTokenSecret = Readable::read(reader)?;
			pos_secrets.insert(pos_id, secret);
		}

		Ok(Self { pos_secrets })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_pos_delegation_config_add_remove() {
		let mut config = PosDelegationConfig::new();
		assert_eq!(config.num_pos_devices(), 0);

		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		config.add_pos_secret(b"pos-1".to_vec(), secret.clone());
		assert_eq!(config.num_pos_devices(), 1);

		let retrieved = config.get_pos_secret(b"pos-1");
		assert!(retrieved.is_some());

		let removed = config.remove_pos_secret(b"pos-1");
		assert!(removed.is_some());
		assert_eq!(config.num_pos_devices(), 0);
	}

	#[test]
	fn test_pos_delegation_config_serialization() {
		let mut config = PosDelegationConfig::new();
		config.add_pos_secret(b"pos-1".to_vec(), PaymentTokenSecret::from_bytes([1u8; 32]));
		config.add_pos_secret(b"pos-2".to_vec(), PaymentTokenSecret::from_bytes([2u8; 32]));

		let mut serialized = Vec::new();
		config.write(&mut serialized).unwrap();

		let mut reader = io::Cursor::new(&serialized);
		let deserialized: PosDelegationConfig = Readable::read(&mut reader).unwrap();

		assert_eq!(deserialized.num_pos_devices(), 2);
		assert!(deserialized.get_pos_secret(b"pos-1").is_some());
		assert!(deserialized.get_pos_secret(b"pos-2").is_some());
	}

	#[test]
	fn test_try_decrypt_token() {
		use crate::offers::payment_token::encrypt_payment_token;

		let secret1 = PaymentTokenSecret::from_bytes([1u8; 32]);
		let secret2 = PaymentTokenSecret::from_bytes([2u8; 32]);

		let mut config = PosDelegationConfig::new();
		config.add_pos_secret(b"pos-1".to_vec(), secret1.clone());
		config.add_pos_secret(b"pos-2".to_vec(), secret2.clone());

		// Encrypt with secret1
		let order_id = b"order:12345";
		let entropy = [0u8; 32];
		let encrypted = encrypt_payment_token(&secret1, order_id, &entropy);

		// Should decrypt successfully
		let result = config.try_decrypt_token(&encrypted);
		assert!(result.is_some());
		let (decrypted, pos_id) = result.unwrap();
		assert_eq!(decrypted, order_id);
		assert_eq!(pos_id, b"pos-1".to_vec());

		// Encrypt with unknown secret - should fail
		let unknown_secret = PaymentTokenSecret::from_bytes([99u8; 32]);
		let encrypted_unknown = encrypt_payment_token(&unknown_secret, order_id, &entropy);
		assert!(config.try_decrypt_token(&encrypted_unknown).is_none());
	}

	#[test]
	fn test_pos_delegation_manager() {
		use crate::blinded_path::BlindedHop;
		use crate::offers::invoice_request::InvoiceRequestFields;
		use crate::offers::offer::OfferId;
		use bitcoin::secp256k1::PublicKey;

		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let mut config = PosDelegationConfig::new();
		config.add_pos_secret(b"pos-1".to_vec(), secret.clone());

		let manager = PosDelegationManager::new(config);

		// Create a dummy context
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let notification_path = BlindedMessagePath::from_blinded_path(
			dummy_pk,
			dummy_pk,
			vec![BlindedHop { blinded_node_id: dummy_pk, encrypted_payload: vec![0; 32] }],
		);

		// Encrypt a token
		use crate::offers::payment_token::encrypt_payment_token;
		let order_id = b"order:67890";
		let encrypted = encrypt_payment_token(&secret, order_id, &[0u8; 32]);

		let context = DelegatedBolt12OfferContext {
			offer_id: OfferId([0u8; 32]),
			invoice_request: InvoiceRequestFields {
				payer_signing_pubkey: dummy_pk,
				quantity: None,
				payer_note_truncated: None,
				human_readable_name: None,
			},
			encrypted_payment_token: encrypted,
			notification_paths: vec![notification_path],
		};

		let preimage = PaymentPreimage([1u8; 32]);
		let result = manager.process_delegated_payment(&context, preimage);

		assert!(result.is_some());
		let info = result.unwrap();
		assert_eq!(info.preimage, preimage);
		assert_eq!(info.notification_paths.len(), 1);
		assert!(info.decrypted_order_id.is_some());
		assert_eq!(info.decrypted_order_id.unwrap(), order_id);
	}

	#[test]
	fn test_process_delegated_payment_no_paths() {
		use crate::offers::invoice_request::InvoiceRequestFields;
		use crate::offers::offer::OfferId;
		use bitcoin::secp256k1::PublicKey;

		let manager = PosDelegationManager::empty();
		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();

		let context = DelegatedBolt12OfferContext {
			offer_id: OfferId([0u8; 32]),
			invoice_request: InvoiceRequestFields {
				payer_signing_pubkey: dummy_pk,
				quantity: None,
				payer_note_truncated: None,
				human_readable_name: None,
			},
			encrypted_payment_token: vec![1, 2, 3],
			notification_paths: vec![], // No paths
		};

		let preimage = PaymentPreimage([1u8; 32]);
		let result = manager.process_delegated_payment(&context, preimage);

		// Should return None because there are no notification paths
		assert!(result.is_none());
	}

	#[test]
	fn test_try_decrypt_token_payload() {
		use crate::offers::payment_token::{encrypt_payment_token_payload, PaymentTokenPayload};

		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let mut config = PosDelegationConfig::new();
		config.add_pos_secret(b"pos-1".to_vec(), secret.clone());

		let payload =
			PaymentTokenPayload { amount_msats: 50_000, description: "coffee".to_string() };
		let encrypted = encrypt_payment_token_payload(&secret, &payload, &[1u8; 32]);

		let result = config.try_decrypt_token_payload(&encrypted);
		assert!(result.is_some());
		let (decrypted_payload, pos_id) = result.unwrap();
		assert_eq!(decrypted_payload.amount_msats, 50_000);
		assert_eq!(decrypted_payload.description, "coffee");
		assert_eq!(pos_id, b"pos-1".to_vec());
	}

	#[test]
	fn test_try_decrypt_token_payload_unknown_secret() {
		use crate::offers::payment_token::{encrypt_payment_token_payload, PaymentTokenPayload};

		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let unknown_secret = PaymentTokenSecret::from_bytes([99u8; 32]);
		let mut config = PosDelegationConfig::new();
		config.add_pos_secret(b"pos-1".to_vec(), secret);

		let payload =
			PaymentTokenPayload { amount_msats: 50_000, description: "coffee".to_string() };
		let encrypted = encrypt_payment_token_payload(&unknown_secret, &payload, &[1u8; 32]);

		assert!(config.try_decrypt_token_payload(&encrypted).is_none());
	}

	#[test]
	fn test_process_delegated_payment_with_structured_payload() {
		use crate::blinded_path::BlindedHop;
		use crate::offers::invoice_request::InvoiceRequestFields;
		use crate::offers::offer::OfferId;
		use crate::offers::payment_token::{encrypt_payment_token_payload, PaymentTokenPayload};
		use bitcoin::secp256k1::PublicKey;

		let secret = PaymentTokenSecret::from_bytes([42u8; 32]);
		let mut config = PosDelegationConfig::new();
		config.add_pos_secret(b"pos-1".to_vec(), secret.clone());

		let manager = PosDelegationManager::new(config);

		let dummy_pk = PublicKey::from_slice(&[2; 33]).unwrap();
		let notification_path = BlindedMessagePath::from_blinded_path(
			dummy_pk,
			dummy_pk,
			vec![BlindedHop { blinded_node_id: dummy_pk, encrypted_payload: vec![0; 32] }],
		);

		let payload =
			PaymentTokenPayload { amount_msats: 100_000, description: "coffee".to_string() };
		let encrypted = encrypt_payment_token_payload(&secret, &payload, &[0u8; 32]);

		let context = DelegatedBolt12OfferContext {
			offer_id: OfferId([0u8; 32]),
			invoice_request: InvoiceRequestFields {
				payer_signing_pubkey: dummy_pk,
				quantity: None,
				payer_note_truncated: None,
				human_readable_name: None,
			},
			encrypted_payment_token: encrypted,
			notification_paths: vec![notification_path],
		};

		let preimage = PaymentPreimage([1u8; 32]);
		let result = manager.process_delegated_payment(&context, preimage);
		assert!(result.is_some());
		let info = result.unwrap();
		assert!(info.decrypted_order_id.is_none());
	}
}
