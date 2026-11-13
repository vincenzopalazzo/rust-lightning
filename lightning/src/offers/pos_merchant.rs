// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The merchant side of [bLIP 56]: checking invoice requests for per-order offers.
//!
//! A per-order offer is built by a point-of-sale device, so the merchant has never seen it. What
//! stands in for checking the request against the offer is checking the request's cleartext
//! offer fields against the order the device sealed into its `payment_token`.
//!
//! A request that passes yields [`PosPaymentData`], everything the merchant needs to notify the
//! device once the payment settles. It travels in the invoice's blinded payment paths, encrypted
//! to the merchant, so nothing is stored for requests that are never paid.
//!
//! [bLIP 56]: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md

use bitcoin::constants::ChainHash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;

use crate::blinded_path::message::BlindedMessagePath;
use crate::io::Cursor;
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::nonce::Nonce;
use crate::offers::offer::Amount;
use crate::offers::payment_token::{payment_token_hash, SealedOrder};
use crate::prelude::*;
use crate::util::ser::{Readable, Writeable};

use alloc::collections::BTreeMap;

/// The `payment_metadata` key for [`PosPaymentData::template_nonce`].
pub const POS_TEMPLATE_NONCE_KEY: u64 = 128;

/// The `payment_metadata` key for [`PosPaymentData::payment_token_hash`].
pub const POS_PAYMENT_TOKEN_HASH_KEY: u64 = 129;

/// The `payment_metadata` key for [`PosPaymentData::notification_path`].
pub const POS_NOTIFICATION_PATH_KEY: u64 = 130;

/// What a merchant needs, once a payment for a per-order offer settles, to notify the
/// point-of-sale device that built the offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosPaymentData {
	/// The nonce of the offer template, from which the key the notification is signed with is
	/// derived.
	pub template_nonce: Nonce,
	/// The SHA256 of the `payment_token` the paid invoice request carried.
	pub payment_token_hash: Sha256,
	/// A `notification_path` from the paid invoice request.
	///
	/// Only one is kept: it travels in the payment onion, which has little room to spare.
	pub notification_path: BlindedMessagePath,
}

impl PosPaymentData {
	/// Encodes the data as `payment_metadata` entries.
	pub fn to_payment_metadata(&self) -> BTreeMap<u64, Vec<u8>> {
		let mut metadata = BTreeMap::new();
		metadata.insert(POS_TEMPLATE_NONCE_KEY, self.template_nonce.as_slice().to_vec());
		metadata
			.insert(POS_PAYMENT_TOKEN_HASH_KEY, self.payment_token_hash.to_byte_array().to_vec());
		metadata.insert(POS_NOTIFICATION_PATH_KEY, self.notification_path.encode());
		metadata
	}

	/// Decodes the data from `payment_metadata`, if all of its entries are present and valid.
	pub fn from_payment_metadata(metadata: &BTreeMap<u64, Vec<u8>>) -> Option<Self> {
		let template_nonce =
			Nonce::try_from(metadata.get(&POS_TEMPLATE_NONCE_KEY)?.as_slice()).ok()?;
		let payment_token_hash =
			Sha256::from_slice(metadata.get(&POS_PAYMENT_TOKEN_HASH_KEY)?).ok()?;
		let path_bytes = metadata.get(&POS_NOTIFICATION_PATH_KEY)?;
		let mut reader = Cursor::new(path_bytes);
		let notification_path: BlindedMessagePath = Readable::read(&mut reader).ok()?;
		if reader.position() != path_bytes.len() as u64 {
			return None;
		}
		Some(Self { template_nonce, payment_token_hash, notification_path })
	}
}

/// Why an invoice request for a point-of-sale per-order offer was rejected.
///
/// None of these carry the sealed values: the draft forbids disclosing them to anyone, and a
/// reason echoing them back would make the merchant an oracle for redacted order details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PosInvoiceRequestError {
	/// The request has no `payment_token`.
	MissingPaymentToken,
	/// The `payment_token` does not open with the template's key, or is not a valid order.
	InvalidPaymentToken,
	/// The offer's amount is not the sealed amount, or is not denominated in bitcoin.
	AmountMismatch,
	/// The offer's description is not the sealed description.
	DescriptionMismatch,
	/// The request asks for a quantity.
	UnexpectedQuantity,
	/// The offer or the request is for a chain other than ours.
	UnsupportedChain,
	/// The request has no usable `notification_path`.
	InvalidNotificationPath,
	/// The amount to invoice is below the sealed amount.
	InsufficientAmount,
}

/// Checks an invoice request for a per-order offer against the order sealed into its
/// `payment_token`, with the secret key of the template's issuer id, as the draft requires of the
/// merchant.
///
/// The request must already have been verified as being for a template of ours. Descriptions are
/// compared as raw octets, with no normalization.
///
/// One deliberate deviation: the draft forbids `offer_chains`, which makes the protocol unusable
/// outside mainnet. Here the offer may name exactly our chain, and the request must be for it.
pub fn check_pos_invoice_request(
	invoice_request: &InvoiceRequest, template_nonce: Nonce, issuer_secret: &SecretKey,
	chain_hash: ChainHash,
) -> Result<PosPaymentData, PosInvoiceRequestError> {
	let payment_token =
		invoice_request.payment_token().ok_or(PosInvoiceRequestError::MissingPaymentToken)?;
	let order = SealedOrder::unseal(issuer_secret, payment_token)
		.map_err(|()| PosInvoiceRequestError::InvalidPaymentToken)?;

	match invoice_request.amount() {
		Some(Amount::Bitcoin { amount_msats }) if amount_msats == order.amount_msats => {},
		_ => return Err(PosInvoiceRequestError::AmountMismatch),
	}
	match invoice_request.description() {
		Some(description) if description.0 == order.description => {},
		_ => return Err(PosInvoiceRequestError::DescriptionMismatch),
	}
	if invoice_request.quantity().is_some() {
		return Err(PosInvoiceRequestError::UnexpectedQuantity);
	}
	if invoice_request.chains() != [chain_hash] || invoice_request.chain() != chain_hash {
		return Err(PosInvoiceRequestError::UnsupportedChain);
	}

	let notification_paths = invoice_request.notification_paths();
	if notification_paths.is_empty()
		|| notification_paths.iter().any(|p| p.blinded_hops().is_empty())
	{
		return Err(PosInvoiceRequestError::InvalidNotificationPath);
	}

	if invoice_request.amount_msats().unwrap_or(order.amount_msats) < order.amount_msats {
		return Err(PosInvoiceRequestError::InsufficientAmount);
	}

	Ok(PosPaymentData {
		template_nonce,
		payment_token_hash: payment_token_hash(payment_token),
		notification_path: notification_paths[0].clone(),
	})
}

#[cfg(test)]
mod tests {
	use super::PosPaymentData;

	use crate::blinded_path::message::BlindedMessagePath;
	use crate::blinded_path::BlindedHop;
	use crate::offers::nonce::Nonce;
	use crate::offers::test_utils::pubkey;

	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;

	#[test]
	fn round_trips_payment_metadata() {
		let data = PosPaymentData {
			template_nonce: Nonce([3; Nonce::LENGTH]),
			payment_token_hash: Sha256::from_byte_array([4; 32]),
			notification_path: BlindedMessagePath::from_blinded_path(
				pubkey(40),
				pubkey(41),
				vec![BlindedHop { blinded_node_id: pubkey(42), encrypted_payload: vec![0; 43] }],
			),
		};
		let mut metadata = data.to_payment_metadata();
		assert_eq!(PosPaymentData::from_payment_metadata(&metadata), Some(data.clone()));

		// Unrelated entries do not interfere.
		metadata.insert(7, vec![1, 2, 3]);
		assert_eq!(PosPaymentData::from_payment_metadata(&metadata), Some(data.clone()));

		// Missing or malformed entries yield nothing.
		for key in [super::POS_TEMPLATE_NONCE_KEY, super::POS_PAYMENT_TOKEN_HASH_KEY] {
			let mut truncated = data.to_payment_metadata();
			truncated.get_mut(&key).unwrap().pop();
			assert_eq!(PosPaymentData::from_payment_metadata(&truncated), None);
			let mut missing = data.to_payment_metadata();
			missing.remove(&key);
			assert_eq!(PosPaymentData::from_payment_metadata(&missing), None);
		}
		let mut trailing = data.to_payment_metadata();
		trailing.get_mut(&super::POS_NOTIFICATION_PATH_KEY).unwrap().push(0);
		assert_eq!(PosPaymentData::from_payment_metadata(&trailing), None);
	}
}
