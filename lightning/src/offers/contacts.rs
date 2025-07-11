// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for BOLT 12 contacts implementation.
//!
//! Contact secrets are used to mutually authenticate payments between trusted contacts.
//! See [bLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md) for more details.

use crate::blinded_path::IntroductionNode;
use crate::offers::offer::Offer;
use crate::prelude::*;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{Secp256k1, SecretKey};

/// Contact secrets are used to mutually authenticate payments.
///
/// The first node to add the other to its contacts list will generate the `primary_secret` and send it when paying.
/// If the second node adds the first node to its contacts list from the received payment, it will use the same
/// `primary_secret` and both nodes are able to identify payments from each other.
///
/// But if the second node independently added the first node to its contacts list, it may have generated a
/// different `primary_secret`. Each node has a different `primary_secret`, but they will store the other node's
/// `primary_secret` in their `additional_remote_secrets`, which lets them correctly identify payments.
///
/// When sending a payment, we must always send the `primary_secret`.
/// When receiving payments, we must check if the received contact_secret matches either the `primary_secret`
/// or any of the `additional_remote_secrets`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactSecrets {
	/// The primary secret used when sending payments to this contact.
	pub primary_secret: SecretKey,
	/// Additional remote secrets that we accept when receiving payments from this contact.
	pub additional_remote_secrets: Vec<SecretKey>,
}

impl ContactSecrets {
	/// Creates a new `ContactSecrets` with the given primary secret and no additional remote secrets.
	pub fn new(primary_secret: SecretKey) -> Self {
		Self { primary_secret, additional_remote_secrets: Vec::new() }
	}

	/// Creates a new `ContactSecrets` with the given primary secret and additional remote secrets.
	pub fn with_additional_secrets(
		primary_secret: SecretKey, additional_remote_secrets: Vec<SecretKey>,
	) -> Self {
		Self { primary_secret, additional_remote_secrets }
	}

	/// This function should be used when we attribute an incoming payment to an existing contact.
	/// This can be necessary when:
	///  - our contact added us without using the contact_secret we initially sent them
	///  - our contact is using a different wallet from the one(s) we have already stored
	pub fn add_remote_secret(&mut self, remote_secret: SecretKey) {
		// Only add if it's not already present
		if !self.additional_remote_secrets.iter().any(|s| s == &remote_secret) {
			self.additional_remote_secrets.push(remote_secret);
		}
	}

	/// Returns a new `ContactSecrets` with the additional remote secret added.
	pub fn with_remote_secret(mut self, remote_secret: SecretKey) -> Self {
		self.add_remote_secret(remote_secret);
		self
	}

	/// Checks if the given secret matches either the primary secret or any of the additional remote secrets.
	pub fn matches_secret(&self, secret: &SecretKey) -> bool {
		&self.primary_secret == secret || self.additional_remote_secrets.iter().any(|s| s == secret)
	}

	/// Returns the primary secret that should be used when sending payments to this contact.
	pub fn primary_secret(&self) -> SecretKey {
		self.primary_secret
	}

	/// Returns a reference to the additional remote secrets.
	pub fn additional_remote_secrets(&self) -> &[SecretKey] {
		&self.additional_remote_secrets
	}
}

/// Contacts are trusted people to which we may want to reveal our identity when paying them.
/// We're also able to figure out when incoming payments have been made by one of our contacts.
/// See [bLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md) for more details.
pub struct Contacts;

impl Contacts {
	/// We derive our contact secret deterministically based on our offer and our contact's offer.
	/// This provides a few interesting properties:
	///  - if we remove a contact and re-add it using the same offer, we will generate the same contact secret
	///  - if our contact is using the same deterministic algorithm with a single static offer, they will also generate the same contact secret
	///
	/// Note that this function must only be used when adding a contact that hasn't paid us before.
	/// If we're adding a contact that paid us before, we must use the contact_secret they sent us,
	/// which ensures that when we pay them, they'll be able to know it was coming from us (see
	/// [`from_remote_secret`]).
	///
	/// [`from_remote_secret`]: Self::from_remote_secret
	pub fn compute_contact_secret<T: bitcoin::secp256k1::Signing>(
		our_private_key: &SecretKey, their_offer: &Offer, _secp_ctx: &Secp256k1<T>,
	) -> Result<ContactSecrets, ()> {
		// If their offer doesn't contain an issuer_signing_pubkey, it must contain blinded paths.
		let offer_node_id = their_offer
			.issuer_signing_pubkey()
			.or_else(|| {
				their_offer.paths().first().and_then(|path| match path.introduction_node() {
					IntroductionNode::NodeId(node_id) => Some(*node_id),
					IntroductionNode::DirectedShortChannelId(_, _) => None,
				})
			})
			.ok_or(())?;

		// Compute ECDH shared secret
		let shared_secret =
			bitcoin::secp256k1::ecdh::shared_secret_point(&offer_node_id, our_private_key);

		// Derive the contact secret using SHA256("blip42_contact_secret" || shared_secret)
		let mut engine = Sha256::engine();
		engine.input(b"blip42_contact_secret");
		engine.input(&shared_secret[..]);
		let hash = Sha256::from_engine(engine);

		let primary_secret = SecretKey::from_slice(&hash.to_byte_array()).map_err(|_| ())?;

		Ok(ContactSecrets::new(primary_secret))
	}

	/// When adding a contact from which we've received a payment, we must use the contact_secret
	/// they sent us: this ensures that they'll be able to identify payments coming from us.
	pub fn from_remote_secret(remote_secret: SecretKey) -> ContactSecrets {
		ContactSecrets::new(remote_secret)
	}
}
