// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and utilities for managing Lightning Network contacts.
//!
//! Contacts are trusted people to which we may want to reveal our identity when paying them.
//! We're also able to figure out when incoming payments have been made by one of our contacts.
//! See [bLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md) for more details.
//!
//! The typical lifecycle of a contact relationship is:
//! 1. The payer adds the recipient to their contacts list using the recipient's long-lived
//!    offer, deterministically deriving [`ContactSecrets`] from both parties' offers via
//!    `ChannelManager::compute_contact_secret`.
//! 2. When paying that contact's offer, the payer opts into revealing their identity by setting
//!    `OptionalOfferPaymentParams::contact_secrets` (and optionally their own return offer via
//!    `OptionalOfferPaymentParams::payer_offer`).
//! 3. The recipient finds the received secret and offer in
//!    [`InvoiceRequestFields::contact_secret`] and [`InvoiceRequestFields::payer_offer`] when
//!    claiming the payment. If the secret matches an existing contact (see
//!    [`ContactSecrets::matches`]), the payment came from that contact and any received offer
//!    MUST be ignored. Otherwise, the recipient may offer the user to add the payer as a
//!    contact, storing the received secret via [`ContactSecrets::from_remote_secret`] so the
//!    payer can recognize payments coming back from us.
//! 4. If both parties added each other independently (with differing primary secrets), incoming
//!    secrets can be attributed to a contact manually, after which they should be stored via
//!    [`ContactSecrets::add_remote_secret`] for future matching.
//!
//! [`InvoiceRequestFields::contact_secret`]: crate::offers::invoice_request::InvoiceRequestFields::contact_secret
//! [`InvoiceRequestFields::payer_offer`]: crate::offers::invoice_request::InvoiceRequestFields::payer_offer

use crate::io::{self, Read};
use crate::ln::msgs::DecodeError;
use crate::offers::offer::Offer;
use crate::offers::parse::Bolt12SemanticError;
use crate::util::ser::{Readable, Writeable, Writer};
use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::Scalar;
use bitcoin::secp256k1::{self, Secp256k1, SecretKey};

#[allow(unused_imports)]
use crate::prelude::*;

/// TLV record type for the `invreq_contact_secret` field defined in
/// [BLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md).
pub(super) const INVREQ_CONTACT_SECRET_TYPE: u64 = 2_000_001_729;

/// TLV record type for the `invreq_payer_offer` field defined in
/// [BLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md).
pub(super) const INVREQ_PAYER_OFFER_TYPE: u64 = 2_000_001_731;

/// The maximum encoded size of an [`Offer`] used as a payer offer.
///
/// [BLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md) recommends keeping
/// payer offers below this size so that invoice requests containing them still fit the sender
/// data that recipients store in blinded path padding and, for async payments, the payment
/// onion.
pub const PAYER_OFFER_MAX_BYTES: usize = 300;

/// A contact secret used in experimental TLV fields for BLIP-42.
///
/// This is a 32-byte secret that can be included in invoice requests to establish
/// contact relationships between Lightning nodes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContactSecret {
	contents: [u8; 32],
}

impl ContactSecret {
	/// Creates a new [`ContactSecret`] from a 32-byte array.
	pub fn new(contents: [u8; 32]) -> Self {
		Self { contents }
	}

	/// Returns the inner 32-byte array.
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.contents
	}
}

impl From<[u8; 32]> for ContactSecret {
	fn from(contents: [u8; 32]) -> Self {
		Self { contents }
	}
}

impl AsRef<[u8; 32]> for ContactSecret {
	fn as_ref(&self) -> &[u8; 32] {
		&self.contents
	}
}

impl Readable for ContactSecret {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let mut buf = [0u8; 32];
		r.read_exact(&mut buf)?;
		Ok(ContactSecret { contents: buf })
	}
}

impl Writeable for ContactSecret {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self.contents)
	}
}

/// Contact secrets are used to mutually authenticate payments.
///
/// The first node to add the other to its contacts list will generate the `primary_secret` and
/// send it when paying. If the second node adds the first node to its contacts list from the
/// received payment, it will use the same `primary_secret` and both nodes are able to identify
/// payments from each other.
///
/// But if the second node independently added the first node to its contacts list, it may have
/// generated a different `primary_secret`. Each node has a different `primary_secret`, but they
/// will store the other node's `primary_secret` in their `additional_remote_secrets`, which lets
/// them correctly identify payments.
///
/// When sending a payment, we must always send the `primary_secret`.
/// When receiving payments, we must check if the received contact_secret matches either the
/// `primary_secret` or any of the `additional_remote_secrets`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactSecrets {
	primary_secret: ContactSecret,
	additional_remote_secrets: Vec<ContactSecret>,
}

impl ContactSecrets {
	/// Creates a new [`ContactSecrets`] with the given primary secret.
	pub fn new(primary_secret: ContactSecret) -> Self {
		Self { primary_secret, additional_remote_secrets: Vec::new() }
	}

	/// Creates a new [`ContactSecrets`] from the contact secret a contact sent us in a payment.
	///
	/// When adding a contact from which we've received a payment, we must use the contact secret
	/// they sent us: this ensures that they'll be able to identify payments coming from us.
	pub fn from_remote_secret(remote_secret: ContactSecret) -> Self {
		Self::new(remote_secret)
	}

	/// Creates a new [`ContactSecrets`] with the given primary secret and additional remote secrets.
	pub fn with_additional_secrets(
		primary_secret: ContactSecret, additional_remote_secrets: Vec<ContactSecret>,
	) -> Self {
		Self { primary_secret, additional_remote_secrets }
	}

	/// Returns the primary secret.
	pub fn primary_secret(&self) -> &ContactSecret {
		&self.primary_secret
	}

	/// Returns the additional remote secrets.
	pub fn additional_remote_secrets(&self) -> &[ContactSecret] {
		&self.additional_remote_secrets
	}

	/// This function should be used when we attribute an incoming payment to an existing contact.
	///
	/// This can be necessary when:
	///  - our contact added us without using the contact_secret we initially sent them
	///  - our contact is using a different wallet from the one(s) we have already stored
	pub fn add_remote_secret(&mut self, remote_secret: ContactSecret) {
		if !self.additional_remote_secrets.contains(&remote_secret) {
			self.additional_remote_secrets.push(remote_secret);
		}
	}

	/// Checks if the given secret matches either the primary secret or any additional remote secret.
	///
	/// Comparisons are made in constant time to avoid leaking which stored secret matched.
	pub fn matches(&self, secret: &ContactSecret) -> bool {
		let mut found = fixed_time_eq(self.primary_secret.as_bytes(), secret.as_bytes());
		for remote_secret in &self.additional_remote_secrets {
			found |= fixed_time_eq(remote_secret.as_bytes(), secret.as_bytes());
		}
		found
	}
}

/// We derive our contact secret deterministically based on our offer and our contact's offer.
///
/// This provides a few interesting properties:
///  - if we remove a contact and re-add it using the same offer, we will generate the same
///    contact secret
///  - if our contact is using the same deterministic algorithm with a single static offer, they
///    will also generate the same contact secret
///
/// Note that this function must only be used when adding a contact that hasn't paid us before.
/// If we're adding a contact that paid us before, we must use the contact_secret they sent us,
/// which ensures that when we pay them, they'll be able to know it was coming from us (see
/// [`ContactSecrets::from_remote_secret`]).
///
/// # Arguments
/// * `our_offer_signing_key` - The private key behind our offer's `offer_node_id`, i.e. its
///   issuer signing pubkey if set, otherwise the final `blinded_node_id` of its first path.
///   For offers whose signing pubkey was derived (e.g. ones built by
///   [`OffersMessageFlow::create_offer_builder`]), use
///   [`OffersMessageFlow::compute_contact_secret`] instead, which re-derives this key
///   internally.
/// * `their_offer` - The offer from the contact
///
/// # Errors
/// Returns [`Bolt12SemanticError::MissingSigningPubkey`] if their offer has neither an
/// issuer signing key nor a blinded path.
///
/// [`OffersMessageFlow::create_offer_builder`]: crate::offers::flow::OffersMessageFlow::create_offer_builder
/// [`OffersMessageFlow::compute_contact_secret`]: crate::offers::flow::OffersMessageFlow::compute_contact_secret
pub fn compute_contact_secret<T: secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, our_offer_signing_key: &SecretKey, their_offer: &Offer,
) -> Result<ContactSecrets, Bolt12SemanticError> {
	let offer_node_id = if let Some(issuer) = their_offer.issuer_signing_pubkey() {
		issuer
	} else {
		// Otherwise, use the last node in the first blinded path (if any)
		their_offer
			.paths()
			.first()
			.and_then(|path| path.blinded_hops().last())
			.map(|hop| hop.blinded_node_id)
			.ok_or(Bolt12SemanticError::MissingSigningPubkey)?
	};
	// Compute ECDH shared secret (multiply their public key by our private key)
	let scalar: Scalar = (*our_offer_signing_key).into();
	let ecdh = offer_node_id
		.mul_tweak(secp_ctx, &scalar)
		.map_err(|_| Bolt12SemanticError::InvalidSigningPubkey)?;
	// Hash the shared secret with the bLIP 42 tag
	let mut engine = sha256::Hash::engine();
	engine.input(b"blip42_contact_secret");
	engine.input(&ecdh.serialize());
	let primary_secret = ContactSecret::new(sha256::Hash::from_engine(engine).to_byte_array());

	Ok(ContactSecrets::new(primary_secret))
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hex::DisplayHex;
	use bitcoin::secp256k1::Secp256k1;
	use core::str::FromStr;

	const ALICE_OFFER: &str = "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsrejlwh4vyz70s46r62vtakl4sxztqj6gxjged0wx0ly8qtrygufcsyq5agaes6v605af5rr9ydnj9srneudvrmc73n7evp72tzpqcnd28puqr8a3wmcff9wfjwgk32650vl747m2ev4zsjagzucntctlmcpc6vhmdnxlywneg5caqz0ansr45z2faxq7unegzsnyuduzys7kzyugpwcmhdqqj0h70zy92p75pseunclwsrwhaelvsqy9zsejcytxulndppmykcznn7y5h";
	const ALICE_SECRET: &str = "4ed1a01dae275f7b7ba503dbae23dddd774a8d5f64788ef7a768ed647dd0e1eb";
	const ALICE_OFFER_NODE_ID: &str =
		"0284c9c6f04487ac22710176377680127dfcf110aa0fa8186793c7dd01bafdcfd9";

	struct TestVector {
		bob_offer: &'static str,
		bob_secret: &'static str,
		bob_offer_node_id: &'static str,
		expected_contact_secret: &'static str,
	}

	// Test vectors from bLIP 42. Alice's offer only contains a blinded path, while Bob's offer
	// differs per vector in how its `offer_node_id` is conveyed.
	const TEST_VECTORS: &[TestVector] = &[
		// Bob's offer also only uses a blinded path.
		TestVector {
			bob_offer: "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsz4n88s74qhussxsu0vs3c4unck4yelk67zdc29ree3sztvjn7pc9qyqlcpj54jnj67aa9rd2n5dhjlxyfmv3vgqymrks2nf7gnf5u200mn5qrxfrxh9d0ug43j5egklhwgyrfv3n84gyjd2aajhwqxa0cc7zn37sncrwptz4uhlp523l83xpjx9dw72spzecrtex3ku3h3xpepeuend5rtmurekfmnqsq6kva9yr4k3dtplku9v6qqyxr5ep6lls3hvrqyt9y7htaz9qj",
			bob_secret: "12afb8248c7336e6aea5fe247bc4bac5dcabfb6017bd67b32c8195a6c56b8333",
			bob_offer_node_id: "035e4d1b7237898390e7999b6835ef83cd93b98200d599d29075b45ab0fedc2b34",
			expected_contact_secret: "810641fab614f8bc1441131dc50b132fd4d1e2ccd36f84b887bbab3a6d8cc3d8",
		},
		// Bob's offer uses both a blinded path and an issuer_id, which takes precedence.
		TestVector {
			bob_offer: "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsesp0grlulxv3jygx83h7tghy3233sqd6xlcccvpar2l8jshxrtwvtcsz4n88s74qhussxsu0vs3c4unck4yelk67zdc29ree3sztvjn7pc9qyqlcpj54jnj67aa9rd2n5dhjlxyfmv3vgqymrks2nf7gnf5u200mn5qrxfrxh9d0ug43j5egklhwgyrfv3n84gyjd2aajhwqxa0cc7zn37sncrwptz4uhlp523l83xpjx9dw72spzecrtex3ku3h3xpepeuend5rtmurekfmnqsq6kva9yr4k3dtplku9v6qqyxr5ep6lls3hvrqyt9y7htaz9qjzcssy065ctv38c5h03lu0hlvq2t4p5fg6u668y6pmzcg64hmdm050jxx",
			bob_secret: "bcaafa8ed73da11437ce58c7b3458567a870168c0da325a40292fed126b97845",
			bob_offer_node_id: "023f54c2d913e2977c7fc7dfec029750d128d735a39341d8b08d56fb6edf47c8c6",
			expected_contact_secret: "4e0aa72cc42eae9f8dc7c6d2975bbe655683ada2e9abfdfe9f299d391ed9736c",
		},
	];

	#[test]
	fn computes_contact_secret_test_vectors() {
		let secp_ctx = Secp256k1::verification_only();
		let alice_offer = Offer::from_str(ALICE_OFFER).unwrap();
		let alice_key = SecretKey::from_str(ALICE_SECRET).unwrap();

		assert!(alice_offer.issuer_signing_pubkey().is_none());
		assert_eq!(alice_offer.paths().len(), 1);
		let alice_offer_node_id = alice_offer
			.paths()
			.first()
			.and_then(|path| path.blinded_hops().last())
			.map(|hop| hop.blinded_node_id)
			.unwrap();
		assert_eq!(alice_offer_node_id.to_string(), ALICE_OFFER_NODE_ID);

		for vector in TEST_VECTORS {
			let bob_offer = Offer::from_str(vector.bob_offer).unwrap();
			let bob_key = SecretKey::from_str(vector.bob_secret).unwrap();
			let bob_offer_node_id = bob_offer.issuer_signing_pubkey().unwrap_or_else(|| {
				bob_offer
					.paths()
					.first()
					.and_then(|path| path.blinded_hops().last())
					.map(|hop| hop.blinded_node_id)
					.unwrap()
			});
			assert_eq!(bob_offer_node_id.to_string(), vector.bob_offer_node_id);

			let alice_computed = compute_contact_secret(&secp_ctx, &alice_key, &bob_offer).unwrap();
			let bob_computed = compute_contact_secret(&secp_ctx, &bob_key, &alice_offer).unwrap();

			assert_eq!(
				alice_computed.primary_secret().as_bytes().to_hex_string(bitcoin::hex::Case::Lower),
				vector.expected_contact_secret
			);
			assert_eq!(alice_computed, bob_computed);
		}
	}

	#[test]
	fn matches_primary_and_additional_secrets() {
		let primary = ContactSecret::new([1; 32]);
		let remote = ContactSecret::new([2; 32]);
		let unknown = ContactSecret::new([3; 32]);

		let mut secrets = ContactSecrets::new(primary);
		assert!(secrets.matches(&primary));
		assert!(!secrets.matches(&remote));

		secrets.add_remote_secret(remote);
		secrets.add_remote_secret(remote);
		assert_eq!(secrets.additional_remote_secrets().len(), 1);
		assert!(secrets.matches(&primary));
		assert!(secrets.matches(&remote));
		assert!(!secrets.matches(&unknown));

		let from_remote = ContactSecrets::from_remote_secret(remote);
		assert_eq!(*from_remote.primary_secret(), remote);
	}
}
