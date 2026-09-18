// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Types and derivation for bLIP 42 contact secrets.
//!
//! [`ContactSecret`] is a 32-byte value derived from both parties' offers.
//! [`ContactSecrets`] holds the primary secret plus any additional remote secrets.
//! See [bLIP 42](https://github.com/lightning/blips/blob/master/blip-0042.md) for the derivation.
//!
//! Persist the offer you will reveal to contacts together with its derivation [`Nonce`]. A
//! [`Nonce`] is returned by builders such as
//! [`OffersMessageFlow::create_async_receive_offer_builder`]. Call
//! [`OffersMessageFlow::compute_contact_secret`] with that offer, nonce, and their offer, then
//! store the returned [`ContactSecrets`]. Do not derive a secret unless the user opts in (for
//! example a "save to contacts" toggle).
//!
//! If the wallet already has a secret from this contact, use
//! [`ContactSecrets::from_remote_secret`] instead of deriving. [`ContactSecrets::matches`] is
//! constant-time equality against the stored secrets. [`ContactSecrets::add_remote_secret`]
//! records another secret for the same contact: a second wallet, or an independent add with a
//! different offer pair.
//!
//! [`Nonce`]: crate::offers::nonce::Nonce
//! [`OffersMessageFlow::create_async_receive_offer_builder`]: crate::offers::flow::OffersMessageFlow::create_async_receive_offer_builder
//! [`OffersMessageFlow::compute_contact_secret`]: crate::offers::flow::OffersMessageFlow::compute_contact_secret

use crate::io::{self, Read};
use crate::ln::msgs::DecodeError;
use crate::offers::offer::Offer;
use crate::offers::parse::Bolt12SemanticError;
use crate::util::ser::{Readable, Writeable, Writer};
use bitcoin::hashes::cmp::fixed_time_eq;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::ecdh::shared_secret_point;
use bitcoin::secp256k1::{PublicKey, SecretKey};

#[allow(unused_imports)]
use crate::prelude::*;

/// A 32-byte contact secret as defined by [bLIP 42].
///
/// Do not log it: a leaked secret lets others impersonate this contact's payment identity.
///
/// [bLIP 42]: https://github.com/lightning/blips/blob/master/blip-0042.md
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd)]
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

impl PartialEq for ContactSecret {
	fn eq(&self, other: &Self) -> bool {
		fixed_time_eq(self.as_bytes(), other.as_bytes())
	}
}

impl core::fmt::Debug for ContactSecret {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		f.write_str("ContactSecret")
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

/// The primary contact secret plus any additional remote secrets for one contact.
///
/// The first node to add the other generates [`Self::primary_secret`]. If the second node
/// independently added the first, it may have generated a different primary secret; each node
/// stores the other's in [`Self::additional_remote_secrets`].
///
/// [`Self::matches`] checks a candidate against the primary and any additional remotes.
/// [`Self::primary_secret`] is the secret this node generated or adopted for the contact.
///
/// `additional_remote_secrets` is a list, not a single optional value, because one contact can
/// have more than one secret: a second wallet, or an independent add that used a different offer
/// pair.
#[derive(Clone, PartialEq, Eq)]
pub struct ContactSecrets {
	primary_secret: ContactSecret,
	additional_remote_secrets: Vec<ContactSecret>,
}

impl ContactSecrets {
	/// Creates a new [`ContactSecrets`] with the given primary secret.
	pub fn new(primary_secret: ContactSecret) -> Self {
		Self { primary_secret, additional_remote_secrets: Vec::new() }
	}

	/// Creates a new [`ContactSecrets`] from a secret the wallet already has for this contact.
	///
	/// Use this instead of deriving when the contact provided a secret first.
	pub fn from_remote_secret(remote_secret: ContactSecret) -> Self {
		Self::new(remote_secret)
	}

	/// Creates a new [`ContactSecrets`] with the given primary secret and additional remote secrets.
	///
	/// This is not exported to bindings users as it takes a [`Vec`].
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
	///
	/// This is not exported to bindings users as it returns a slice.
	pub fn additional_remote_secrets(&self) -> &[ContactSecret] {
		&self.additional_remote_secrets
	}

	/// Records another secret for an existing contact.
	///
	/// The wallet UI is: if a candidate secret did not match any contact, offer "add to
	/// existing contact" after the user confirms who it is (out of band). Do not invent an
	/// automatic matcher from the secret alone.
	///
	/// This can be necessary when:
	///  - the contact used a different secret than the one we derived
	///  - the contact is using a different wallet from the one(s) we have already stored
	pub fn add_remote_secret(&mut self, remote_secret: ContactSecret) {
		if self.matches(&remote_secret) {
			return;
		}
		self.additional_remote_secrets.push(remote_secret);
	}

	/// Checks if the given secret matches either the primary secret or any additional remote secret.
	///
	/// Each comparison is constant time so a match does not reveal which stored secret hit. The
	/// number of additional secrets still affects runtime; use [`PartialEq`] only as a convenience
	/// for storage, not as a substitute for this method when authenticating a received secret.
	pub fn matches(&self, secret: &ContactSecret) -> bool {
		let mut found = fixed_time_eq(self.primary_secret.as_bytes(), secret.as_bytes());
		for remote_secret in &self.additional_remote_secrets {
			found |= fixed_time_eq(remote_secret.as_bytes(), secret.as_bytes());
		}
		found
	}
}

impl core::fmt::Debug for ContactSecrets {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		f.debug_struct("ContactSecrets")
			.field("additional_remote_secrets_len", &self.additional_remote_secrets.len())
			.finish_non_exhaustive()
	}
}

impl_ser_tlv_based!(ContactSecrets, {
	(1, primary_secret, required),
	(3, additional_remote_secrets, optional_vec),
});

/// Derives the contact secret from our offer signing key and the contact's offer.
///
/// This is deterministic: re-adding the same offer pair yields the same secret, and a contact
/// using the same algorithm with a static offer derives the same value.
///
/// Use this when deriving a new secret from two offers. If the wallet already has a secret from
/// this contact, use [`ContactSecrets::from_remote_secret`] instead.
///
/// # Arguments
/// * `our_offer_signing_key` - The private key behind our offer's `offer_node_id`, i.e. its
///   issuer signing pubkey if set, otherwise the final `blinded_node_id` of its first path.
///   This is an offer identity key, never the node's unique `node_id` key.
///   For offers whose signing pubkey was derived, prefer
///   [`OffersMessageFlow::compute_contact_secret`], which re-derives this key from the offer's
///   nonce (for example after
///   [`OffersMessageFlow::create_async_receive_offer_builder`]).
/// * `their_offer` - The offer from the contact
///
/// # Errors
/// Returns [`Bolt12SemanticError::MissingSigningPubkey`] if their offer has neither an
/// issuer signing key nor a blinded path.
///
/// [`OffersMessageFlow::create_async_receive_offer_builder`]: crate::offers::flow::OffersMessageFlow::create_async_receive_offer_builder
/// [`OffersMessageFlow::compute_contact_secret`]: crate::offers::flow::OffersMessageFlow::compute_contact_secret
pub fn compute_contact_secret(
	our_offer_signing_key: &SecretKey, their_offer: &Offer,
) -> Result<ContactSecrets, Bolt12SemanticError> {
	let offer_node_id = offer_node_id(their_offer)?;
	// bLIP 42 defines the secret as SHA256(tag || shared_point) where shared_point is the ECDH
	// result in compressed 33-byte encoding. Build that encoding from the raw x and y coordinates
	// so the hash input is exactly the compressed point and nothing else.
	let xy = shared_secret_point(&offer_node_id, our_offer_signing_key);
	let mut compressed = [0u8; 33];
	compressed[0] = if xy[63] & 1 == 1 { 0x03 } else { 0x02 };
	compressed[1..].copy_from_slice(&xy[..32]);
	let mut engine = sha256::Hash::engine();
	engine.input(b"blip42_contact_secret");
	engine.input(&compressed);
	let primary_secret = ContactSecret::new(sha256::Hash::from_engine(engine).to_byte_array());

	Ok(ContactSecrets::new(primary_secret))
}

/// The `offer_node_id` of a Bolt 12 offer, as defined by BLIP 42: `offer_issuer_id` if
/// present, otherwise the last `blinded_node_id` of the first path.
pub(super) fn offer_node_id(offer: &Offer) -> Result<PublicKey, Bolt12SemanticError> {
	if let Some(issuer) = offer.issuer_signing_pubkey() {
		Ok(issuer)
	} else {
		offer
			.paths()
			.first()
			.and_then(|path| path.blinded_hops().last())
			.map(|hop| hop.blinded_node_id)
			.ok_or(Bolt12SemanticError::MissingSigningPubkey)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hex::DisplayHex;
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

			let alice_computed = compute_contact_secret(&alice_key, &bob_offer).unwrap();
			let bob_computed = compute_contact_secret(&bob_key, &alice_offer).unwrap();

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
		secrets.add_remote_secret(primary);
		assert_eq!(secrets.additional_remote_secrets().len(), 1);
		assert!(secrets.matches(&primary));
		assert!(secrets.matches(&remote));
		assert!(!secrets.matches(&unknown));

		let from_remote = ContactSecrets::from_remote_secret(remote);
		assert_eq!(*from_remote.primary_secret(), remote);
	}

	#[test]
	fn contact_secrets_tlv_roundtrip() {
		let mut secrets = ContactSecrets::new(ContactSecret::new([1; 32]));
		secrets.add_remote_secret(ContactSecret::new([2; 32]));
		let encoded = secrets.encode();
		let decoded = ContactSecrets::read(&mut &encoded[..]).unwrap();
		assert_eq!(secrets, decoded);
		assert_eq!(decoded.additional_remote_secrets().len(), 1);
	}

	#[test]
	fn offer_node_id_prefers_issuer_id() {
		let alice_offer = Offer::from_str(ALICE_OFFER).unwrap();
		assert_eq!(offer_node_id(&alice_offer).unwrap().to_string(), ALICE_OFFER_NODE_ID);

		let bob_offer = Offer::from_str(TEST_VECTORS[1].bob_offer).unwrap();
		let issuer = bob_offer.issuer_signing_pubkey().unwrap();
		let path_last_hop = bob_offer
			.paths()
			.first()
			.and_then(|path| path.blinded_hops().last())
			.map(|hop| hop.blinded_node_id)
			.unwrap();
		assert_ne!(issuer, path_last_hop);
		assert_eq!(offer_node_id(&bob_offer).unwrap(), issuer);
	}
}
