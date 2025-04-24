// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request_metadata` records.

use crate::offers::offer::Offer;
use crate::offers::signer::Metadata;
use crate::util::ser::WithoutLength;
use bitcoin::secp256k1::{PublicKey, schnorr::Signature};

#[allow(unused_imports)]
use crate::prelude::*;

/// An unpredictable sequence of bytes typically containing information needed to derive
/// [`InvoiceRequest::payer_signing_pubkey`] and [`Refund::payer_signing_pubkey`].
///
/// [`InvoiceRequest::payer_signing_pubkey`]: crate::offers::invoice_request::InvoiceRequest::payer_signing_pubkey
/// [`Refund::payer_signing_pubkey`]: crate::offers::refund::Refund::payer_signing_pubkey
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct PayerContents(pub Metadata);

/// TLV record type for [`InvoiceRequest::payer_metadata`] and [`Refund::payer_metadata`].
///
/// [`InvoiceRequest::payer_metadata`]: crate::offers::invoice_request::InvoiceRequest::payer_metadata
/// [`Refund::payer_metadata`]: crate::offers::refund::Refund::payer_metadata
pub(super) const PAYER_METADATA_TYPE: u64 = 0;

/// TLV record type for [`InvoiceRequest::contact_secret`].
///
/// This is an identifier for a contact pair that allows the recipient to identify
/// the payer as a contact.
pub(super) const INVOICE_REQUEST_CONTACT_SECRET_TYPE: u64 = 2000001729;

/// TLV record type for [`InvoiceRequest::payer_offer`].
///
/// This field allows the payer to reveal a Bolt12 offer that can be used by contacts to pay them back.
pub(super) const INVOICE_REQUEST_PAYER_OFFER_TYPE: u64 = 2000001731;

/// TLV record type for [`InvoiceRequest::payer_bip353_name`].
///
/// This field allows the payer to reveal their BIP 353 name to allow contacts to pay them back.
pub(super) const INVOICE_REQUEST_PAYER_BIP353_NAME_TYPE: u64 = 2000001733;

/// TLV record type for [`InvoiceRequest::payer_bip353_signature`].
///
/// This field lets payers provide a signature of the invoice_request using one of the signing keys
/// of the offer associated with their BIP 353 name, thus proving ownership of this BIP 353 name.
pub(super) const INVOICE_REQUEST_PAYER_BIP353_SIGNATURE_TYPE: u64 = 2000001735;

/// BIP 353 human-readable name information
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip353Name {
    /// Name part of the BIP 353 name
    pub name: String,
    /// Domain part of the BIP 353 name
    pub domain: String,
}

/// Structure to hold a contact secret
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactSecret([u8; 32]);

impl ContactSecret {
    /// Create a new contact secret from a 32-byte array
    pub fn new(secret: [u8; 32]) -> Self {
        Self(secret)
    }

    /// Get the byte representation of the contact secret
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

tlv_stream!(PayerTlvStream, PayerTlvStreamRef<'a>, 0..1, {
	(PAYER_METADATA_TYPE, metadata: (Vec<u8>, WithoutLength)),
});

/// TLV stream for experimental invoice request types including contacts
tlv_stream!(PayerContactTlvStream, PayerContactTlvStreamRef<'a>, 2000000000..3000000000, {
    (INVOICE_REQUEST_CONTACT_SECRET_TYPE, contact_secret: [u8; 32]),
    (INVOICE_REQUEST_PAYER_OFFER_TYPE, payer_offer: (Vec<u8>, WithoutLength)),
    (INVOICE_REQUEST_PAYER_BIP353_NAME_TYPE, payer_bip353_name: (Vec<u8>, WithoutLength)),
    (INVOICE_REQUEST_PAYER_BIP353_SIGNATURE_TYPE, payer_bip353_signature: (Vec<u8>, WithoutLength)),
});

/// Helper for generating deterministic contact secret
pub fn derive_contact_secret(payer_offer: &Offer, recipient_offer: &Offer) -> ContactSecret {
    // Implementation of the BLIP-0042 contact secret derivation
    use sha2::{Digest, Sha256};

    let payer_id_bytes = match payer_offer.issuer_signing_pubkey() {
        Some(pubkey) => pubkey.serialize(),
        None => {
            // If no issuer signing pubkey, use first blinded path node id
            match payer_offer.paths().first() {
                Some(path) => path.introduction_node().serialize(),
                None => [0u8; 33], // Fallback, should not happen
            }
        }
    };

    let recipient_id_bytes = match recipient_offer.issuer_signing_pubkey() {
        Some(pubkey) => pubkey.serialize(),
        None => {
            // If no issuer signing pubkey, use first blinded path node id
            match recipient_offer.paths().first() {
                Some(path) => path.introduction_node().serialize(),
                None => [0u8; 33], // Fallback, should not happen
            }
        }
    };

    // Sort lexicographically to ensure the same secret regardless of order
    let (first_id, second_id) = if payer_id_bytes < recipient_id_bytes {
        (payer_id_bytes, recipient_id_bytes)
    } else {
        (recipient_id_bytes, payer_id_bytes)
    };

    // Create a hash of both pubkeys to derive the contact secret
    let mut hasher = Sha256::new();
    hasher.update(b"bolt12_contact_secret");
    hasher.update(&first_id);
    hasher.update(&second_id);

    let hash = hasher.finalize();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&hash);

    ContactSecret(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use core::str::FromStr;
    use crate::offers::offer::{Offer, OfferBuilder};

    #[test]
    fn test_derive_contact_secret() {
        // Example from BLIP-0042
        // First, create the test offers with specific keys
        let secp_ctx = Secp256k1::new();

        // Alice's key
        let alice_secret = SecretKey::from_str("4ed1a01dae275f7b7ba503dbae23dddd774a8d5f64788ef7a768ed647dd0e1eb").unwrap();
        let alice_pubkey = PublicKey::from_secret_key(&secp_ctx, &alice_secret);

        // Bob's key
        let bob_secret = SecretKey::from_str("bcaafa8ed73da11437ce58c7b3458567a870168c0da325a40292fed126b97845").unwrap();
        let bob_pubkey = PublicKey::from_secret_key(&secp_ctx, &bob_secret);

        // Create Alice and Bob offers
        let alice_offer = OfferBuilder::new(alice_pubkey)
            .description("Alice's Store".to_string())
            .build().unwrap();

        let bob_offer = OfferBuilder::new(bob_pubkey)
            .description("Bob's Store".to_string())
            .build().unwrap();

        // Derive the contact secret
        let contact_secret = derive_contact_secret(&alice_offer, &bob_offer);

        // Derive the same contact secret in reverse order (should be the same)
        let reverse_contact_secret = derive_contact_secret(&bob_offer, &alice_offer);

        // Verify that the contact secrets match
        assert_eq!(contact_secret.as_bytes(), reverse_contact_secret.as_bytes());

        // Create a third offer
        let carol_secret = SecretKey::from_str("12afb8248c7336e6aea5fe247bc4bac5dcabfb6017bd67b32c8195a6c56b8333").unwrap();
        let carol_pubkey = PublicKey::from_secret_key(&secp_ctx, &carol_secret);
        let carol_offer = OfferBuilder::new(carol_pubkey)
            .description("Carol's Store".to_string())
            .build().unwrap();

        // Verify that contact secrets are different for different pairs
        let alice_carol_secret = derive_contact_secret(&alice_offer, &carol_offer);
        let bob_carol_secret = derive_contact_secret(&bob_offer, &carol_offer);

        assert_ne!(contact_secret.as_bytes(), alice_carol_secret.as_bytes());
        assert_ne!(contact_secret.as_bytes(), bob_carol_secret.as_bytes());
        assert_ne!(alice_carol_secret.as_bytes(), bob_carol_secret.as_bytes());
    }
}
