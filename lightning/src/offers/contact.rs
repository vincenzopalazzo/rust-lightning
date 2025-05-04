// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for BLIP-0042 contact protocol.
//!
//! The contact protocol enables users to establish peer relationships in Lightning
//! for easier recurring payments and identification.

use crate::offers::offer::Offer;
use crate::util::ser::{Writeable, Writer};
use bitcoin::secp256k1::{PublicKey, schnorr::Signature};

#[allow(unused_imports)]
use crate::prelude::*;
use core::convert::TryFrom;
use crate::io;
use sha2::{Digest, Sha256};

/// Structure representing a contact secret for BLIP-0042
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactSecret(pub(crate) [u8; 32]);

impl ContactSecret {
    /// Create a new contact secret from a 32-byte array
    pub fn new(secret: [u8; 32]) -> Self {
        Self(secret)
    }

    /// Get the byte representation of the contact secret
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Derive a contact secret from two offers
    pub fn derive_from_offers(payer_offer: &Offer, recipient_offer: &Offer) -> Self {
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
}

impl Writeable for ContactSecret {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(&self.0[..])
    }
}

/// BIP 353 human-readable name information
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip353Name {
    /// Name part of the BIP 353 name
    pub name: String,
    /// Domain part of the BIP 353 name
    pub domain: String,
}

impl Bip353Name {
    /// Create a new BIP 353 name
    pub fn new(name: String, domain: String) -> Self {
        Self { name, domain }
    }

    /// Get the formatted BIP 353 name as name@domain
    pub fn formatted_name(&self) -> String {
        format!("{}@{}", self.name, self.domain)
    }
}

/// A structure representing a contact pair in the Lightning Network
#[derive(Clone, Debug)]
pub struct Contact {
    /// The contact secret shared between two parties
    pub secret: ContactSecret,
    /// Optional BIP 353 name associated with this contact
    pub bip353_name: Option<Bip353Name>,
    /// Optional node ID (if available)
    pub node_id: Option<PublicKey>,
}

impl Contact {
    /// Create a new contact with the given secret
    pub fn new(secret: ContactSecret) -> Self {
        Self {
            secret,
            bip353_name: None,
            node_id: None,
        }
    }
    
    /// Create a new contact from a pair of offers
    pub fn from_offers(payer_offer: &Offer, recipient_offer: &Offer) -> Self {
        let secret = ContactSecret::derive_from_offers(payer_offer, recipient_offer);
        Self::new(secret)
    }
    
    /// Set the BIP 353 name for this contact
    pub fn with_bip353_name(mut self, name: String, domain: String) -> Self {
        self.bip353_name = Some(Bip353Name::new(name, domain));
        self
    }
    
    /// Set the node ID for this contact
    pub fn with_node_id(mut self, node_id: PublicKey) -> Self {
        self.node_id = Some(node_id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use core::str::FromStr;
    use crate::offers::offer::OfferBuilder;

    #[test]
    fn test_contact_secret_derivation() {
        // Example from BLIP-0042
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

        // Create contact from offers
        let contact = Contact::from_offers(&alice_offer, &bob_offer);
        
        // Create contact in reverse order (should be the same)
        let reverse_contact = Contact::from_offers(&bob_offer, &alice_offer);

        // Verify that the contact secrets match
        assert_eq!(contact.secret.as_bytes(), reverse_contact.secret.as_bytes());
    }

    #[test]
    fn test_bip353_name_formatting() {
        let name = Bip353Name::new("alice".to_string(), "example.com".to_string());
        assert_eq!(name.formatted_name(), "alice@example.com");
    }
}