// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Functional tests for the merchant side of bLIP 56 point-of-sale payment notifications.
//!
//! The point-of-sale device is played by a fixture that builds per-order offers from the
//! merchant's template with the wire types alone.

use crate::blinded_path::message::{BlindedMessagePath, OffersContext};
use crate::blinded_path::BlindedHop;
use crate::ln::channelmanager::PaymentId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{OnionMessage, OnionMessageHandler};
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::nonce::Nonce;
use crate::offers::offer::{Offer, Quantity};
use crate::offers::payment_token::SealedOrder;
use crate::onion_message::messenger::PeeledOnion;
use crate::onion_message::offers::OffersMessage;
use crate::sign::NodeSigner;

use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::prelude::*;

/// A `notification_path` standing in for one built by a point-of-sale device.
fn fixture_notification_path() -> BlindedMessagePath {
	let pubkey = |byte: u8| {
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[byte; 32]).unwrap())
	};
	BlindedMessagePath::from_blinded_path(
		pubkey(60),
		pubkey(61),
		vec![BlindedHop { blinded_node_id: pubkey(62), encrypted_payload: vec![0; 40] }],
	)
}

/// Builds a per-order offer from `template` the way a point-of-sale device would.
fn fixture_order_offer(template: &Offer, amount_msats: u64, description: &str) -> Offer {
	let sealed_order = SealedOrder {
		amount_msats,
		description: description.to_string(),
		order_metadata: vec![0x5a; 32],
	};
	let issuer_id = template.issuer_signing_pubkey().unwrap();
	let entropy = crate::util::test_utils::TestKeysInterface::new(&[7; 32], Network::Testnet);
	let payment_token = sealed_order.seal(&issuer_id, &entropy, &Secp256k1::new()).unwrap();
	template
		.with_per_order_records(
			amount_msats,
			description.to_string(),
			None,
			vec![fixture_notification_path()],
			payment_token,
		)
		.unwrap()
}

/// Returns the invoice request and the context of the path it arrived over.
fn peel_invoice_request<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, message: &OnionMessage,
) -> (InvoiceRequest, Option<OffersContext>) {
	match node.onion_messenger.peel_onion_message(message) {
		Ok(PeeledOnion::Offers(OffersMessage::InvoiceRequest(request), context, _)) => {
			(request, context)
		},
		Ok(_) => panic!("Unexpected onion message"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

#[test]
fn creates_pos_offer_template() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let customer = &nodes[0];
	let merchant = &nodes[1];
	let merchant_id = merchant.node.get_our_node_id();

	let template = merchant.node.create_pos_offer_template().unwrap();
	assert!(template.offer_features().supports_payment_notifications());
	assert_eq!(template.amount(), None);
	assert_eq!(template.description(), None);
	assert_eq!(template.supported_quantity(), Quantity::One);
	assert_eq!(template.chains(), vec![ChainHash::using_genesis_block(Network::Testnet)]);
	assert_eq!(template.paths().len(), 1);
	let issuer_id = template.issuer_signing_pubkey().unwrap();
	assert_ne!(issuer_id, merchant_id);

	// Each template gets its own issuer id.
	let other = merchant.node.create_pos_offer_template().unwrap();
	assert_ne!(other.issuer_signing_pubkey(), Some(issuer_id));

	// An invoice request for a per-order offer built from the template reaches the merchant over
	// the template's path, and verifies against the template's keys even though the device
	// changed the offer.
	let offer = fixture_order_offer(&template, 5_000, "espresso");
	customer.node.pay_for_offer(&offer, None, PaymentId([1; 32]), Default::default()).unwrap();
	let message = customer.onion_messenger.next_onion_message_for_peer(merchant_id).unwrap();
	let (request, context) = peel_invoice_request(merchant, &message);
	let nonce = match context {
		Some(OffersContext::PosTemplateInvoiceRequest { nonce }) => nonce,
		context => panic!("Unexpected context: {:?}", context),
	};

	let expanded_key = merchant.keys_manager.get_expanded_key();
	// Verification requires the keys derived from the nonce to be the offer's issuer id.
	let verified = request.clone().verify_for_pos_template(nonce, &expanded_key).unwrap();
	assert_eq!(verified.offer_id, offer.id());

	let other_nonce = Nonce([9; Nonce::LENGTH]);
	assert!(request.verify_for_pos_template(other_nonce, &expanded_key).is_err());
}
