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
use crate::blinded_path::payment::{Bolt12OfferContext, PaymentContext};
use crate::blinded_path::BlindedHop;
use crate::ln::channelmanager::PaymentId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{OnionMessage, OnionMessageHandler};
use crate::ln::offers_tests::{claim_bolt12_payment, extract_invoice, route_bolt12_payment};
use crate::offers::invoice_request::{InvoiceRequest, PayerFields};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{Offer, Quantity};
use crate::offers::payment_token::{payment_token_hash, SealedOrder};
use crate::offers::pos_merchant::PosPaymentData;
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
	let issuer_id = template.issuer_signing_pubkey().unwrap();
	let token = fixture_token(&issuer_id, amount_msats, description);
	fixture_offer_with(
		template,
		amount_msats,
		description,
		vec![fixture_notification_path()],
		token,
	)
}

/// Seals an order to `issuer_id` the way a point-of-sale device would.
fn fixture_token(issuer_id: &PublicKey, amount_msats: u64, description: &str) -> Vec<u8> {
	let sealed_order = SealedOrder {
		amount_msats,
		description: description.to_string(),
		order_metadata: vec![0x5a; 32],
	};
	let entropy = crate::util::test_utils::TestKeysInterface::new(&[7; 32], Network::Testnet);
	sealed_order.seal(issuer_id, &entropy, &Secp256k1::new()).unwrap()
}

/// A per-order offer with the given cleartext fields and records, consistent with them or not.
fn fixture_offer_with(
	template: &Offer, amount_msats: u64, description: &str,
	notification_paths: Vec<BlindedMessagePath>, payment_token: Vec<u8>,
) -> Offer {
	template
		.with_per_order_records(
			amount_msats,
			description.to_string(),
			None,
			notification_paths,
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

/// Has `customer` request an invoice for `offer` and delivers the request to `merchant`,
/// returning the request as the merchant received it and the context of the path it took.
fn request_invoice<'a, 'b, 'c>(
	customer: &Node<'a, 'b, 'c>, merchant: &Node<'a, 'b, 'c>, offer: &Offer, amount: Option<u64>,
	payment_id: PaymentId,
) -> (InvoiceRequest, Option<OffersContext>) {
	let merchant_id = merchant.node.get_our_node_id();
	customer.node.pay_for_offer(offer, amount, payment_id, Default::default()).unwrap();
	let message = customer.onion_messenger.next_onion_message_for_peer(merchant_id).unwrap();
	merchant.onion_messenger.handle_onion_message(customer.node.get_our_node_id(), &message);
	peel_invoice_request(merchant, &message)
}

#[test]
fn pays_for_per_order_offer() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let customer = &nodes[0];
	let merchant = &nodes[1];
	let merchant_id = merchant.node.get_our_node_id();
	let customer_id = customer.node.get_our_node_id();

	let template = merchant.node.create_pos_offer_template().unwrap();
	let offer = fixture_order_offer(&template, 5_000_000, "espresso");
	let payment_id = PaymentId([1; 32]);
	let (invoice_request, context) = request_invoice(customer, merchant, &offer, None, payment_id);
	let nonce = match context {
		Some(OffersContext::PosTemplateInvoiceRequest { nonce }) => nonce,
		context => panic!("Unexpected context: {:?}", context),
	};

	let message = merchant.onion_messenger.next_onion_message_for_peer(customer_id).unwrap();
	customer.onion_messenger.handle_onion_message(merchant_id, &message);
	let (invoice, _) = extract_invoice(customer, &message);

	// The invoice is signed with the template's issuer id and carries the token byte for byte.
	assert_eq!(invoice.signing_pubkey(), template.issuer_signing_pubkey().unwrap());
	assert_eq!(invoice.payment_token(), offer.payment_token());
	assert_eq!(invoice.amount_msats(), 5_000_000);

	// What the merchant needs to notify the device travels in the payment paths.
	let payment_data = PosPaymentData {
		template_nonce: nonce,
		payment_token_hash: payment_token_hash(offer.payment_token().unwrap()),
		notification_path: fixture_notification_path(),
	};
	let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
		offer_id: offer.id(),
		invoice_request: PayerFields {
			payer_signing_pubkey: invoice_request.payer_signing_pubkey(),
			quantity: None,
			payer_note_truncated: None,
			human_readable_name: None,
		},
		payment_metadata: Some(payment_data.to_payment_metadata()),
	});

	route_bolt12_payment(customer, &[merchant], &invoice);
	// The customer also pays the proportional fee of the dummy hops in the payment path.
	claim_bolt12_payment(customer, &[merchant], payment_context, &invoice, Some(25));
}

#[test]
fn rejects_invalid_per_order_invoice_requests() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let customer = &nodes[0];
	let merchant = &nodes[1];
	let customer_id = customer.node.get_our_node_id();

	let template = merchant.node.create_pos_offer_template().unwrap();
	let issuer_id = template.issuer_signing_pubkey().unwrap();
	let path = fixture_notification_path;
	let token = |amount, description| fixture_token(&issuer_id, amount, description);
	let other_issuer =
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[44; 32]).unwrap());

	let invalid_offers = [
		// The cleartext amount was lowered after sealing.
		fixture_offer_with(&template, 4_000, "espresso", vec![path()], token(5_000, "espresso")),
		// The cleartext description was changed after sealing.
		fixture_offer_with(&template, 5_000, "espressO", vec![path()], token(5_000, "espresso")),
		// Sealed to someone else.
		fixture_offer_with(
			&template,
			5_000,
			"espresso",
			vec![path()],
			fixture_token(&other_issuer, 5_000, "espresso"),
		),
		// Not a token at all.
		fixture_offer_with(&template, 5_000, "espresso", vec![path()], vec![1; 100]),
		// No notification path.
		fixture_offer_with(&template, 5_000, "espresso", vec![], token(5_000, "espresso")),
	];
	for (i, offer) in invalid_offers.iter().enumerate() {
		request_invoice(customer, merchant, offer, None, PaymentId([i as u8 + 1; 32]));
		assert!(
			merchant.onion_messenger.next_onion_message_for_peer(customer_id).is_none(),
			"invalid offer {} was answered",
			i
		);
	}

	// The template itself is not meant to be paid: a request without a token is rejected.
	request_invoice(customer, merchant, &template, Some(5_000), PaymentId([42; 32]));
	assert!(merchant.onion_messenger.next_onion_message_for_peer(customer_id).is_none());

	// A request paying more than the order is fine.
	let offer = fixture_order_offer(&template, 5_000, "espresso");
	request_invoice(customer, merchant, &offer, Some(6_000), PaymentId([43; 32]));
	assert!(merchant.onion_messenger.next_onion_message_for_peer(customer_id).is_some());
}
