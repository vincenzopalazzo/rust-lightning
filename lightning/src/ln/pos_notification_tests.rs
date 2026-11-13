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

use crate::blinded_path::message::{
	BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext, PosNotificationContext,
};
use crate::blinded_path::payment::{Bolt12OfferContext, PaymentContext};
use crate::blinded_path::BlindedHop;
use crate::blinded_path::EmptyNodeIdLookUp;
use crate::events::Event;
use crate::events::PaidBolt12Invoice;
use crate::ln::channelmanager::PaymentId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::Init;
use crate::ln::msgs::{BaseMessageHandler, OnionMessage, OnionMessageHandler};
use crate::ln::offers_tests::{claim_bolt12_payment, extract_invoice, route_bolt12_payment};
use crate::ln::peer_handler::IgnoringMessageHandler;
use crate::offers::invoice::Bolt12Invoice;
use crate::offers::invoice_request::{InvoiceRequest, PayerFields};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{Offer, Quantity};
use crate::offers::payer_proof::PayerProof;
use crate::offers::payment_notification::PaymentNotification;
use crate::offers::payment_token::{payment_token_hash, SealedOrder};
use crate::offers::pos_merchant::PosPaymentData;
use crate::offers::pos_merchant::{PaymentNotificationOutcome, MAX_PAYMENT_NOTIFICATION_ATTEMPTS};
use crate::offers::pos_terminal::{PosConfig, PosEvent, PosTerminal};
use crate::onion_message::messenger::{DefaultMessageRouter, OnionMessenger};
use crate::onion_message::messenger::{Destination, MessageSendInstructions, PeeledOnion};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::pos_notification::PaymentProof;
use crate::onion_message::pos_notification::{
	NackReason, NotificationAck, NotificationNack, PosNotificationMessage,
};
use crate::routing::gossip::NetworkGraph;
use crate::sign::NodeSigner;
use crate::types::features::InitFeatures;
use crate::types::payment::PaymentHash;
use crate::types::payment::PaymentPreimage;
use crate::util::ser::{ReadableArgs, Writeable};
use crate::util::test_utils::{TestKeysInterface, TestLogger};

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

/// Has `customer` pay `offer`, a per-order offer built from `template` whose notification path is
/// `notification_path`, and has `merchant` claim the payment. Returns the invoice that was paid.
fn pay_and_claim<'a, 'b, 'c>(
	customer: &Node<'a, 'b, 'c>, merchant: &Node<'a, 'b, 'c>, template: &Offer, offer: &Offer,
	notification_path: BlindedMessagePath, payment_id: PaymentId,
) -> Bolt12Invoice {
	let merchant_id = merchant.node.get_our_node_id();
	let customer_id = customer.node.get_our_node_id();

	let (invoice_request, context) = request_invoice(customer, merchant, offer, None, payment_id);
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

	// What the merchant needs to notify the device travels in the payment paths.
	let payment_data = PosPaymentData {
		template_nonce: nonce,
		payment_token_hash: payment_token_hash(offer.payment_token().unwrap()),
		notification_path,
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
	let dummy_hop_fees = invoice.amount_msats() / 200_000;
	claim_bolt12_payment(customer, &[merchant], payment_context, &invoice, Some(dummy_hop_fees));
	invoice
}

#[test]
fn pays_for_per_order_offer() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let (customer, merchant) = (&nodes[0], &nodes[1]);
	let template = merchant.node.create_pos_offer_template().unwrap();
	let offer = fixture_order_offer(&template, 5_000_000, "espresso");
	let path = fixture_notification_path();
	let invoice = pay_and_claim(customer, merchant, &template, &offer, path, PaymentId([1; 32]));
	assert_eq!(invoice.amount_msats(), 5_000_000);
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

/// A `notification_path` built by `pos`, introduced by `merchant`, as a point-of-sale device
/// connected to its merchant would build one.
fn pos_notification_path<'a, 'b, 'c>(
	pos: &Node<'a, 'b, 'c>, merchant: &Node<'a, 'b, 'c>,
) -> BlindedMessagePath {
	let intro =
		MessageForwardNode { node_id: merchant.node.get_our_node_id(), short_channel_id: None };
	let context = PosNotificationContext::NotificationPath { order_id: [7; 32] };
	BlindedMessagePath::new(
		&[intro],
		pos.node.get_our_node_id(),
		pos.keys_manager.get_receive_auth_key(),
		MessageContext::PosNotification(context),
		false,
		pos.keys_manager,
		&Secp256k1::new(),
	)
}

/// Takes the next payment notification `merchant` sends to `pos`, as `pos` receives it, along with
/// the reply path to answer over.
fn receive_notification<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>, pos: &Node<'a, 'b, 'c>,
) -> Option<(PaymentNotification, BlindedMessagePath)> {
	let message =
		merchant.onion_messenger.next_onion_message_for_peer(pos.node.get_our_node_id())?;
	match pos.onion_messenger.peel_onion_message(&message) {
		Ok(PeeledOnion::PosNotification(
			PosNotificationMessage::PaymentNotification(notification),
			PosNotificationContext::NotificationPath { order_id },
			Some(reply_path),
		)) => {
			assert_eq!(order_id, [7; 32]);
			Some((notification, reply_path))
		},
		Ok(_) => panic!("Unexpected onion message"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

/// Has `pos` send `answer` to `merchant` over `destination`.
fn answer<'a, 'b, 'c>(
	pos: &Node<'a, 'b, 'c>, merchant: &Node<'a, 'b, 'c>, answer: PosNotificationMessage,
	destination: Destination,
) {
	let instructions = MessageSendInstructions::WithoutReplyPath { destination };
	pos.onion_messenger.send_onion_message(answer, instructions).unwrap();
	let merchant_id = merchant.node.get_our_node_id();
	let message = pos.onion_messenger.next_onion_message_for_peer(merchant_id).unwrap();
	merchant.onion_messenger.handle_onion_message(pos.node.get_our_node_id(), &message);
}

fn ack(payment_hash: PaymentHash) -> PosNotificationMessage {
	PosNotificationMessage::NotificationAck(NotificationAck { payment_hash })
}

fn nack(payment_hash: PaymentHash, reason: NackReason) -> PosNotificationMessage {
	PosNotificationMessage::NotificationNack(NotificationNack { payment_hash, reason })
}

fn resolved_notifications<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>,
) -> Vec<(PaymentHash, PaymentNotificationOutcome)> {
	merchant
		.node
		.get_and_clear_pending_events()
		.into_iter()
		.filter_map(|event| match event {
			Event::PaymentNotificationResolved { payment_hash, outcome } => {
				Some((payment_hash, outcome))
			},
			_ => None,
		})
		.collect()
}

/// Sets up a customer (node 0) with a channel to a merchant (node 1), and a point-of-sale device
/// (node 2) connected to the merchant without channels. The customer pays a per-order offer whose
/// notification path leads to the device, and the merchant claims it.
macro_rules! settle_order {
	($nodes: expr) => {{
		create_announced_chan_between_nodes_with_value(&$nodes, 0, 1, 10_000_000, 1_000_000_000);
		let (customer, merchant, pos) = (&$nodes[0], &$nodes[1], &$nodes[2]);
		let template = merchant.node.create_pos_offer_template().unwrap();
		let path = pos_notification_path(pos, merchant);
		let issuer_id = template.issuer_signing_pubkey().unwrap();
		let token = fixture_token(&issuer_id, 5_000_000, "espresso");
		let offer = fixture_offer_with(&template, 5_000_000, "espresso", vec![path.clone()], token);
		let invoice =
			pay_and_claim(customer, merchant, &template, &offer, path, PaymentId([1; 32]));
		(template, offer, invoice)
	}};
}

#[test]
fn notifies_point_of_sale_of_settled_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (template, offer, invoice) = settle_order!(nodes);
	let (merchant, pos) = (&nodes[1], &nodes[2]);

	let (notification, reply_path) = receive_notification(merchant, pos).unwrap();
	let payment_hash = invoice.payment_hash();

	// Signed by the template's issuer key and bound to this order's token and payment.
	assert!(notification.verify(template.issuer_signing_pubkey().unwrap()).is_ok());
	assert_eq!(
		notification.payment_token_hash(),
		payment_token_hash(offer.payment_token().unwrap())
	);
	assert_eq!(notification.payment_hash(), payment_hash);
	assert_eq!(PaymentHash::from(notification.preimage()), payment_hash);
	// The amount claimed, which includes the dummy-hop fees the customer paid on top of the
	// invoice, is what the notification reports.
	assert!(notification.amount_msats() > invoice.amount_msats());

	// The reply path starts at the merchant, which the device is connected to.
	assert_eq!(
		reply_path.introduction_node(),
		&crate::blinded_path::IntroductionNode::NodeId(merchant.node.get_our_node_id())
	);

	answer(pos, merchant, ack(payment_hash), Destination::BlindedPath(reply_path));
	assert_eq!(
		resolved_notifications(merchant),
		vec![(payment_hash, PaymentNotificationOutcome::Acknowledged)]
	);

	// Once acknowledged, the notification is not sent again.
	for _ in 0..100 {
		merchant.node.timer_tick_occurred();
	}
	assert!(receive_notification(merchant, pos).is_none());
	assert!(resolved_notifications(merchant).is_empty());
}

#[test]
fn retries_payment_notification_until_answered() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (_, _, invoice) = settle_order!(nodes);
	let (merchant, pos) = (&nodes[1], &nodes[2]);
	let payment_hash = invoice.payment_hash();

	// The first attempt goes unanswered; retries come after 1, 2 and 4 ticks.
	let (first, reply_path) = receive_notification(merchant, pos).unwrap();
	let mut sent_at = Vec::new();
	for tick in 1..=7 {
		merchant.node.timer_tick_occurred();
		if let Some((notification, retry_reply_path)) = receive_notification(merchant, pos) {
			// Retries are the same notification, answerable over the same reply path.
			assert_eq!(notification, first);
			assert_eq!(retry_reply_path, reply_path);
			sent_at.push(tick);
		}
	}
	assert_eq!(sent_at, vec![1, 3, 7]);

	// An answer for another payment is ignored, as is one sent outside the reply path.
	answer(pos, merchant, ack(PaymentHash([1; 32])), Destination::BlindedPath(reply_path.clone()));
	answer(pos, merchant, ack(payment_hash), Destination::Node(merchant.node.get_our_node_id()));
	assert!(resolved_notifications(merchant).is_empty());

	// A refusal ends the retries and is reported for reconciliation.
	let reason = NackReason::OrderExpired;
	answer(pos, merchant, nack(payment_hash, reason), Destination::BlindedPath(reply_path));
	assert_eq!(
		resolved_notifications(merchant),
		vec![(payment_hash, PaymentNotificationOutcome::Refused { reason })]
	);
	for _ in 0..100 {
		merchant.node.timer_tick_occurred();
	}
	assert!(receive_notification(merchant, pos).is_none());
}

#[test]
fn gives_up_on_payment_notification() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (_, _, invoice) = settle_order!(nodes);
	let (merchant, pos) = (&nodes[1], &nodes[2]);
	let payment_hash = invoice.payment_hash();

	// The device says it does not know the order, which may be a state loss it recovers from,
	// so the merchant keeps trying.
	let (_, reply_path) = receive_notification(merchant, pos).unwrap();
	let reason = NackReason::UnknownOrder;
	answer(pos, merchant, nack(payment_hash, reason), Destination::BlindedPath(reply_path));
	assert!(resolved_notifications(merchant).is_empty());

	let mut attempts = 1;
	let mut outcomes = Vec::new();
	for _ in 0..200 {
		merchant.node.timer_tick_occurred();
		if receive_notification(merchant, pos).is_some() {
			attempts += 1;
		}
		outcomes.extend(resolved_notifications(merchant));
	}
	assert_eq!(attempts, MAX_PAYMENT_NOTIFICATION_ATTEMPTS);

	// It gives up eventually, reporting the last answer it got.
	assert_eq!(outcomes, vec![(payment_hash, PaymentNotificationOutcome::Refused { reason })]);
}

#[test]
fn keeps_payment_notification_across_restart() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let persister;
	let chain_monitor;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let merchant_deserialized;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	let (_, _, invoice) = settle_order!(nodes);
	let payment_hash = invoice.payment_hash();

	// The notification is sent but its answer is lost.
	assert!(receive_notification(&nodes[1], &nodes[2]).is_some());

	let channel_id = nodes[1].node.list_channels()[0].channel_id;
	let monitor = get_monitor!(nodes[1], channel_id).encode();
	let manager = nodes[1].node.encode();
	reload_node!(nodes[1], &manager, &[&monitor], persister, chain_monitor, merchant_deserialized);
	let merchant_id = nodes[1].node.get_our_node_id();
	nodes[2].node.peer_disconnected(merchant_id);
	nodes[2].onion_messenger.peer_disconnected(merchant_id);
	connect_nodes(&nodes[1], &nodes[2]);

	// The merchant resumes retrying after the restart, and the answer then settles it.
	merchant_tick_until_sent(&nodes[1], &nodes[2], payment_hash);
}

fn merchant_tick_until_sent<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>, pos: &Node<'a, 'b, 'c>, payment_hash: PaymentHash,
) {
	for _ in 0..10 {
		merchant.node.timer_tick_occurred();
		if let Some((notification, reply_path)) = receive_notification(merchant, pos) {
			assert_eq!(notification.payment_hash(), payment_hash);
			answer(pos, merchant, ack(payment_hash), Destination::BlindedPath(reply_path));
			assert_eq!(
				resolved_notifications(merchant),
				vec![(payment_hash, PaymentNotificationOutcome::Acknowledged)]
			);
			return;
		}
	}
	panic!("The notification was not retried");
}

type TestPosTerminal<'a> =
	PosTerminal<&'a TestKeysInterface, &'a TestKeysInterface, &'a TestLogger>;

/// The onion messenger of a point-of-sale device: no channels, just a [`PosTerminal`] handling
/// payment notifications.
type PosMessenger<'a> = OnionMessenger<
	&'a TestKeysInterface,
	&'a TestKeysInterface,
	&'a TestLogger,
	EmptyNodeIdLookUp,
	DefaultMessageRouter<&'a NetworkGraph<&'a TestLogger>, &'a TestLogger, &'a TestKeysInterface>,
	IgnoringMessageHandler,
	IgnoringMessageHandler,
	IgnoringMessageHandler,
	&'a TestPosTerminal<'a>,
	IgnoringMessageHandler,
>;

fn pos_messenger<'a>(
	keys: &'a TestKeysInterface, logger: &'a TestLogger, graph: &'a NetworkGraph<&'a TestLogger>,
	terminal: &'a TestPosTerminal<'a>,
) -> PosMessenger<'a> {
	OnionMessenger::new(
		keys,
		keys,
		logger,
		EmptyNodeIdLookUp {},
		DefaultMessageRouter::new(graph, keys),
		IgnoringMessageHandler {},
		IgnoringMessageHandler {},
		IgnoringMessageHandler {},
		terminal,
		IgnoringMessageHandler {},
	)
}

/// Connects a point-of-sale device's messenger to its merchant, the way a terminal without
/// channels is connected to the node it takes payments for.
fn connect_pos<'a, 'b, 'c>(pos: &PosMessenger, pos_id: PublicKey, merchant: &Node<'a, 'b, 'c>) {
	let mut features = InitFeatures::empty();
	features.set_onion_messages_optional();
	let init = Init { features, networks: None, remote_network_address: None };
	let merchant_id = merchant.node.get_our_node_id();
	pos.peer_connected(merchant_id, &init, false).unwrap();
	merchant.onion_messenger.peer_connected(pos_id, &init, true).unwrap();
}

/// Delivers the notification `merchant` sends to the device, and the device's answer back.
fn deliver_notification<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>, pos: &PosMessenger, pos_id: PublicKey,
) {
	let merchant_id = merchant.node.get_our_node_id();
	let notification = merchant.onion_messenger.next_onion_message_for_peer(pos_id).unwrap();
	pos.handle_onion_message(merchant_id, &notification);
	let answer = pos.next_onion_message_for_peer(merchant_id).unwrap();
	merchant.onion_messenger.handle_onion_message(pos_id, &answer);
}

/// Sets up a point-of-sale device connected to `$merchant`: keys, a [`PosTerminal`] and its
/// [`PosMessenger`], bound to the given names.
macro_rules! point_of_sale {
	($merchant: expr, $keys: ident, $logger: ident, $graph: ident, $terminal: ident,
	 $messenger: ident, $pos_id: ident) => {
		let $keys = TestKeysInterface::new(&[9; 32], Network::Testnet);
		let $logger = TestLogger::with_id("pos".to_string());
		let $graph = NetworkGraph::new(Network::Testnet, &$logger);
		let chain = ChainHash::using_genesis_block(Network::Testnet);
		let config = PosConfig::new(chain, Some($merchant.node.get_our_node_id()));
		let $terminal = PosTerminal::new(&$keys, &$keys, &$logger, config);
		let $messenger = pos_messenger(&$keys, &$logger, &$graph, &$terminal);
		let $pos_id = $keys.get_node_id(crate::sign::Recipient::Node).unwrap();
		connect_pos(&$messenger, $pos_id, $merchant);
	};
}

#[test]
fn point_of_sale_terminal_settles_paid_order() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	let (customer, merchant) = (&nodes[0], &nodes[1]);

	point_of_sale!(merchant, pos_keys, pos_logger, pos_graph, terminal, pos, pos_id);

	// The merchant hands its template to the device, which shows the customer a per-order offer.
	let template = merchant.node.create_pos_offer_template().unwrap();
	let (order_id, offer) =
		terminal.create_order(&template, 5_000_000, "espresso".to_string(), None).unwrap();

	let path = offer.notification_paths()[0].clone();
	let invoice = pay_and_claim(customer, merchant, &template, &offer, path, PaymentId([1; 32]));
	let payment_hash = invoice.payment_hash();

	deliver_notification(merchant, &pos, pos_id);

	let events = terminal.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		PosEvent::OrderPaid { order_id: paid, payment_hash: hash, amount_msats } => {
			assert_eq!(*paid, order_id);
			assert_eq!(*hash, payment_hash);
			assert!(*amount_msats >= 5_000_000);
		},
		event => panic!("Unexpected event: {:?}", event),
	}
	let payment = terminal.order(&order_id).unwrap().payment.unwrap();
	assert_eq!(payment.payment_hash, payment_hash);
	assert!(payment.notification.is_some());

	assert_eq!(
		resolved_notifications(merchant),
		vec![(payment_hash, PaymentNotificationOutcome::Acknowledged)]
	);
}

#[test]
fn point_of_sale_terminal_refuses_resealed_offer() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	let (customer, merchant) = (&nodes[0], &nodes[1]);

	point_of_sale!(merchant, pos_keys, pos_logger, pos_graph, terminal, pos, pos_id);

	let template = merchant.node.create_pos_offer_template().unwrap();
	let (order_id, offer) =
		terminal.create_order(&template, 5_000_000, "espresso".to_string(), None).unwrap();

	// The customer keeps the price and the notification path but seals a description of their
	// own. Nothing the merchant can check tells this apart from the device's offer.
	let issuer_id = template.issuer_signing_pubkey().unwrap();
	let resealed = fixture_offer_with(
		&template,
		5_000_000,
		"two espressos",
		offer.notification_paths().to_vec(),
		fixture_token(&issuer_id, 5_000_000, "two espressos"),
	);
	let path = offer.notification_paths()[0].clone();
	let invoice = pay_and_claim(customer, merchant, &template, &resealed, path, PaymentId([1; 32]));
	let payment_hash = invoice.payment_hash();

	// The device refuses it: the notification commits to a token it did not seal.
	deliver_notification(merchant, &pos, pos_id);
	let reason = NackReason::OrderMismatch;
	assert_eq!(
		terminal.get_and_clear_pending_events(),
		vec![PosEvent::NotificationRefused { order_id, payment_hash, reason }]
	);
	assert!(terminal.order(&order_id).unwrap().payment.is_none());
	assert_eq!(
		resolved_notifications(merchant),
		vec![(payment_hash, PaymentNotificationOutcome::Refused { reason })]
	);
}

#[test]
fn point_of_sale_terminal_settles_order_after_restart() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	let (customer, merchant) = (&nodes[0], &nodes[1]);
	let merchant_id = merchant.node.get_our_node_id();

	let pos_keys = TestKeysInterface::new(&[9; 32], Network::Testnet);
	let pos_logger = TestLogger::with_id("pos".to_string());
	let pos_graph = NetworkGraph::new(Network::Testnet, &pos_logger);
	let chain = ChainHash::using_genesis_block(Network::Testnet);
	let config = PosConfig::new(chain, Some(merchant_id));
	let pos_id = pos_keys.get_node_id(crate::sign::Recipient::Node).unwrap();

	let template = merchant.node.create_pos_offer_template().unwrap();
	let (order_id, offer, persisted) = {
		let terminal = PosTerminal::new(&pos_keys, &pos_keys, &pos_logger, config.clone());
		let (order_id, offer) =
			terminal.create_order(&template, 5_000_000, "espresso".to_string(), None).unwrap();
		(order_id, offer, terminal.encode())
	};

	// The device restarts between showing the offer and the payment settling.
	let terminal: TestPosTerminal = ReadableArgs::read(
		&mut crate::io::Cursor::new(&persisted),
		(&pos_keys, &pos_keys, &pos_logger, config),
	)
	.unwrap();
	let pos = pos_messenger(&pos_keys, &pos_logger, &pos_graph, &terminal);
	connect_pos(&pos, pos_id, merchant);

	let path = offer.notification_paths()[0].clone();
	let invoice = pay_and_claim(customer, merchant, &template, &offer, path, PaymentId([1; 32]));
	deliver_notification(merchant, &pos, pos_id);

	assert_eq!(
		terminal.order(&order_id).unwrap().payment.map(|p| p.payment_hash),
		Some(invoice.payment_hash())
	);
	assert_eq!(
		resolved_notifications(merchant),
		vec![(invoice.payment_hash(), PaymentNotificationOutcome::Acknowledged)]
	);
}

/// The customer's payer proof for `invoice`, disclosing what a point-of-sale device needs to check
/// it, or not disclosing the payment token if `include_payment_token` is false.
fn customer_payment_proof<'a, 'b, 'c>(
	customer: &Node<'a, 'b, 'c>, invoice: &Bolt12Invoice, preimage: PaymentPreimage,
	payment_id: PaymentId, include_payment_token: bool,
) -> PayerProof {
	let expanded_key = customer.keys_manager.get_expanded_key();
	let builder = PaidBolt12Invoice::Bolt12Invoice(invoice.clone())
		.prove_payer_derived(preimage, &expanded_key, payment_id, &Secp256k1::new())
		.unwrap()
		.include_invoice_amount();
	let builder = if include_payment_token { builder.include_payment_token() } else { builder };
	builder.build_and_sign().unwrap()
}

/// Takes the notification `merchant` sends to the device without delivering it, as if it were
/// lost, returning its preimage.
fn lose_notification<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>, pos: &PosMessenger, pos_id: PublicKey,
) -> PaymentPreimage {
	let message = merchant.onion_messenger.next_onion_message_for_peer(pos_id).unwrap();
	match pos.peel_onion_message(&message) {
		Ok(PeeledOnion::PosNotification(
			PosNotificationMessage::PaymentNotification(notification),
			_,
			_,
		)) => notification.preimage(),
		_ => panic!("Unexpected onion message"),
	}
}

/// Delivers a payment proof the customer queued to the device, through the merchant, which
/// introduces the device's notification paths.
fn deliver_proof<'a, 'b, 'c>(
	customer: &Node<'a, 'b, 'c>, merchant: &Node<'a, 'b, 'c>, pos: &PosMessenger, pos_id: PublicKey,
) {
	let merchant_id = merchant.node.get_our_node_id();
	let message = customer.onion_messenger.next_onion_message_for_peer(merchant_id).unwrap();
	merchant.onion_messenger.handle_onion_message(customer.node.get_our_node_id(), &message);
	let message = merchant.onion_messenger.next_onion_message_for_peer(pos_id).unwrap();
	pos.handle_onion_message(merchant_id, &message);
}

#[test]
fn point_of_sale_terminal_accepts_payment_proof() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	let (customer, merchant) = (&nodes[0], &nodes[1]);
	point_of_sale!(merchant, pos_keys, pos_logger, pos_graph, terminal, pos, pos_id);

	let template = merchant.node.create_pos_offer_template().unwrap();
	let (order_id, offer) =
		terminal.create_order(&template, 5_000_000, "espresso".to_string(), None).unwrap();
	let payment_id = PaymentId([1; 32]);
	let path = offer.notification_paths()[0].clone();
	let invoice = pay_and_claim(customer, merchant, &template, &offer, path, payment_id);
	let payment_hash = invoice.payment_hash();

	// The merchant's notification never arrives, but the customer proves the payment themselves.
	let preimage = lose_notification(merchant, &pos, pos_id);
	let proof = customer_payment_proof(customer, &invoice, preimage, payment_id, true);
	customer.node.send_pos_payment_proof(&proof, &offer).unwrap();
	deliver_proof(customer, merchant, &pos, pos_id);

	let events = terminal.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	assert!(matches!(
		&events[0],
		PosEvent::OrderPaid { order_id: paid, payment_hash: hash, amount_msats: 5_000_000 }
			if *paid == order_id && *hash == payment_hash
	));
	let payment = terminal.order(&order_id).unwrap().payment.unwrap();
	assert_eq!(payment.payment_hash, payment_hash);
	assert_eq!(payment.notification, None);

	// The merchant's retry is then acknowledged as for an order already paid.
	merchant.node.timer_tick_occurred();
	deliver_notification(merchant, &pos, pos_id);
	assert!(terminal.get_and_clear_pending_events().is_empty());
	assert_eq!(
		resolved_notifications(merchant),
		vec![(payment_hash, PaymentNotificationOutcome::Acknowledged)]
	);
}

#[test]
fn point_of_sale_terminal_ignores_proof_for_another_order() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);
	let (customer, merchant) = (&nodes[0], &nodes[1]);
	point_of_sale!(merchant, pos_keys, pos_logger, pos_graph, terminal, pos, pos_id);

	// Two orders at the same price; only the first is paid.
	let template = merchant.node.create_pos_offer_template().unwrap();
	let (paid_id, paid) =
		terminal.create_order(&template, 5_000_000, "espresso".to_string(), None).unwrap();
	let (unpaid_id, unpaid) =
		terminal.create_order(&template, 5_000_000, "espresso".to_string(), None).unwrap();
	let payment_id = PaymentId([1; 32]);
	let path = paid.notification_paths()[0].clone();
	let invoice = pay_and_claim(customer, merchant, &template, &paid, path, payment_id);
	deliver_notification(merchant, &pos, pos_id);
	terminal.get_and_clear_pending_events();
	resolved_notifications(merchant);
	let preimage = terminal.order(&paid_id).unwrap().payment.unwrap().preimage;

	// A proof must disclose the token, and is only sent for the offer it proves.
	let proof = customer_payment_proof(customer, &invoice, preimage, payment_id, false);
	assert!(customer.node.send_pos_payment_proof(&proof, &paid).is_err());
	let proof = customer_payment_proof(customer, &invoice, preimage, payment_id, true);
	assert!(customer.node.send_pos_payment_proof(&proof, &unpaid).is_err());

	// Sent down the unpaid order's path anyway, the device does not take it for that order.
	let destination = Destination::BlindedPath(unpaid.notification_paths()[0].clone());
	let message = PosNotificationMessage::PaymentProof(PaymentProof::new(&proof));
	let instructions = MessageSendInstructions::WithoutReplyPath { destination };
	customer.onion_messenger.send_onion_message(message, instructions).unwrap();
	deliver_proof(customer, merchant, &pos, pos_id);
	assert!(terminal.get_and_clear_pending_events().is_empty());
	assert!(terminal.order(&unpaid_id).unwrap().payment.is_none());
}
