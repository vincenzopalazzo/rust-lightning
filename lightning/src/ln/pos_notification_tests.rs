// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Functional tests for point-of-sale payment notifications, per
//! [bLIP 56](https://github.com/lightning/blips/pull/56).
//!
//! Tests use three nodes:
//!
//! Customer --- Merchant ... PoS
//!
//! where the customer and merchant have an announced channel and the point-of-sale device has no
//! channels, communicating with the merchant via onion messages only.

use alloc::collections::BTreeMap;

use bitcoin::secp256k1::Secp256k1;
use core::time::Duration;

use crate::blinded_path::message::{MessageContext, PosNotificationContext};
use crate::blinded_path::payment::{Bolt12OfferContext, DummyTlvs, PaymentContext};
use crate::events::{Event, PaidBolt12Invoice, PaymentPurpose};
use crate::ln::channelmanager::PaymentId;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, OnionMessage, OnionMessageHandler};
use crate::ln::offers_tests::extract_invoice_request;
use crate::offers::flow::{
	POS_NOTIFICATION_PATHS_PAYMENT_METADATA_KEY, POS_ORDER_ID_PAYMENT_METADATA_KEY,
};
use crate::offers::invoice::Bolt12Invoice;
use crate::offers::invoice_request::InvoiceRequestFields;
use crate::offers::offer::{Amount, Offer};
use crate::onion_message::messenger::{Destination, MessageSendInstructions, PeeledOnion};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::pos_notification::{
	NackReason, PaymentNotification, PosNotificationMessage,
};
use crate::routing::router::DEFAULT_PAYMENT_DUMMY_HOPS;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{WithoutLength, Writeable};

use crate::prelude::*;

const ORDER_AMOUNT_MSATS: u64 = 10_000_000;

fn expected_pos_payment_context(
	offer: &Offer, order_id: &[u8], invoice_request_fields: InvoiceRequestFields,
) -> PaymentContext {
	let mut payment_metadata = BTreeMap::new();
	payment_metadata.insert(POS_ORDER_ID_PAYMENT_METADATA_KEY, order_id.to_vec());
	payment_metadata.insert(
		POS_NOTIFICATION_PATHS_PAYMENT_METADATA_KEY,
		WithoutLength(&offer.notification_paths().to_vec()).encode(),
	);

	PaymentContext::Bolt12Offer(Bolt12OfferContext {
		offer_id: offer.id(),
		invoice_request: invoice_request_fields,
		payment_metadata: Some(payment_metadata),
	})
}

/// Drives the customer's `invoice_request` to the merchant and returns the resulting invoice
/// after delivering it back to the customer.
fn deliver_invoice_request_and_get_invoice<'a, 'b, 'c>(
	customer: &Node<'a, 'b, 'c>, merchant: &Node<'a, 'b, 'c>,
) -> Option<Bolt12Invoice> {
	let customer_id = customer.node.get_our_node_id();
	let merchant_id = merchant.node.get_our_node_id();

	let onion_message = customer.onion_messenger.next_onion_message_for_peer(merchant_id).unwrap();
	merchant.onion_messenger.handle_onion_message(customer_id, &onion_message);

	let onion_message = merchant.onion_messenger.next_onion_message_for_peer(customer_id)?;
	customer.onion_messenger.handle_onion_message(merchant_id, &onion_message);

	match customer.onion_messenger.peel_onion_message(&onion_message) {
		Ok(PeeledOnion::Offers(OffersMessage::Invoice(invoice), _, _)) => Some(invoice),
		Ok(_) => None,
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

/// Delivers the merchant's queued payment notification to the point-of-sale device, returning the
/// device's response, if any.
fn deliver_pos_notification<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>, pos: &Node<'a, 'b, 'c>,
) -> Option<OnionMessage> {
	let merchant_id = merchant.node.get_our_node_id();
	let pos_id = pos.node.get_our_node_id();

	let onion_message = merchant.onion_messenger.next_onion_message_for_peer(pos_id).unwrap();
	pos.onion_messenger.handle_onion_message(merchant_id, &onion_message);

	pos.onion_messenger.next_onion_message_for_peer(merchant_id)
}

fn extract_nack_reason<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>, message: &OnionMessage,
) -> NackReason {
	match merchant.onion_messenger.peel_onion_message(message) {
		Ok(PeeledOnion::PosNotification(PosNotificationMessage::NotificationNack(nack), _, _)) => {
			nack.reason
		},
		Ok(_) => panic!("Unexpected onion message"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	}
}

/// Creates the customer/merchant/PoS network, returning the per-order offer and its `order_id`.
fn create_pos_order<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>, pos: &Node<'a, 'b, 'c>, order_absolute_expiry: Option<Duration>,
) -> (Offer, Vec<u8>) {
	let merchant_id = merchant.node.get_our_node_id();

	let template = merchant.node.create_pos_delegation_template(None).unwrap();
	assert!(template.offer_features().supports_payment_notifications());
	assert!(template.amount().is_none());
	assert!(template.description().is_none());
	assert!(template.notification_paths().is_empty());
	assert!(template.payment_token().is_none());
	assert!(!template.paths().is_empty());

	let (offer, order_id) = pos
		.node
		.create_pos_order_offer(
			&template,
			merchant_id,
			ORDER_AMOUNT_MSATS,
			Some("coffee".to_string()),
			order_absolute_expiry,
		)
		.unwrap();
	assert!(offer.offer_features().supports_payment_notifications());
	assert_eq!(offer.amount(), Some(Amount::Bitcoin { amount_msats: ORDER_AMOUNT_MSATS }));
	assert_eq!(offer.description().unwrap().to_string(), "coffee");
	assert_eq!(offer.notification_paths().len(), 1);
	assert!(offer.payment_token().is_some());

	// A standard wallet must be able to parse the per-order offer, with the new odd TLV records
	// reflected in re-parsed bytes.
	let reparsed = Offer::try_from(offer.as_ref().to_vec()).unwrap();
	assert_eq!(reparsed, offer);

	(offer, order_id)
}

fn pay_pos_order<'a, 'b, 'c>(
	customer: &Node<'a, 'b, 'c>, merchant: &Node<'a, 'b, 'c>, offer: &Offer, order_id: &[u8],
) {
	let payment_id = PaymentId([1; 32]);
	customer.node.pay_for_offer(offer, None, payment_id, Default::default()).unwrap();

	let onion_message =
		customer.onion_messenger.next_onion_message_for_peer(merchant.node.get_our_node_id());
	let onion_message = onion_message.unwrap();
	let (invoice_request, _) = extract_invoice_request(merchant, &onion_message);
	merchant.onion_messenger.handle_onion_message(customer.node.get_our_node_id(), &onion_message);

	let onion_message = merchant
		.onion_messenger
		.next_onion_message_for_peer(customer.node.get_our_node_id())
		.unwrap();
	customer.onion_messenger.handle_onion_message(merchant.node.get_our_node_id(), &onion_message);

	let invoice = match customer.onion_messenger.peel_onion_message(&onion_message) {
		Ok(PeeledOnion::Offers(OffersMessage::Invoice(invoice), _, _)) => invoice,
		Ok(_) => panic!("Unexpected onion message"),
		Err(e) => panic!("Failed to process onion message {:?}", e),
	};
	assert_eq!(invoice.amount_msats(), ORDER_AMOUNT_MSATS);

	route_bolt12_payment(customer, &[merchant], &invoice);

	let expected_payment_context = expected_pos_payment_context(
		offer,
		order_id,
		InvoiceRequestFields {
			payer_signing_pubkey: invoice_request.payer_signing_pubkey(),
			quantity: None,
			payer_note_truncated: None,
			human_readable_name: None,
		},
	);
	claim_bolt12_payment(customer, &[merchant], expected_payment_context, &invoice);
}

fn route_bolt12_payment<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, path: &[&Node<'a, 'b, 'c>], invoice: &Bolt12Invoice,
) {
	check_added_monitors(node, 1);

	let mut events = node.node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let ev = remove_first_msg_event_to_node(&path[0].node.get_our_node_id(), &mut events);

	let amount_msats = invoice.amount_msats();
	let payment_hash = invoice.payment_hash();
	let args = PassAlongPathArgs::new(node, path, amount_msats, payment_hash, ev)
		.without_clearing_recipient_events()
		.with_dummy_tlvs(&[DummyTlvs::default(); DEFAULT_PAYMENT_DUMMY_HOPS]);
	do_pass_along_path(args);
}

fn claim_bolt12_payment<'a, 'b, 'c>(
	node: &Node<'a, 'b, 'c>, path: &[&Node<'a, 'b, 'c>], expected_payment_context: PaymentContext,
	invoice: &Bolt12Invoice,
) {
	let recipient = path.last().expect("Empty path?");
	let payment_purpose = match get_event!(recipient, Event::PaymentClaimable) {
		Event::PaymentClaimable { purpose, .. } => purpose,
		_ => panic!("No Event::PaymentClaimable"),
	};
	let payment_preimage = match payment_purpose.preimage() {
		Some(preimage) => preimage,
		None => panic!("No preimage in Event::PaymentClaimable"),
	};
	let context = match payment_purpose {
		PaymentPurpose::Bolt12OfferPayment { payment_context, .. } => {
			PaymentContext::Bolt12Offer(payment_context)
		},
		_ => panic!("Unexpected payment purpose: {:?}", payment_purpose),
	};
	assert_eq!(context, expected_payment_context);

	let expected_paths = [path];
	let args = ClaimAlongRouteArgs::new(node, &expected_paths, payment_preimage);
	let (inv, _) = claim_payment_along_route(args);
	assert_eq!(inv, Some(PaidBolt12Invoice::Bolt12Invoice(invoice.clone())));
}

fn expect_payment_notification_received<'a, 'b, 'c>(
	pos: &Node<'a, 'b, 'c>, expected_order_id: &[u8],
) {
	let events = pos.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::PaymentNotificationReceived {
			order_id,
			amount_msats,
			payment_hash,
			payment_preimage,
			description,
		} => {
			assert_eq!(order_id, &expected_order_id.to_vec());
			assert_eq!(*amount_msats, ORDER_AMOUNT_MSATS);
			assert_eq!(PaymentHash::from(*payment_preimage), *payment_hash);
			assert_eq!(description.as_deref(), Some("coffee"));
		},
		event => panic!("Unexpected event: {:?}", event),
	}
}

/// Checks the full bLIP 56 flow: the merchant creates a template, the point-of-sale device
/// derives a per-order offer, the customer pays it without any sender-side modifications, and the
/// merchant's payment notification is authenticated and acknowledged by the device.
#[test]
fn pays_pos_order_offer_and_delivers_notification() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let (customer, merchant, pos) = (&nodes[0], &nodes[1], &nodes[2]);
	let pos_id = pos.node.get_our_node_id();

	// The point-of-sale device only ever talks to the merchant.
	disconnect_peers(customer, &[pos]);

	let (offer, order_id) = create_pos_order(merchant, pos, None);
	pay_pos_order(customer, merchant, &offer, &order_id);

	// Claiming the payment queues a notification to the point-of-sale device.
	let ack = deliver_pos_notification(merchant, pos).unwrap();
	expect_payment_notification_received(pos, &order_id);

	// The merchant retries the notification on timer ticks until it is acknowledged. A duplicate
	// is authenticated and acknowledged again; deduplication is the event consumer's
	// responsibility.
	merchant.node.timer_tick_occurred();
	let duplicate_ack = deliver_pos_notification(merchant, pos).unwrap();
	expect_payment_notification_received(pos, &order_id);

	merchant.onion_messenger.handle_onion_message(pos_id, &ack);
	merchant.onion_messenger.handle_onion_message(pos_id, &duplicate_ack);

	// Once acknowledged, the notification is no longer retried.
	merchant.node.timer_tick_occurred();
	assert!(merchant.onion_messenger.next_onion_message_for_peer(pos_id).is_none());
}

/// Checks that a customer cannot forge a payment notification: it knows the notification path
/// from the offer but not the `order_id` sealed in the `payment_token`, so its notification is
/// rejected without generating an event.
#[test]
fn rejects_forged_payment_notification() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let (customer, merchant, pos) = (&nodes[0], &nodes[1], &nodes[2]);
	let customer_id = customer.node.get_our_node_id();
	let merchant_id = merchant.node.get_our_node_id();
	let pos_id = pos.node.get_our_node_id();

	disconnect_peers(customer, &[pos]);

	let (offer, _order_id) = create_pos_order(merchant, pos, None);

	// The customer asserts an arbitrary amount with a self-consistent preimage but cannot know
	// the order_id, since the token ciphertext is opaque to it.
	let payment_preimage = PaymentPreimage([7; 32]);
	let forged = PosNotificationMessage::PaymentNotification(PaymentNotification {
		payment_hash: PaymentHash::from(payment_preimage),
		payment_preimage,
		amount_msats: ORDER_AMOUNT_MSATS,
		order_id: vec![9; 16],
	});
	let instructions = MessageSendInstructions::WithoutReplyPath {
		destination: Destination::BlindedPath(offer.notification_paths()[0].clone()),
	};
	customer.onion_messenger.send_onion_message(forged, instructions).unwrap();

	// The forged notification reaches the device via the merchant, the path's introduction node.
	let onion_message = customer.onion_messenger.next_onion_message_for_peer(merchant_id).unwrap();
	merchant.onion_messenger.handle_onion_message(customer_id, &onion_message);
	let onion_message = merchant.onion_messenger.next_onion_message_for_peer(pos_id).unwrap();
	pos.onion_messenger.handle_onion_message(merchant_id, &onion_message);

	assert!(pos.node.get_and_clear_pending_events().is_empty());
}

/// Checks each rejection reason for a payment notification that fails validation against the
/// notification path's message context.
#[test]
fn nacks_invalid_payment_notifications() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let (customer, merchant, pos) = (&nodes[0], &nodes[1], &nodes[2]);
	disconnect_peers(customer, &[pos]);

	let (offer, order_id) = create_pos_order(merchant, pos, None);
	let payment_preimage = PaymentPreimage([7; 32]);
	let payment_hash = PaymentHash::from(payment_preimage);

	let cases = [
		(
			PaymentNotification {
				payment_hash,
				payment_preimage,
				amount_msats: ORDER_AMOUNT_MSATS,
				order_id: vec![9; 16],
			},
			NackReason::OrderIdMismatch,
		),
		(
			PaymentNotification {
				payment_hash,
				payment_preimage,
				amount_msats: ORDER_AMOUNT_MSATS - 1,
				order_id: order_id.clone(),
			},
			NackReason::AmountInsufficient,
		),
		(
			PaymentNotification {
				payment_hash: PaymentHash([8; 32]),
				payment_preimage,
				amount_msats: ORDER_AMOUNT_MSATS,
				order_id: order_id.clone(),
			},
			NackReason::InvalidPreimage,
		),
	];

	for (notification, expected_reason) in cases {
		send_notification_from_merchant(merchant, &offer, notification, payment_hash);
		let nack = deliver_pos_notification(merchant, pos).unwrap();
		assert_eq!(extract_nack_reason(merchant, &nack), expected_reason);
		assert!(pos.node.get_and_clear_pending_events().is_empty());
	}
}

/// Checks that notifications for an expired order are rejected.
#[test]
fn nacks_payment_notification_for_expired_order() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let (customer, merchant, pos) = (&nodes[0], &nodes[1], &nodes[2]);
	disconnect_peers(customer, &[pos]);

	let expired = Some(pos.node.duration_since_epoch() - Duration::from_secs(1));
	let (offer, order_id) = create_pos_order(merchant, pos, expired);

	let payment_preimage = PaymentPreimage([7; 32]);
	let payment_hash = PaymentHash::from(payment_preimage);
	let notification = PaymentNotification {
		payment_hash,
		payment_preimage,
		amount_msats: ORDER_AMOUNT_MSATS,
		order_id,
	};
	send_notification_from_merchant(merchant, &offer, notification, payment_hash);
	let nack = deliver_pos_notification(merchant, pos).unwrap();
	assert_eq!(extract_nack_reason(merchant, &nack), NackReason::OrderExpired);
	assert!(pos.node.get_and_clear_pending_events().is_empty());
}

fn send_notification_from_merchant<'a, 'b, 'c>(
	merchant: &Node<'a, 'b, 'c>, offer: &Offer, notification: PaymentNotification,
	payment_hash: PaymentHash,
) {
	let message = PosNotificationMessage::PaymentNotification(notification);
	let instructions = MessageSendInstructions::WithReplyPath {
		destination: Destination::BlindedPath(offer.notification_paths()[0].clone()),
		context: MessageContext::PosNotification(PosNotificationContext::OutboundNotification {
			payment_hash,
		}),
	};
	merchant.onion_messenger.send_onion_message(message, instructions).unwrap();
}

/// Checks that the merchant rejects invoice requests for the bare template and for per-order
/// offers whose cleartext fields do not match the fields sealed in the `payment_token`.
#[test]
fn rejects_invoice_request_for_template_or_tampered_offer() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let (customer, merchant, pos) = (&nodes[0], &nodes[1], &nodes[2]);
	let merchant_id = merchant.node.get_our_node_id();
	disconnect_peers(customer, &[pos]);

	// Paying the bare template is rejected: it advertises payment_notifications but carries no
	// notification_path or payment_token, so no notification could be delivered.
	let template = merchant.node.create_pos_delegation_template(None).unwrap();
	let payment_id = PaymentId([2; 32]);
	customer
		.node
		.pay_for_offer(&template, Some(ORDER_AMOUNT_MSATS), payment_id, Default::default())
		.unwrap();
	assert!(deliver_invoice_request_and_get_invoice(customer, merchant).is_none());

	// A per-order offer whose amount was lowered relative to the amount sealed in the token is
	// rejected before any payment happens.
	let (full_price_offer, _) = pos
		.node
		.create_pos_order_offer(
			&template,
			merchant_id,
			ORDER_AMOUNT_MSATS,
			Some("coffee".to_string()),
			None,
		)
		.unwrap();
	let tampered_offer = template
		.modify()
		.unwrap()
		.with_pos_order(
			ORDER_AMOUNT_MSATS / 2,
			Some("coffee".to_string()),
			vec![3; 16],
			full_price_offer.notification_paths().to_vec(),
			None,
			customer.keys_manager,
			&Secp256k1::new(),
		)
		.unwrap()
		.payment_token_unchecked(full_price_offer.payment_token().unwrap().clone())
		.build();

	let payment_id = PaymentId([3; 32]);
	customer.node.pay_for_offer(&tampered_offer, None, payment_id, Default::default()).unwrap();
	assert!(deliver_invoice_request_and_get_invoice(customer, merchant).is_none());
}

/// Checks that a customer's `payment_proof` is delivered to the point-of-sale device over the
/// offer's notification path and surfaced unverified.
#[test]
fn delivers_payment_proof_to_pos() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 10_000_000, 1_000_000_000);

	let (customer, merchant, pos) = (&nodes[0], &nodes[1], &nodes[2]);
	let customer_id = customer.node.get_our_node_id();
	let merchant_id = merchant.node.get_our_node_id();
	let pos_id = pos.node.get_our_node_id();

	disconnect_peers(customer, &[pos]);

	let (offer, order_id) = create_pos_order(merchant, pos, None);

	let proof = vec![42; 80];
	customer.node.send_payment_proof(&offer, proof.clone()).unwrap();

	let onion_message = customer.onion_messenger.next_onion_message_for_peer(merchant_id).unwrap();
	merchant.onion_messenger.handle_onion_message(customer_id, &onion_message);
	let onion_message = merchant.onion_messenger.next_onion_message_for_peer(pos_id).unwrap();
	pos.onion_messenger.handle_onion_message(merchant_id, &onion_message);

	let events = pos.node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match &events[0] {
		Event::PaymentProofReceived {
			order_id: event_order_id,
			proof: event_proof,
			amount_msats,
			description,
		} => {
			assert_eq!(event_order_id, &order_id);
			assert_eq!(event_proof, &proof);
			assert_eq!(*amount_msats, ORDER_AMOUNT_MSATS);
			assert_eq!(description.as_deref(), Some("coffee"));
		},
		event => panic!("Unexpected event: {:?}", event),
	}
}

fn disconnect_peers<'a, 'b, 'c>(node_a: &Node<'a, 'b, 'c>, peers: &[&Node<'a, 'b, 'c>]) {
	for node_b in peers {
		node_a.node.peer_disconnected(node_b.node.get_our_node_id());
		node_b.node.peer_disconnected(node_a.node.get_our_node_id());
		node_a.onion_messenger.peer_disconnected(node_b.node.get_our_node_id());
		node_b.onion_messenger.peer_disconnected(node_a.node.get_our_node_id());
	}
}
