// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The point-of-sale side of [bLIP 56].
//!
//! A [`PosTerminal`] turns a merchant's offer template into per-order offers and keeps the
//! per-order state it needs to check the merchant's payment notifications later. It never touches
//! funds and needs no channels: it only builds offers and receives onion messages.
//!
//! It implements [`PosNotificationMessageHandler`], so passing it to the terminal's
//! [`OnionMessenger`] is all it takes to have the merchant's notifications checked and answered.
//! Accepted payments are reported through [`PosTerminal::get_and_clear_pending_events`].
//!
//! [bLIP 56]: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md
//! [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger

use bitcoin::constants::ChainHash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::blinded_path::message::{
	BlindedMessagePath, MessageContext, MessageForwardNode, PosNotificationContext,
};
use crate::io;
use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
use crate::offers::offer::{Offer, Quantity};
use crate::offers::parse::Bolt12ParseError;
use crate::offers::payment_token::{payment_token_hash, SealedOrder};
use crate::onion_message::messenger::{Responder, ResponseInstruction};
use crate::onion_message::pos_notification::{
	NackReason, NotificationAck, NotificationNack, PaymentNotification, PaymentProof,
	PosNotificationMessage, PosNotificationMessageHandler,
};
use crate::prelude::*;
use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::sync::Mutex;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::logger::{Logger, WithContext};
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

/// How many notifications for one order may fail signature verification within
/// [`SIGNATURE_CHECK_WINDOW`] before the terminal stops verifying notifications for that order
/// until the window ends.
///
/// Every notification arriving over an order's path costs a BIP 340 verification before it can be
/// told apart from a forgery, and anyone holding the order's offer can send them. Budgeting per
/// order, rather than for the whole terminal, keeps a customer flooding their own order from
/// delaying the notifications for everyone else's; the merchant retries with backoff, so a
/// genuine notification refused during the window gets through after it.
pub const MAX_FAILED_SIGNATURE_CHECKS: u32 = 8;

/// The window [`MAX_FAILED_SIGNATURE_CHECKS`] applies to.
pub const SIGNATURE_CHECK_WINDOW: Duration = Duration::from_secs(60);

/// How long after an order's expiry a notification for it is still accepted, by default.
///
/// A customer who fetched an invoice just before the offer expired may pay after it did. This
/// covers the default BOLT 12 invoice expiry plus some payment and notification latency.
pub const DEFAULT_EXPIRY_GRACE_PERIOD: Duration = Duration::from_secs(2 * 60 * 60 + 10 * 60);

/// Identifies an order at a [`PosTerminal`].
///
/// It is chosen at random when the order is created and travels only inside the order's own
/// blinded `notification_path`, where only the terminal can read it.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PosOrderId(pub [u8; 32]);

impl Writeable for PosOrderId {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}
}

impl Readable for PosOrderId {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self(Readable::read(r)?))
	}
}

/// Configuration for a [`PosTerminal`].
#[derive(Clone, Debug)]
pub struct PosConfig {
	/// The chain the terminal takes payments on. Templates must be usable on exactly this chain.
	pub chain_hash: ChainHash,
	/// The node to use as the introduction node of the `notification_path`s the terminal builds,
	/// normally the merchant node it is connected to. The merchant must be able to reach it, and it
	/// must be able to forward to the terminal.
	///
	/// If `None`, the terminal is the introduction node, which puts its node id in every offer.
	pub notification_path_intro_node: Option<MessageForwardNode>,
	/// How long after an order's expiry a notification for it is still accepted.
	pub expiry_grace_period: Duration,
}

impl PosConfig {
	/// A configuration for `chain_hash`, with the default grace period and the given introduction
	/// node.
	pub fn new(chain_hash: ChainHash, notification_path_intro_node: Option<PublicKey>) -> Self {
		Self {
			chain_hash,
			notification_path_intro_node: notification_path_intro_node
				.map(|node_id| MessageForwardNode { node_id, short_channel_id: None }),
			expiry_grace_period: DEFAULT_EXPIRY_GRACE_PERIOD,
		}
	}
}

/// Why an offer cannot be used as an offer template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PosTemplateError {
	/// The template does not set the `payment_notifications` feature, so the merchant has not
	/// said it will send payment notifications.
	MissingFeature,
	/// The template does not name the merchant's `offer_issuer_id`, which payment tokens are
	/// sealed to and notifications are signed with.
	MissingIssuerId,
	/// The template has no blinded paths to the merchant for invoice requests.
	MissingPaths,
	/// The template already has an amount; per-order offers set their own.
	UnexpectedAmount,
	/// The template already has a description; per-order offers set their own.
	UnexpectedDescription,
	/// The template allows requesting more than one item, so the amount paid could differ from
	/// the order's.
	UnexpectedQuantity,
	/// The template is not usable on the terminal's chain alone.
	UnsupportedChain,
}

/// Why a per-order offer could not be created.
#[derive(Clone, Debug, PartialEq)]
pub enum PosOrderError {
	/// The offer cannot be used as a template.
	InvalidTemplate(PosTemplateError),
	/// The amount is zero or larger than any payment can be.
	InvalidAmount,
	/// Sealing the payment token failed, which only happens if the entropy source returned bytes
	/// that are not a valid secret key.
	Sealing,
	/// The terminal's node id could not be obtained from its node signer.
	NodeId,
	/// The resulting offer did not parse.
	InvalidOffer(Bolt12ParseError),
}

/// The payment that settled a [`PosOrder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosOrderPayment {
	/// The payment hash of the settled payment.
	pub payment_hash: PaymentHash,
	/// The preimage of the settled payment.
	pub preimage: PaymentPreimage,
	/// The amount the merchant claimed, in millisatoshis.
	pub amount_msats: u64,
	/// When the terminal accepted the payment, as a duration since the Unix epoch.
	pub accepted_at: Duration,
	/// The merchant-signed payment notification that settled the order, if it was settled by a
	/// notification. Kept as evidence: it is the only artifact a third party can check against the
	/// merchant's published issuer id.
	pub notification: Option<Vec<u8>>,
}

impl_ser_tlv_based!(PosOrderPayment, {
	(0, payment_hash, required),
	(2, preimage, required),
	(4, amount_msats, required),
	(6, accepted_at, required),
	(8, notification, option),
});

/// An order created by a [`PosTerminal`], and the state kept to check payments for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosOrder {
	/// The order's identifier.
	pub order_id: PosOrderId,
	/// The `offer_issuer_id` of the template the order was built from, which the merchant's
	/// notifications for this order must be signed with.
	pub issuer_id: PublicKey,
	/// The `payment_token` ciphertext sealed into the order's offer.
	pub payment_token: Vec<u8>,
	/// The order's amount in millisatoshis.
	pub amount_msats: u64,
	/// The order's description.
	pub description: String,
	/// When the order's offer expires, as a duration since the Unix epoch, if it does.
	pub absolute_expiry: Option<Duration>,
	/// When the order was created, as a duration since the Unix epoch.
	pub created_at: Duration,
	/// The payment that settled the order, once one has.
	pub payment: Option<PosOrderPayment>,
	/// Further payments the merchant notified for the order after it was settled, meaning the
	/// customer paid more than once. They need operator attention, such as a refund.
	pub additional_payments: Vec<PosOrderPayment>,
}

impl_ser_tlv_based!(PosOrder, {
	(0, order_id, required),
	(2, issuer_id, required),
	(4, payment_token, required_vec),
	(6, amount_msats, required),
	(8, description, required),
	(10, absolute_expiry, option),
	(12, created_at, required),
	(14, payment, option),
	(15, additional_payments, optional_vec),
});

/// The point-of-sale side of [bLIP 56].
///
/// Build one per terminal node with the same [`NodeSigner`] its [`OnionMessenger`] uses, since the
/// `notification_path`s it builds must authenticate as this node's own. Persist it (it is
/// [`Writeable`]) after creating an order and after handling a payment, and restore it with
/// [`ReadableArgs`] so notifications for existing orders can still be checked after a restart.
///
/// [bLIP 56]: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md
/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
pub struct PosTerminal<ES: EntropySource, NS: NodeSigner, L: Logger> {
	entropy_source: ES,
	node_signer: NS,
	logger: L,
	config: PosConfig,
	secp_ctx: Secp256k1<secp256k1::All>,
	orders: Mutex<HashMap<PosOrderId, PosOrder>>,
	highest_seen_timestamp: AtomicU64,
	/// Per order, the start of the current signature check window and the failures in it.
	failed_signature_checks: Mutex<HashMap<PosOrderId, (Duration, u32)>>,
	/// Paths over which an `unknown_order` nack has been sent, so it is sent only once per path.
	unknown_orders_answered: Mutex<HashSet<PosOrderId>>,
	pending_events: Mutex<Vec<PosEvent>>,
}

/// An event a [`PosTerminal`] reports, to be handled and then persisted along with the terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PosEvent {
	/// The merchant notified that an order was paid, and the notification passed every check.
	/// The order can be shown as paid.
	OrderPaid {
		/// The order that was paid.
		order_id: PosOrderId,
		/// The payment hash of the payment that settled it.
		payment_hash: PaymentHash,
		/// The amount the merchant claimed, in millisatoshis, which is at least the order's amount.
		amount_msats: u64,
	},
	/// The merchant notified a second, different payment for an order that was already paid,
	/// meaning the customer paid twice. It needs operator attention, such as a refund.
	AdditionalPayment {
		/// The order that was paid again.
		order_id: PosOrderId,
		/// The payment hash of the additional payment.
		payment_hash: PaymentHash,
		/// The amount the merchant claimed for it, in millisatoshis.
		amount_msats: u64,
	},
	/// The merchant sent a notification for an order, signed with the order's issuer key, that the
	/// terminal refused. The merchant has already claimed the payment, so this needs
	/// reconciliation with the merchant.
	NotificationRefused {
		/// The order the notification arrived for.
		order_id: PosOrderId,
		/// The notification's payment hash.
		payment_hash: PaymentHash,
		/// Why it was refused.
		reason: NackReason,
	},
}

/// The result of checking a payment notification against the order it arrived for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationCheck {
	/// The signature does not verify against the order's issuer key, so the notification cannot be
	/// attributed to the merchant. It must not be answered.
	Unattributable,
	/// The notification is accepted and must be acknowledged.
	Accepted {
		/// Whether the notification settles the order now, rather than repeating the
		/// notification of a payment already accepted.
		settles_order: bool,
		/// Whether the order was already settled by a different payment, so the customer paid
		/// twice.
		additional_payment: bool,
	},
	/// The notification is refused with the given reason.
	Refused(NackReason),
}

/// Checks a payment notification against the order whose `notification_path` it arrived over, as
/// the draft requires of the point-of-sale device, at time `now` (since the Unix epoch).
///
/// The signature is verified against the issuer key recorded for the order, never one taken from
/// the notification. Expiry is extended by `expiry_grace_period`, and does not apply to an order
/// that is already paid.
pub fn check_notification(
	order: &PosOrder, notification: &PaymentNotification, now: Duration,
	expiry_grace_period: Duration,
) -> NotificationCheck {
	if notification.verify(order.issuer_id).is_err() {
		return NotificationCheck::Unattributable;
	}

	let payment_hash = notification.payment_hash();
	if Sha256::hash(&notification.preimage().0).to_byte_array() != payment_hash.0 {
		return NotificationCheck::Refused(NackReason::PreimageMismatch);
	}

	let is_known_payment = |payment: &PosOrderPayment| payment.payment_hash == payment_hash;
	if let Some(payment) = &order.payment {
		if is_known_payment(payment) || order.additional_payments.iter().any(is_known_payment) {
			let settles_order = false;
			let additional_payment = false;
			return NotificationCheck::Accepted { settles_order, additional_payment };
		}
	} else if let Some(expiry) = order.absolute_expiry {
		if now > expiry + expiry_grace_period {
			return NotificationCheck::Refused(NackReason::OrderExpired);
		}
	}

	if notification.payment_token_hash() != payment_token_hash(&order.payment_token) {
		return NotificationCheck::Refused(NackReason::OrderMismatch);
	}
	if notification.amount_msats() < order.amount_msats {
		return NotificationCheck::Refused(NackReason::AmountInsufficient);
	}

	let settles_order = order.payment.is_none();
	NotificationCheck::Accepted { settles_order, additional_payment: !settles_order }
}

/// Checks that `template` can be used to build per-order offers on `chain_hash`.
pub fn check_template(template: &Offer, chain_hash: ChainHash) -> Result<(), PosTemplateError> {
	if !template.offer_features().supports_payment_notifications() {
		return Err(PosTemplateError::MissingFeature);
	}
	if template.issuer_signing_pubkey().is_none() {
		return Err(PosTemplateError::MissingIssuerId);
	}
	if template.paths().is_empty() {
		return Err(PosTemplateError::MissingPaths);
	}
	if template.amount().is_some() {
		return Err(PosTemplateError::UnexpectedAmount);
	}
	if template.description().is_some() {
		return Err(PosTemplateError::UnexpectedDescription);
	}
	if template.supported_quantity() != Quantity::One {
		return Err(PosTemplateError::UnexpectedQuantity);
	}
	if template.chains() != [chain_hash] {
		return Err(PosTemplateError::UnsupportedChain);
	}
	Ok(())
}

impl<ES: EntropySource, NS: NodeSigner, L: Logger> PosTerminal<ES, NS, L> {
	/// Creates a terminal with no orders.
	pub fn new(entropy_source: ES, node_signer: NS, logger: L, config: PosConfig) -> Self {
		Self::with_orders(entropy_source, node_signer, logger, config, new_hash_map())
	}

	fn with_orders(
		entropy_source: ES, node_signer: NS, logger: L, config: PosConfig,
		orders: HashMap<PosOrderId, PosOrder>,
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		let highest_seen_timestamp = orders.values().map(|o| o.created_at.as_secs()).max();
		Self {
			entropy_source,
			node_signer,
			logger,
			config,
			secp_ctx,
			orders: Mutex::new(orders),
			highest_seen_timestamp: AtomicU64::new(highest_seen_timestamp.unwrap_or(0)),
			failed_signature_checks: Mutex::new(new_hash_map()),
			unknown_orders_answered: Mutex::new(new_hash_set()),
			pending_events: Mutex::new(Vec::new()),
		}
	}

	/// Tells the terminal the current time, as a duration since the Unix epoch.
	///
	/// Only needed without the `std` feature, where the terminal cannot read the clock itself.
	pub fn update_time(&self, now: Duration) {
		self.highest_seen_timestamp.fetch_max(now.as_secs(), Ordering::AcqRel);
	}

	pub(crate) fn duration_since_epoch(&self) -> Duration {
		#[cfg(any(not(feature = "std"), fuzzing))]
		let now = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire));
		#[cfg(all(feature = "std", not(fuzzing)))]
		let now = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
		now
	}

	/// The terminal's configuration.
	pub fn config(&self) -> &PosConfig {
		&self.config
	}

	/// Builds a per-order offer from a merchant's `template` and records the order.
	///
	/// The offer gets the given amount, description and, if given, absolute expiry, a single
	/// `notification_path` back to this terminal (as is best for a QR code), and a `payment_token`
	/// sealing the amount, description and a fresh `order_metadata` to the template's issuer id.
	/// If no expiry is given, any expiry the template has is kept.
	///
	/// The terminal must be persisted after this returns, so that it can still check the order's
	/// notifications after a restart.
	pub fn create_order(
		&self, template: &Offer, amount_msats: u64, description: String,
		absolute_expiry: Option<Duration>,
	) -> Result<(PosOrderId, Offer), PosOrderError> {
		check_template(template, self.config.chain_hash).map_err(PosOrderError::InvalidTemplate)?;
		if amount_msats == 0 || amount_msats > MAX_VALUE_MSAT {
			return Err(PosOrderError::InvalidAmount);
		}
		let issuer_id = template.issuer_signing_pubkey().expect("checked by check_template");

		let order_metadata = self.entropy_source.get_secure_random_bytes().to_vec();
		let sealed_order = SealedOrder { amount_msats, description, order_metadata };
		let payment_token = sealed_order
			.seal(&issuer_id, &self.entropy_source, &self.secp_ctx)
			.map_err(|()| PosOrderError::Sealing)?;

		let order_id = PosOrderId(self.entropy_source.get_secure_random_bytes());
		let notification_path = self.notification_path(order_id)?;

		let offer = template
			.with_per_order_records(
				amount_msats,
				sealed_order.description.clone(),
				absolute_expiry,
				vec![notification_path],
				payment_token.clone(),
			)
			.map_err(PosOrderError::InvalidOffer)?;

		let order = PosOrder {
			order_id,
			issuer_id,
			payment_token,
			amount_msats,
			description: sealed_order.description,
			absolute_expiry: offer.absolute_expiry(),
			created_at: self.duration_since_epoch(),
			payment: None,
			additional_payments: Vec::new(),
		};
		self.orders.lock().unwrap().insert(order_id, order);

		Ok((order_id, offer))
	}

	fn notification_path(&self, order_id: PosOrderId) -> Result<BlindedMessagePath, PosOrderError> {
		let node_id =
			self.node_signer.get_node_id(Recipient::Node).map_err(|()| PosOrderError::NodeId)?;
		let context = MessageContext::PosNotification(PosNotificationContext::NotificationPath {
			order_id: order_id.0,
		});
		let intermediate_nodes: Vec<MessageForwardNode> =
			self.config.notification_path_intro_node.iter().cloned().collect();
		Ok(BlindedMessagePath::new(
			&intermediate_nodes,
			node_id,
			self.node_signer.get_receive_auth_key(),
			context,
			true,
			&self.entropy_source,
			&self.secp_ctx,
		))
	}

	/// Returns the order with the given id, if the terminal still has it.
	pub fn order(&self, order_id: &PosOrderId) -> Option<PosOrder> {
		self.orders.lock().unwrap().get(order_id).cloned()
	}

	/// Returns all orders the terminal still has.
	pub fn orders(&self) -> Vec<PosOrder> {
		self.orders.lock().unwrap().values().cloned().collect()
	}

	/// Forgets orders that were paid, or expired unpaid, more than `retention` ago.
	///
	/// Until an order is forgotten, a repeated notification for it is acknowledged again and a late
	/// one is refused as expired; afterwards both are answered as for an unknown order. Orders that
	/// never expire are kept until paid.
	pub fn prune_orders(&self, retention: Duration) {
		let now = self.duration_since_epoch();
		self.orders.lock().unwrap().retain(|_, order| {
			let finished_at = match &order.payment {
				Some(payment) => Some(payment.accepted_at),
				None => {
					order.absolute_expiry.map(|expiry| expiry + self.config.expiry_grace_period)
				},
			};
			match finished_at {
				Some(finished_at) => finished_at + retention > now,
				None => true,
			}
		});
	}
}

impl<ES: EntropySource, NS: NodeSigner, L: Logger> PosTerminal<ES, NS, L> {
	/// Returns the events generated since the last call. The terminal should be persisted after
	/// handling them.
	pub fn get_and_clear_pending_events(&self) -> Vec<PosEvent> {
		core::mem::take(&mut *self.pending_events.lock().unwrap())
	}

	/// Processes a payment notification that arrived over the `notification_path` of `order_id`,
	/// at time `now`, returning the response to send, if any.
	fn process_notification(
		&self, notification: PaymentNotification, order_id: PosOrderId, now: Duration,
	) -> Option<PosNotificationMessage> {
		let payment_hash = notification.payment_hash();
		let logger = WithContext::from(&self.logger, None, None, Some(payment_hash));

		let mut orders = self.orders.lock().unwrap();
		let order = match orders.get_mut(&order_id) {
			Some(order) => order,
			None => {
				// The path is ours but its order is gone. Unauthenticated senders can elicit this
				// one response, so it is given once per path.
				if !self.unknown_orders_answered.lock().unwrap().insert(order_id) {
					return None;
				}
				log_debug!(logger, "Refusing payment notification for an unknown order");
				let reason = NackReason::UnknownOrder;
				return Some(PosNotificationMessage::NotificationNack(NotificationNack {
					payment_hash,
					reason,
				}));
			},
		};

		{
			let mut failed_checks = self.failed_signature_checks.lock().unwrap();
			if let Some((window_start, failures)) = failed_checks.get(&order_id) {
				let window_open = now < *window_start + SIGNATURE_CHECK_WINDOW;
				if window_open && *failures >= MAX_FAILED_SIGNATURE_CHECKS {
					log_trace!(logger, "Not verifying payment notification: budget exhausted");
					return None;
				}
				if !window_open {
					failed_checks.remove(&order_id);
				}
			}
		}

		let expiry_grace_period = self.config.expiry_grace_period;
		match check_notification(order, &notification, now, expiry_grace_period) {
			NotificationCheck::Unattributable => {
				log_debug!(logger, "Ignoring payment notification with an invalid signature");
				let mut failed_checks = self.failed_signature_checks.lock().unwrap();
				let entry = failed_checks.entry(order_id).or_insert((now, 0));
				entry.1 += 1;
				None
			},
			NotificationCheck::Refused(reason) => {
				log_info!(logger, "Refusing payment notification: {:?}", reason);
				let event = PosEvent::NotificationRefused { order_id, payment_hash, reason };
				self.pending_events.lock().unwrap().push(event);
				Some(PosNotificationMessage::NotificationNack(NotificationNack {
					payment_hash,
					reason,
				}))
			},
			NotificationCheck::Accepted { settles_order, additional_payment } => {
				let amount_msats = notification.amount_msats();
				let payment = PosOrderPayment {
					payment_hash,
					preimage: notification.preimage(),
					amount_msats,
					accepted_at: now,
					notification: Some(notification.bytes().to_vec()),
				};
				if settles_order {
					log_info!(logger, "Order paid");
					order.payment = Some(payment);
					let event = PosEvent::OrderPaid { order_id, payment_hash, amount_msats };
					self.pending_events.lock().unwrap().push(event);
				} else if additional_payment {
					log_info!(logger, "Order paid again by a different payment");
					order.additional_payments.push(payment);
					let event =
						PosEvent::AdditionalPayment { order_id, payment_hash, amount_msats };
					self.pending_events.lock().unwrap().push(event);
				}
				Some(PosNotificationMessage::NotificationAck(NotificationAck { payment_hash }))
			},
		}
	}
}

impl<ES: EntropySource, NS: NodeSigner, L: Logger> PosNotificationMessageHandler
	for PosTerminal<ES, NS, L>
{
	fn handle_payment_notification(
		&self, message: PaymentNotification, context: PosNotificationContext,
		responder: Option<Responder>,
	) -> Option<(PosNotificationMessage, ResponseInstruction)> {
		let order_id = match context {
			PosNotificationContext::NotificationPath { order_id } => PosOrderId(order_id),
			PosNotificationContext::ReplyPath { .. } => return None,
		};
		let response = self.process_notification(message, order_id, self.duration_since_epoch());
		match (response, responder) {
			(Some(response), Some(responder)) => Some((response, responder.respond())),
			_ => None,
		}
	}

	fn handle_notification_ack(&self, _message: NotificationAck, _context: PosNotificationContext) {
	}

	fn handle_notification_nack(
		&self, _message: NotificationNack, _context: PosNotificationContext,
	) {
	}

	fn handle_payment_proof(&self, _message: PaymentProof, _context: PosNotificationContext) {
		log_trace!(self.logger, "Ignoring payment proof: not supported yet");
	}
}

impl<ES: EntropySource, NS: NodeSigner, L: Logger> Writeable for PosTerminal<ES, NS, L> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(w, 1, 1);
		let orders: Vec<PosOrder> = self.orders.lock().unwrap().values().cloned().collect();
		write_tlv_fields!(w, {
			(0, orders, required_vec),
		});
		Ok(())
	}
}

impl<ES: EntropySource, NS: NodeSigner, L: Logger> ReadableArgs<(ES, NS, L, PosConfig)>
	for PosTerminal<ES, NS, L>
{
	fn read<R: io::Read>(r: &mut R, args: (ES, NS, L, PosConfig)) -> Result<Self, DecodeError> {
		let (entropy_source, node_signer, logger, config) = args;
		let _ver = read_ver_prefix!(r, 1);
		let mut orders: Vec<PosOrder> = Vec::new();
		read_tlv_fields!(r, {
			(0, orders, required_vec),
		});
		let orders = orders.into_iter().map(|order| (order.order_id, order)).collect();
		Ok(Self::with_orders(entropy_source, node_signer, logger, config, orders))
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use super::{
		check_notification, check_template, NotificationCheck, PosConfig, PosEvent, PosOrder,
		PosOrderError, PosOrderId, PosTemplateError, PosTerminal, DEFAULT_EXPIRY_GRACE_PERIOD,
		MAX_FAILED_SIGNATURE_CHECKS, SIGNATURE_CHECK_WINDOW,
	};
	use crate::blinded_path::message::PosNotificationContext;
	use crate::offers::payment_notification::{PaymentNotification, UnsignedPaymentNotification};
	use crate::offers::payment_token::payment_token_hash;
	use crate::onion_message::pos_notification::{
		NackReason, NotificationAck, NotificationNack, PosNotificationMessage,
		PosNotificationMessageHandler,
	};
	use crate::types::payment::{PaymentHash, PaymentPreimage};

	use crate::blinded_path::message::BlindedMessagePath;
	use crate::blinded_path::BlindedHop;
	use crate::ln::msgs::MAX_VALUE_MSAT;
	use crate::offers::merkle::TlvStream;
	use crate::offers::offer::{Amount, Offer, OfferBuilder, Quantity};
	use crate::offers::payment_token::SealedOrder;
	use crate::prelude::*;
	use crate::types::features::OfferFeatures;
	use crate::util::ser::{BigSize, ReadableArgs, WithoutLength, Writeable};
	use crate::util::test_utils::{TestKeysInterface, TestLogger};

	use bitcoin::constants::ChainHash;
	use bitcoin::network::Network;
	use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};

	use core::num::NonZeroU64;
	use core::time::Duration;

	pub(crate) type TestPosTerminal<'a> =
		PosTerminal<&'a TestKeysInterface, &'a TestKeysInterface, &'a TestLogger>;

	pub(crate) fn merchant_keys() -> Keypair {
		Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	pub(crate) fn chain() -> ChainHash {
		ChainHash::using_genesis_block(Network::Testnet)
	}

	pub(crate) fn merchant_path() -> BlindedMessagePath {
		let pubkey = |byte: u8| {
			PublicKey::from_secret_key(
				&Secp256k1::new(),
				&SecretKey::from_slice(&[byte; 32]).unwrap(),
			)
		};
		BlindedMessagePath::from_blinded_path(
			pubkey(40),
			pubkey(41),
			vec![BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] }],
		)
	}

	/// Returns `offer` with the record of type `r#type` set to `value`, replacing any existing one.
	fn with_record(offer: &Offer, r#type: u64, value: &[u8]) -> Offer {
		let mut records: Vec<(u64, Vec<u8>)> = TlvStream::new(&offer.bytes)
			.filter(|record| record.r#type != r#type)
			.map(|record| (record.r#type, record.record_bytes.to_vec()))
			.collect();
		let mut record = Vec::new();
		BigSize(r#type).write(&mut record).unwrap();
		BigSize(value.len() as u64).write(&mut record).unwrap();
		record.extend_from_slice(value);
		records.push((r#type, record));
		records.sort_by_key(|(t, _)| *t);
		Offer::try_from(records.into_iter().flat_map(|(_, r)| r).collect::<Vec<u8>>()).unwrap()
	}

	fn with_payment_notifications(offer: &Offer) -> Offer {
		let mut features = OfferFeatures::empty();
		features.set_payment_notifications_optional();
		with_record(offer, 12, &WithoutLength(&features).encode())
	}

	/// A template from a merchant whose issuer key is [`merchant_keys`], for [`chain`].
	pub(crate) fn template() -> Offer {
		let offer = OfferBuilder::new(merchant_keys().public_key())
			.chain(Network::Testnet)
			.path(merchant_path())
			.build()
			.unwrap();
		with_payment_notifications(&offer)
	}

	pub(crate) fn config() -> PosConfig {
		let intro = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&[50; 32]).unwrap(),
		);
		PosConfig::new(chain(), Some(intro))
	}

	pub(crate) fn terminal<'a>(
		keys: &'a TestKeysInterface, logger: &'a TestLogger,
	) -> TestPosTerminal<'a> {
		PosTerminal::new(keys, keys, logger, config())
	}

	#[test]
	fn accepts_valid_template() {
		assert_eq!(check_template(&template(), chain()), Ok(()));

		// A template without explicit chains is for bitcoin only.
		let offer =
			OfferBuilder::new(merchant_keys().public_key()).path(merchant_path()).build().unwrap();
		let bitcoin = ChainHash::using_genesis_block(Network::Bitcoin);
		assert_eq!(check_template(&with_payment_notifications(&offer), bitcoin), Ok(()));
	}

	#[test]
	fn rejects_unusable_templates() {
		let keys = merchant_keys().public_key();
		let builder = || OfferBuilder::new(keys).chain(Network::Testnet).path(merchant_path());

		let no_feature = builder().build().unwrap();
		assert_eq!(check_template(&no_feature, chain()), Err(PosTemplateError::MissingFeature));

		let no_paths = with_payment_notifications(
			&OfferBuilder::new(keys).chain(Network::Testnet).build().unwrap(),
		);
		assert_eq!(check_template(&no_paths, chain()), Err(PosTemplateError::MissingPaths));

		let amount = with_payment_notifications(
			&builder().amount_msats(1_000).description("x".to_string()).build().unwrap(),
		);
		assert_eq!(check_template(&amount, chain()), Err(PosTemplateError::UnexpectedAmount));

		let description =
			with_payment_notifications(&builder().description("x".to_string()).build().unwrap());
		assert_eq!(
			check_template(&description, chain()),
			Err(PosTemplateError::UnexpectedDescription)
		);

		let quantity = with_payment_notifications(
			&builder()
				.supported_quantity(Quantity::Bounded(NonZeroU64::new(2).unwrap()))
				.build()
				.unwrap(),
		);
		assert_eq!(check_template(&quantity, chain()), Err(PosTemplateError::UnexpectedQuantity));

		let other_chain = ChainHash::using_genesis_block(Network::Signet);
		assert_eq!(
			check_template(&template(), other_chain),
			Err(PosTemplateError::UnsupportedChain)
		);
		let two_chains =
			with_payment_notifications(&builder().chain(Network::Signet).build().unwrap());
		assert_eq!(check_template(&two_chains, chain()), Err(PosTemplateError::UnsupportedChain));
	}

	#[test]
	fn creates_order_offer() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);

		let expiry = Duration::from_secs(1_900_000_000);
		let (order_id, offer) = terminal
			.create_order(&template(), 21_000, "espresso".to_string(), Some(expiry))
			.unwrap();

		assert_eq!(offer.amount(), Some(Amount::Bitcoin { amount_msats: 21_000 }));
		assert_eq!(offer.description().unwrap().0, "espresso");
		assert_eq!(offer.absolute_expiry(), Some(expiry));
		assert_eq!(offer.paths(), template().paths());
		assert_eq!(offer.chains(), vec![chain()]);
		assert_eq!(offer.supported_quantity(), Quantity::One);
		assert!(offer.offer_features().supports_payment_notifications());
		assert_eq!(offer.notification_paths().len(), 1);

		// The notification path is introduced by the configured node.
		let intro = config().notification_path_intro_node.unwrap().node_id;
		let path = &offer.notification_paths()[0];
		assert_eq!(path.introduction_node(), &crate::blinded_path::IntroductionNode::NodeId(intro));

		// The token seals the order for the merchant.
		let merchant_secret = merchant_keys().secret_key();
		let sealed = SealedOrder::unseal(&merchant_secret, offer.payment_token().unwrap()).unwrap();
		assert_eq!(sealed.amount_msats, 21_000);
		assert_eq!(sealed.description, "espresso");
		assert!(sealed.order_metadata.len() >= 16);

		let order = terminal.order(&order_id).unwrap();
		assert_eq!(order.order_id, order_id);
		assert_eq!(order.issuer_id, merchant_keys().public_key());
		assert_eq!(&order.payment_token[..], offer.payment_token().unwrap());
		assert_eq!(order.amount_msats, 21_000);
		assert_eq!(order.description, "espresso");
		assert_eq!(order.absolute_expiry, Some(expiry));
		assert_eq!(order.payment, None);
	}

	#[test]
	fn creates_distinct_orders_for_identical_items() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);

		let (id_a, offer_a) =
			terminal.create_order(&template(), 1_000, "tea".to_string(), None).unwrap();
		let (id_b, offer_b) =
			terminal.create_order(&template(), 1_000, "tea".to_string(), None).unwrap();
		assert_ne!(id_a, id_b);
		assert_ne!(offer_a.payment_token(), offer_b.payment_token());

		let merchant_secret = merchant_keys().secret_key();
		let metadata = |offer: &Offer| {
			SealedOrder::unseal(&merchant_secret, offer.payment_token().unwrap())
				.unwrap()
				.order_metadata
		};
		assert_ne!(metadata(&offer_a), metadata(&offer_b));
	}

	#[test]
	fn keeps_template_expiry_without_order_expiry() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);

		let expiry = Duration::from_secs(1_950_000_000);
		let template = with_payment_notifications(
			&OfferBuilder::new(merchant_keys().public_key())
				.chain(Network::Testnet)
				.path(merchant_path())
				.absolute_expiry(expiry)
				.build()
				.unwrap(),
		);
		let (order_id, offer) =
			terminal.create_order(&template, 1_000, "tea".to_string(), None).unwrap();
		assert_eq!(offer.absolute_expiry(), Some(expiry));
		assert_eq!(terminal.order(&order_id).unwrap().absolute_expiry, Some(expiry));
	}

	#[test]
	fn fails_creating_invalid_orders() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);

		for amount in [0, MAX_VALUE_MSAT + 1] {
			assert_eq!(
				terminal.create_order(&template(), amount, "tea".to_string(), None),
				Err(PosOrderError::InvalidAmount),
			);
		}
		let unusable = OfferBuilder::new(merchant_keys().public_key()).build().unwrap();
		assert_eq!(
			terminal.create_order(&unusable, 1_000, "tea".to_string(), None),
			Err(PosOrderError::InvalidTemplate(PosTemplateError::MissingFeature)),
		);
		assert!(terminal.orders().is_empty());
	}

	#[test]
	fn persists_orders() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (id_a, _) = terminal.create_order(&template(), 1_000, "tea".to_string(), None).unwrap();
		let (id_b, _) = terminal
			.create_order(&template(), 2_000, "cake".to_string(), Some(Duration::from_secs(1)))
			.unwrap();

		let bytes = terminal.encode();
		let restored: TestPosTerminal = ReadableArgs::read(
			&mut crate::io::Cursor::new(&bytes),
			(&keys, &keys, &logger, config()),
		)
		.unwrap();
		assert_eq!(restored.order(&id_a), terminal.order(&id_a));
		assert_eq!(restored.order(&id_b), terminal.order(&id_b));
		assert_eq!(restored.orders().len(), 2);
	}

	#[test]
	fn prunes_finished_orders() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let now = terminal.duration_since_epoch();
		let retention = Duration::from_secs(24 * 60 * 60);

		let long_expired = now - retention - DEFAULT_EXPIRY_GRACE_PERIOD - Duration::from_secs(60);
		let recently_expired = now - Duration::from_secs(60);
		let (old, _) =
			terminal.create_order(&template(), 1_000, "a".to_string(), Some(long_expired)).unwrap();
		let (recent, _) = terminal
			.create_order(&template(), 1_000, "b".to_string(), Some(recently_expired))
			.unwrap();
		let (open, _) = terminal.create_order(&template(), 1_000, "c".to_string(), None).unwrap();

		terminal.prune_orders(retention);
		assert!(terminal.order(&old).is_none());
		assert!(terminal.order(&recent).is_some());
		assert!(terminal.order(&open).is_some());
	}

	/// How much a per-order offer adds to its template, which matters for QR codes.
	#[test]
	fn per_order_offer_size() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (_, offer) =
			terminal.create_order(&template(), 21_000, "espresso".to_string(), None).unwrap();

		// The ephemeral key, then the sealed order's records (a 2-byte amount, the 8-byte
		// description and 32 bytes of metadata, each with a 2-byte type and length), then the tag.
		let token_len = offer.payment_token().unwrap().len();
		assert_eq!(token_len, 33 + (2 + 2) + (2 + 8) + (2 + 32) + 16);

		// One compactly padded notification path through the configured introduction node.
		let path_len = offer.notification_paths()[0].encode().len();
		assert!(path_len <= 300, "notification path is {} bytes", path_len);

		// The amount and description records, then the two odd experimental records, whose 5-byte
		// types are the cost of living in the experimental range.
		let record_len =
			|value_len: usize| 5 + BigSize(value_len as u64).serialized_length() + value_len;
		let added = offer.bytes.len() - template().bytes.len();
		assert_eq!(added, (2 + 2) + (2 + 8) + record_len(path_len) + record_len(token_len));

		// With one notification path the per-order records add 371 bytes, about 593 bech32
		// characters, to the template.
		assert_eq!(added, 371);
		assert_eq!(offer.to_string().len() - template().to_string().len(), 593);
	}

	/// A notification for `order` signed by `keys`, for a payment of `amount_msats` with the
	/// preimage `[preimage_byte; 32]`.
	fn notification_for(
		order: &PosOrder, keys: &Keypair, amount_msats: u64, preimage_byte: u8,
	) -> PaymentNotification {
		let entropy = TestKeysInterface::new(&[preimage_byte; 32], Network::Testnet);
		let preimage = PaymentPreimage([preimage_byte; 32]);
		UnsignedPaymentNotification::new(
			&entropy,
			payment_token_hash(&order.payment_token),
			preimage.into(),
			preimage,
			amount_msats,
		)
		.sign_with_keys(keys, &Secp256k1::new())
	}

	/// The response to a notification, reduced to the echoed payment hash and the nack reason.
	type Response = Option<(PaymentHash, Option<NackReason>)>;

	fn process(
		terminal: &TestPosTerminal, notification: PaymentNotification, order_id: PosOrderId,
		now: Duration,
	) -> Response {
		match terminal.process_notification(notification, order_id, now) {
			Some(PosNotificationMessage::NotificationAck(NotificationAck { payment_hash })) => {
				Some((payment_hash, None))
			},
			Some(PosNotificationMessage::NotificationNack(NotificationNack {
				payment_hash,
				reason,
			})) => Some((payment_hash, Some(reason))),
			Some(response) => panic!("unexpected response: {:?}", response),
			None => None,
		}
	}

	fn ack(payment_hash: PaymentHash) -> Response {
		Some((payment_hash, None))
	}

	fn nack(payment_hash: PaymentHash, reason: NackReason) -> Response {
		Some((payment_hash, Some(reason)))
	}

	fn other_keys() -> Keypair {
		Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[43; 32]).unwrap())
	}

	#[test]
	fn accepts_and_records_valid_notification() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (order_id, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let order = terminal.order(&order_id).unwrap();
		let now = terminal.duration_since_epoch();

		// The merchant may claim more than the order's amount.
		let notification = notification_for(&order, &merchant_keys(), 5_100, 7);
		let payment_hash = notification.payment_hash();
		assert_eq!(process(&terminal, notification.clone(), order_id, now), ack(payment_hash));
		assert_eq!(
			terminal.get_and_clear_pending_events(),
			vec![PosEvent::OrderPaid { order_id, payment_hash, amount_msats: 5_100 }],
		);

		let payment = terminal.order(&order_id).unwrap().payment.unwrap();
		assert_eq!(payment.payment_hash, payment_hash);
		assert_eq!(payment.preimage, PaymentPreimage([7; 32]));
		assert_eq!(payment.amount_msats, 5_100);
		assert_eq!(payment.notification.as_deref(), Some(notification.bytes()));

		// A retried notification is acknowledged again without settling the order twice.
		assert_eq!(process(&terminal, notification, order_id, now), ack(payment_hash));
		assert!(terminal.get_and_clear_pending_events().is_empty());
	}

	#[test]
	fn ignores_notifications_not_signed_by_the_orders_merchant() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);

		// A second merchant using the same terminal, with a template of its own.
		let other_template = with_payment_notifications(
			&OfferBuilder::new(other_keys().public_key())
				.chain(Network::Testnet)
				.path(merchant_path())
				.build()
				.unwrap(),
		);
		let (order_id, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		terminal.create_order(&other_template, 5_000, "tea".to_string(), None).unwrap();
		let order = terminal.order(&order_id).unwrap();
		let now = terminal.duration_since_epoch();

		// Signed by a key the terminal knows, but not the one this order's template named.
		let notification = notification_for(&order, &other_keys(), 5_000, 7);
		assert_eq!(process(&terminal, notification, order_id, now), None);
		assert!(terminal.get_and_clear_pending_events().is_empty());
		assert!(terminal.order(&order_id).unwrap().payment.is_none());
	}

	#[test]
	fn refuses_notifications_failing_checks() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (order_a, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let (order_b, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let a = terminal.order(&order_a).unwrap();
		let now = terminal.duration_since_epoch();

		// Too little claimed.
		let notification = notification_for(&a, &merchant_keys(), 4_999, 7);
		let payment_hash = notification.payment_hash();
		assert_eq!(
			process(&terminal, notification, order_a, now),
			nack(payment_hash, NackReason::AmountInsufficient),
		);

		// A genuine notification for order A replayed down order B's path: same price, signed by
		// the right merchant, but committing to A's token.
		let notification = notification_for(&a, &merchant_keys(), 5_000, 8);
		let payment_hash = notification.payment_hash();
		assert_eq!(
			process(&terminal, notification, order_b, now),
			nack(payment_hash, NackReason::OrderMismatch),
		);

		// A signed notification whose preimage does not match its payment hash.
		let preimage = PaymentPreimage([9; 32]);
		let entropy = TestKeysInterface::new(&[9; 32], Network::Testnet);
		let notification = UnsignedPaymentNotification::new(
			&entropy,
			payment_token_hash(&a.payment_token),
			PaymentHash([1; 32]),
			preimage,
			5_000,
		)
		.sign_with_keys(&merchant_keys(), &Secp256k1::new());
		assert_eq!(
			process(&terminal, notification, order_a, now),
			nack(PaymentHash([1; 32]), NackReason::PreimageMismatch),
		);

		let events = terminal.get_and_clear_pending_events();
		assert_eq!(events.len(), 3);
		assert!(events.iter().all(|e| matches!(e, PosEvent::NotificationRefused { .. })));
		assert!(terminal.order(&order_a).unwrap().payment.is_none());
		assert!(terminal.order(&order_b).unwrap().payment.is_none());
	}

	#[test]
	fn applies_expiry_with_grace_period() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let expiry = Duration::from_secs(1_800_000_000);
		let (order_id, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), Some(expiry)).unwrap();
		let mut order = terminal.order(&order_id).unwrap();
		let notification = notification_for(&order, &merchant_keys(), 5_000, 7);
		let grace = DEFAULT_EXPIRY_GRACE_PERIOD;
		let settles =
			NotificationCheck::Accepted { settles_order: true, additional_payment: false };

		assert_eq!(check_notification(&order, &notification, expiry, grace), settles);
		assert_eq!(check_notification(&order, &notification, expiry + grace, grace), settles);
		let late = expiry + grace + Duration::from_secs(1);
		assert_eq!(
			check_notification(&order, &notification, late, grace),
			NotificationCheck::Refused(NackReason::OrderExpired),
		);

		// Once paid, the payment is acknowledged again however late the retry.
		process(&terminal, notification.clone(), order_id, expiry).unwrap();
		order = terminal.order(&order_id).unwrap();
		let repeat =
			NotificationCheck::Accepted { settles_order: false, additional_payment: false };
		let much_later = late + Duration::from_secs(365 * 24 * 60 * 60);
		assert_eq!(check_notification(&order, &notification, much_later, grace), repeat);

		// An order without an expiry never expires.
		order.absolute_expiry = None;
		order.payment = None;
		assert_eq!(check_notification(&order, &notification, much_later, grace), settles);
	}

	#[test]
	fn flags_additional_payment() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (order_id, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let order = terminal.order(&order_id).unwrap();
		let now = terminal.duration_since_epoch();

		let first = notification_for(&order, &merchant_keys(), 5_000, 7);
		process(&terminal, first.clone(), order_id, now).unwrap();
		terminal.get_and_clear_pending_events();

		let second = notification_for(&order, &merchant_keys(), 5_000, 8);
		let second_hash = second.payment_hash();
		assert_eq!(process(&terminal, second.clone(), order_id, now), ack(second_hash));
		assert_eq!(
			terminal.get_and_clear_pending_events(),
			vec![PosEvent::AdditionalPayment {
				order_id,
				payment_hash: second_hash,
				amount_msats: 5_000
			}],
		);

		// Retries of either payment are acknowledged without new events, and the order stays
		// settled by the first.
		assert_eq!(process(&terminal, second, order_id, now), ack(second_hash));
		assert_eq!(process(&terminal, first.clone(), order_id, now), ack(first.payment_hash()));
		assert!(terminal.get_and_clear_pending_events().is_empty());
		let order = terminal.order(&order_id).unwrap();
		assert_eq!(order.payment.unwrap().payment_hash, first.payment_hash());
		assert_eq!(order.additional_payments.len(), 1);
	}

	#[test]
	fn answers_unknown_order_once_per_path() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (order_id, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let order = terminal.order(&order_id).unwrap();
		let now = terminal.duration_since_epoch();
		let notification = notification_for(&order, &merchant_keys(), 5_000, 7);
		let payment_hash = notification.payment_hash();

		let gone = PosOrderId([3; 32]);
		assert_eq!(
			process(&terminal, notification.clone(), gone, now),
			nack(payment_hash, NackReason::UnknownOrder),
		);
		assert_eq!(process(&terminal, notification, gone, now), None);
		assert!(terminal.get_and_clear_pending_events().is_empty());
	}

	#[test]
	fn limits_failed_signature_checks_per_order() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (flooded, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let (other, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let flooded_order = terminal.order(&flooded).unwrap();
		let other_order = terminal.order(&other).unwrap();
		let now = terminal.duration_since_epoch();

		let forged = notification_for(&flooded_order, &other_keys(), 5_000, 7);
		for _ in 0..MAX_FAILED_SIGNATURE_CHECKS {
			assert_eq!(process(&terminal, forged.clone(), flooded, now), None);
		}

		// The flooded order is not verified again until the window ends, so even the genuine
		// notification is dropped for now...
		let genuine = notification_for(&flooded_order, &merchant_keys(), 5_000, 8);
		assert_eq!(process(&terminal, genuine.clone(), flooded, now), None);

		// ...while other orders are unaffected...
		let other_notification = notification_for(&other_order, &merchant_keys(), 5_000, 9);
		let other_hash = other_notification.payment_hash();
		assert_eq!(process(&terminal, other_notification, other, now), ack(other_hash));

		// ...and the merchant's retry after the window is accepted.
		let later = now + SIGNATURE_CHECK_WINDOW;
		assert_eq!(
			process(&terminal, genuine.clone(), flooded, later),
			ack(genuine.payment_hash())
		);
	}

	#[test]
	fn handles_notifications_through_the_handler() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (order_id, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let order = terminal.order(&order_id).unwrap();
		let notification = notification_for(&order, &merchant_keys(), 5_000, 7);

		// A notification over a merchant reply path is not for the terminal.
		let reply_context =
			PosNotificationContext::ReplyPath { payment_hash: notification.payment_hash() };
		assert!(terminal
			.handle_payment_notification(notification.clone(), reply_context, None)
			.is_none());
		assert!(terminal.order(&order_id).unwrap().payment.is_none());

		// Without a reply path the notification is still processed, just not answered.
		let context = PosNotificationContext::NotificationPath { order_id: order_id.0 };
		assert!(terminal.handle_payment_notification(notification, context, None).is_none());
		assert!(terminal.order(&order_id).unwrap().payment.is_some());
		assert_eq!(terminal.get_and_clear_pending_events().len(), 1);
	}

	#[test]
	fn keeps_payments_across_restarts() {
		let keys = TestKeysInterface::new(&[1; 32], Network::Testnet);
		let logger = TestLogger::new();
		let terminal = terminal(&keys, &logger);
		let (order_id, _) =
			terminal.create_order(&template(), 5_000, "tea".to_string(), None).unwrap();
		let order = terminal.order(&order_id).unwrap();
		let now = terminal.duration_since_epoch();
		let first = notification_for(&order, &merchant_keys(), 5_000, 7);
		let second = notification_for(&order, &merchant_keys(), 5_000, 8);
		process(&terminal, first.clone(), order_id, now).unwrap();
		process(&terminal, second, order_id, now).unwrap();
		terminal.get_and_clear_pending_events();

		let bytes = terminal.encode();
		let restored: TestPosTerminal = ReadableArgs::read(
			&mut crate::io::Cursor::new(&bytes),
			(&keys, &keys, &logger, config()),
		)
		.unwrap();
		assert_eq!(restored.order(&order_id), terminal.order(&order_id));
		assert_eq!(process(&restored, first.clone(), order_id, now), ack(first.payment_hash()));
		assert!(restored.get_and_clear_pending_events().is_empty());
	}
}
