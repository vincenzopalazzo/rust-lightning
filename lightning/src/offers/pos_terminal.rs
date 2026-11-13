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
//! [bLIP 56]: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md

use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::blinded_path::message::{
	BlindedMessagePath, MessageContext, MessageForwardNode, PosNotificationContext,
};
use crate::io;
use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
use crate::offers::offer::{Offer, Quantity};
use crate::offers::parse::Bolt12ParseError;
use crate::offers::payment_token::SealedOrder;
use crate::prelude::*;
use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::sync::Mutex;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::logger::Logger;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

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
	#[allow(unused)]
	logger: L,
	config: PosConfig,
	secp_ctx: Secp256k1<secp256k1::All>,
	orders: Mutex<HashMap<PosOrderId, PosOrder>>,
	highest_seen_timestamp: AtomicU64,
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
		check_template, PosConfig, PosOrderError, PosTemplateError, PosTerminal,
		DEFAULT_EXPIRY_GRACE_PERIOD,
	};

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
}
