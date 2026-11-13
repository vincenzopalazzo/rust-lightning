// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion messages for point-of-sale payment notifications, as defined by [bLIP 56].
//!
//! A merchant sends a [`PaymentNotification`] to a point-of-sale device over a per-order offer's
//! `notification_path` once the order's payment settles, and the device answers over the
//! notification's reply path with a [`NotificationAck`] or a [`NotificationNack`]. A customer may
//! also send the device a [`PaymentProof`] over the same path.
//!
//! [bLIP 56]: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md

use crate::blinded_path::message::PosNotificationContext;
use crate::io::{self, Read};
use crate::ln::msgs::DecodeError;
use crate::offers::parse::Bolt12ParseError;
use crate::offers::payer_proof::PayerProof;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
use crate::types::payment::PaymentHash;
use crate::util::ser::{ReadableArgs, Writeable, Writer};

use core::ops::Deref;

pub use crate::offers::payment_notification::PaymentNotification;

// TLV record types for the `onionmsg_tlv` TLV stream as defined in BOLT 4.
const PAYMENT_NOTIFICATION_TLV_TYPE: u64 = 65540;
const NOTIFICATION_ACK_TLV_TYPE: u64 = 65542;
const NOTIFICATION_NACK_TLV_TYPE: u64 = 65544;
const PAYMENT_PROOF_TLV_TYPE: u64 = 65546;

/// The length of a [`NotificationAck`] on the wire.
const NOTIFICATION_ACK_LEN: usize = 32;

/// The length of a [`NotificationNack`] on the wire.
const NOTIFICATION_NACK_LEN: usize = 33;

/// A handler for an [`OnionMessage`] containing a point-of-sale payment notification message as
/// its payload.
///
/// Messages are only passed to the handler when they arrived over a blinded path this node built
/// with a [`PosNotificationContext`], as authenticated by the [`OnionMessenger`]; any other is
/// dropped. A point-of-sale device receives [`PaymentNotification`]s and [`PaymentProof`]s over a
/// per-order offer's `notification_path`, and a merchant receives [`NotificationAck`]s and
/// [`NotificationNack`]s over the reply paths of the notifications it sent.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
pub trait PosNotificationMessageHandler {
	/// Handles a [`PaymentNotification`] from a merchant, returning the [`NotificationAck`] or
	/// [`NotificationNack`] to answer it with, if any.
	fn handle_payment_notification(
		&self, message: PaymentNotification, context: PosNotificationContext,
		responder: Option<Responder>,
	) -> Option<(PosNotificationMessage, ResponseInstruction)>;

	/// Handles a [`NotificationAck`] from a point-of-sale device.
	fn handle_notification_ack(&self, message: NotificationAck, context: PosNotificationContext);

	/// Handles a [`NotificationNack`] from a point-of-sale device.
	fn handle_notification_nack(&self, message: NotificationNack, context: PosNotificationContext);

	/// Handles a [`PaymentProof`] from a customer.
	fn handle_payment_proof(&self, message: PaymentProof, context: PosNotificationContext);

	/// Releases any [`PosNotificationMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a message flow rather than in response to
	/// another message, such as a merchant's [`PaymentNotification`].
	fn release_pending_messages(&self) -> Vec<(PosNotificationMessage, MessageSendInstructions)> {
		vec![]
	}
}

impl<T: PosNotificationMessageHandler + ?Sized, D: Deref<Target = T>> PosNotificationMessageHandler
	for D
{
	fn handle_payment_notification(
		&self, message: PaymentNotification, context: PosNotificationContext,
		responder: Option<Responder>,
	) -> Option<(PosNotificationMessage, ResponseInstruction)> {
		self.deref().handle_payment_notification(message, context, responder)
	}
	fn handle_notification_ack(&self, message: NotificationAck, context: PosNotificationContext) {
		self.deref().handle_notification_ack(message, context)
	}
	fn handle_notification_nack(&self, message: NotificationNack, context: PosNotificationContext) {
		self.deref().handle_notification_nack(message, context)
	}
	fn handle_payment_proof(&self, message: PaymentProof, context: PosNotificationContext) {
		self.deref().handle_payment_proof(message, context)
	}
	fn release_pending_messages(&self) -> Vec<(PosNotificationMessage, MessageSendInstructions)> {
		self.deref().release_pending_messages()
	}
}

/// Possible point-of-sale payment notification messages sent and received via an
/// [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone, Debug)]
pub enum PosNotificationMessage {
	/// A notification from a merchant that the payment for an order settled.
	PaymentNotification(PaymentNotification),
	/// A point-of-sale device's acceptance of a [`PaymentNotification`].
	NotificationAck(NotificationAck),
	/// A point-of-sale device's refusal of a [`PaymentNotification`].
	NotificationNack(NotificationNack),
	/// A payer proof sent by a customer to a point-of-sale device.
	PaymentProof(PaymentProof),
}

impl PosNotificationMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for these messages.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			PAYMENT_NOTIFICATION_TLV_TYPE
			| NOTIFICATION_ACK_TLV_TYPE
			| NOTIFICATION_NACK_TLV_TYPE
			| PAYMENT_PROOF_TLV_TYPE => true,
			_ => false,
		}
	}
}

/// A point-of-sale device's acceptance of a [`PaymentNotification`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationAck {
	/// The [`PaymentNotification::payment_hash`] of the notification being answered.
	pub payment_hash: PaymentHash,
}

/// A point-of-sale device's refusal of a [`PaymentNotification`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationNack {
	/// The [`PaymentNotification::payment_hash`] of the notification being answered.
	pub payment_hash: PaymentHash,
	/// Why the notification was refused.
	pub reason: NackReason,
}

/// Why a point-of-sale device refused a [`PaymentNotification`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NackReason {
	/// The notification arrived over a path the device built, but no order owns that path.
	UnknownOrder,
	/// The order is past its expiry.
	OrderExpired,
	/// The signature verified, but the notification commits to a `payment_token` other than the
	/// one the device sealed for the order.
	OrderMismatch,
	/// The notified amount is below the order's amount.
	AmountInsufficient,
	/// The notified preimage does not hash to the notified payment hash.
	PreimageMismatch,
	/// A reason code this implementation does not know, which is treated as a terminal failure.
	Unknown(u8),
}

impl NackReason {
	/// The reason code sent on the wire.
	pub fn to_code(&self) -> u8 {
		match self {
			Self::UnknownOrder => 0,
			Self::OrderExpired => 1,
			Self::OrderMismatch => 2,
			Self::AmountInsufficient => 3,
			Self::PreimageMismatch => 4,
			Self::Unknown(code) => *code,
		}
	}

	/// The reason for a code received on the wire.
	pub fn from_code(code: u8) -> Self {
		match code {
			0 => Self::UnknownOrder,
			1 => Self::OrderExpired,
			2 => Self::OrderMismatch,
			3 => Self::AmountInsufficient,
			4 => Self::PreimageMismatch,
			code => Self::Unknown(code),
		}
	}
}

impl Writeable for NackReason {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.to_code().write(w)
	}
}

impl crate::util::ser::Readable for NackReason {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let code: u8 = crate::util::ser::Readable::read(r)?;
		Ok(Self::from_code(code))
	}
}

/// A payer proof sent by a customer to a point-of-sale device, so the device can learn of a
/// payment independently of the merchant.
///
/// The proof is carried unparsed. Parsing a payer proof verifies two signatures, and an onion
/// message's payload is decoded before the messenger has checked that it arrived over a path this
/// node built; deferring the parse to [`Self::parse`] keeps that cost off messages that are about
/// to be dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentProof {
	bytes: Vec<u8>,
}

impl PaymentProof {
	/// Wraps a BOLT 12 payer proof for sending. It must disclose the invoice's `payment_token` and
	/// amount for the point-of-sale device to be able to check it.
	pub fn new(proof: &PayerProof) -> Self {
		Self { bytes: proof.bytes().to_vec() }
	}

	/// The serialized payer proof, as received.
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Parses the payer proof, which includes verifying its invoice and payer signatures.
	pub fn parse(&self) -> Result<PayerProof, Bolt12ParseError> {
		PayerProof::try_from(self.bytes.clone())
	}
}

impl OnionMessageContents for PosNotificationMessage {
	fn tlv_type(&self) -> u64 {
		match self {
			Self::PaymentNotification(_) => PAYMENT_NOTIFICATION_TLV_TYPE,
			Self::NotificationAck(_) => NOTIFICATION_ACK_TLV_TYPE,
			Self::NotificationNack(_) => NOTIFICATION_NACK_TLV_TYPE,
			Self::PaymentProof(_) => PAYMENT_PROOF_TLV_TYPE,
		}
	}
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		match self {
			Self::PaymentNotification(_) => "Payment Notification".to_string(),
			Self::NotificationAck(_) => "Notification Ack".to_string(),
			Self::NotificationNack(_) => "Notification Nack".to_string(),
			Self::PaymentProof(_) => "Payment Proof".to_string(),
		}
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match self {
			Self::PaymentNotification(_) => "Payment Notification",
			Self::NotificationAck(_) => "Notification Ack",
			Self::NotificationNack(_) => "Notification Nack",
			Self::PaymentProof(_) => "Payment Proof",
		}
	}
}

impl Writeable for PosNotificationMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::PaymentNotification(message) => message.write(w),
			Self::NotificationAck(message) => message.write(w),
			Self::NotificationNack(message) => message.write(w),
			Self::PaymentProof(message) => w.write_all(&message.bytes),
		}
	}
}

impl Writeable for NotificationAck {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self.payment_hash.0)
	}
}

impl Writeable for NotificationNack {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		w.write_all(&self.payment_hash.0)?;
		w.write_all(&[self.reason.to_code()])
	}
}

impl ReadableArgs<u64> for PosNotificationMessage {
	fn read<R: Read>(r: &mut R, tlv_type: u64) -> Result<Self, DecodeError> {
		let mut bytes = Vec::new();
		r.read_to_limit(&mut bytes, u64::MAX)?;

		let payment_hash = |bytes: &[u8]| {
			let mut payment_hash = [0; 32];
			payment_hash.copy_from_slice(&bytes[..32]);
			PaymentHash(payment_hash)
		};

		match tlv_type {
			PAYMENT_NOTIFICATION_TLV_TYPE => {
				Ok(Self::PaymentNotification(PaymentNotification::try_from(bytes)?))
			},
			NOTIFICATION_ACK_TLV_TYPE if bytes.len() == NOTIFICATION_ACK_LEN => {
				Ok(Self::NotificationAck(NotificationAck { payment_hash: payment_hash(&bytes) }))
			},
			NOTIFICATION_NACK_TLV_TYPE if bytes.len() == NOTIFICATION_NACK_LEN => {
				Ok(Self::NotificationNack(NotificationNack {
					payment_hash: payment_hash(&bytes),
					reason: NackReason::from_code(bytes[32]),
				}))
			},
			PAYMENT_PROOF_TLV_TYPE if !bytes.is_empty() => {
				Ok(Self::PaymentProof(PaymentProof { bytes }))
			},
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{
		NackReason, NotificationAck, NotificationNack, PaymentProof, PosNotificationMessage,
	};

	use crate::io::Cursor;
	use crate::ln::msgs::DecodeError;
	use crate::offers::payer_proof::PaidBolt12Invoice;
	use crate::offers::payment_notification::UnsignedPaymentNotification;
	use crate::offers::refund::RefundBuilder;
	use crate::offers::test_utils::*;
	use crate::onion_message::packet::OnionMessageContents;
	use crate::prelude::*;
	use crate::sign::EntropySource;
	use crate::types::payment::{PaymentHash, PaymentPreimage};
	use crate::util::ser::{ReadableArgs, Writeable};

	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

	use core::time::Duration;

	struct FixedEntropy;

	impl EntropySource for FixedEntropy {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			[0x31; 32]
		}
	}

	fn round_trip(message: &PosNotificationMessage) -> Result<PosNotificationMessage, DecodeError> {
		let bytes = message.encode();
		PosNotificationMessage::read(&mut Cursor::new(&bytes), message.tlv_type())
	}

	fn read(tlv_type: u64, bytes: &[u8]) -> Result<PosNotificationMessage, DecodeError> {
		PosNotificationMessage::read(&mut Cursor::new(bytes), tlv_type)
	}

	#[test]
	fn uses_blip56_tlv_types() {
		assert!(PosNotificationMessage::is_known_type(65540));
		assert!(PosNotificationMessage::is_known_type(65542));
		assert!(PosNotificationMessage::is_known_type(65544));
		assert!(PosNotificationMessage::is_known_type(65546));
		assert!(!PosNotificationMessage::is_known_type(65548));

		let ack = PosNotificationMessage::NotificationAck(NotificationAck {
			payment_hash: PaymentHash([1; 32]),
		});
		assert_eq!(ack.tlv_type(), 65542);
	}

	#[test]
	fn round_trips_payment_notification() {
		let preimage = PaymentPreimage([0x44; 32]);
		let keys =
			Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[42; 32]).unwrap());
		let notification = UnsignedPaymentNotification::new(
			FixedEntropy,
			Sha256::from_byte_array([0x22; 32]),
			preimage.into(),
			preimage,
			50_000,
		)
		.sign_with_keys(&keys, &Secp256k1::new());

		let message = PosNotificationMessage::PaymentNotification(notification.clone());
		assert_eq!(message.tlv_type(), 65540);
		match round_trip(&message) {
			Ok(PosNotificationMessage::PaymentNotification(parsed)) => {
				assert_eq!(parsed, notification);
				assert!(parsed.verify(keys.public_key()).is_ok());
			},
			result => panic!("unexpected result: {:?}", result),
		}

		let mut bytes = notification.bytes().to_vec();
		bytes.truncate(bytes.len() - 1);
		assert!(read(65540, &bytes).is_err());
	}

	#[test]
	fn round_trips_ack_and_nack() {
		let ack = NotificationAck { payment_hash: PaymentHash([1; 32]) };
		assert_eq!(ack.encode(), vec![1; 32]);
		match round_trip(&PosNotificationMessage::NotificationAck(ack.clone())) {
			Ok(PosNotificationMessage::NotificationAck(parsed)) => assert_eq!(parsed, ack),
			result => panic!("unexpected result: {:?}", result),
		}

		for code in 0..=255u8 {
			let reason = NackReason::from_code(code);
			assert_eq!(reason.to_code(), code);
			let nack = NotificationNack { payment_hash: PaymentHash([2; 32]), reason };
			let mut expected = vec![2; 32];
			expected.push(code);
			assert_eq!(nack.encode(), expected);
			match round_trip(&PosNotificationMessage::NotificationNack(nack.clone())) {
				Ok(PosNotificationMessage::NotificationNack(parsed)) => assert_eq!(parsed, nack),
				result => panic!("unexpected result: {:?}", result),
			}
		}
		assert_eq!(NackReason::from_code(0), NackReason::UnknownOrder);
		assert_eq!(NackReason::from_code(1), NackReason::OrderExpired);
		assert_eq!(NackReason::from_code(2), NackReason::OrderMismatch);
		assert_eq!(NackReason::from_code(3), NackReason::AmountInsufficient);
		assert_eq!(NackReason::from_code(4), NackReason::PreimageMismatch);
		assert_eq!(NackReason::from_code(5), NackReason::Unknown(5));
	}

	#[test]
	fn fails_reading_ack_or_nack_with_wrong_length() {
		for len in [0, 31, 33] {
			assert!(read(65542, &vec![1; len]).is_err());
		}
		for len in [0, 32, 34] {
			assert!(read(65544, &vec![1; len]).is_err());
		}
		assert!(read(65548, &[1; 32]).is_err());
	}

	#[test]
	fn round_trips_payment_proof() {
		let preimage = PaymentPreimage([64; 32]);
		let invoice = RefundBuilder::new(vec![1; 32], payer_pubkey(), 42_000)
			.unwrap()
			.build()
			.unwrap()
			.respond_with_no_std(
				payment_paths(),
				preimage.into(),
				recipient_pubkey(),
				Duration::from_secs(1_700_000_000),
			)
			.unwrap()
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		let proof = PaidBolt12Invoice::Bolt12Invoice(invoice)
			.prove_payer(preimage)
			.unwrap()
			.include_invoice_amount()
			.build()
			.unwrap()
			.sign(payer_sign)
			.unwrap();

		let message = PosNotificationMessage::PaymentProof(PaymentProof::new(&proof));
		assert_eq!(message.tlv_type(), 65546);
		match round_trip(&message) {
			Ok(PosNotificationMessage::PaymentProof(received)) => {
				assert_eq!(received.bytes(), proof.bytes());
				let parsed = received.parse().unwrap();
				assert_eq!(parsed.bytes(), proof.bytes());
				assert_eq!(parsed.invoice_amount_msats(), Some(42_000));
			},
			result => panic!("unexpected result: {:?}", result),
		}

		// Invalid proofs are only rejected when parsed, not when the message is read.
		match read(65546, &[1, 2, 3]) {
			Ok(PosNotificationMessage::PaymentProof(received)) => {
				assert!(received.parse().is_err())
			},
			result => panic!("unexpected result: {:?}", result),
		}
		assert!(read(65546, &[]).is_err());
	}
}
