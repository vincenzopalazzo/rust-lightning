// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Message handling for point-of-sale payment notifications.
//!
//! A merchant that claims a payment for a per-order offer constructed by a point-of-sale (PoS)
//! device sends a [`PaymentNotification`] over the offer's `notification_path`. The device
//! authenticates the notification by matching the relayed `order_id` against the one in the
//! path's message context and responds with a [`NotificationAck`] or a [`NotificationNack`].
//! Optionally, the customer's wallet may send a [`PaymentProof`] over the same path.
//!
//! See [bLIP 56](https://github.com/lightning/blips/pull/56) for more information.

use crate::blinded_path::message::PosNotificationContext;
use crate::io;
use crate::ln::msgs::DecodeError;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

use core::ops::Deref;

// TLV record types for the messages, provisional until assigned in the bLIP 56 specification.
const PAYMENT_NOTIFICATION_TLV_TYPE: u64 = 65560;
const NOTIFICATION_ACK_TLV_TYPE: u64 = 65562;
const NOTIFICATION_NACK_TLV_TYPE: u64 = 65564;
const PAYMENT_PROOF_TLV_TYPE: u64 = 65566;

/// A handler for [`PosNotificationMessage`]s.
pub trait PosNotificationMessageHandler {
	/// Handles a [`PaymentNotification`] from the merchant, returning a [`NotificationAck`] or
	/// [`NotificationNack`] wrapped in a [`PosNotificationMessage`] to send in response.
	///
	/// This is called on the point-of-sale device.
	fn handle_payment_notification(
		&self, message: PaymentNotification, context: PosNotificationContext,
		responder: Option<Responder>,
	) -> Option<(PosNotificationMessage, ResponseInstruction)>;

	/// Handles a [`NotificationAck`] from the point-of-sale device, confirming delivery of a
	/// previously sent [`PaymentNotification`].
	///
	/// This is called on the merchant node.
	fn handle_notification_ack(&self, message: NotificationAck, context: PosNotificationContext);

	/// Handles a [`NotificationNack`] from the point-of-sale device, indicating a previously sent
	/// [`PaymentNotification`] was rejected.
	///
	/// Since the payment was already claimed when the notification was sent, a nack should be
	/// reported to the node's operator for manual reconciliation rather than retried.
	///
	/// This is called on the merchant node.
	fn handle_notification_nack(&self, message: NotificationNack, context: PosNotificationContext);

	/// Handles a [`PaymentProof`] from the customer's wallet.
	///
	/// This is called on the point-of-sale device.
	fn handle_payment_proof(&self, message: PaymentProof, context: PosNotificationContext);

	/// Releases any [`PosNotificationMessage`]s that need to be sent.
	fn release_pending_messages(&self) -> Vec<(PosNotificationMessage, MessageSendInstructions)> {
		vec![]
	}
}

impl<T: PosNotificationMessageHandler + ?Sized, P: Deref<Target = T>> PosNotificationMessageHandler
	for P
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

/// Possible point-of-sale notification messages sent and received via an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone, Debug)]
pub enum PosNotificationMessage {
	/// A notification that a payment was claimed, sent by the merchant to the point-of-sale
	/// device.
	PaymentNotification(PaymentNotification),
	/// A positive acknowledgement of a [`PaymentNotification`], sent by the point-of-sale device
	/// to the merchant.
	NotificationAck(NotificationAck),
	/// A negative acknowledgement of a [`PaymentNotification`], sent by the point-of-sale device
	/// to the merchant.
	NotificationNack(NotificationNack),
	/// A proof of payment, sent by the customer's wallet to the point-of-sale device.
	PaymentProof(PaymentProof),
}

/// A notification that the merchant claimed a payment for a per-order offer, sent to the
/// point-of-sale device over the offer's `notification_path`.
///
/// The device must only trust the notification if [`Self::order_id`] matches the `order_id` in
/// the notification path's message context, since anyone holding the offer can send messages over
/// the path but only the merchant can recover the `order_id` from the offer's `payment_token`.
#[derive(Clone, Debug)]
pub struct PaymentNotification {
	/// The payment hash of the claimed payment, from the invoice the merchant issued.
	pub payment_hash: PaymentHash,
	/// The payment preimage released when claiming the payment.
	pub payment_preimage: PaymentPreimage,
	/// The amount claimed, in millisatoshis.
	pub amount_msats: u64,
	/// The per-order secret recovered from the offer's `payment_token`.
	pub order_id: Vec<u8>,
}

/// A positive acknowledgement of a [`PaymentNotification`], sent by the point-of-sale device once
/// the notification has been authenticated.
#[derive(Clone, Debug)]
pub struct NotificationAck {}

/// A negative acknowledgement of a [`PaymentNotification`], carrying the reason the notification
/// was rejected.
#[derive(Clone, Debug)]
pub struct NotificationNack {
	/// The reason the notification was rejected.
	pub reason: NackReason,
}

/// The reason a [`PaymentNotification`] was rejected with a [`NotificationNack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NackReason {
	/// No order state matching the notification was found.
	UnknownOrder,
	/// The order expired before the notification arrived.
	OrderExpired,
	/// The relayed `order_id` did not match the one in the notification path's message context,
	/// indicating a possible forgery or a corrupted `payment_token`.
	OrderIdMismatch,
	/// The notified amount was less than the order amount.
	AmountInsufficient,
	/// The notified preimage did not hash to the notified payment hash.
	InvalidPreimage,
	/// A reason code not known to this version of LDK.
	Unknown(u8),
}

impl NackReason {
	fn to_byte(&self) -> u8 {
		match self {
			Self::UnknownOrder => 0,
			Self::OrderExpired => 1,
			Self::OrderIdMismatch => 2,
			Self::AmountInsufficient => 3,
			Self::InvalidPreimage => 4,
			Self::Unknown(reason) => *reason,
		}
	}

	fn from_byte(byte: u8) -> Self {
		match byte {
			0 => Self::UnknownOrder,
			1 => Self::OrderExpired,
			2 => Self::OrderIdMismatch,
			3 => Self::AmountInsufficient,
			4 => Self::InvalidPreimage,
			reason => Self::Unknown(reason),
		}
	}
}

impl Writeable for NackReason {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.to_byte().write(w)
	}
}

impl Readable for NackReason {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self::from_byte(Readable::read(r)?))
	}
}

/// A proof of payment for a per-order offer, sent by the customer's wallet to the point-of-sale
/// device over the offer's `notification_path`.
#[derive(Clone, Debug)]
pub struct PaymentProof {
	/// A serialized BOLT 12 payer proof, as defined in
	/// [bolts#1295](https://github.com/lightning/bolts/pull/1295).
	///
	/// This is treated as opaque bytes; verifying it per the bolts#1295 reader requirements is the
	/// responsibility of the consumer.
	pub proof: Vec<u8>,
}

impl_ser_tlv_based!(PaymentNotification, {
	(0, payment_hash, required),
	(2, payment_preimage, required),
	(4, amount_msats, required),
	(6, order_id, required_vec),
});

impl_ser_tlv_based!(NotificationAck, {});

impl_ser_tlv_based!(NotificationNack, {
	(0, reason, required),
});

impl_ser_tlv_based!(PaymentProof, {
	(0, proof, required_vec),
});

impl PosNotificationMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for point-of-sale notification
	/// messages.
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
		match &self {
			Self::PaymentNotification(_) => "Payment Notification".to_string(),
			Self::NotificationAck(_) => "Notification Ack".to_string(),
			Self::NotificationNack(_) => "Notification Nack".to_string(),
			Self::PaymentProof(_) => "Payment Proof".to_string(),
		}
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match &self {
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
			Self::PaymentProof(message) => message.write(w),
		}
	}
}

impl ReadableArgs<u64> for PosNotificationMessage {
	fn read<R: io::Read>(r: &mut R, tlv_type: u64) -> Result<Self, DecodeError> {
		match tlv_type {
			PAYMENT_NOTIFICATION_TLV_TYPE => Ok(Self::PaymentNotification(Readable::read(r)?)),
			NOTIFICATION_ACK_TLV_TYPE => Ok(Self::NotificationAck(Readable::read(r)?)),
			NOTIFICATION_NACK_TLV_TYPE => Ok(Self::NotificationNack(Readable::read(r)?)),
			PAYMENT_PROOF_TLV_TYPE => Ok(Self::PaymentProof(Readable::read(r)?)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::io::Cursor;

	fn payment_notification() -> PaymentNotification {
		PaymentNotification {
			payment_hash: PaymentHash([1; 32]),
			payment_preimage: PaymentPreimage([2; 32]),
			amount_msats: 100_000,
			order_id: vec![3; 16],
		}
	}

	#[test]
	fn payment_notification_round_trips() {
		let message = PosNotificationMessage::PaymentNotification(payment_notification());
		let bytes = message.encode();
		let decoded =
			PosNotificationMessage::read(&mut Cursor::new(&bytes), PAYMENT_NOTIFICATION_TLV_TYPE)
				.unwrap();
		match decoded {
			PosNotificationMessage::PaymentNotification(decoded) => {
				assert_eq!(decoded.payment_hash, PaymentHash([1; 32]));
				assert_eq!(decoded.payment_preimage, PaymentPreimage([2; 32]));
				assert_eq!(decoded.amount_msats, 100_000);
				assert_eq!(decoded.order_id, vec![3; 16]);
			},
			_ => panic!("unexpected message"),
		}
	}

	#[test]
	fn notification_nack_reason_round_trips() {
		for reason in [
			NackReason::UnknownOrder,
			NackReason::OrderExpired,
			NackReason::OrderIdMismatch,
			NackReason::AmountInsufficient,
			NackReason::InvalidPreimage,
			NackReason::Unknown(57),
		] {
			let message = PosNotificationMessage::NotificationNack(NotificationNack { reason });
			let bytes = message.encode();
			let decoded =
				PosNotificationMessage::read(&mut Cursor::new(&bytes), NOTIFICATION_NACK_TLV_TYPE)
					.unwrap();
			match decoded {
				PosNotificationMessage::NotificationNack(decoded) => {
					assert_eq!(decoded.reason, reason);
				},
				_ => panic!("unexpected message"),
			}
		}
	}

	#[test]
	fn rejects_unknown_tlv_type() {
		let message = PosNotificationMessage::NotificationAck(NotificationAck {});
		let bytes = message.encode();
		assert!(PosNotificationMessage::read(&mut Cursor::new(&bytes), 65568).is_err());
	}

	#[test]
	fn known_types_match_constants() {
		assert!(PosNotificationMessage::is_known_type(PAYMENT_NOTIFICATION_TLV_TYPE));
		assert!(PosNotificationMessage::is_known_type(NOTIFICATION_ACK_TLV_TYPE));
		assert!(PosNotificationMessage::is_known_type(NOTIFICATION_NACK_TLV_TYPE));
		assert!(PosNotificationMessage::is_known_type(PAYMENT_PROOF_TLV_TYPE));
		assert!(!PosNotificationMessage::is_known_type(65568));
	}
}
