// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Messages for PoS payment notifications in delegated BOLT 12 offers.
//!
//! This module defines the onion message types used for communication between
//! merchants, PoS devices, and customers in a delegated offer flow.
//!
//! # Message Flow
//!
//! 1. **Customer → Merchant**: Customer pays the invoice
//! 2. **Merchant → PoS**: [`PaymentNotification`] sent via `notification_paths`
//! 3. **PoS → Merchant**: [`PaymentAck`] or [`PaymentNack`] in response
//!
//! # Example
//!
//! ```ignore
//! use lightning::onion_message::pos_notification::{PaymentNotification, PosNotificationMessage};
//!
//! // Merchant creates a payment notification
//! let notification = PaymentNotification {
//!     encrypted_payment_token: encrypted_token.clone(),
//!     offer_id: None,
//!     amount_msat: None,
//!     payment_hash: None,
//!     preimage: payment_preimage,
//! };
//!
//! // Wrap in the enum for sending
//! let message = PosNotificationMessage::PaymentNotification(notification);
//! ```

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::offers::offer::OfferId;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};
use core::ops::Deref;

// TLV record types for PoS notification messages (experimental range).
// Using 1_000_000_1xx range for PoS notification messages.
const PAYMENT_NOTIFICATION_TLV_TYPE: u64 = 1_000_000_100;
const PAYMENT_ACK_TLV_TYPE: u64 = 1_000_000_102;
const PAYMENT_NACK_TLV_TYPE: u64 = 1_000_000_104;

/// A handler for [`OnionMessage`]s containing PoS notification messages.
///
/// Implementations of this trait can be used to handle payment notifications
/// in a PoS delegation scenario.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
pub trait PosNotificationHandler {
	/// Handle a [`PaymentNotification`] message from a merchant indicating
	/// a payment was received.
	///
	/// The PoS should verify the payment token matches a known order and
	/// respond with either [`PaymentAck`] or [`PaymentNack`].
	fn handle_payment_notification(
		&self, message: PaymentNotification, responder: Option<Responder>,
	) -> Option<(PosNotificationMessage, ResponseInstruction)>;

	/// Handle a [`PaymentAck`] message from a PoS acknowledging the payment
	/// notification was received and recognized.
	fn handle_payment_ack(&self, message: PaymentAck);

	/// Handle a [`PaymentNack`] message from a PoS indicating the payment
	/// token was not recognized.
	fn handle_payment_nack(&self, message: PaymentNack);

	/// Release any [`PosNotificationMessage`]s that need to be sent.
	///
	/// Typically, this is used for initiating payment notifications after
	/// a payment is received.
	fn release_pending_messages(&self) -> Vec<(PosNotificationMessage, MessageSendInstructions)> {
		vec![]
	}
}

impl<T: PosNotificationHandler + ?Sized, R: Deref<Target = T>> PosNotificationHandler for R {
	fn handle_payment_notification(
		&self, message: PaymentNotification, responder: Option<Responder>,
	) -> Option<(PosNotificationMessage, ResponseInstruction)> {
		self.deref().handle_payment_notification(message, responder)
	}

	fn handle_payment_ack(&self, message: PaymentAck) {
		self.deref().handle_payment_ack(message)
	}

	fn handle_payment_nack(&self, message: PaymentNack) {
		self.deref().handle_payment_nack(message)
	}

	fn release_pending_messages(&self) -> Vec<(PosNotificationMessage, MessageSendInstructions)> {
		self.deref().release_pending_messages()
	}
}

/// Possible PoS notification messages sent and received via an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone, Debug)]
pub enum PosNotificationMessage {
	/// Payment received notification (Merchant → PoS).
	PaymentNotification(PaymentNotification),

	/// Positive acknowledgment (PoS → Merchant).
	PaymentAck(PaymentAck),

	/// Negative acknowledgment (PoS → Merchant).
	PaymentNack(PaymentNack),
}

/// A message from the Merchant to the PoS indicating a payment was received.
///
/// Sent via onion message using the `notification_paths` from the offer.
/// Upon receiving this message, the PoS should verify the payment token
/// matches a known order and update the order status accordingly. When available,
/// the merchant also includes enough invoice data for the PoS to verify the
/// payment against the original delegated offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentNotification {
	/// The encrypted payment token from the offer.
	///
	/// This is returned verbatim so the PoS can correlate the notification with
	/// the token it embedded in the delegated offer.
	pub encrypted_payment_token: Vec<u8>,

	/// The identifier of the delegated offer that was paid, if available.
	pub offer_id: Option<OfferId>,

	/// The amount that was ultimately paid for the delegated offer, if available.
	pub amount_msat: Option<u64>,

	/// The payment hash associated with the paid invoice, if available.
	pub payment_hash: Option<PaymentHash>,

	/// The payment preimage proving the payment was made.
	///
	/// This can be used by the PoS to verify the payment actually occurred
	/// and as proof of payment for record-keeping.
	pub preimage: PaymentPreimage,
}

/// Acknowledgment that the payment notification was recognized.
///
/// Sent from PoS to Merchant after receiving [`PaymentNotification`]
/// when the payment token matches a known order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAck {
	/// The encrypted payment token being acknowledged.
	///
	/// Echoed back so the merchant can correlate this ack with the
	/// original notification.
	pub encrypted_payment_token: Vec<u8>,
}

/// Negative acknowledgment - the payment token was not recognized.
///
/// Sent from PoS to Merchant if the token doesn't match any known order.
/// This could happen if:
/// - The order was already fulfilled
/// - The order was cancelled
/// - The PoS was restarted and lost state
/// - The token was corrupted
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentNack {
	/// The encrypted payment token that was not recognized.
	pub encrypted_payment_token: Vec<u8>,

	/// Optional human-readable reason for the rejection.
	pub reason: Option<String>,
}

impl PosNotificationMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for PoS notification messages.
	pub fn is_known_type(tlv_type: u64) -> bool {
		matches!(
			tlv_type,
			PAYMENT_NOTIFICATION_TLV_TYPE | PAYMENT_ACK_TLV_TYPE | PAYMENT_NACK_TLV_TYPE
		)
	}
}

impl OnionMessageContents for PosNotificationMessage {
	fn tlv_type(&self) -> u64 {
		match self {
			Self::PaymentNotification(_) => PAYMENT_NOTIFICATION_TLV_TYPE,
			Self::PaymentAck(_) => PAYMENT_ACK_TLV_TYPE,
			Self::PaymentNack(_) => PAYMENT_NACK_TLV_TYPE,
		}
	}

	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		match self {
			Self::PaymentNotification(_) => "Payment Notification".to_string(),
			Self::PaymentAck(_) => "Payment Ack".to_string(),
			Self::PaymentNack(_) => "Payment Nack".to_string(),
		}
	}

	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match self {
			Self::PaymentNotification(_) => "Payment Notification",
			Self::PaymentAck(_) => "Payment Ack",
			Self::PaymentNack(_) => "Payment Nack",
		}
	}
}

impl OnionMessageContents for PaymentNotification {
	fn tlv_type(&self) -> u64 {
		PAYMENT_NOTIFICATION_TLV_TYPE
	}

	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		"Payment Notification".to_string()
	}

	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		"Payment Notification"
	}
}

impl OnionMessageContents for PaymentAck {
	fn tlv_type(&self) -> u64 {
		PAYMENT_ACK_TLV_TYPE
	}

	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		"Payment Ack".to_string()
	}

	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		"Payment Ack"
	}
}

impl OnionMessageContents for PaymentNack {
	fn tlv_type(&self) -> u64 {
		PAYMENT_NACK_TLV_TYPE
	}

	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		"Payment Nack".to_string()
	}

	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		"Payment Nack"
	}
}

impl_writeable_tlv_based!(PaymentNotification, {
	(0, encrypted_payment_token, required_vec),
	(2, offer_id, option),
	(4, amount_msat, option),
	(6, payment_hash, option),
	(8, preimage, required),
});

impl_writeable_tlv_based!(PaymentAck, {
	(0, encrypted_payment_token, required_vec),
});

impl_writeable_tlv_based!(PaymentNack, {
	(0, encrypted_payment_token, required_vec),
	(2, reason, option),
});

impl Writeable for PosNotificationMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::PaymentNotification(message) => message.write(w),
			Self::PaymentAck(message) => message.write(w),
			Self::PaymentNack(message) => message.write(w),
		}
	}
}

impl ReadableArgs<u64> for PosNotificationMessage {
	fn read<R: io::Read>(r: &mut R, tlv_type: u64) -> Result<Self, DecodeError> {
		match tlv_type {
			PAYMENT_NOTIFICATION_TLV_TYPE => Ok(Self::PaymentNotification(Readable::read(r)?)),
			PAYMENT_ACK_TLV_TYPE => Ok(Self::PaymentAck(Readable::read(r)?)),
			PAYMENT_NACK_TLV_TYPE => Ok(Self::PaymentNack(Readable::read(r)?)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::util::ser::Writeable;

	fn test_roundtrip<T: Writeable + Readable + PartialEq + core::fmt::Debug>(msg: T) {
		let mut encoded = Vec::new();
		msg.write(&mut encoded).unwrap();

		let mut reader = io::Cursor::new(&encoded);
		let decoded: T = Readable::read(&mut reader).unwrap();

		assert_eq!(msg, decoded);
	}

	#[test]
	fn payment_notification_roundtrip() {
		let preimage = PaymentPreimage([42u8; 32]);
		let msg = PaymentNotification {
			encrypted_payment_token: vec![1, 2, 3, 4, 5],
			offer_id: Some(OfferId([1; 32])),
			amount_msat: Some(42_000),
			payment_hash: Some(PaymentHash([2; 32])),
			preimage,
		};
		test_roundtrip(msg);
	}

	#[test]
	fn payment_notification_empty_token() {
		let preimage = PaymentPreimage([0u8; 32]);
		let msg = PaymentNotification {
			encrypted_payment_token: vec![],
			offer_id: None,
			amount_msat: None,
			payment_hash: None,
			preimage,
		};
		test_roundtrip(msg);
	}

	#[test]
	fn payment_notification_large_token() {
		let preimage = PaymentPreimage([255u8; 32]);
		let msg = PaymentNotification {
			encrypted_payment_token: vec![0xAB; 1024],
			offer_id: Some(OfferId([3; 32])),
			amount_msat: Some(21_000_000),
			payment_hash: Some(PaymentHash([4; 32])),
			preimage,
		};
		test_roundtrip(msg);
	}

	#[test]
	fn payment_ack_roundtrip() {
		let msg = PaymentAck { encrypted_payment_token: vec![1, 2, 3, 4, 5] };
		test_roundtrip(msg);
	}

	#[test]
	fn payment_nack_roundtrip_with_reason() {
		let msg = PaymentNack {
			encrypted_payment_token: vec![1, 2, 3, 4, 5],
			reason: Some("Order not found".to_string()),
		};
		test_roundtrip(msg);
	}

	#[test]
	fn payment_nack_roundtrip_without_reason() {
		let msg = PaymentNack { encrypted_payment_token: vec![1, 2, 3, 4, 5], reason: None };
		test_roundtrip(msg);
	}

	#[test]
	fn pos_notification_message_enum_roundtrip() {
		let preimage = PaymentPreimage([42u8; 32]);

		// Test PaymentNotification variant
		let notification = PosNotificationMessage::PaymentNotification(PaymentNotification {
			encrypted_payment_token: vec![1, 2, 3],
			offer_id: Some(OfferId([5; 32])),
			amount_msat: Some(5_000),
			payment_hash: Some(PaymentHash([6; 32])),
			preimage,
		});
		let mut encoded = Vec::new();
		notification.write(&mut encoded).unwrap();
		let mut reader = io::Cursor::new(&encoded);
		let decoded =
			PosNotificationMessage::read(&mut reader, PAYMENT_NOTIFICATION_TLV_TYPE).unwrap();
		assert!(matches!(decoded, PosNotificationMessage::PaymentNotification(_)));

		// Test PaymentAck variant
		let ack =
			PosNotificationMessage::PaymentAck(PaymentAck { encrypted_payment_token: vec![4, 5] });
		let mut encoded = Vec::new();
		ack.write(&mut encoded).unwrap();
		let mut reader = io::Cursor::new(&encoded);
		let decoded = PosNotificationMessage::read(&mut reader, PAYMENT_ACK_TLV_TYPE).unwrap();
		assert!(matches!(decoded, PosNotificationMessage::PaymentAck(_)));

		// Test PaymentNack variant
		let nack = PosNotificationMessage::PaymentNack(PaymentNack {
			encrypted_payment_token: vec![6, 7],
			reason: Some("test".to_string()),
		});
		let mut encoded = Vec::new();
		nack.write(&mut encoded).unwrap();
		let mut reader = io::Cursor::new(&encoded);
		let decoded = PosNotificationMessage::read(&mut reader, PAYMENT_NACK_TLV_TYPE).unwrap();
		assert!(matches!(decoded, PosNotificationMessage::PaymentNack(_)));
	}

	#[test]
	fn is_known_type_returns_correct_values() {
		assert!(PosNotificationMessage::is_known_type(PAYMENT_NOTIFICATION_TLV_TYPE));
		assert!(PosNotificationMessage::is_known_type(PAYMENT_ACK_TLV_TYPE));
		assert!(PosNotificationMessage::is_known_type(PAYMENT_NACK_TLV_TYPE));
		assert!(!PosNotificationMessage::is_known_type(0));
		assert!(!PosNotificationMessage::is_known_type(1_000_000_000));
		assert!(!PosNotificationMessage::is_known_type(u64::MAX));
	}

	#[test]
	fn tlv_types_are_correct() {
		let preimage = PaymentPreimage([0u8; 32]);

		let notification = PosNotificationMessage::PaymentNotification(PaymentNotification {
			encrypted_payment_token: vec![],
			offer_id: None,
			amount_msat: None,
			payment_hash: None,
			preimage,
		});
		assert_eq!(notification.tlv_type(), PAYMENT_NOTIFICATION_TLV_TYPE);

		let ack =
			PosNotificationMessage::PaymentAck(PaymentAck { encrypted_payment_token: vec![] });
		assert_eq!(ack.tlv_type(), PAYMENT_ACK_TLV_TYPE);

		let nack = PosNotificationMessage::PaymentNack(PaymentNack {
			encrypted_payment_token: vec![],
			reason: None,
		});
		assert_eq!(nack.tlv_type(), PAYMENT_NACK_TLV_TYPE);
	}

	#[test]
	fn msg_type_returns_correct_strings() {
		let preimage = PaymentPreimage([0u8; 32]);

		let notification = PosNotificationMessage::PaymentNotification(PaymentNotification {
			encrypted_payment_token: vec![],
			offer_id: None,
			amount_msat: None,
			payment_hash: None,
			preimage,
		});
		assert_eq!(notification.msg_type(), "Payment Notification");

		let ack =
			PosNotificationMessage::PaymentAck(PaymentAck { encrypted_payment_token: vec![] });
		assert_eq!(ack.msg_type(), "Payment Ack");

		let nack = PosNotificationMessage::PaymentNack(PaymentNack {
			encrypted_payment_token: vec![],
			reason: None,
		});
		assert_eq!(nack.msg_type(), "Payment Nack");
	}

	#[test]
	fn invalid_tlv_type_returns_error() {
		let encoded = vec![0u8; 10];
		let mut reader = io::Cursor::new(&encoded);
		let result = PosNotificationMessage::read(&mut reader, 12345);
		assert!(result.is_err());
	}
}
