// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion message types and handler trait for BLIP-0056 PoS payment notifications.
//!
//! BLIP-0056 (BOLT 12 PoS notifications) lets a merchant inform a point-of-sale (PoS) device
//! that a customer's payment for a previously published offer has been claimed, without the PoS
//! ever holding funds or sitting on the payment path.
//!
//! This module defines:
//!
//! - [`PaymentNotification`] — sent merchant → PoS once `PaymentClaimable` is processed for a
//!   PoS-delegated offer. Carries the order hash, payment hash, amount, and a Schnorr signature
//!   produced via [`PaymentNotificationDigest::sign`].
//! - [`PaymentAck`] — sent PoS → merchant after the PoS has verified the notification's
//!   signature and recognised the order.
//! - [`PaymentNack`] — sent PoS → merchant when the notification cannot be matched to an
//!   active order, with an optional human-readable reason.
//! - [`PosNotificationMessage`] — enum wrapper used as the [`OnionMessageContents`] payload.
//! - [`PosNotificationHandler`] — trait an LDK consumer implements to receive notifications.
//!
//! The handler trait mirrors [`DNSResolverMessageHandler`] and
//! [`AsyncPaymentsMessageHandler`] so it can be wired into [`OnionMessenger`] as a sibling
//! handler in a follow-up patch in this stack.
//!
//! [`PaymentNotificationDigest::sign`]: crate::offers::payment_token::PaymentNotificationDigest::sign
//! [`DNSResolverMessageHandler`]: crate::onion_message::dns_resolution::DNSResolverMessageHandler
//! [`AsyncPaymentsMessageHandler`]: crate::onion_message::async_payments::AsyncPaymentsMessageHandler
//! [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
//! [`OnionMessageContents`]: crate::onion_message::packet::OnionMessageContents

use core::ops::Deref;

use bitcoin::secp256k1::schnorr::Signature;

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
use crate::types::payment::PaymentHash;
use crate::types::string::UntrustedString;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

/// Onion-message TLV type for [`PaymentNotification`].
///
/// Defined in BLIP-0056 (BOLT 12 PoS notifications). The type number is tentative pending BLIP
/// finalization.
pub const POS_PAYMENT_NOTIFICATION_TLV_TYPE: u64 = 1_000_000_100;

/// Onion-message TLV type for [`PaymentAck`].
pub const POS_PAYMENT_ACK_TLV_TYPE: u64 = 1_000_000_102;

/// Onion-message TLV type for [`PaymentNack`].
pub const POS_PAYMENT_NACK_TLV_TYPE: u64 = 1_000_000_104;

/// A merchant → PoS notification sent once the merchant has claimed a payment for an
/// `invoice_request` derived from a PoS-delegated offer.
///
/// The PoS authenticates the notification by reconstructing
/// [`PaymentNotificationDigest`](crate::offers::payment_token::PaymentNotificationDigest) from
/// the contained fields and verifying the signature against the merchant's offer issuer pubkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentNotification {
	/// 32-byte order hash matching the `payment_token` TLV embedded in the offer.
	pub order_hash: [u8; 32],
	/// Hash of the preimage of the claimed payment.
	pub payment_hash: PaymentHash,
	/// Amount in millisatoshi that was claimed.
	pub amount_msat: u64,
	/// Schnorr signature over the digest derived from `(order_hash, payment_hash, amount_msat)`,
	/// produced by the merchant's offer issuer key.
	pub signature: Signature,
}

/// PoS → merchant acknowledgement of a [`PaymentNotification`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAck {
	/// 32-byte order hash that the PoS recognised.
	pub order_hash: [u8; 32],
}

/// PoS → merchant rejection of a [`PaymentNotification`].
///
/// The PoS sends this when the notification cannot be matched to an active order (signature
/// invalid, order unknown, amount mismatch, etc). The optional `reason` is a free-form
/// debugging hint and must not be trusted by the merchant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentNack {
	/// 32-byte order hash from the rejected notification.
	pub order_hash: [u8; 32],
	/// Optional, untrusted human-readable reason.
	pub reason: Option<UntrustedString>,
}

/// Enum wrapper for the three BLIP-0056 PoS notification onion-message bodies.
///
/// This is the type that flows through [`OnionMessenger`] when handling the new message types.
///
/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PosNotificationMessage {
	/// Merchant → PoS notification of a claimed payment.
	PaymentNotification(PaymentNotification),
	/// PoS → merchant acknowledgement.
	PaymentAck(PaymentAck),
	/// PoS → merchant rejection.
	PaymentNack(PaymentNack),
}

impl PosNotificationMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record handled by this module.
	pub fn is_known_type(tlv_type: u64) -> bool {
		matches!(
			tlv_type,
			POS_PAYMENT_NOTIFICATION_TLV_TYPE
				| POS_PAYMENT_ACK_TLV_TYPE
				| POS_PAYMENT_NACK_TLV_TYPE
		)
	}
}

impl Writeable for PaymentNotification {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.order_hash.write(w)?;
		self.payment_hash.write(w)?;
		self.amount_msat.write(w)?;
		self.signature.as_ref().write(w)
	}
}

impl Readable for PaymentNotification {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let order_hash: [u8; 32] = Readable::read(r)?;
		let payment_hash = PaymentHash(Readable::read(r)?);
		let amount_msat: u64 = Readable::read(r)?;
		let signature_bytes: [u8; 64] = Readable::read(r)?;
		let signature =
			Signature::from_slice(&signature_bytes).map_err(|_| DecodeError::InvalidValue)?;
		Ok(Self { order_hash, payment_hash, amount_msat, signature })
	}
}

impl Writeable for PaymentAck {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.order_hash.write(w)
	}
}

impl Readable for PaymentAck {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		Ok(Self { order_hash: Readable::read(r)? })
	}
}

impl Writeable for PaymentNack {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.order_hash.write(w)?;
		match &self.reason {
			Some(reason) => {
				1u8.write(w)?;
				reason.0.as_bytes().to_vec().write(w)
			},
			None => 0u8.write(w),
		}
	}
}

impl Readable for PaymentNack {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let order_hash: [u8; 32] = Readable::read(r)?;
		let has_reason: u8 = Readable::read(r)?;
		let reason = match has_reason {
			0 => None,
			1 => {
				let bytes: Vec<u8> = Readable::read(r)?;
				let s = String::from_utf8(bytes).map_err(|_| DecodeError::InvalidValue)?;
				Some(UntrustedString(s))
			},
			_ => return Err(DecodeError::InvalidValue),
		};
		Ok(Self { order_hash, reason })
	}
}

impl Writeable for PosNotificationMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::PaymentNotification(m) => m.write(w),
			Self::PaymentAck(m) => m.write(w),
			Self::PaymentNack(m) => m.write(w),
		}
	}
}

impl ReadableArgs<u64> for PosNotificationMessage {
	fn read<R: io::Read>(r: &mut R, message_type: u64) -> Result<Self, DecodeError> {
		match message_type {
			POS_PAYMENT_NOTIFICATION_TLV_TYPE => {
				Ok(PosNotificationMessage::PaymentNotification(Readable::read(r)?))
			},
			POS_PAYMENT_ACK_TLV_TYPE => Ok(PosNotificationMessage::PaymentAck(Readable::read(r)?)),
			POS_PAYMENT_NACK_TLV_TYPE => {
				Ok(PosNotificationMessage::PaymentNack(Readable::read(r)?))
			},
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl OnionMessageContents for PosNotificationMessage {
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		match self {
			Self::PaymentNotification(_) => "PoS Payment Notification".to_string(),
			Self::PaymentAck(_) => "PoS Payment Ack".to_string(),
			Self::PaymentNack(_) => "PoS Payment Nack".to_string(),
		}
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match self {
			Self::PaymentNotification(_) => "PoS Payment Notification",
			Self::PaymentAck(_) => "PoS Payment Ack",
			Self::PaymentNack(_) => "PoS Payment Nack",
		}
	}
	fn tlv_type(&self) -> u64 {
		match self {
			Self::PaymentNotification(_) => POS_PAYMENT_NOTIFICATION_TLV_TYPE,
			Self::PaymentAck(_) => POS_PAYMENT_ACK_TLV_TYPE,
			Self::PaymentNack(_) => POS_PAYMENT_NACK_TLV_TYPE,
		}
	}
}

/// Handler for the BLIP-0056 PoS notification onion messages.
///
/// A PoS device implements this trait and registers it with [`OnionMessenger`] so the messenger
/// can dispatch [`PaymentNotification`]s and let the handler return a matching [`PaymentAck`]
/// or [`PaymentNack`]. A merchant implements the handler to receive the PoS responses.
///
/// [`OnionMessenger`]: crate::onion_message::messenger::OnionMessenger
pub trait PosNotificationHandler {
	/// Handle a [`PaymentNotification`].
	///
	/// The implementation should verify the signature against the merchant's offer issuer pubkey
	/// (which the PoS already knows from the template offer) and look up the order by
	/// `order_hash`. The returned tuple, if any, is sent as the response over the same blinded
	/// path the notification arrived on.
	fn handle_payment_notification(
		&self, message: PaymentNotification, responder: Option<Responder>,
	) -> Option<(PosNotificationMessage, ResponseInstruction)>;

	/// Handle a [`PaymentAck`] for a notification this handler previously dispatched.
	fn handle_payment_ack(&self, message: PaymentAck);

	/// Handle a [`PaymentNack`] for a notification this handler previously dispatched.
	fn handle_payment_nack(&self, message: PaymentNack);

	/// Release any [`PosNotificationMessage`]s that have been queued for sending.
	fn release_pending_messages(&self) -> Vec<(PosNotificationMessage, MessageSendInstructions)> {
		vec![]
	}
}

impl<T: PosNotificationHandler + ?Sized, D: Deref<Target = T>> PosNotificationHandler for D {
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

#[cfg(test)]
mod tests {
	use super::*;

	use crate::util::ser::Writeable;

	fn dummy_signature() -> Signature {
		// 64 bytes that form a valid Schnorr signature shape (the cryptographic validity is
		// not exercised in serialization tests; we only need the bytes to round-trip).
		let bytes = [7u8; 64];
		Signature::from_slice(&bytes)
			.expect("64 zero-and-non-zero bytes are a valid Schnorr scalar shape")
	}

	#[test]
	fn payment_notification_round_trips() {
		let original = PaymentNotification {
			order_hash: [42u8; 32],
			payment_hash: PaymentHash([1u8; 32]),
			amount_msat: 20_000,
			signature: dummy_signature(),
		};
		let mut buffer = Vec::new();
		original.write(&mut buffer).unwrap();
		let parsed: PaymentNotification = Readable::read(&mut buffer.as_slice()).unwrap();
		assert_eq!(parsed, original);
	}

	#[test]
	fn payment_ack_round_trips() {
		let original = PaymentAck { order_hash: [9u8; 32] };
		let mut buffer = Vec::new();
		original.write(&mut buffer).unwrap();
		let parsed: PaymentAck = Readable::read(&mut buffer.as_slice()).unwrap();
		assert_eq!(parsed, original);
	}

	#[test]
	fn payment_nack_round_trips_with_reason() {
		let original = PaymentNack {
			order_hash: [3u8; 32],
			reason: Some(UntrustedString("amount mismatch".to_string())),
		};
		let mut buffer = Vec::new();
		original.write(&mut buffer).unwrap();
		let parsed: PaymentNack = Readable::read(&mut buffer.as_slice()).unwrap();
		assert_eq!(parsed, original);
	}

	#[test]
	fn payment_nack_round_trips_without_reason() {
		let original = PaymentNack { order_hash: [3u8; 32], reason: None };
		let mut buffer = Vec::new();
		original.write(&mut buffer).unwrap();
		let parsed: PaymentNack = Readable::read(&mut buffer.as_slice()).unwrap();
		assert_eq!(parsed, original);
	}

	#[test]
	fn message_dispatches_via_known_type() {
		assert!(PosNotificationMessage::is_known_type(POS_PAYMENT_NOTIFICATION_TLV_TYPE));
		assert!(PosNotificationMessage::is_known_type(POS_PAYMENT_ACK_TLV_TYPE));
		assert!(PosNotificationMessage::is_known_type(POS_PAYMENT_NACK_TLV_TYPE));
		assert!(!PosNotificationMessage::is_known_type(POS_PAYMENT_NOTIFICATION_TLV_TYPE - 1));
	}

	#[test]
	fn enum_dispatch_preserves_tlv_type() {
		let n = PosNotificationMessage::PaymentNotification(PaymentNotification {
			order_hash: [0u8; 32],
			payment_hash: PaymentHash([0u8; 32]),
			amount_msat: 0,
			signature: dummy_signature(),
		});
		assert_eq!(n.tlv_type(), POS_PAYMENT_NOTIFICATION_TLV_TYPE);

		let a = PosNotificationMessage::PaymentAck(PaymentAck { order_hash: [0u8; 32] });
		assert_eq!(a.tlv_type(), POS_PAYMENT_ACK_TLV_TYPE);

		let nack = PosNotificationMessage::PaymentNack(PaymentNack {
			order_hash: [0u8; 32],
			reason: None,
		});
		assert_eq!(nack.tlv_type(), POS_PAYMENT_NACK_TLV_TYPE);
	}
}
