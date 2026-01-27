// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Message handling for PoS (Point of Sale) payment notifications.
//!
//! When a PoS device delegates payment to a merchant (by creating an offer with the merchant's
//! payment paths but including notification paths back to the PoS), the merchant needs to notify
//! the PoS when payment is received. This module provides the message types and handler trait
//! for this notification flow.

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::onion_message::messenger::MessageSendInstructions;
use crate::onion_message::packet::OnionMessageContents;
use crate::prelude::*;
use crate::types::payment::PaymentPreimage;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

// TLV record type for PaymentNotification in experimental range.
const PAYMENT_NOTIFICATION_TLV_TYPE: u64 = 1_000_000_100;

/// A handler for PoS payment notification messages.
///
/// PoS devices implement this to receive [`PaymentNotification`] messages from merchants
/// when payments are received for delegated offers.
pub trait PosNotificationHandler {
	/// Handle an incoming [`PaymentNotification`] message.
	///
	/// This is called on the PoS device when a merchant sends a notification that
	/// payment has been received for a delegated offer.
	fn handle_payment_notification(&self, message: PaymentNotification);

	/// Release any [`PosNotificationMessage`]s that need to be sent.
	///
	/// Typically used by merchants to send payment notifications to PoS devices
	/// after receiving payment for delegated offers.
	fn release_pending_messages(&self) -> Vec<(PosNotificationMessage, MessageSendInstructions)> {
		vec![]
	}
}

/// Possible PoS notification messages sent and received via an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PosNotificationMessage {
	/// Notification from a merchant to a PoS device that payment was received.
	PaymentNotification(PaymentNotification),
}

/// Notification sent from a merchant to a PoS device when payment is received.
///
/// When a PoS device creates an offer delegating payment to a merchant, it includes
/// [`notification_paths`] in the offer. After the merchant receives payment, it sends
/// this message through one of those blinded paths to notify the PoS.
///
/// [`notification_paths`]: crate::offers::offer::Offer::notification_paths
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentNotification {
	/// The payment preimage proving the payment was made.
	pub preimage: PaymentPreimage,
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

impl_writeable_tlv_based!(PaymentNotification, {
	(0, preimage, required),
});

impl PosNotificationMessage {
	/// Returns whether `tlv_type` corresponds to a TLV record for PoS notification messages.
	pub fn is_known_type(tlv_type: u64) -> bool {
		match tlv_type {
			PAYMENT_NOTIFICATION_TLV_TYPE => true,
			_ => false,
		}
	}
}

impl OnionMessageContents for PosNotificationMessage {
	fn tlv_type(&self) -> u64 {
		match self {
			Self::PaymentNotification(msg) => msg.tlv_type(),
		}
	}
	#[cfg(c_bindings)]
	fn msg_type(&self) -> String {
		match &self {
			Self::PaymentNotification(msg) => msg.msg_type(),
		}
	}
	#[cfg(not(c_bindings))]
	fn msg_type(&self) -> &'static str {
		match &self {
			Self::PaymentNotification(msg) => msg.msg_type(),
		}
	}
}

impl Writeable for PosNotificationMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::PaymentNotification(message) => message.write(w),
		}
	}
}

impl ReadableArgs<u64> for PosNotificationMessage {
	fn read<R: io::Read>(r: &mut R, tlv_type: u64) -> Result<Self, DecodeError> {
		match tlv_type {
			PAYMENT_NOTIFICATION_TLV_TYPE => Ok(Self::PaymentNotification(Readable::read(r)?)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}
