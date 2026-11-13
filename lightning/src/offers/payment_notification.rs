// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The signed `payment_notification` of [bLIP 56].
//!
//! Once a payment for a point-of-sale per-order offer settles, the merchant tells the
//! point-of-sale device over the offer's `notification_path`. The notification is a TLV stream
//! signed the way BOLT 12 signs its own messages: a BIP 340 signature over a tagged hash of the
//! merkle root of every non-signature record, made with the key of the `offer_issuer_id` the
//! order's offer named.
//!
//! The signature says who sent the notification; `payment_token_hash` says which order it is for.
//! Neither is enough on its own, and neither says the payment happened: the merchant chooses the
//! payment hash and preimage it signs. Checking a notification against an order is left to the
//! point-of-sale device.
//!
//! [bLIP 56]: https://github.com/jkczyz/blips/blob/claude/spec-blocking-findings-ca4402/blip-0056.md

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, Keypair, PublicKey, Secp256k1};

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::offers::merkle::{
	self, SignError, SignFn, SignatureTlvStream, SignatureTlvStreamRef, TaggedHash, TlvStream,
	SIGNATURE_TYPES,
};
use crate::offers::parse::ParsedMessage;
use crate::prelude::*;
use crate::sign::EntropySource;
use crate::types::payment::{PaymentHash, PaymentPreimage};
use crate::util::ser::{
	CursorReadable, HighZeroBytesDroppedBigSize, LengthLimitedRead, LengthReadable, WithoutLength,
	Writeable, Writer,
};

/// The tag of the tagged hash a [`PaymentNotification`] signature is computed over.
pub const SIGNATURE_TAG: &'static str = concat!("lightning", "payment_notification", "signature");

/// The length of the `notification_metadata` [`UnsignedPaymentNotification::new`] generates.
const NOTIFICATION_METADATA_LEN: usize = 32;

/// Valid type range for the non-signature records defined for a `payment_notification`.
const PAYMENT_NOTIFICATION_TYPES: core::ops::Range<u64> = 0..240;

/// Type range for records above the signature range, none of which are defined yet.
const EXPERIMENTAL_PAYMENT_NOTIFICATION_TYPES: core::ops::Range<u64> = 1001..u64::MAX;

tlv_stream!(PaymentNotificationTlvStream, PaymentNotificationTlvStreamRef<'a>, PAYMENT_NOTIFICATION_TYPES, {
	(0, notification_metadata: (Vec<u8>, WithoutLength)),
	(2, payment_token_hash: Sha256),
	(4, payment_hash: PaymentHash),
	(6, preimage: PaymentPreimage),
	(8, amount_msats: (u64, HighZeroBytesDroppedBigSize)),
});

tlv_stream!(
	ExperimentalPaymentNotificationTlvStream,
	ExperimentalPaymentNotificationTlvStreamRef,
	EXPERIMENTAL_PAYMENT_NOTIFICATION_TYPES,
	{}
);

type FullPaymentNotificationTlvStream =
	(PaymentNotificationTlvStream, SignatureTlvStream, ExperimentalPaymentNotificationTlvStream);

impl CursorReadable for FullPaymentNotificationTlvStream {
	fn read<R: AsRef<[u8]>>(r: &mut io::Cursor<R>) -> Result<Self, DecodeError> {
		let notification = CursorReadable::read(r)?;
		let signature = CursorReadable::read(r)?;
		let experimental = CursorReadable::read(r)?;
		Ok((notification, signature, experimental))
	}
}

/// The contents of a `payment_notification`, shared by the signed and unsigned forms.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PaymentNotificationContents {
	notification_metadata: Vec<u8>,
	payment_token_hash: Sha256,
	payment_hash: PaymentHash,
	preimage: PaymentPreimage,
	amount_msats: u64,
}

impl PaymentNotificationContents {
	fn as_tlv_stream(&self) -> PaymentNotificationTlvStreamRef<'_> {
		PaymentNotificationTlvStreamRef {
			notification_metadata: Some(&self.notification_metadata),
			payment_token_hash: Some(&self.payment_token_hash),
			payment_hash: Some(&self.payment_hash),
			preimage: Some(&self.preimage),
			amount_msats: Some(self.amount_msats),
		}
	}
}

macro_rules! payment_notification_accessors { ($self: ident, $contents: expr) => {
	/// An unpredictable value, fresh per notification. It is the first record of the stream, which
	/// is what keeps the nonce leaves of the signature's merkle tree unguessable.
	pub fn notification_metadata(&$self) -> &[u8] {
		&$contents.notification_metadata
	}

	/// The SHA256 of the `payment_token` the paid invoice request carried, which identifies the
	/// order the notification is for.
	pub fn payment_token_hash(&$self) -> Sha256 {
		$contents.payment_token_hash
	}

	/// The payment hash of the settled payment.
	pub fn payment_hash(&$self) -> PaymentHash {
		$contents.payment_hash
	}

	/// The preimage of the settled payment.
	pub fn preimage(&$self) -> PaymentPreimage {
		$contents.preimage
	}

	/// The amount the merchant claimed, in millisatoshis.
	pub fn amount_msats(&$self) -> u64 {
		$contents.amount_msats
	}
} }

/// A `payment_notification` that has not been signed yet.
#[derive(Clone, Debug)]
pub struct UnsignedPaymentNotification {
	bytes: Vec<u8>,
	contents: PaymentNotificationContents,
	tagged_hash: TaggedHash,
}

impl UnsignedPaymentNotification {
	/// Creates a notification for a settled payment, with a fresh `notification_metadata` drawn
	/// from `entropy_source`.
	///
	/// `payment_token_hash` must be the SHA256 of the `payment_token` value as it appeared in the
	/// invoice request that was paid, and `amount_msats` the amount actually claimed rather than
	/// the amount invoiced.
	pub fn new<ES: EntropySource>(
		entropy_source: ES, payment_token_hash: Sha256, payment_hash: PaymentHash,
		preimage: PaymentPreimage, amount_msats: u64,
	) -> Self {
		let notification_metadata =
			entropy_source.get_secure_random_bytes()[..NOTIFICATION_METADATA_LEN].to_vec();
		let contents = PaymentNotificationContents {
			notification_metadata,
			payment_token_hash,
			payment_hash,
			preimage,
			amount_msats,
		};
		let bytes = contents.as_tlv_stream().encode();
		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);
		Self { bytes, contents, tagged_hash }
	}

	payment_notification_accessors!(self, self.contents);

	/// The tagged hash to sign.
	pub fn tagged_hash(&self) -> &TaggedHash {
		&self.tagged_hash
	}

	/// Signs the notification using `sign`, checking that the signature verifies against
	/// `offer_issuer_id`.
	pub fn sign<F: SignPaymentNotificationFn>(
		mut self, sign: F, offer_issuer_id: PublicKey,
	) -> Result<PaymentNotification, SignError> {
		let signature = merkle::sign_message(sign, &self, offer_issuer_id)?;

		let signature_tlv_stream = SignatureTlvStreamRef { signature: Some(&signature) };
		signature_tlv_stream.write(&mut self.bytes).expect("writing to a Vec never fails");

		Ok(PaymentNotification {
			bytes: self.bytes,
			contents: self.contents,
			signature,
			tagged_hash: self.tagged_hash,
		})
	}

	/// Signs the notification with `keys`, the key pair of the `offer_issuer_id` the paid offer
	/// named.
	pub fn sign_with_keys<T: secp256k1::Signing>(
		self, keys: &Keypair, secp_ctx: &Secp256k1<T>,
	) -> PaymentNotification {
		let sign = |message: &UnsignedPaymentNotification| {
			Ok(secp_ctx.sign_schnorr_no_aux_rand(message.tagged_hash.as_digest(), keys))
		};
		self.sign(sign, keys.public_key())
			.expect("a signature made with keys verifies against them")
	}
}

impl AsRef<TaggedHash> for UnsignedPaymentNotification {
	fn as_ref(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

/// A function for signing an [`UnsignedPaymentNotification`].
pub trait SignPaymentNotificationFn {
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	fn sign_payment_notification(
		&self, message: &UnsignedPaymentNotification,
	) -> Result<Signature, ()>;
}

impl<F> SignPaymentNotificationFn for F
where
	F: Fn(&UnsignedPaymentNotification) -> Result<Signature, ()>,
{
	fn sign_payment_notification(
		&self, message: &UnsignedPaymentNotification,
	) -> Result<Signature, ()> {
		self(message)
	}
}

impl<F> SignFn<UnsignedPaymentNotification> for F
where
	F: SignPaymentNotificationFn,
{
	fn sign(&self, message: &UnsignedPaymentNotification) -> Result<Signature, ()> {
		self.sign_payment_notification(message)
	}
}

/// A signed `payment_notification`, as sent by a merchant to a point-of-sale device.
///
/// Parsing checks the encoding only. The signature is checked by [`Self::verify`] against the key
/// the order's offer named, which the recipient takes from its own record of the order, never
/// from the notification.
#[derive(Clone, Debug)]
pub struct PaymentNotification {
	bytes: Vec<u8>,
	contents: PaymentNotificationContents,
	signature: Signature,
	tagged_hash: TaggedHash,
}

impl PaymentNotification {
	payment_notification_accessors!(self, self.contents);

	/// The BIP 340 signature over the notification.
	pub fn signature(&self) -> Signature {
		self.signature
	}

	/// The tagged hash the signature is over.
	pub fn tagged_hash(&self) -> &TaggedHash {
		&self.tagged_hash
	}

	/// The serialized notification, including any records this implementation does not understand.
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Checks the signature against `offer_issuer_id`.
	pub fn verify(&self, offer_issuer_id: PublicKey) -> Result<(), secp256k1::Error> {
		merkle::verify_signature(&self.signature, &self.tagged_hash, offer_issuer_id)
	}
}

impl PartialEq for PaymentNotification {
	fn eq(&self, other: &Self) -> bool {
		self.bytes == other.bytes
	}
}

impl Eq for PaymentNotification {}

impl Writeable for PaymentNotification {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl LengthReadable for PaymentNotification {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let bytes: WithoutLength<Vec<u8>> = LengthReadable::read_from_fixed_length_buffer(r)?;
		Self::try_from(bytes.0)
	}
}

impl TryFrom<Vec<u8>> for PaymentNotification {
	type Error = DecodeError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let ParsedMessage { bytes, tlv_stream } =
			ParsedMessage::<FullPaymentNotificationTlvStream>::try_from(bytes)?;
		let (
			PaymentNotificationTlvStream {
				notification_metadata,
				payment_token_hash,
				payment_hash,
				preimage,
				amount_msats,
			},
			SignatureTlvStream { signature },
			ExperimentalPaymentNotificationTlvStream {},
		) = tlv_stream;

		// The signature must be the only record in the signature range, since the others would
		// be left out of the merkle root.
		if TlvStream::new(&bytes).filter(|r| SIGNATURE_TYPES.contains(&r.r#type)).count() != 1 {
			return Err(DecodeError::InvalidValue);
		}

		let contents =
			match (notification_metadata, payment_token_hash, payment_hash, preimage, amount_msats)
			{
				(
					Some(notification_metadata),
					Some(payment_token_hash),
					Some(payment_hash),
					Some(preimage),
					Some(amount_msats),
				) => PaymentNotificationContents {
					notification_metadata,
					payment_token_hash,
					payment_hash,
					preimage,
					amount_msats,
				},
				_ => return Err(DecodeError::InvalidValue),
			};
		let signature = signature.ok_or(DecodeError::InvalidValue)?;
		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);

		Ok(PaymentNotification { bytes, contents, signature, tagged_hash })
	}
}

#[cfg(test)]
mod tests {
	use super::{PaymentNotification, UnsignedPaymentNotification, SIGNATURE_TAG};

	use crate::ln::msgs::DecodeError;
	use crate::offers::merkle::{SignError, TaggedHash};
	use crate::prelude::*;
	use crate::sign::EntropySource;
	use crate::types::payment::{PaymentHash, PaymentPreimage};
	use crate::util::ser::{BigSize, Writeable};

	use bitcoin::hashes::sha256::Hash as Sha256;
	use bitcoin::hashes::Hash;
	use bitcoin::hex::DisplayHex;
	use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

	struct FixedEntropy;

	impl EntropySource for FixedEntropy {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			[0x31; 32]
		}
	}

	fn issuer_keys() -> Keypair {
		let secp_ctx = Secp256k1::new();
		Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	fn unsigned() -> UnsignedPaymentNotification {
		let preimage = PaymentPreimage([0x44; 32]);
		UnsignedPaymentNotification::new(
			FixedEntropy,
			Sha256::from_byte_array([0x22; 32]),
			preimage.into(),
			preimage,
			50_000,
		)
	}

	fn signed() -> PaymentNotification {
		unsigned().sign_with_keys(&issuer_keys(), &Secp256k1::new())
	}

	fn write_record(bytes: &mut Vec<u8>, r#type: u64, value: &[u8]) {
		BigSize(r#type).write(bytes).unwrap();
		BigSize(value.len() as u64).write(bytes).unwrap();
		bytes.extend_from_slice(value);
	}

	/// Encodes `records` (type, value) as a notification signed with the issuer key over every
	/// record, placing the signature after the records below the signature range.
	fn sign_records(records: &[(u64, Vec<u8>)]) -> Vec<u8> {
		let mut unsigned = Vec::new();
		for (r#type, value) in records {
			write_record(&mut unsigned, *r#type, value);
		}
		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned);
		let signature =
			Secp256k1::new().sign_schnorr_no_aux_rand(tagged_hash.as_digest(), &issuer_keys());

		let mut signed = Vec::new();
		for (r#type, value) in records.iter().filter(|(t, _)| *t < 240) {
			write_record(&mut signed, *r#type, value);
		}
		write_record(&mut signed, 240, signature.as_ref());
		for (r#type, value) in records.iter().filter(|(t, _)| *t >= 240) {
			write_record(&mut signed, *r#type, value);
		}
		signed
	}

	fn base_records() -> Vec<(u64, Vec<u8>)> {
		vec![
			(0, vec![0x31; 32]),
			(2, vec![0x22; 32]),
			(4, PaymentHash::from(PaymentPreimage([0x44; 32])).0.to_vec()),
			(6, vec![0x44; 32]),
			(8, vec![0xc3, 0x50]),
		]
	}

	#[test]
	fn signs_and_verifies_notification() {
		let notification = signed();
		assert!(notification.verify(issuer_keys().public_key()).is_ok());
		assert_eq!(notification.notification_metadata(), &[0x31; 32]);
		assert_eq!(notification.payment_token_hash(), Sha256::from_byte_array([0x22; 32]));
		assert_eq!(notification.preimage(), PaymentPreimage([0x44; 32]));
		assert_eq!(notification.payment_hash(), PaymentPreimage([0x44; 32]).into());
		assert_eq!(notification.amount_msats(), 50_000);

		let other_keys =
			Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[43; 32]).unwrap());
		assert!(notification.verify(other_keys.public_key()).is_err());
	}

	#[test]
	fn parses_signed_notification() {
		let notification = signed();
		let parsed = PaymentNotification::try_from(notification.bytes().to_vec()).unwrap();
		assert_eq!(parsed, notification);
		assert_eq!(parsed.signature(), notification.signature());
		assert!(parsed.verify(issuer_keys().public_key()).is_ok());
		assert_eq!(notification.encode(), notification.bytes());
	}

	#[test]
	fn fails_signing_with_mismatched_key() {
		let secp_ctx = Secp256k1::new();
		let other_keys =
			Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[43; 32]).unwrap());
		let sign = |message: &UnsignedPaymentNotification| {
			Ok(secp_ctx.sign_schnorr_no_aux_rand(message.tagged_hash().as_digest(), &other_keys))
		};
		match unsigned().sign(sign, issuer_keys().public_key()) {
			Err(SignError::Verification(_)) => {},
			result => panic!("expected verification error: {:?}", result),
		}
	}

	#[test]
	fn verifies_notification_with_unknown_odd_records() {
		// Unknown odd records are kept and covered by the signature, both below and above the
		// signature range.
		for extra in [9u64, 1001] {
			let mut records = base_records();
			records.push((extra, vec![1, 2, 3]));
			let bytes = sign_records(&records);
			let parsed = PaymentNotification::try_from(bytes.clone()).unwrap();
			assert_eq!(parsed.bytes(), &bytes[..]);
			assert!(parsed.verify(issuer_keys().public_key()).is_ok());

			// Dropping the unknown record while keeping the signature breaks it.
			let mut record = Vec::new();
			write_record(&mut record, extra, &[1, 2, 3]);
			let position = bytes.windows(record.len()).position(|w| w == &record[..]).unwrap();
			let mut stripped = bytes.clone();
			stripped.drain(position..position + record.len());
			let stripped = PaymentNotification::try_from(stripped).unwrap();
			assert!(stripped.verify(issuer_keys().public_key()).is_err());
		}
	}

	#[test]
	fn fails_parsing_malformed_notification() {
		// Each required record missing.
		for missing in [0u64, 2, 4, 6, 8] {
			let records: Vec<_> =
				base_records().into_iter().filter(|(t, _)| *t != missing).collect();
			assert_eq!(
				PaymentNotification::try_from(sign_records(&records)),
				Err(DecodeError::InvalidValue),
			);
		}

		// Missing signature.
		let mut bytes = Vec::new();
		for (r#type, value) in base_records() {
			write_record(&mut bytes, r#type, &value);
		}
		assert_eq!(PaymentNotification::try_from(bytes), Err(DecodeError::InvalidValue));

		// Unknown even record.
		for extra in [10u64, 1002] {
			let mut records = base_records();
			records.push((extra, vec![1]));
			assert_eq!(
				PaymentNotification::try_from(sign_records(&records)),
				Err(DecodeError::UnknownRequiredFeature),
			);
		}

		// A second record in the signature range.
		let mut bytes = sign_records(&base_records());
		write_record(&mut bytes, 241, &[1]);
		assert_eq!(PaymentNotification::try_from(bytes), Err(DecodeError::InvalidValue));

		// Records out of order.
		let mut records = base_records();
		records.swap(1, 2);
		assert!(PaymentNotification::try_from(sign_records(&records)).is_err());

		// A non-minimal amount.
		let mut records = base_records();
		records[4].1 = vec![0x00, 0xc3, 0x50];
		assert!(PaymentNotification::try_from(sign_records(&records)).is_err());
	}

	/// A test vector for the signature, with every input fixed.
	#[test]
	fn payment_notification_test_vector() {
		// Reproduced, signature included, by an independent implementation of the BOLT 12 merkle
		// construction and BIP 340.
		let notification = signed();
		assert_eq!(
			notification.tagged_hash().merkle_root().as_byte_array().as_hex().to_string(),
			"20c90adceb59ccce2ac413989b9053e9b477e94313a9ce691fdf0ca229cf60b2",
		);
		assert_eq!(
			notification.tagged_hash().as_digest().as_ref().as_hex().to_string(),
			"46669ea18f43fc4bb9b02caddf78cf4e9241e3d39a7f0c745b42b43df72be6a2",
		);
		assert_eq!(
			notification.bytes().as_hex().to_string(),
			"0020313131313131313131313131313131313131313131313131313131313131313102202222222222222222\
			2222222222222222222222222222222222222222222222220420bb391415c05e39d77ca17381d3be3f7d0cd5\
			e5332e5a579311adaa0aa62106e9062044444444444444444444444444444444444444444444444444444444\
			444444440802c350f040da11e15a51e05166a2447ecc8bb6b4190832f17e158cbef99994fae3a3f775ba9978\
			e87c5bfcc290088a49b57a0a264cbae653ad4014f2f75a7fe5533b6e03db",
		);
	}
}
