//! Funding output for a Phoenix simple-taproot purchase.
//!
//! The LSP expects a BIP341 key-path spend of the MuSig2 aggregate of the two
//! funding keys, not a 2-of-2 p2wsh. Key aggregation follows BIP 327: the keys
//! are sorted, the second distinct key has coefficient 1, and the other is
//! multiplied by `SHA256(SHA256("KeyAgg coefficient") || SHA256("KeyAgg coefficient") || L || pk)`.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::script::ScriptBuf;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};

use crate::sign::EntropySource;

const CURVE_ORDER: [u8; 32] = [
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

fn tagged_sha256(tag: &str, msg: &[u8]) -> [u8; 32] {
	let tag_hash = sha256::Hash::hash(tag.as_bytes());
	let mut engine = sha256::Hash::engine();
	engine.input(tag_hash.as_ref());
	engine.input(tag_hash.as_ref());
	engine.input(msg);
	sha256::Hash::from_engine(engine).to_byte_array()
}

fn scalar_mod_order(bytes: [u8; 32]) -> Scalar {
	if let Ok(scalar) = Scalar::from_be_bytes(bytes) {
		return scalar;
	}
	let mut reduced = [0u8; 32];
	let mut borrow = 0i16;
	for index in (0..32).rev() {
		let value = bytes[index] as i16 - CURVE_ORDER[index] as i16 - borrow;
		if value < 0 {
			reduced[index] = (value + 256) as u8;
			borrow = 1;
		} else {
			reduced[index] = value as u8;
			borrow = 0;
		}
	}
	Scalar::from_be_bytes(reduced).expect("hash minus the curve order is in range")
}

/// X-only MuSig2 aggregate of two funding keys, in the order BIP 327 uses
/// after lexicographic sort of the compressed keys.
pub(super) fn aggregate_funding_keys(
	secp: &Secp256k1<secp256k1::All>, local: &PublicKey, remote: &PublicKey,
) -> bitcoin::secp256k1::XOnlyPublicKey {
	let mut keys = [local.serialize(), remote.serialize()];
	keys.sort();
	let mut list = Vec::with_capacity(66);
	list.extend_from_slice(&keys[0]);
	list.extend_from_slice(&keys[1]);
	let key_list_hash = tagged_sha256("KeyAgg list", &list);
	// The second distinct key. Two identical keys fall back to 33 zero bytes,
	// which neither real funding key equals, so both would be hashed.
	let second = if keys[0] != keys[1] { keys[1] } else { [0u8; 33] };

	let mut aggregated: Option<PublicKey> = None;
	for key_bytes in keys {
		let point = PublicKey::from_slice(&key_bytes).expect("compressed funding key");
		let scaled = if key_bytes == second {
			point
		} else {
			let mut coeff_input = Vec::with_capacity(65);
			coeff_input.extend_from_slice(&key_list_hash);
			coeff_input.extend_from_slice(&key_bytes);
			let coefficient = scalar_mod_order(tagged_sha256("KeyAgg coefficient", &coeff_input));
			point.mul_tweak(secp, &coefficient).expect("key aggregation coefficient")
		};
		aggregated = Some(match aggregated {
			None => scaled,
			Some(so_far) => so_far.combine(&scaled).expect("funding key aggregate"),
		});
	}
	aggregated.expect("two funding keys").x_only_public_key().0
}

/// P2TR funding script the Phoenix LSP puts on a simple-taproot channel.
pub(super) fn funding_script(
	secp: &Secp256k1<secp256k1::All>, local: &PublicKey, remote: &PublicKey,
) -> ScriptBuf {
	ScriptBuf::new_p2tr(secp, aggregate_funding_keys(secp, local, remote), None)
}

/// Two 66-byte MuSig2 nonces (each two compressed points) for `tx_complete` TLV 4.
pub(super) fn commit_nonces<ES: EntropySource>(
	secp: &Secp256k1<secp256k1::All>, entropy: &ES,
) -> Vec<u8> {
	let mut nonces = Vec::with_capacity(132);
	for _ in 0..4 {
		loop {
			let bytes = entropy.get_secure_random_bytes();
			if let Ok(secret) = SecretKey::from_slice(&bytes) {
				nonces.extend_from_slice(&PublicKey::from_secret_key(secp, &secret).serialize());
				break;
			}
		}
	}
	nonces
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::secp256k1::Secp256k1;

	#[test]
	fn aggregate_is_deterministic_and_order_independent() {
		let secp = Secp256k1::new();
		let first = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
		let second = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
		let left = aggregate_funding_keys(&secp, &first, &second);
		let right = aggregate_funding_keys(&secp, &second, &first);
		assert_eq!(left, right);
		let script = funding_script(&secp, &first, &second);
		assert_eq!(script.as_bytes().len(), 34);
		assert_eq!(script.as_bytes()[0], 0x51);
		assert_eq!(script.as_bytes()[1], 0x20);
	}
}
