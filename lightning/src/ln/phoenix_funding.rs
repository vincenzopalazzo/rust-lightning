//! Funding output for a Phoenix simple-taproot purchase.
//!
//! The LSP expects a BIP341 key-path spend of the MuSig2 aggregate of the two
//! funding keys, not a 2-of-2 p2wsh. Key aggregation follows BIP 327: the keys
//! are sorted, the second distinct key has coefficient 1, and the other is
//! multiplied by `SHA256(SHA256("KeyAgg coefficient") || SHA256("KeyAgg coefficient") || L || pk)`.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP};
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{self, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::{Transaction, TxIn, TxOut};
use bitcoin::{Amount, OutPoint, Sequence, Witness};

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

/// Full aggregate point, before the x-only conversion. The y parity decides
/// the BIP 327 negation inside the taproot tweak.
fn aggregate_point(
	secp: &Secp256k1<secp256k1::All>, local: &PublicKey, remote: &PublicKey,
) -> PublicKey {
	let mut keys = [local.serialize(), remote.serialize()];
	keys.sort();
	let mut list = Vec::with_capacity(66);
	list.extend_from_slice(&keys[0]);
	list.extend_from_slice(&keys[1]);
	let key_list_hash = tagged_sha256("KeyAgg list", &list);
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
	aggregated.expect("two funding keys")
}

fn key_agg_coeff(local: &PublicKey, remote: &PublicKey) -> Scalar {
	let ours = local.serialize();
	let theirs = remote.serialize();
	let mut keys = [ours, theirs];
	keys.sort();
	let second = if keys[0] != keys[1] { keys[1] } else { [0u8; 33] };
	if ours == second {
		return Scalar::ONE;
	}
	let mut list = Vec::with_capacity(66);
	list.extend_from_slice(&keys[0]);
	list.extend_from_slice(&keys[1]);
	let key_list_hash = tagged_sha256("KeyAgg list", &list);
	let mut coeff_input = Vec::with_capacity(65);
	coeff_input.extend_from_slice(&key_list_hash);
	coeff_input.extend_from_slice(&ours);
	scalar_mod_order(tagged_sha256("KeyAgg coefficient", &coeff_input))
}

fn point_from_secret(secp: &Secp256k1<secp256k1::All>, secret: &SecretKey) -> PublicKey {
	PublicKey::from_secret_key(secp, secret)
}

fn add_secret(left: SecretKey, right: SecretKey) -> SecretKey {
	left.add_tweak(&Scalar::from(right)).expect("scalar addition")
}

fn mul_secret(left: SecretKey, factor: &Scalar) -> SecretKey {
	left.mul_tweak(factor).expect("scalar multiplication")
}

/// BIP 327 partial signature of `message` for a key-path taproot spend of the
/// aggregate. `our_nonce` and `their_nonce` are 66 bytes each.
pub(super) fn partial_sign(
	secp: &Secp256k1<secp256k1::All>, our_secret: &SecretKey, remote: &PublicKey,
	our_k1: &SecretKey, our_k2: &SecretKey, our_nonce: &[u8; 66], their_nonce: &[u8; 66],
	message: &[u8; 32],
) -> [u8; 32] {
	let ours = point_from_secret(secp, our_secret);
	let untweaked = aggregate_point(secp, &ours, remote);
	let internal = untweaked.x_only_public_key().0;
	let tweak = scalar_mod_order(tagged_sha256("TapTweak", &internal.serialize()));
	let untweaked_even = untweaked.x_only_public_key().1 == Parity::Even;
	let even_untweaked = if untweaked_even { untweaked } else { untweaked.negate(secp) };
	let tweak_point =
		point_from_secret(secp, &SecretKey::from_slice(&tweak.to_be_bytes()).expect("tweak"));
	let tweaked = even_untweaked.combine(&tweak_point).expect("taproot tweak");
	let tweaked_x = tweaked.x_only_public_key().0;
	let tweaked_even = tweaked.x_only_public_key().1 == Parity::Even;

	let our_r1 = PublicKey::from_slice(&our_nonce[..33]).expect("our R1");
	let our_r2 = PublicKey::from_slice(&our_nonce[33..]).expect("our R2");
	let their_r1 = PublicKey::from_slice(&their_nonce[..33]).expect("their R1");
	let their_r2 = PublicKey::from_slice(&their_nonce[33..]).expect("their R2");
	let r1 = our_r1.combine(&their_r1).expect("aggregate R1");
	let r2 = our_r2.combine(&their_r2).expect("aggregate R2");
	let mut aggregate_nonce = [0u8; 66];
	aggregate_nonce[..33].copy_from_slice(&r1.serialize());
	aggregate_nonce[33..].copy_from_slice(&r2.serialize());
	let mut nonce_input = Vec::with_capacity(66 + 32 + 32);
	nonce_input.extend_from_slice(&aggregate_nonce);
	nonce_input.extend_from_slice(&tweaked_x.serialize());
	nonce_input.extend_from_slice(message);
	let nonce_coeff = scalar_mod_order(tagged_sha256("MuSig/noncecoef", &nonce_input));
	let r_point = r1.combine(&r2.mul_tweak(secp, &nonce_coeff).expect("b*R2")).expect("R");
	let r_x = r_point.x_only_public_key().0;
	let r_even = r_point.x_only_public_key().1 == Parity::Even;

	let mut challenge_input = Vec::with_capacity(96);
	challenge_input.extend_from_slice(&r_x.serialize());
	challenge_input.extend_from_slice(&tweaked_x.serialize());
	challenge_input.extend_from_slice(message);
	let challenge = scalar_mod_order(tagged_sha256("BIP0340/challenge", &challenge_input));

	let mut secret = our_secret.clone();
	if !untweaked_even {
		secret = secret.negate();
	}
	if !tweaked_even {
		secret = secret.negate();
	}
	let coefficient = key_agg_coeff(&ours, remote);
	let mut k1 = our_k1.clone();
	let mut k2 = our_k2.clone();
	if !r_even {
		k1 = k1.negate();
		k2 = k2.negate();
	}
	let partial = add_secret(
		add_secret(k1, mul_secret(k2, &nonce_coeff)),
		mul_secret(mul_secret(secret, &coefficient), &challenge),
	);
	partial.secret_bytes()
}

/// Final even nonce point and tweaked output key, shared by the unit test.
#[cfg(test)]
fn session_points(
	secp: &Secp256k1<secp256k1::All>, local: &PublicKey, remote: &PublicKey, our_nonce: &[u8; 66],
	their_nonce: &[u8; 66], message: &[u8; 32],
) -> (XOnlyPublicKey, XOnlyPublicKey) {
	let untweaked = aggregate_point(secp, local, remote);
	let internal = untweaked.x_only_public_key().0;
	let tweak = scalar_mod_order(tagged_sha256("TapTweak", &internal.serialize()));
	let even_untweaked = if untweaked.x_only_public_key().1 == Parity::Even {
		untweaked
	} else {
		untweaked.negate(secp)
	};
	let tweak_point =
		PublicKey::from_secret_key(secp, &SecretKey::from_slice(&tweak.to_be_bytes()).unwrap());
	let tweaked = even_untweaked.combine(&tweak_point).unwrap();
	let output = tweaked.x_only_public_key().0;
	let r1 = PublicKey::from_slice(&our_nonce[..33])
		.unwrap()
		.combine(&PublicKey::from_slice(&their_nonce[..33]).unwrap())
		.unwrap();
	let r2 = PublicKey::from_slice(&our_nonce[33..])
		.unwrap()
		.combine(&PublicKey::from_slice(&their_nonce[33..]).unwrap())
		.unwrap();
	let mut aggregate_nonce = [0u8; 66];
	aggregate_nonce[..33].copy_from_slice(&r1.serialize());
	aggregate_nonce[33..].copy_from_slice(&r2.serialize());
	let mut nonce_input = Vec::new();
	nonce_input.extend_from_slice(&aggregate_nonce);
	nonce_input.extend_from_slice(&output.serialize());
	nonce_input.extend_from_slice(message);
	let nonce_coeff = scalar_mod_order(tagged_sha256("MuSig/noncecoef", &nonce_input));
	let r_point = r1.combine(&r2.mul_tweak(secp, &nonce_coeff).unwrap()).unwrap();
	(r_point.x_only_public_key().0, output)
}

/// P2TR funding script the Phoenix LSP puts on a simple-taproot channel.
pub(super) fn funding_script(
	secp: &Secp256k1<secp256k1::All>, local: &PublicKey, remote: &PublicKey,
) -> ScriptBuf {
	ScriptBuf::new_p2tr(secp, aggregate_funding_keys(secp, local, remote), None)
}

/// Public nonces for `tx_complete`, and the secrets of the first nonce.
pub(super) struct CommitNonces {
	pub wire: Vec<u8>,
	pub k1: SecretKey,
	pub k2: SecretKey,
}

/// Two 66-byte MuSig2 nonces (each two compressed points) for `tx_complete` TLV 4.
pub(super) fn commit_nonces<ES: EntropySource>(
	secp: &Secp256k1<secp256k1::All>, entropy: &ES,
) -> CommitNonces {
	let mut secrets = Vec::with_capacity(4);
	let mut wire = Vec::with_capacity(132);
	for _ in 0..4 {
		loop {
			let bytes = entropy.get_secure_random_bytes();
			if let Ok(secret) = SecretKey::from_slice(&bytes) {
				wire.extend_from_slice(&PublicKey::from_secret_key(secp, &secret).serialize());
				secrets.push(secret);
				break;
			}
		}
	}
	CommitNonces { wire, k1: secrets[0], k2: secrets[1] }
}

const NUMS: &str = "02dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6bf4bc130a279";

fn nums_key() -> XOnlyPublicKey {
	PublicKey::from_slice(&hex_decode(NUMS)).expect("NUMS point").x_only_public_key().0
}

fn hex_decode(hex_str: &str) -> Vec<u8> {
	(0..hex_str.len())
		.step_by(2)
		.map(|index| u8::from_str_radix(&hex_str[index..index + 2], 16).expect("hex"))
		.collect()
}

fn p2tr_with_leaves(
	secp: &Secp256k1<secp256k1::All>, internal: XOnlyPublicKey, leaves: &[ScriptBuf],
) -> ScriptBuf {
	let mut builder = TaprootBuilder::new();
	let depth = if leaves.len() == 1 { 0 } else { 1 };
	for leaf in leaves {
		builder = builder.add_leaf(depth, leaf.clone()).expect("taproot leaf");
	}
	let spend = builder.finalize(secp, internal).expect("taproot tree");
	ScriptBuf::new_p2tr(secp, internal, spend.merkle_root())
}

/// Sighash of the counterparty's first Phoenix taproot commitment.
///
/// They pay the commitment fee. There are no HTLCs. A balance below
/// `dust_limit_sat` is omitted, including its anchor. The fee still reserves
/// both anchors, matching eclair. Returns `None` when nothing is left to sign.
pub(super) fn remote_commitment_sighash(
	secp: &Secp256k1<secp256k1::All>, funding_outpoint: OutPoint, funding_output: &TxOut,
	our_payment: &PublicKey, their_payment: &PublicKey, their_delayed: &PublicKey,
	revocation: &PublicKey, to_self_delay: u16, feerate_per_kw: u32, our_balance_sat: u64,
	their_balance_sat: u64, dust_limit_sat: u64,
) -> Option<([u8; 32], Transaction)> {
	let fee_msat = u64::from(feerate_per_kw).saturating_mul(968).saturating_add(660_000);
	let fee_sat = fee_msat / 1000;
	let their_output = their_balance_sat.checked_sub(fee_sat)?;
	let dust = dust_limit_sat.max(354);
	let nums = nums_key();
	let their_delayed_x = their_delayed.x_only_public_key().0;
	let revocation_x = revocation.x_only_public_key().0;
	let our_payment_x = our_payment.x_only_public_key().0;
	let to_local = p2tr_with_leaves(
		secp,
		nums,
		&[
			Builder::new()
				.push_x_only_key(&their_delayed_x)
				.push_opcode(OP_CHECKSIGVERIFY)
				.push_int(i64::from(to_self_delay))
				.push_opcode(OP_CSV)
				.into_script(),
			Builder::new()
				.push_x_only_key(&their_delayed_x)
				.push_opcode(OP_DROP)
				.push_x_only_key(&revocation_x)
				.push_opcode(OP_CHECKSIG)
				.into_script(),
		],
	);
	let to_remote = p2tr_with_leaves(
		secp,
		nums,
		&[Builder::new()
			.push_x_only_key(&our_payment_x)
			.push_opcode(OP_CHECKSIGVERIFY)
			.push_int(1)
			.push_opcode(OP_CSV)
			.into_script()],
	);
	let their_anchor = p2tr_with_leaves(
		secp,
		their_delayed_x,
		&[Builder::new().push_int(16).push_opcode(OP_CSV).into_script()],
	);
	let our_anchor = p2tr_with_leaves(
		secp,
		our_payment_x,
		&[Builder::new().push_int(16).push_opcode(OP_CSV).into_script()],
	);
	let mut outputs = Vec::with_capacity(4);
	if their_output >= dust {
		outputs.push(TxOut { value: Amount::from_sat(their_output), script_pubkey: to_local });
		outputs.push(TxOut { value: Amount::from_sat(330), script_pubkey: their_anchor });
	}
	if our_balance_sat >= dust {
		outputs.push(TxOut { value: Amount::from_sat(our_balance_sat), script_pubkey: to_remote });
		outputs.push(TxOut { value: Amount::from_sat(330), script_pubkey: our_anchor });
	}
	if outputs.is_empty() {
		return None;
	}
	outputs.sort_by(|left, right| serialize(left).cmp(&serialize(right)));

	let mut preimage = Vec::with_capacity(66);
	preimage.extend_from_slice(&our_payment.serialize());
	preimage.extend_from_slice(&their_payment.serialize());
	let blind_hash = sha256::Hash::hash(&preimage).to_byte_array();
	let mut blind = 0u64;
	for byte in &blind_hash[26..32] {
		blind = (blind << 8) | u64::from(*byte);
	}
	// Eclair's first commitment index is 0. LDK stores that same
	// transaction as `INITIAL_COMMITMENT_NUMBER` and encodes
	// `obscure_factor XOR (INITIAL - number)`, which is the factor
	// itself. XORing `(1 << 48) - 1` here changes the locktime, so the
	// LSP rejects the partial as an invalid commitment signature.
	let obscured = blind;
	let sequence = 0x8000_0000 | u32::try_from((obscured >> 24) & 0x00ff_ffff).unwrap();
	let locktime = 0x2000_0000 | u32::try_from(obscured & 0x00ff_ffff).unwrap();
	let tx = Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: LockTime::from_consensus(locktime),
		input: vec![TxIn {
			previous_output: bitcoin::OutPoint {
				txid: funding_outpoint.txid,
				vout: funding_outpoint.vout,
			},
			script_sig: ScriptBuf::new(),
			sequence: Sequence(sequence),
			witness: Witness::default(),
		}],
		output: outputs,
	};
	let sighash = SighashCache::new(&tx)
		.taproot_key_spend_signature_hash(
			0,
			&Prevouts::All(&[funding_output]),
			TapSighashType::Default,
		)
		.expect("taproot sighash");
	Some((sighash.to_byte_array(), tx))
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

	#[test]
	fn two_partial_signatures_verify_as_schnorr() {
		let secp = Secp256k1::new();
		let our_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
		let their_secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
		let our_k1 = SecretKey::from_slice(&[4u8; 32]).unwrap();
		let our_k2 = SecretKey::from_slice(&[5u8; 32]).unwrap();
		let their_k1 = SecretKey::from_slice(&[6u8; 32]).unwrap();
		let their_k2 = SecretKey::from_slice(&[7u8; 32]).unwrap();
		let our_pub = PublicKey::from_secret_key(&secp, &our_secret);
		let their_pub = PublicKey::from_secret_key(&secp, &their_secret);
		let mut our_nonce = [0u8; 66];
		our_nonce[..33].copy_from_slice(&PublicKey::from_secret_key(&secp, &our_k1).serialize());
		our_nonce[33..].copy_from_slice(&PublicKey::from_secret_key(&secp, &our_k2).serialize());
		let mut their_nonce = [0u8; 66];
		their_nonce[..33]
			.copy_from_slice(&PublicKey::from_secret_key(&secp, &their_k1).serialize());
		their_nonce[33..]
			.copy_from_slice(&PublicKey::from_secret_key(&secp, &their_k2).serialize());
		let message = [9u8; 32];
		let ours = partial_sign(
			&secp,
			&our_secret,
			&their_pub,
			&our_k1,
			&our_k2,
			&our_nonce,
			&their_nonce,
			&message,
		);
		let theirs = partial_sign(
			&secp,
			&their_secret,
			&our_pub,
			&their_k1,
			&their_k2,
			&their_nonce,
			&our_nonce,
			&message,
		);
		let untweaked = aggregate_point(&secp, &our_pub, &their_pub);
		let tweak = scalar_mod_order(tagged_sha256(
			"TapTweak",
			&untweaked.x_only_public_key().0.serialize(),
		));
		let even_untweaked = if untweaked.x_only_public_key().1 == Parity::Even {
			untweaked
		} else {
			untweaked.negate(&secp)
		};
		let tweak_point = PublicKey::from_secret_key(
			&secp,
			&SecretKey::from_slice(&tweak.to_be_bytes()).unwrap(),
		);
		let tweaked = even_untweaked.combine(&tweak_point).unwrap();
		let tweak_negated = tweaked.x_only_public_key().1 != Parity::Even;
		let mut tweak_term = mul_secret(SecretKey::from_slice(&tweak.to_be_bytes()).unwrap(), &{
			let (nonce_x, output) =
				session_points(&secp, &our_pub, &their_pub, &our_nonce, &their_nonce, &message);
			let mut challenge_input = Vec::new();
			challenge_input.extend_from_slice(&nonce_x.serialize());
			challenge_input.extend_from_slice(&output.serialize());
			challenge_input.extend_from_slice(&message);
			scalar_mod_order(tagged_sha256("BIP0340/challenge", &challenge_input))
		});
		if tweak_negated {
			tweak_term = tweak_term.negate();
		}
		let sum = ours_plus(&ours_plus(&ours, &theirs), &tweak_term.secret_bytes());
		let (nonce_x, output) =
			session_points(&secp, &our_pub, &their_pub, &our_nonce, &their_nonce, &message);
		let s_point = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sum).unwrap());
		let r_even = nonce_x.public_key(Parity::Even);
		let mut challenge_input = Vec::new();
		challenge_input.extend_from_slice(&nonce_x.serialize());
		challenge_input.extend_from_slice(&output.serialize());
		challenge_input.extend_from_slice(&message);
		let challenge = scalar_mod_order(tagged_sha256("BIP0340/challenge", &challenge_input));
		let e_point = output.public_key(Parity::Even).mul_tweak(&secp, &challenge).unwrap();
		let right = r_even.combine(&e_point).unwrap();
		assert_eq!(s_point, right, "s*G != R + e*P");
		let mut sig = [0u8; 64];
		sig[..32].copy_from_slice(&nonce_x.serialize());
		sig[32..].copy_from_slice(&sum);
		let signature = schnorr::Signature::from_slice(&sig).unwrap();
		output
			.verify(&secp, &secp256k1::Message::from_digest(message), &signature)
			.expect("aggregated MuSig2 signature");
	}

	#[test]
	fn first_commitment_number_is_zero() {
		let secp = Secp256k1::new();
		let our_payment =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
		let their_payment =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
		let their_delayed =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[4u8; 32]).unwrap());
		let revocation =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[5u8; 32]).unwrap());
		let funding = TxOut { value: Amount::from_sat(17_500), script_pubkey: ScriptBuf::new() };
		let outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([9u8; 32]), vout: 1 };
		let (_, tx) = remote_commitment_sighash(
			&secp,
			outpoint,
			&funding,
			&our_payment,
			&their_payment,
			&their_delayed,
			&revocation,
			144,
			253,
			0,
			17_500,
			354,
		)
		.unwrap();
		let mut preimage = Vec::new();
		preimage.extend_from_slice(&our_payment.serialize());
		preimage.extend_from_slice(&their_payment.serialize());
		let blind_hash = sha256::Hash::hash(&preimage).to_byte_array();
		let mut blind = 0u64;
		for byte in &blind_hash[26..32] {
			blind = (blind << 8) | u64::from(*byte);
		}
		let sequence = 0x8000_0000 | u32::try_from((blind >> 24) & 0x00ff_ffff).unwrap();
		let locktime = 0x2000_0000 | u32::try_from(blind & 0x00ff_ffff).unwrap();
		assert_eq!(tx.input[0].sequence, Sequence(sequence));
		assert_eq!(tx.lock_time, LockTime::from_consensus(locktime));
		let backwards = ((1u64 << 48) - 1) ^ blind;
		let backwards_lock = 0x2000_0000 | u32::try_from(backwards & 0x00ff_ffff).unwrap();
		assert_ne!(tx.lock_time, LockTime::from_consensus(backwards_lock));
	}

	#[test]
	fn zero_opener_balance_still_has_a_commitment() {
		let secp = Secp256k1::new();
		let our_payment =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
		let their_payment =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[3u8; 32]).unwrap());
		let their_delayed =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[4u8; 32]).unwrap());
		let revocation =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[5u8; 32]).unwrap());
		let funding = TxOut { value: Amount::from_sat(265_000), script_pubkey: ScriptBuf::new() };
		let outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([9u8; 32]), vout: 1 };
		let sighash = remote_commitment_sighash(
			&secp,
			outpoint,
			&funding,
			&our_payment,
			&their_payment,
			&their_delayed,
			&revocation,
			144,
			253,
			0,
			265_000,
			546,
		);
		assert!(sighash.is_some());
	}

	fn ours_plus(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
		let sum = SecretKey::from_slice(left)
			.unwrap()
			.add_tweak(&Scalar::from(SecretKey::from_slice(right).unwrap()))
			.unwrap();
		sum.secret_bytes()
	}
}
