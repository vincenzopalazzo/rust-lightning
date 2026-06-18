// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Selective disclosure support for BOLT 12 payer proofs.

use alloc::collections::BTreeSet;

use bitcoin::hashes::{sha256, Hash, HashEngine};

use crate::offers::invoice::INVOICE_TYPES;
use crate::offers::merkle::{
	tagged_branch_hash_from_engine, tagged_hash_engine, tagged_hash_from_engine, TlvRecord,
};
use crate::offers::offer::EXPERIMENTAL_OFFER_TYPES;

#[allow(unused_imports)]
use crate::prelude::*;

/// Error during selective disclosure operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectiveDisclosureError {
	/// The omitted markers are not in strict ascending order.
	InvalidOmittedMarkersOrder,
	/// The omitted markers contain an invalid marker (0 or signature type).
	InvalidOmittedMarkersMarker,
	/// The leaf_hashes count doesn't match included TLVs.
	LeafHashCountMismatch,
	/// Insufficient missing_hashes to reconstruct the tree.
	InsufficientMissingHashes,
	/// The TLV stream is empty.
	EmptyTlvStream,
}

/// Data needed to reconstruct a merkle root with selective disclosure.
///
/// This is used in payer proofs to allow verification of an invoice signature
/// without revealing all invoice fields.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct SelectiveDisclosure {
	/// Nonce hashes for included TLVs (in TLV type order).
	pub(super) leaf_hashes: Vec<sha256::Hash>,
	/// Marker numbers for omitted TLVs (excluding implicit TLV0).
	pub(super) omitted_markers: Vec<u64>,
	/// Minimal merkle hashes for omitted subtrees.
	pub(super) missing_hashes: Vec<sha256::Hash>,
	/// The complete merkle root.
	pub(super) merkle_root: sha256::Hash,
}

/// Internal data for each TLV during tree construction.
struct TlvMerkleData {
	tlv_type: u64,
	per_tlv_hash: sha256::Hash,
	is_included: bool,
}

/// Compute selective disclosure data from a TLV stream.
///
/// This builds the full merkle tree and extracts the data needed for a payer proof:
/// - `leaf_hashes`: nonce hashes for included TLVs
/// - `omitted_markers`: marker numbers for omitted TLVs
/// - `missing_hashes`: minimal merkle hashes for omitted subtrees
///
/// # Arguments
/// * `records` - Iterator of [`TlvRecord`]s (non-signature TLVs from the invoice)
/// * `included_types` - Set of TLV types to include in the disclosure
pub(super) fn compute_selective_disclosure<'a>(
	records: impl Iterator<Item = TlvRecord<'a>>, included_types: &BTreeSet<u64>,
) -> Result<SelectiveDisclosure, SelectiveDisclosureError> {
	let mut records = records.peekable();
	let first_record_bytes =
		records.peek().ok_or(SelectiveDisclosureError::EmptyTlvStream)?.record_bytes;
	let nonce_tag_hash = sha256::Hash::from_engine({
		let mut engine = sha256::Hash::engine();
		engine.input("LnNonce".as_bytes());
		engine.input(first_record_bytes);
		engine
	});

	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let nonce_tag = tagged_hash_engine(nonce_tag_hash);
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	let mut tlv_data: Vec<TlvMerkleData> = Vec::with_capacity(1024);
	let mut leaf_hashes: Vec<sha256::Hash> = Vec::with_capacity(included_types.len());
	for record in records {
		let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record.record_bytes);
		let nonce_hash = tagged_hash_from_engine(nonce_tag.clone(), record.type_bytes);
		let per_tlv_hash =
			tagged_branch_hash_from_engine(branch_tag.clone(), leaf_hash, nonce_hash);

		let is_included = included_types.contains(&record.r#type);
		if is_included {
			leaf_hashes.push(nonce_hash);
		}
		tlv_data.push(TlvMerkleData { tlv_type: record.r#type, per_tlv_hash, is_included });
	}

	if tlv_data.is_empty() {
		return Err(SelectiveDisclosureError::EmptyTlvStream);
	}
	let num_omitted_markers =
		tlv_data.iter().filter(|data| !data.is_included && data.tlv_type != 0).count();
	let mut omitted_markers = Vec::with_capacity(num_omitted_markers);
	omitted_markers.extend(compute_omitted_markers(tlv_data.iter()));
	let (merkle_root, missing_hashes) = build_tree_with_disclosure(&tlv_data, &branch_tag);

	Ok(SelectiveDisclosure { leaf_hashes, omitted_markers, missing_hashes, merkle_root })
}

/// Returns the marker number that follows `prev` (an included TLV type or a
/// previous marker) per BOLT 12 PR 1295.
///
/// A marker is one greater than the previous value, except that a value landing
/// in the gap between the invoice TLV range and the experimental range (the
/// signature/payer-proof range) jumps to the start of the experimental range.
/// The producer and the readers all go through this so their marker sequences
/// stay in agreement.
pub(super) fn next_marker(prev: u64) -> u64 {
	let next = prev.saturating_add(1);
	if (INVOICE_TYPES.end..EXPERIMENTAL_OFFER_TYPES.start).contains(&next) {
		EXPERIMENTAL_OFFER_TYPES.start
	} else {
		next
	}
}

/// Compute omitted markers per BOLT 12 payer proof spec.
///
/// Each omitted TLV gets the marker number following the previous included TLV
/// type or the previous marker (see [`next_marker`]). TLV type 0 is implicitly
/// omitted (never assigned a marker).
fn compute_omitted_markers<'a>(
	tlv_data: impl Iterator<Item = &'a TlvMerkleData> + 'a,
) -> impl Iterator<Item = u64> + 'a {
	tlv_data
		.filter(|data| data.tlv_type != 0)
		.scan(0u64, |prev_value, data| {
			if data.is_included {
				*prev_value = data.tlv_type;
				Some(None)
			} else {
				let marker = next_marker(*prev_value);
				*prev_value = marker;
				Some(Some(marker))
			}
		})
		.flatten()
}

/// Build merkle tree recursively (DFS, left-to-right) and collect missing_hashes.
///
/// Per the spec, missing_hashes are in depth-first left-to-right order.
///
/// Note: a level-by-level approach cannot produce DFS-ordered missing_hashes because it processes
/// all subtrees at each depth simultaneously rather than completing each subtree before the next.
fn build_tree_with_disclosure(
	tlv_data: &[TlvMerkleData], branch_tag: &sha256::HashEngine,
) -> (sha256::Hash, Vec<sha256::Hash>) {
	debug_assert!(!tlv_data.is_empty(), "TLV stream must contain at least one record");

	let mut missing_hashes = Vec::new();
	let (root, _) = build_tree_dfs(tlv_data, branch_tag, &mut missing_hashes);
	(root, missing_hashes)
}

fn build_tree_dfs(
	tlv_data: &[TlvMerkleData], branch_tag: &sha256::HashEngine,
	missing_hashes: &mut Vec<sha256::Hash>,
) -> (sha256::Hash, bool) {
	if tlv_data.len() == 1 {
		return (tlv_data[0].per_tlv_hash, tlv_data[0].is_included);
	}

	let mid = tlv_data.len().next_power_of_two() / 2;
	let (left_data, right_data) = tlv_data.split_at(mid);
	let (left_hash, left_incl) = build_tree_dfs(left_data, branch_tag, missing_hashes);
	let (right_hash, right_incl) = build_tree_dfs(right_data, branch_tag, missing_hashes);

	if left_incl && !right_incl {
		missing_hashes.push(right_hash);
	} else if !left_incl && right_incl {
		missing_hashes.push(left_hash);
	}

	let combined = tagged_branch_hash_from_engine(branch_tag.clone(), left_hash, right_hash);
	(combined, left_incl || right_incl)
}

/// Reconstruct merkle root from selective disclosure data.
///
/// `missing_hashes` must be in DFS (left-to-right recursive traversal) order,
/// matching the order produced by [`build_tree_with_disclosure`].
pub(super) fn reconstruct_merkle_root(
	included_records: &[TlvRecord<'_>], leaf_hashes: &[sha256::Hash], omitted_markers: &[u64],
	missing_hashes: &[sha256::Hash],
) -> Result<sha256::Hash, SelectiveDisclosureError> {
	debug_assert!({
		let included_types: BTreeSet<u64> = included_records.iter().map(|r| r.r#type).collect();
		validate_omitted_markers(omitted_markers, &included_types).is_ok()
	});

	if included_records.len() != leaf_hashes.len() {
		return Err(SelectiveDisclosureError::LeafHashCountMismatch);
	}

	let leaf_tag = tagged_hash_engine(sha256::Hash::hash("LnLeaf".as_bytes()));
	let branch_tag = tagged_hash_engine(sha256::Hash::hash("LnBranch".as_bytes()));

	// Build per-position hash array: Some(hash) for included positions, None for omitted.
	// TLV0 is always at position 0 (implicitly omitted).
	let num_nodes = 1 + included_records.len() + omitted_markers.len();
	let mut hashes: Vec<Option<sha256::Hash>> = Vec::with_capacity(num_nodes);
	hashes.push(None); // TLV0 always omitted

	let mut inc_idx = 0;
	let mut mrk_idx = 0;
	let mut prev_marker: u64 = 0;

	while inc_idx < included_records.len() || mrk_idx < omitted_markers.len() {
		if mrk_idx >= omitted_markers.len() {
			let record = &included_records[inc_idx];
			let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record.record_bytes);
			let nonce_hash = leaf_hashes[inc_idx];
			hashes.push(Some(tagged_branch_hash_from_engine(
				branch_tag.clone(),
				leaf_hash,
				nonce_hash,
			)));
			inc_idx += 1;
		} else if inc_idx >= included_records.len() {
			hashes.push(None);
			prev_marker = omitted_markers[mrk_idx];
			mrk_idx += 1;
		} else {
			let marker = omitted_markers[mrk_idx];
			let inc_type = included_records[inc_idx].r#type;
			if marker == next_marker(prev_marker) {
				hashes.push(None);
				prev_marker = marker;
				mrk_idx += 1;
			} else {
				let record = &included_records[inc_idx];
				let leaf_hash = tagged_hash_from_engine(leaf_tag.clone(), record.record_bytes);
				let nonce_hash = leaf_hashes[inc_idx];
				hashes.push(Some(tagged_branch_hash_from_engine(
					branch_tag.clone(),
					leaf_hash,
					nonce_hash,
				)));
				prev_marker = inc_type;
				inc_idx += 1;
			}
		}
	}

	let mut missing_idx: usize = 0;
	let root = reconstruct_merkle_root_dfs(&hashes, &branch_tag, missing_hashes, &mut missing_idx)?;

	if missing_idx != missing_hashes.len() {
		return Err(SelectiveDisclosureError::InsufficientMissingHashes);
	}

	root.ok_or(SelectiveDisclosureError::InsufficientMissingHashes)
}

fn reconstruct_merkle_root_dfs(
	hashes: &[Option<sha256::Hash>], branch_tag: &sha256::HashEngine,
	missing_hashes: &[sha256::Hash], missing_idx: &mut usize,
) -> Result<Option<sha256::Hash>, SelectiveDisclosureError> {
	if hashes.len() == 1 {
		return Ok(hashes[0]);
	}

	let mid = hashes.len().next_power_of_two() / 2;
	let (left_hashes, right_hashes) = hashes.split_at(mid);
	let left = reconstruct_merkle_root_dfs(left_hashes, branch_tag, missing_hashes, missing_idx)?;
	let right = reconstruct_merkle_root_dfs(right_hashes, branch_tag, missing_hashes, missing_idx)?;

	match (left, right) {
		(None, None) => Ok(None),
		(Some(l), None) => {
			if *missing_idx >= missing_hashes.len() {
				return Err(SelectiveDisclosureError::InsufficientMissingHashes);
			}
			let r = missing_hashes[*missing_idx];
			*missing_idx += 1;
			Ok(Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r)))
		},
		(None, Some(r)) => {
			if *missing_idx >= missing_hashes.len() {
				return Err(SelectiveDisclosureError::InsufficientMissingHashes);
			}
			let l = missing_hashes[*missing_idx];
			*missing_idx += 1;
			Ok(Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r)))
		},
		(Some(l), Some(r)) => Ok(Some(tagged_branch_hash_from_engine(branch_tag.clone(), l, r))),
	}
}

/// Validates that `markers` is a minimized omitted-marker sequence per BOLT 12 PR 1295, relative
/// to `included_types`. Each marker MUST be strictly ascending, non-zero, MUST NOT be an included
/// TLV type, and MUST be minimized: it equals the marker following the previous marker (continuing
/// a run) or the previous included type (starting a new run), per [`next_marker`]. The
/// signature-gap jump is handled by [`next_marker`], so signature-range markers are rejected
/// implicitly. This is the single source of truth for marker minimality; callers layer any
/// additional range restrictions on top (e.g. the payer-proof valid ranges).
pub(super) fn validate_omitted_markers(
	markers: &[u64], included_types: &BTreeSet<u64>,
) -> Result<(), SelectiveDisclosureError> {
	let mut inc_iter = included_types.iter().copied().peekable();
	// After the implicit TLV0 (marker 0), the first minimized marker is `next_marker(0)`.
	let mut expected_next: u64 = next_marker(0);
	let mut prev = 0u64;

	for &marker in markers {
		if marker == 0 {
			return Err(SelectiveDisclosureError::InvalidOmittedMarkersMarker);
		}
		if marker <= prev {
			return Err(SelectiveDisclosureError::InvalidOmittedMarkersOrder);
		}
		if included_types.contains(&marker) {
			return Err(SelectiveDisclosureError::InvalidOmittedMarkersMarker);
		}

		// Minimization: `marker` continues the current run (`expected_next`), or an included type
		// X sits between the previous position and `marker` with `next_marker(X) == marker`.
		if marker != expected_next {
			let mut found = false;
			for inc_type in inc_iter.by_ref() {
				if next_marker(inc_type) == marker {
					found = true;
					break;
				}
				if inc_type >= marker {
					return Err(SelectiveDisclosureError::InvalidOmittedMarkersMarker);
				}
			}
			if !found {
				return Err(SelectiveDisclosureError::InvalidOmittedMarkersMarker);
			}
		}

		expected_next = next_marker(marker);
		prev = marker;
	}

	Ok(())
}

/// Reconstruct position inclusion map from included types and omitted markers.
///
/// This reverses the marker encoding algorithm from `compute_omitted_markers`:
/// - Markers form "runs" of consecutive values (e.g., [11, 12] is a run)
/// - A "jump" in markers (e.g., 12 -> 41) indicates an included TLV came between
/// - After included type X, the next marker in that run equals X + 1
///
/// The algorithm tracks `prev_marker` to detect continuations vs jumps:
/// - If `marker == next_marker(prev_marker)`: continuation -> omitted position
/// - Otherwise: jump -> included position comes first, then process marker as continuation
///
/// Example: included=[10, 40], markers=[11, 12, 41, 42]
/// - Position 0: TLV0 (always omitted)
/// - marker=11, prev=0: 11 != 1, jump! Insert included (10), prev=10
/// - marker=11, prev=10: 11 == 11, continuation -> omitted, prev=11
/// - marker=12, prev=11: 12 == 12, continuation -> omitted, prev=12
/// - marker=41, prev=12: 41 != 13, jump! Insert included (40), prev=40
/// - marker=41, prev=40: 41 == 41, continuation -> omitted, prev=41
/// - marker=42, prev=41: 42 == 42, continuation -> omitted, prev=42
/// Result: [O, I, O, O, I, O, O]
#[cfg(test)]
fn reconstruct_positions(included_types: &[u64], omitted_markers: &[u64]) -> Vec<bool> {
	let total = 1 + included_types.len() + omitted_markers.len();
	let mut positions = Vec::with_capacity(total);
	positions.push(false); // TLV0 is always omitted

	let mut inc_idx = 0;
	let mut mrk_idx = 0;
	// After TLV0 (implicit marker 0), next continuation would be marker 1
	let mut prev_marker: u64 = 0;

	while inc_idx < included_types.len() || mrk_idx < omitted_markers.len() {
		if mrk_idx >= omitted_markers.len() {
			// No more markers, remaining positions are included
			positions.push(true);
			inc_idx += 1;
		} else if inc_idx >= included_types.len() {
			// No more included types, remaining positions are omitted
			positions.push(false);
			prev_marker = omitted_markers[mrk_idx];
			mrk_idx += 1;
		} else {
			let marker = omitted_markers[mrk_idx];
			let inc_type = included_types[inc_idx];

			if marker == next_marker(prev_marker) {
				// Continuation of current run -> this position is omitted
				positions.push(false);
				prev_marker = marker;
				mrk_idx += 1;
			} else {
				// Jump detected! An included TLV comes before this marker.
				// After the included type, prev_marker resets to that type,
				// so the marker will be processed as a continuation next iteration.
				positions.push(true);
				prev_marker = inc_type;
				inc_idx += 1;
				// Don't advance mrk_idx - same marker will be continuation next
			}
		}
	}

	positions
}

#[cfg(test)]
mod tests {
	use super::{compute_omitted_markers, TlvMerkleData};
	use crate::offers::merkle::{TlvRecord, TlvStream};

	use bitcoin::hashes::{sha256, Hash};

	/// Test reconstruct_positions with the BOLT 12 payer proof spec example.
	///
	/// TLVs: 0(omit), 10(incl), 20(omit), 30(omit), 40(incl), 50(omit), 60(omit)
	/// Markers: [11, 12, 41, 42]
	/// Expected positions: [O, I, O, O, I, O, O]
	#[test]
	fn test_reconstruct_positions_spec_example() {
		let included_types = vec![10, 40];
		let markers = vec![11, 12, 41, 42];
		let positions = super::reconstruct_positions(&included_types, &markers);
		assert_eq!(positions, vec![false, true, false, false, true, false, false]);
	}

	/// Test reconstruct_positions when there are omitted TLVs before the first included.
	///
	/// TLVs: 0(omit), 5(omit), 10(incl), 20(omit)
	/// Markers: [1, 11] (1 is first omitted after TLV0, 11 is after included 10)
	/// Expected positions: [O, O, I, O]
	#[test]
	fn test_reconstruct_positions_omitted_before_included() {
		let included_types = vec![10];
		let markers = vec![1, 11];
		let positions = super::reconstruct_positions(&included_types, &markers);
		assert_eq!(positions, vec![false, false, true, false]);
	}

	/// Test reconstruct_positions with only included TLVs (no omitted except TLV0).
	///
	/// TLVs: 0(omit), 10(incl), 20(incl)
	/// Markers: [] (no omitted TLVs after TLV0)
	/// Expected positions: [O, I, I]
	#[test]
	fn test_reconstruct_positions_no_omitted() {
		let included_types = vec![10, 20];
		let markers = vec![];
		let positions = super::reconstruct_positions(&included_types, &markers);
		assert_eq!(positions, vec![false, true, true]);
	}

	/// Test reconstruct_positions with only omitted TLVs (no included).
	///
	/// TLVs: 0(omit), 5(omit), 10(omit)
	/// Markers: [1, 2] (consecutive omitted after TLV0)
	/// Expected positions: [O, O, O]
	#[test]
	fn test_reconstruct_positions_no_included() {
		let included_types = vec![];
		let markers = vec![1, 2];
		let positions = super::reconstruct_positions(&included_types, &markers);
		assert_eq!(positions, vec![false, false, false]);
	}

	/// Test round-trip: compute selective disclosure then reconstruct merkle root.
	#[test]
	fn test_selective_disclosure_round_trip() {
		use alloc::collections::BTreeSet;

		// Build TLV stream matching spec example structure
		// TLVs: 0, 10, 20, 30, 40, 50, 60
		let mut tlv_bytes = Vec::new();
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // TLV 0
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]); // TLV 10
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]); // TLV 20
		tlv_bytes.extend_from_slice(&[0x1e, 0x02, 0x00, 0x00]); // TLV 30
		tlv_bytes.extend_from_slice(&[0x28, 0x02, 0x00, 0x00]); // TLV 40
		tlv_bytes.extend_from_slice(&[0x32, 0x02, 0x00, 0x00]); // TLV 50
		tlv_bytes.extend_from_slice(&[0x3c, 0x02, 0x00, 0x00]); // TLV 60

		// Include types 10 and 40
		let mut included = BTreeSet::new();
		included.insert(10);
		included.insert(40);

		// Compute selective disclosure
		let disclosure =
			super::compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included).unwrap();

		// Verify markers match spec example
		assert_eq!(disclosure.omitted_markers, vec![11, 12, 41, 42]);

		// Verify leaf_hashes count matches included TLVs
		assert_eq!(disclosure.leaf_hashes.len(), 2);

		// Collect included records for reconstruction
		let included_records: Vec<TlvRecord<'_>> =
			TlvStream::new(&tlv_bytes).filter(|r| included.contains(&r.r#type)).collect();

		// Reconstruct merkle root
		let reconstructed = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.leaf_hashes,
			&disclosure.omitted_markers,
			&disclosure.missing_hashes,
		)
		.unwrap();

		// Must match original
		assert_eq!(reconstructed, disclosure.merkle_root);
	}

	/// Test that the synthetic 7-node example still requires four missing hashes.
	///
	/// For the synthetic tree with TLVs [0(o), 10(I), 20(o), 30(o), 40(I), 50(o), 60(o)]:
	/// - hash(0) covers type 0
	/// - hash(B(20,30)) covers types 20-30
	/// - hash(50) covers type 50
	/// - hash(60) covers type 60
	///
	/// This still needs 4 missing hashes. The DFS-ordering fix changes the order
	/// they are emitted and consumed in, but not the count for this tree shape.
	#[test]
	fn test_missing_hashes_for_synthetic_tree() {
		use alloc::collections::BTreeSet;

		// Build TLV stream: 0, 10, 20, 30, 40, 50, 60
		let mut tlv_bytes = Vec::new();
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // TLV 0
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]); // TLV 10
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]); // TLV 20
		tlv_bytes.extend_from_slice(&[0x1e, 0x02, 0x00, 0x00]); // TLV 30
		tlv_bytes.extend_from_slice(&[0x28, 0x02, 0x00, 0x00]); // TLV 40
		tlv_bytes.extend_from_slice(&[0x32, 0x02, 0x00, 0x00]); // TLV 50
		tlv_bytes.extend_from_slice(&[0x3c, 0x02, 0x00, 0x00]); // TLV 60

		// Include types 10 and 40 (same as spec example)
		let mut included = BTreeSet::new();
		included.insert(10);
		included.insert(40);

		let disclosure =
			super::compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included).unwrap();

		// We should still have 4 missing hashes for omitted types:
		// - type 0 (single leaf)
		// - types 20+30 (combined branch)
		// - type 50 (single leaf)
		// - type 60 (single leaf)
		assert_eq!(
			disclosure.missing_hashes.len(),
			4,
			"Expected 4 missing hashes for omitted types [0, 20+30, 50, 60]"
		);

		// Verify the round-trip still works with the correct ordering
		let included_records: Vec<TlvRecord<'_>> =
			TlvStream::new(&tlv_bytes).filter(|r| included.contains(&r.r#type)).collect();

		let reconstructed = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.leaf_hashes,
			&disclosure.omitted_markers,
			&disclosure.missing_hashes,
		)
		.unwrap();

		assert_eq!(reconstructed, disclosure.merkle_root);
	}

	/// Test that reconstruction fails with wrong number of missing_hashes.
	#[test]
	fn test_reconstruction_fails_with_wrong_missing_hashes() {
		use alloc::collections::BTreeSet;

		let mut tlv_bytes = Vec::new();
		tlv_bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // TLV 0
		tlv_bytes.extend_from_slice(&[0x0a, 0x02, 0x00, 0x00]); // TLV 10
		tlv_bytes.extend_from_slice(&[0x14, 0x02, 0x00, 0x00]); // TLV 20

		let mut included = BTreeSet::new();
		included.insert(10);

		let disclosure =
			super::compute_selective_disclosure(TlvStream::new(&tlv_bytes), &included).unwrap();

		let included_records: Vec<TlvRecord<'_>> =
			TlvStream::new(&tlv_bytes).filter(|r| included.contains(&r.r#type)).collect();

		// Try with empty missing_hashes (should fail)
		let result = super::reconstruct_merkle_root(
			&included_records,
			&disclosure.leaf_hashes,
			&disclosure.omitted_markers,
			&[], // Wrong!
		);

		assert!(result.is_err());
	}

	/// Verify that [`compute_omitted_markers`] jumps from the top of the low
	/// marker range (239) to the start of the high range (1_000_000_000) per
	/// BOLT 12 PR 1295, rather than entering the signature type range. Real
	/// BOLT 12 invoices have far fewer than 239 non-signature TLVs, so this
	/// case is unreachable in practice.
	#[test]
	fn compute_omitted_markers_jumps_to_high_range_after_239() {
		// 240 consecutive omitted TLVs at types 1..=240. The first 239 markers
		// climb 1..=239; the 240th would be 240 (in the signature range), so it
		// jumps to 1_000_000_000 instead.
		let dummy_hash = sha256::Hash::all_zeros();
		let tlv_data: Vec<TlvMerkleData> = (1u64..=240)
			.map(|tlv_type| TlvMerkleData {
				tlv_type,
				per_tlv_hash: dummy_hash,
				is_included: false,
			})
			.collect();

		let markers: Vec<u64> = compute_omitted_markers(tlv_data.iter()).collect();

		let mut expected: Vec<u64> = (1..=239).collect();
		expected.push(1_000_000_000);
		assert_eq!(markers, expected);
	}

	/// An *included* TLV at the top of the low range (type 239) followed by an
	/// omitted TLV: the marker must skip the signature/payer-proof gap and jump
	/// to the start of the experimental range, not land on 240.
	#[test]
	fn compute_omitted_markers_jumps_after_included_at_top_of_low_range() {
		let dummy_hash = sha256::Hash::all_zeros();
		let tlv_data = [
			TlvMerkleData { tlv_type: 239, per_tlv_hash: dummy_hash, is_included: true },
			TlvMerkleData { tlv_type: 1_500_000_000, per_tlv_hash: dummy_hash, is_included: false },
		];
		let markers: Vec<u64> = compute_omitted_markers(tlv_data.iter()).collect();
		assert_eq!(markers, vec![1_000_000_000]);
	}

	/// After a jump into the experimental range, subsequent omitted markers
	/// continue sequentially within that range.
	#[test]
	fn compute_omitted_markers_continue_in_experimental_range_after_jump() {
		let dummy_hash = sha256::Hash::all_zeros();
		let tlv_data = [
			TlvMerkleData { tlv_type: 239, per_tlv_hash: dummy_hash, is_included: true },
			TlvMerkleData { tlv_type: 3_000_000_000, per_tlv_hash: dummy_hash, is_included: false },
			TlvMerkleData { tlv_type: 3_000_000_001, per_tlv_hash: dummy_hash, is_included: false },
		];
		let markers: Vec<u64> = compute_omitted_markers(tlv_data.iter()).collect();
		assert_eq!(markers, vec![1_000_000_000, 1_000_000_001]);
	}

	/// [`next_marker`] increments by one within a range but jumps over the
	/// signature/payer-proof gap, so producer and readers stay in agreement.
	#[test]
	fn next_marker_jumps_the_gap() {
		assert_eq!(super::next_marker(0), 1);
		assert_eq!(super::next_marker(5), 6);
		assert_eq!(super::next_marker(238), 239);
		// 240 would land in the signature range, so it jumps to the experimental range.
		assert_eq!(super::next_marker(239), 1_000_000_000);
		assert_eq!(super::next_marker(1_000_000_000), 1_000_000_001);
	}

	#[test]
	fn validate_omitted_markers_direct() {
		use alloc::collections::BTreeSet;
		let none: BTreeSet<u64> = BTreeSet::new();

		// A minimized leading run with nothing included is accepted.
		assert!(super::validate_omitted_markers(&[1, 2, 3], &none).is_ok());
		// The empty sequence is accepted.
		assert!(super::validate_omitted_markers(&[], &none).is_ok());
		// Zero is rejected (it is the implicit TLV0 marker).
		assert!(super::validate_omitted_markers(&[0], &none).is_err());
		// A non-ascending sequence is rejected.
		assert!(super::validate_omitted_markers(&[2, 1], &none).is_err());
		// A gap with no intervening included type to justify it is non-minimized -> rejected.
		assert!(super::validate_omitted_markers(&[1, 3], &none).is_err());

		// The same `[1, 3]` is accepted when included type 2 sits between them, because
		// next_marker(2) == 3 justifies the jump.
		let inc2: BTreeSet<u64> = [2u64].into_iter().collect();
		assert!(super::validate_omitted_markers(&[1, 3], &inc2).is_ok());
		// A marker equal to an included type is rejected.
		assert!(super::validate_omitted_markers(&[2], &inc2).is_err());

		// The signature-gap jump is accepted when justified by an included type at the top of the
		// low range: included 239, omitted marker 1_000_000_000 (next_marker(239)).
		let inc239: BTreeSet<u64> = [239u64].into_iter().collect();
		assert!(super::validate_omitted_markers(&[1_000_000_000], &inc239).is_ok());
		// ...but not without that justification.
		assert!(super::validate_omitted_markers(&[1_000_000_000], &none).is_err());
	}
}
