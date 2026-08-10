use alloy_primitives::{Address, U256};
use dkg_core::{PartyId, RecordId, SessionId};
use dkg_crypto::{BlsG2SerializedBytes, BLS_G2_SERIALIZED_BYTES};
use dkg_protocol::{
    BveQc, ChainCall, ChainEvent, DkgDoneQc, DkgMessageId, DkgMessageKey, NativeVotingWeight,
    QcSignature, QcSignatureBytes, TAG_PC_ACK,
};
use monad_crypto::{certificate_signature::CertificateKeyPair, NopKeyPair, NopSignature};
use monad_types::{Epoch, NodeId};
use tempfile::TempDir;

use super::*;
use crate::{test_registered_key_material, test_registered_session, DkgValidator};

#[test]
fn retrieval_response_completes_its_request() {
    let dealer = PartyId(2);
    let requester = PartyId(0);
    let responder = PartyId(1);
    let response = DkgMessage::PcRetrievalResponse {
        dealer,
        bytes: Bytes::new(),
    };

    assert_eq!(
        request_completed_by_response(&response, requester, responder),
        Some(DkgMessageId::single(DkgMessageKey::PcRetrievalRequest {
            dealer,
            requester,
            responder,
        }))
    );
}

#[test]
fn voting_weights_round_wei_to_nearest_mon() {
    let unit = U256::from(1_000_000_000_000_000_000_u64);
    assert_eq!(
        decode_voting_weights(&[
            monad_types::Stake(unit * U256::from(4) + unit * U256::from(49) / U256::from(100)),
            monad_types::Stake(unit * U256::from(3) + unit / U256::from(2)),
            monad_types::Stake(unit * U256::from(2) - U256::from(1)),
        ])
        .unwrap(),
        [4, 4, 2].map(NativeVotingWeight::new).to_vec()
    );

    assert!(decode_voting_weights(&[monad_types::Stake(unit / U256::from(3))]).is_err());
}

#[test]
fn session_submits_chain_call_and_processes_finalized_event() {
    let temp = TempDir::new().unwrap();
    let epoch = Epoch(11);
    let (mut session, wal_path) = test_session(temp.path(), epoch);

    let qc = DkgDoneQc {
        epoch: SessionId(epoch.0),
        session_id: [0x55; 32],
        g2x: BlsG2SerializedBytes([0x44; BLS_G2_SERIALIZED_BYTES]),
        signatures: vec![sig(0), sig(1), sig(2)],
    };
    session
        .handle_chain_call(ChainCall::PostDkgResult { qc: qc.clone() })
        .unwrap();
    let effects = session.take_effects();
    assert_eq!(effects.len(), 1);
    let SessionEffect::Chain(submitted) = &effects[0] else {
        panic!("expected DKG result chain effect");
    };
    assert_eq!(
        submitted.as_ref(),
        &ChainCall::PostDkgResult { qc: qc.clone() }
    );
    let wal_len = std::fs::metadata(&wal_path).unwrap().len();

    let event = ChainEvent::DkgResultRecorded {
        record_id: RecordId(77),
        qc,
    };
    session.handle_chain_event(event.clone()).unwrap();
    assert_eq!(std::fs::metadata(&wal_path).unwrap().len(), wal_len);
    assert!(session.pending_inputs.is_empty());

    let pending_before = session.pending_inputs.len();
    for dealer in 0..3 {
        session
            .pending_inputs
            .push_back(PendingEngineInput::Chain(ChainEvent::BveQcFinalized {
                record_id: RecordId(100 + u64::from(dealer)),
                qc: BveQc {
                    dealer: PartyId(dealer),
                    digest: [dealer as u8; 32],
                    commitment_digest: [dealer as u8 + 1; 32],
                    signatures: vec![sig(0), sig(1), sig(2)],
                },
            }));
    }
    assert_eq!(session.pending_inputs.len(), pending_before + 3);
}

#[test]
fn session_accepts_one_and_two_validator_sets_without_fault_tolerance() {
    for count in [1, 2] {
        let temp = TempDir::new().unwrap();
        let validators = test_validators(count);
        let epoch = Epoch(u64::from(count));
        let self_id = validators[0];
        let validators = validators
            .into_iter()
            .enumerate()
            .map(|(index, node_id)| DkgValidator {
                node_id,
                address: Address::from([index as u8 + 1; 20]),
                stake: monad_types::Stake(U256::from(WEI_PER_MON)),
            })
            .collect();
        let registered = test_registered_session(PartyId(0), validators, epoch);
        let result = start::<NopSignature>(epoch, self_id, temp.path(), registered);

        assert!(result.unwrap().is_some());
    }
}

#[test]
fn protocol_rejection_is_not_persisted_or_dispatched() {
    let temp = TempDir::new().unwrap();
    let epoch = Epoch(19);
    let validators = test_validators(4);
    let (mut session, wal_path) = test_session(temp.path(), epoch);
    let sender = validators[1];
    let mut invalid_ack = vec![TAG_PC_ACK];
    invalid_ack.extend_from_slice(&[0; 96]);
    let payload = Bytes::from(invalid_ack);

    for _ in 0..2 {
        session
            .handle_network_message(sender, payload.clone())
            .unwrap();
    }

    assert!(RecoveryState::load(&wal_path).unwrap().incoming.is_empty());
    assert!(session.effects.is_empty());
}

fn test_session(
    root: &std::path::Path,
    epoch: Epoch,
) -> (DkgSession<NopSignature>, std::path::PathBuf) {
    let validators = test_validators(4);
    let mapping = DkgPeerMap::<NopSignature>::new_ordered(validators.clone()).unwrap();
    let self_party = mapping.party_id(&validators[0]).unwrap();
    let (mut wal, _) = RecoveryWal::open(
        root,
        epoch,
        RecoveryWalConfig {
            preallocate_bytes: 0,
            max_epochs: 2,
        },
    )
    .unwrap();
    let wal_path = wal.path().to_path_buf();
    let mut recovery = RecoveryState::default();
    let engine_seed = recovery.load_or_create_engine_seed(&mut wal).unwrap();
    let (local_keys, parties) = test_registered_key_material(
        self_party,
        4,
        epoch,
        vec![NativeVotingWeight::new(1); validators.len()],
    );
    let mut session = DkgSession::new(SessionInit {
        epoch,
        self_party,
        mapping,
        parties,
        output_count: DKG_OUTPUT_COUNT,
        engine_seed,
        local_keys,
        recovery_wal: wal,
        recovery_state: recovery,
    })
    .unwrap();
    session.finish_chain_recovery().unwrap();
    session.take_effects();
    (session, wal_path)
}

fn test_validators(count: u8) -> Vec<NodeId<CertificateSignaturePubKey<NopSignature>>> {
    (0..count)
        .map(|seed| {
            let mut bytes = [seed.saturating_add(1); 32];
            let keypair = NopKeyPair::from_bytes(&mut bytes).unwrap();
            NodeId::new(keypair.pubkey())
        })
        .collect()
}

fn sig(signer: u32) -> QcSignature {
    QcSignature {
        signer: PartyId(signer),
        signature: QcSignatureBytes([signer as u8; 64]),
    }
}
