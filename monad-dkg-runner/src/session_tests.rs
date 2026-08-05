use dkg_core::{PartyId, RecordId, SessionId};
use dkg_crypto::{BLS_G2_SERIALIZED_BYTES, BlsG2SerializedBytes};
use dkg_protocol::{
    BveQc, ChainCall, ChainEvent, DkgDoneQc, DkgMessageId, DkgMessageKey, QcSignature,
    QcSignatureBytes, TAG_PC_ACK,
};
use monad_crypto::{NopKeyPair, NopSignature, certificate_signature::CertificateKeyPair};
use monad_types::{Epoch, NodeId};
use tempfile::TempDir;

use super::*;
use crate::test_registered_key_material;

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
fn session_submits_chain_call_and_processes_finalized_event() {
    let temp = TempDir::new().unwrap();
    let epoch = Epoch(11);
    let (mut session, wal_path) = test_session(temp.path(), epoch);

    let qc = DkgDoneQc {
        epoch: SessionId(epoch.0),
        g2x: BlsG2SerializedBytes([0x44; BLS_G2_SERIALIZED_BYTES]),
        signatures: vec![sig(0), sig(1), sig(2)],
    };
    session
        .handle_chain_call(ChainCall::PostDkgResult { qc: qc.clone() })
        .unwrap();
    assert_eq!(
        session.take_chain_calls(),
        vec![ChainCall::PostDkgResult { qc: qc.clone() }]
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
fn session_refuses_one_and_two_validator_sets() {
    for count in [1, 2] {
        let temp = TempDir::new().unwrap();
        let validators = test_validators(count);
        let epoch = Epoch(u64::from(count));
        let result = start::<NopSignature>(
            epoch,
            validators[0],
            validators,
            temp.path(),
            test_registered_key_material(PartyId(0), usize::from(count), epoch),
        );

        assert!(matches!(
            result,
            Err(DkgError::InsufficientValidators {
                actual,
                minimum: 4
            }) if actual == usize::from(count)
        ));
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
    assert!(session.delivery_outbound.is_empty());
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
    let mut session = DkgSession::new(SessionInit {
        epoch,
        self_party,
        mapping,
        engine_seed,
        key_material: test_registered_key_material(self_party, 4, epoch),
        recovery_wal: wal,
        recovery_state: recovery,
    })
    .unwrap();
    session.finish_chain_recovery().unwrap();
    session.take_chain_calls();
    session.take_delivery_outbound();
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
