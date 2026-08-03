use dkg_core::{PartyId, RecordId, SessionId};
use dkg_crypto::{BlsG2SerializedBytes, BLS_G2_SERIALIZED_BYTES};
use dkg_protocol::{
    BveQc, ChainCall, ChainEvent, DkgDoneQc, DkgMessageId, DkgMessageKey, QcSignature,
    QcSignatureBytes, TAG_PC_ACK,
};
use monad_crypto::{certificate_signature::CertificateKeyPair, NopKeyPair, NopSignature};
use monad_types::{Epoch, NodeId};
use tempfile::TempDir;

use super::*;
use crate::session::test_registered_key_material;

#[test]
fn runner_submits_chain_call_and_processes_finalized_event() {
    let temp = TempDir::new().unwrap();
    let epoch = Epoch(11);
    let (mut runner, wal_path) = test_runner(temp.path(), epoch);

    let qc = DkgDoneQc {
        epoch: SessionId(epoch.0),
        g2x: BlsG2SerializedBytes([0x44; BLS_G2_SERIALIZED_BYTES]),
        signatures: vec![sig(0), sig(1), sig(2)],
    };
    runner
        .handle_chain_call(ChainCall::PostDkgResult { qc: qc.clone() })
        .unwrap();
    assert_eq!(
        runner.take_chain_calls(),
        vec![ChainCall::PostDkgResult { qc: qc.clone() }]
    );
    let wal_len = std::fs::metadata(&wal_path).unwrap().len();

    let event = ChainEvent::DkgResultRecorded {
        record_id: RecordId(77),
        qc,
    };
    runner.handle_chain_event(event.clone()).unwrap();
    assert_eq!(std::fs::metadata(&wal_path).unwrap().len(), wal_len);
    assert!(runner.pending_inputs.is_empty());

    let pending_before = runner.pending_inputs.len();
    for dealer in 0..3 {
        runner.enqueue_chain_event(ChainEvent::BveQcFinalized {
            record_id: RecordId(100 + u64::from(dealer)),
            qc: BveQc {
                dealer: PartyId(dealer),
                digest: [dealer as u8; 32],
                commitment_digest: [dealer as u8 + 1; 32],
                signatures: vec![sig(0), sig(1), sig(2)],
            },
        });
    }
    assert_eq!(runner.pending_inputs.len(), pending_before + 3);
}

#[test]
fn runner_refuses_one_and_two_validator_sets() {
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
fn protocol_rejection_is_not_persisted_or_acknowledged() {
    let temp = TempDir::new().unwrap();
    let epoch = Epoch(19);
    let validators = test_validators(4);
    let (mut runner, _) = test_runner(temp.path(), epoch);
    let sender = validators[1];
    let self_id = validators[0];
    let self_party = runner.self_party;
    let sender_party = runner.mapping.party_id(&sender).unwrap();

    let message_id = DkgMessageId::single(DkgMessageKey::PcAck {
        dealer: self_party,
        signer: sender_party,
    });
    let mut invalid_ack = vec![TAG_PC_ACK];
    invalid_ack.extend_from_slice(&[0; 96]);
    let mut sender_delivery = DeliveryEngine::<NopSignature>::new(epoch);
    let wire = sender_delivery
        .send(
            DkgSend {
                message_id,
                to: self_id,
                payload: invalid_ack.into(),
                abort_group: None,
            },
            Instant::now(),
        )
        .pop()
        .unwrap()
        .payload;

    for _ in 0..2 {
        runner.handle_network_message(sender, wire.clone()).unwrap();
    }

    assert!(runner.message_store.incoming_records().is_empty());
    assert!(runner.delivery_outbound.is_empty());
    assert!(sender_delivery.next_timer().is_some());
}

fn test_runner(root: &std::path::Path, epoch: Epoch) -> (Runner<NopSignature>, std::path::PathBuf) {
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
    let mut runner = Runner::new(RunnerInit {
        epoch,
        self_party,
        mapping,
        engine_seed,
        key_material: test_registered_key_material(self_party, 4, epoch),
        recovery_wal: wal,
        recovery_state: recovery,
    })
    .unwrap();
    runner.initialize().unwrap();
    runner.finish_chain_recovery().unwrap();
    runner.take_chain_calls();
    runner.take_delivery_outbound();
    (runner, wal_path)
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
