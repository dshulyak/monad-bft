use dkg_protocol::{
    DkgMessageId, DkgMessageKey, TAG_PC_ACK, TAG_PC_PROPOSAL, TAG_PC_RETRIEVAL_REQUEST,
};
use monad_types::Epoch;

use super::{
    super::wal::{RecoveryWal, RecoveryWalConfig},
    *,
};
fn proposal_id(dealer: PartyId, receivers: impl IntoIterator<Item = PartyId>) -> DkgMessageId {
    DkgMessageId::new(
        receivers
            .into_iter()
            .map(|receiver| DkgMessageKey::PcProposal { dealer, receiver }),
    )
    .unwrap()
}

#[test]
fn restart_keeps_one_semantic_slot_and_skips_ephemeral_messages() {
    let dir = tempfile::tempdir().unwrap();
    let epoch = Epoch(12);
    let self_party = PartyId(0);
    let wal = RecoveryWal::open(
        dir.path(),
        epoch,
        RecoveryWalConfig {
            preallocate_bytes: 0,
            max_epochs: 2,
        },
    )
    .unwrap()
    .0;
    let path = wal.path().to_path_buf();
    let mut store = DkgMessageStore::load(self_party, 4, 3, wal, RecoveryState::default());
    let recipients = [PartyId(1), PartyId(2), PartyId(3)].into();
    let proposal = [TAG_PC_PROPOSAL, 0x11];
    assert!(store
        .accept_outgoing(
            recipients,
            DkgMessage::decode(Bytes::copy_from_slice(&proposal)).unwrap(),
        )
        .unwrap()
        .is_some());

    let mut request = vec![TAG_PC_RETRIEVAL_REQUEST];
    request.extend_from_slice(&[0; 64]);
    request.extend_from_slice(&self_party.0.to_le_bytes());
    request.extend_from_slice(&[0; 32]);
    for expected in [true, false] {
        assert_eq!(
            store
                .accept_outgoing(
                    [PartyId(3)].into(),
                    DkgMessage::decode(request.clone()).unwrap(),
                )
                .unwrap()
                .is_some(),
            expected
        );
    }

    let mut ack = vec![TAG_PC_ACK];
    ack.extend_from_slice(&[0x33; 96]);
    let ack_id = DkgMessageId::single(DkgMessageKey::PcAck {
        dealer: self_party,
        signer: PartyId(3),
    });
    for expected in [IncomingStatus::New, IncomingStatus::Conflict] {
        let record = IncomingMessageRecord {
            source: PartyId(3),
            message_id: ack_id.clone(),
            payload: ack.clone().into(),
        };
        let identity = store
            .classify(record.source, self_party, &record.payload)
            .unwrap();
        assert_eq!(store.accept_incoming(record, &identity).unwrap(), expected);
        ack[1] ^= 1;
    }
    assert_eq!(store.incoming_count(), 1);
    let response = store
        .classify(PartyId(3), self_party, &ack)
        .expect("PC acknowledgement identity");
    let (completed_key, target) = response
        .completed_outgoing()
        .next()
        .expect("PC acknowledgement completes proposal");
    assert_eq!(
        store.complete_key(completed_key, target).unwrap(),
        Some(proposal_id(
            self_party,
            [PartyId(1), PartyId(2), PartyId(3)]
        ))
    );
    drop(store);

    let recovery = RecoveryState::load(&path).unwrap();
    assert_eq!(recovery.outbox.len(), 1);
    assert_eq!(recovery.incoming.len(), 1);
    let wal = RecoveryWal::open(
        dir.path(),
        epoch,
        RecoveryWalConfig {
            preallocate_bytes: 0,
            max_epochs: 2,
        },
    )
    .unwrap()
    .0;
    let mut store = DkgMessageStore::load(self_party, 4, 3, wal, recovery);
    assert_eq!(store.outgoing_records()[0].payload.as_ref(), proposal);
    assert!(store.is_complete(
        &proposal_id(self_party, [PartyId(1), PartyId(2), PartyId(3)]),
        PartyId(3)
    ));
    assert!(store
        .accept_outgoing(
            [PartyId(1), PartyId(2), PartyId(3)].into(),
            DkgMessage::decode(Bytes::copy_from_slice(&proposal)).unwrap(),
        )
        .unwrap()
        .is_none());
}
