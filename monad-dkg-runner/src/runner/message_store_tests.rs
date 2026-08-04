use bytes::Bytes;
use dkg_core::PartyId;
use dkg_protocol::{
    DkgMessage, DkgMessageId, DkgMessageKey, TAG_PC_ACK, TAG_PC_PROPOSAL, TAG_PC_RETRIEVAL_REQUEST,
};
use monad_types::Epoch;

use super::*;
use crate::{
    recovery::{RecoveryState, RecoveryWal, RecoveryWalConfig},
    reliable::{IncomingRecord, IncomingStatus},
};

#[test]
fn durable_store_rejects_sync_messages_and_recovers_semantic_slots() {
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
    let mut store = DkgDurableStore::load(self_party, 4, 3, wal, RecoveryState::default());
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
    assert!(matches!(
        store.accept_outgoing([PartyId(3)].into(), DkgMessage::decode(request).unwrap(),),
        Err(DkgDurableStoreError::SyncMessage)
    ));

    let mut ack = vec![TAG_PC_ACK];
    ack.extend_from_slice(&[0x33; 96]);
    let ack_id = DkgMessageId::single(DkgMessageKey::PcAck {
        dealer: self_party,
        signer: PartyId(3),
    });
    for expected in [IncomingStatus::New, IncomingStatus::Conflict] {
        let record = IncomingRecord {
            source: PartyId(3),
            message_id: ack_id.clone(),
            payload: Bytes::from(ack.clone()),
        };
        let identity = store
            .classify(record.source, self_party, &record.payload)
            .unwrap();
        assert_eq!(store.accept_incoming(record, &identity).unwrap(), expected);
        ack[1] ^= 1;
    }
    assert_eq!(store.incoming_count(), 1);
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
    let mut store = DkgDurableStore::load(self_party, 4, 3, wal, recovery);
    assert_eq!(store.outgoing_records()[0].payload.as_ref(), proposal);
    assert!(store
        .accept_outgoing(
            [PartyId(1), PartyId(2), PartyId(3)].into(),
            DkgMessage::decode(Bytes::copy_from_slice(&proposal)).unwrap(),
        )
        .unwrap()
        .is_none());
}
