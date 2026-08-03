use std::sync::Mutex;

use alloy_consensus::TxEnvelope;
use alloy_primitives::Address;
use dkg_core::{PartyId, RecordId};
use dkg_protocol::{PCQc, RegistrationCall};

use super::*;
use crate::chain::{DkgChain, DkgTransactionContext};

#[test]
fn cursor_reads_snapshot_then_finalized_blocks_in_order() {
    let session = test_session();
    let mut reader = ChainEventReader::default();
    reader.notify_finalized(SeqNum(12));
    reader.notify_finalized(SeqNum(11));
    reader.start_session(session);

    let snapshot = reader.next_read().unwrap();
    assert_eq!(snapshot, ChainRead::Snapshot(session));
    assert!(
        !reader
            .complete(snapshot, vec![pc_event(10)])
            .recovery_complete_after
    );

    let block_11 = reader.next_read().unwrap();
    assert_eq!(block_11, ChainRead::Block(SeqNum(11), session));
    assert!(
        !reader
            .complete(block_11, vec![pc_event(11)])
            .recovery_complete_after
    );

    let block_12 = reader.next_read().unwrap();
    assert_eq!(block_12, ChainRead::Block(SeqNum(12), session));
    assert!(
        reader
            .complete(block_12, vec![pc_event(12)])
            .recovery_complete_after
    );
    assert!(reader.next_read().is_none());
}

#[test]
fn read_job_uses_snapshot_then_receipts() {
    let chain = RecordingChain::default();
    let session = test_session();
    let snapshot = chain
        .read_events(ChainRead::Snapshot(session))
        .unwrap()
        .unwrap();
    let block = chain
        .read_events(ChainRead::Block(SeqNum(11), session))
        .unwrap()
        .unwrap();

    assert_eq!(snapshot[0].record_id(), RecordId(10));
    assert_eq!(block[0].record_id(), RecordId(11));
    assert_eq!(
        *chain.reads.lock().unwrap(),
        vec![(true, SeqNum(10)), (false, SeqNum(11))]
    );
}

fn test_session() -> ChainEventSession {
    ChainEventSession {
        epoch: Epoch(2),
        party_count: 4,
        recovery_block: SeqNum(10),
    }
}

#[derive(Default)]
struct RecordingChain {
    reads: Mutex<Vec<(bool, SeqNum)>>,
}

impl DkgChain for RecordingChain {
    fn read_registrations(
        &self,
        _block: SeqNum,
        _epoch: Epoch,
        _parties: &[Address],
    ) -> Result<Option<Vec<RegistrationCall>>, crate::DkgError> {
        unreachable!()
    }

    fn read_events(&self, read: ChainRead) -> Result<Option<Vec<ChainEvent>>, crate::DkgError> {
        self.reads
            .lock()
            .unwrap()
            .push((matches!(read, ChainRead::Snapshot(_)), read.block()));
        Ok(Some(vec![pc_event(read.block().0)]))
    }

    fn transaction_context(
        &self,
        _block: SeqNum,
        _address: Address,
    ) -> Result<DkgTransactionContext, crate::DkgError> {
        unreachable!()
    }

    fn submit_transaction(&self, _transaction: TxEnvelope) -> Result<(), crate::DkgError> {
        unreachable!()
    }
}

fn pc_event(sequence: u64) -> ChainEvent {
    ChainEvent::PCQc {
        record_id: RecordId(sequence),
        qc: PCQc {
            dealer: PartyId(0),
            digest: [sequence as u8; 32],
            signatures: Vec::new(),
        },
    }
}
