use std::sync::Mutex;

use dkg_core::{PartyId, RecordId};
use dkg_protocol::PCQc;

use super::*;

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
            .unwrap()
            .recovery_complete_after
    );

    let block_11 = reader.next_read().unwrap();
    assert_eq!(block_11, ChainRead::Block(SeqNum(11), session));
    assert!(
        !reader
            .complete(block_11, vec![pc_event(11)])
            .unwrap()
            .recovery_complete_after
    );

    let block_12 = reader.next_read().unwrap();
    assert_eq!(block_12, ChainRead::Block(SeqNum(12), session));
    assert!(
        reader
            .complete(block_12, vec![pc_event(12)])
            .unwrap()
            .recovery_complete_after
    );
    assert!(reader.next_read().is_none());
}

#[test]
fn snapshot_is_sorted_and_duplicate_sequence_is_rejected() {
    let session = test_session();
    let mut reader = ChainEventReader::default();
    reader.start_session(session);
    let read = reader.next_read().unwrap();
    let batch = reader
        .complete(read, vec![pc_event(9), pc_event(3), pc_event(7)])
        .unwrap();
    assert_eq!(
        batch
            .events
            .iter()
            .map(ChainEvent::record_id)
            .collect::<Vec<_>>(),
        vec![RecordId(3), RecordId(7), RecordId(9)]
    );

    let mut reader = ChainEventReader::default();
    reader.start_session(session);
    let read = reader.next_read().unwrap();
    assert!(matches!(
        reader
            .complete(read, vec![pc_event(3), pc_event(3)])
            .unwrap_err(),
        crate::DkgError::DuplicateRecoverySequence { sequence: 3 }
    ));
}

#[test]
fn read_job_uses_snapshot_then_receipts() {
    let chain = RecordingChain::default();
    let session = test_session();
    let snapshot = read_chain(&chain, Address::ZERO, ChainRead::Snapshot(session))
        .unwrap()
        .unwrap();
    let block = read_chain(&chain, Address::ZERO, ChainRead::Block(SeqNum(11), session))
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
    fn read_recovery_state(
        &self,
        block: SeqNum,
        _contract: Address,
        _epoch: Epoch,
        _party_count: usize,
    ) -> Result<Option<Vec<ChainEvent>>, crate::DkgError> {
        self.reads.lock().unwrap().push((true, block));
        Ok(Some(vec![pc_event(block.0)]))
    }

    fn read_finalized_events(
        &self,
        block: SeqNum,
        _contract: Address,
        _epoch: Epoch,
        _party_count: usize,
    ) -> Result<Option<Vec<ChainEvent>>, crate::DkgError> {
        self.reads.lock().unwrap().push((false, block));
        Ok(Some(vec![pc_event(block.0)]))
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
