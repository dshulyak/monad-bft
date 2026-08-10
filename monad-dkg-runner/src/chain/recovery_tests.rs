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
    let mut scan = SessionScan::new(session, SeqNum(12));

    let snapshot = scan.next(SeqNum(12)).unwrap();
    assert_eq!(snapshot, ChainRead::Snapshot(session));
    assert!(!scan.advance(snapshot));

    let block_11 = scan.next(SeqNum(12)).unwrap();
    assert_eq!(block_11, ChainRead::Block(SeqNum(11), session));
    assert!(!scan.advance(block_11));

    let block_12 = scan.next(SeqNum(12)).unwrap();
    assert_eq!(block_12, ChainRead::Block(SeqNum(12), session));
    assert!(scan.advance(block_12));
    assert!(scan.next(SeqNum(12)).is_none());
}

#[test]
fn cursor_enters_live_phase_after_snapshot() {
    let session = test_session();
    let mut scan = SessionScan::new(session, session.recovery_block);

    let snapshot = scan.next(SeqNum(10)).unwrap();
    assert!(scan.advance(snapshot));

    let block = scan.next(SeqNum(11)).unwrap();
    assert_eq!(block, ChainRead::Block(SeqNum(11), session));
    assert!(!scan.advance(block));
    assert!(scan.next(SeqNum(11)).is_none());
}

#[test]
fn newer_sync_boundary_restarts_the_snapshot() {
    let session = test_session();
    let mut scan = SessionScan::new(session, SeqNum(12));
    scan.restart(SeqNum(11), SeqNum(12));

    let restarted = ChainEventSession {
        recovery_block: SeqNum(11),
        ..session
    };
    assert_eq!(scan.next(SeqNum(12)), Some(ChainRead::Snapshot(restarted)));
}

#[test]
fn read_job_uses_snapshot_then_receipts() {
    let chain = RecordingChain::default();
    let session = test_session();
    let snapshot = chain.read_events(ChainRead::Snapshot(session)).unwrap();
    let block = chain
        .read_events(ChainRead::Block(SeqNum(11), session))
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
    ) -> Result<Vec<RegistrationCall>, crate::DkgError> {
        unreachable!()
    }

    fn read_events(&self, read: ChainRead) -> Result<Vec<ChainEvent>, crate::DkgError> {
        self.reads
            .lock()
            .unwrap()
            .push((matches!(read, ChainRead::Snapshot(_)), read.block()));
        Ok(vec![pc_event(read.block().0)])
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
