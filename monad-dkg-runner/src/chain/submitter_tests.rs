use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use alloy_consensus::Transaction;
use dkg_core::{PartyId, RecordId, SessionId};
use dkg_crypto::{BlsG2SerializedBytes, BLS_G2_SERIALIZED_BYTES};
use dkg_protocol::{ChainCall, DkgDoneQc, PCQc, QcSignature, QcSignatureBytes};
use monad_types::{Epoch, SeqNum};

use super::*;
use crate::{
    chain::{ChainRead, DkgTransactionContext},
    DkgLocalKeyMaterial,
};

#[test]
fn encodes_post_pc_qc_contract_calldata() {
    let qc = PCQc {
        dealer: PartyId(7),
        digest: [0x11; 32],
        signatures: vec![sig(0)],
    };
    let call = ChainCall::PostPCQc { qc: qc.clone() };
    let calldata = test_tx_config()
        .calldata(Epoch(9), &call, Address::ZERO)
        .unwrap();
    assert_eq!(
        calldata,
        DkgContract::postPcQcCall {
            epoch: 9,
            qc: (&qc).into(),
        }
        .abi_encode()
    );
}

#[test]
fn encodes_submit_result_contract_calldata() {
    let qc = DkgDoneQc {
        epoch: SessionId(9),
        g2x: BlsG2SerializedBytes([0x22; BLS_G2_SERIALIZED_BYTES]),
        signatures: vec![sig(0)],
    };
    let call = ChainCall::PostDkgResult { qc: qc.clone() };
    let calldata = test_tx_config()
        .calldata(Epoch(9), &call, Address::ZERO)
        .unwrap();
    assert_eq!(
        calldata,
        DkgContract::submitResultCall {
            epoch: 9,
            result: (&qc).into(),
        }
        .abi_encode()
    );
}

#[test]
fn submission_waits_for_chain_recovery_gate() {
    let (mut service, local_rx) = test_submitter(5, Arc::new(AtomicUsize::new(0)));
    service.start_session(Epoch(2));
    service.submit(Epoch(2), pc_call(pc_qc(1, 0x11)));

    assert!(local_rx.try_recv().is_err());
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), false);
    assert!(local_rx.try_recv().is_err());

    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);
    assert!(local_rx.recv_timeout(Duration::from_secs(1)).is_ok());
}

#[test]
fn retries_same_local_transaction_on_finalized_blocks_until_matching_event() {
    let nonce_reads = Arc::new(AtomicUsize::new(0));
    let qc = pc_qc(7, 0x11);
    let event = ChainEvent::PCQc {
        record_id: RecordId(42),
        qc: qc.clone(),
    };
    let (mut service, local_rx) = test_submitter(5, Arc::clone(&nonce_reads));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);

    service.submit(Epoch(2), pc_call(qc));
    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(first.is_eip1559());
    service.finalized_block(Epoch(2), SeqNum(11), Vec::new(), false);
    let second = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(first, second);
    assert_eq!(decode_nonce(&first), 5);
    assert_eq!(nonce_reads.load(Ordering::SeqCst), 2);

    service.finalized_block(Epoch(2), SeqNum(12), vec![event], false);
    service.finalized_block(Epoch(2), SeqNum(13), Vec::new(), false);
    assert!(local_rx.try_recv().is_err());
}

#[test]
fn registration_retries_same_transaction_until_finalized_state_confirms_it() {
    let nonce_reads = Arc::new(AtomicUsize::new(0));
    let (mut service, local_rx) = test_submitter(5, Arc::clone(&nonce_reads));
    let registration = DkgLocalKeyMaterial::derive([0x01; 32])
        .registration(service.signer_address().into_array(), 2)
        .unwrap();

    service.submit_registration(Epoch(2), SeqNum(10), registration);
    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    service.retry_registration(Epoch(2), SeqNum(11));
    let second = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(second, first);
    assert_eq!(decode_nonce(&second), 5);
    assert_eq!(nonce_reads.load(Ordering::SeqCst), 2);

    service.confirm_registration(Epoch(2), &registration);
    service.retry_registration(Epoch(2), SeqNum(12));
    assert!(local_rx.try_recv().is_err());
}

#[test]
fn nonce_read_uses_the_scanned_event_block() {
    let context_block = Arc::new(AtomicU64::new(0));
    let (mut service, local_rx) = test_submitter_with_context_block(Arc::clone(&context_block));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(42), Vec::new(), true);
    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));

    local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(context_block.load(Ordering::SeqCst), 42);
}

#[test]
fn serializes_artifacts_without_leaving_a_nonce_gap() {
    let nonce_reads = Arc::new(AtomicUsize::new(0));
    let (mut service, local_rx) = test_submitter(11, Arc::clone(&nonce_reads));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);

    let first_qc = pc_qc(1, 1);
    let second_qc = pc_qc(2, 2);
    for qc in [first_qc.clone(), second_qc] {
        service.submit(Epoch(2), pc_call(qc));
    }

    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(local_rx.try_recv().is_err());

    service.finalized_block(
        Epoch(2),
        SeqNum(11),
        vec![ChainEvent::PCQc {
            record_id: RecordId(9),
            qc: first_qc,
        }],
        false,
    );
    let second = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(decode_nonce(&first), 11);
    assert_eq!(decode_nonce(&second), 11);
}

#[test]
fn retires_active_artifact_after_finalized_nonce_advances_without_event() {
    let nonce = Arc::new(AtomicU64::new(5));
    let (mut service, local_rx) =
        test_submitter_with_nonce(Arc::clone(&nonce), Arc::new(AtomicUsize::new(0)));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);
    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));

    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    nonce.store(6, Ordering::SeqCst);
    service.finalized_block(Epoch(2), SeqNum(11), Vec::new(), false);

    assert_eq!(decode_nonce(&first), 5);
    assert!(local_rx.try_recv().is_err());
    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));
    assert!(local_rx.try_recv().is_err());
}

#[test]
fn new_artifact_uses_newest_context_across_sessions() {
    let nonce = Arc::new(AtomicU64::new(5));
    let context_block = Arc::new(AtomicU64::new(0));
    let (mut service, local_rx) = test_submitter_with_context_and_block(
        Arc::clone(&nonce),
        Arc::new(AtomicU64::new(100)),
        Arc::new(AtomicUsize::new(0)),
        Arc::clone(&context_block),
    );
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);
    let registration = DkgLocalKeyMaterial::derive([0x01; 32])
        .registration(service.signer_address().into_array(), 3)
        .unwrap();
    service.submit_registration(Epoch(3), SeqNum(20), registration);
    local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    service.confirm_registration(Epoch(3), &registration);
    nonce.store(6, Ordering::SeqCst);

    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));
    let transaction = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    assert_eq!(decode_nonce(&transaction), 6);
    assert_eq!(context_block.load(Ordering::SeqCst), 20);
}

#[test]
fn active_artifact_keeps_its_epoch_context() {
    let context_block = Arc::new(AtomicU64::new(0));
    let (mut service, local_rx) = test_submitter_with_context_block(Arc::clone(&context_block));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);
    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));
    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let registration = DkgLocalKeyMaterial::derive([0x01; 32])
        .registration(service.signer_address().into_array(), 3)
        .unwrap();
    service.submit_registration(Epoch(3), SeqNum(20), registration);

    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), false);
    let retry = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    assert_eq!(retry, first);
    assert_eq!(context_block.load(Ordering::SeqCst), 10);
}

#[test]
fn retry_does_not_replace_with_nonce_from_older_context() {
    let nonce = Arc::new(AtomicU64::new(6));
    let (mut service, local_rx) =
        test_submitter_with_nonce(Arc::clone(&nonce), Arc::new(AtomicUsize::new(0)));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);
    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));
    let prepared = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    nonce.store(5, Ordering::SeqCst);
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), false);
    let retry = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    assert_eq!(decode_nonce(&prepared), 6);
    assert_eq!(retry, prepared);
}

#[test]
fn reprepares_active_artifact_when_buffered_base_fee_increases() {
    let nonce = Arc::new(AtomicU64::new(5));
    let base_fee = Arc::new(AtomicU64::new(100));
    let (mut service, local_rx) = test_submitter_with_context(
        Arc::clone(&nonce),
        Arc::clone(&base_fee),
        Arc::new(AtomicUsize::new(0)),
    );
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);
    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));

    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(decode_max_fee_per_gas(&first), 151);

    base_fee.store(200, Ordering::SeqCst);
    service.finalized_block(Epoch(2), SeqNum(11), Vec::new(), false);
    let second = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    assert_eq!(decode_nonce(&second), 5);
    assert_eq!(decode_max_fee_per_gas(&second), 301);
    assert_ne!(first, second);
}

#[test]
fn recovered_finalized_event_suppresses_late_submission() {
    let (mut service, local_rx) = test_submitter(5, Arc::new(AtomicUsize::new(0)));
    service.start_session(Epoch(2));
    let qc = pc_qc(3, 0x77);
    service.finalized_block(
        Epoch(2),
        SeqNum(10),
        vec![ChainEvent::PCQc {
            record_id: RecordId(9),
            qc: qc.clone(),
        }],
        true,
    );
    service.submit(Epoch(2), pc_call(qc));

    assert!(local_rx.try_recv().is_err());
}

#[test]
fn overlapping_session_accepts_late_calls_from_previous_epoch() {
    let (mut service, local_rx) = test_submitter(5, Arc::new(AtomicUsize::new(0)));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), SeqNum(10), Vec::new(), true);
    service.start_session(Epoch(3));
    service.finalized_block(Epoch(3), SeqNum(20), Vec::new(), true);
    let previous = pc_call(pc_qc(2, 2));
    service.submit(Epoch(2), previous.clone());

    let transaction = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let expected = service
        .reliable
        .strategy()
        .config
        .calldata(Epoch(2), &previous, service.signer_address())
        .unwrap();
    assert_eq!(transaction.input().as_ref(), expected.as_slice(),);
    assert!(local_rx.try_recv().is_err());
}

#[test]
fn third_session_evicts_oldest_epoch_and_rejects_its_late_calls() {
    let (mut service, local_rx) = test_submitter(5, Arc::new(AtomicUsize::new(0)));
    for epoch in [Epoch(2), Epoch(3), Epoch(4)] {
        service.start_session(epoch);
        service.finalized_block(epoch, SeqNum(epoch.0 * 10), Vec::new(), true);
    }

    service.submit(Epoch(2), pc_call(pc_qc(2, 2)));
    let current = pc_call(pc_qc(4, 4));
    service.submit(Epoch(4), current.clone());

    let transaction = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let expected = service
        .reliable
        .strategy()
        .config
        .calldata(Epoch(4), &current, service.signer_address())
        .unwrap();
    assert_eq!(transaction.input().as_ref(), expected.as_slice());
    assert!(local_rx.try_recv().is_err());
}

struct TestChain {
    nonce: Arc<AtomicU64>,
    base_fee: Arc<AtomicU64>,
    reads: Arc<AtomicUsize>,
    context_block: Arc<AtomicU64>,
    transactions: flume::Sender<TxEnvelope>,
}

impl DkgChain for TestChain {
    fn read_registrations(
        &self,
        _block: SeqNum,
        _epoch: Epoch,
        _parties: &[Address],
    ) -> Result<Vec<RegistrationCall>, crate::DkgError> {
        unreachable!()
    }

    fn read_events(&self, _read: ChainRead) -> Result<Vec<ChainEvent>, crate::DkgError> {
        unreachable!()
    }

    fn transaction_context(
        &self,
        block: SeqNum,
        _address: Address,
    ) -> Result<DkgTransactionContext, crate::DkgError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.context_block.store(block.0, Ordering::SeqCst);
        Ok(DkgTransactionContext {
            nonce: self.nonce.load(Ordering::SeqCst),
            base_fee_per_gas: self.base_fee.load(Ordering::SeqCst),
        })
    }

    fn submit_transaction(&self, transaction: TxEnvelope) -> Result<(), crate::DkgError> {
        self.transactions
            .send(transaction)
            .map_err(|_| crate::DkgError::ChannelClosed("recording a test DKG transaction"))
    }
}

fn test_submitter(
    nonce: u64,
    reads: Arc<AtomicUsize>,
) -> (TxSubmitter, flume::Receiver<TxEnvelope>) {
    test_submitter_with_nonce(Arc::new(AtomicU64::new(nonce)), reads)
}

fn test_submitter_with_nonce(
    nonce: Arc<AtomicU64>,
    reads: Arc<AtomicUsize>,
) -> (TxSubmitter, flume::Receiver<TxEnvelope>) {
    test_submitter_with_context(nonce, Arc::new(AtomicU64::new(100)), reads)
}

fn test_submitter_with_context(
    nonce: Arc<AtomicU64>,
    base_fee: Arc<AtomicU64>,
    reads: Arc<AtomicUsize>,
) -> (TxSubmitter, flume::Receiver<TxEnvelope>) {
    test_submitter_with_context_and_block(nonce, base_fee, reads, Arc::new(AtomicU64::new(0)))
}

fn test_submitter_with_context_block(
    context_block: Arc<AtomicU64>,
) -> (TxSubmitter, flume::Receiver<TxEnvelope>) {
    test_submitter_with_context_and_block(
        Arc::new(AtomicU64::new(5)),
        Arc::new(AtomicU64::new(100)),
        Arc::new(AtomicUsize::new(0)),
        context_block,
    )
}

fn test_submitter_with_context_and_block(
    nonce: Arc<AtomicU64>,
    base_fee: Arc<AtomicU64>,
    reads: Arc<AtomicUsize>,
    context_block: Arc<AtomicU64>,
) -> (TxSubmitter, flume::Receiver<TxEnvelope>) {
    let (transactions, receiver) = flume::unbounded();
    let chain = Arc::new(TestChain {
        nonce,
        base_fee,
        reads,
        context_block,
        transactions,
    });
    let config = DkgChainConfig::new([0x01; 32], Address::repeat_byte(0x22), 0x4eaf);
    (TxSubmitter::new(&config, chain).unwrap(), receiver)
}

fn test_tx_config() -> TxConfig {
    TxConfig {
        contract: Address::repeat_byte(0x22),
        chain_id: 0x4eaf,
        gas_limit: crate::chain::DEFAULT_TX_GAS_LIMIT,
        max_priority_fee_per_gas: crate::chain::DEFAULT_TX_MAX_PRIORITY_FEE_PER_GAS,
    }
}

fn pc_call(qc: PCQc) -> ChainCall {
    ChainCall::PostPCQc { qc }
}

fn pc_qc(dealer: u32, byte: u8) -> PCQc {
    PCQc {
        dealer: PartyId(dealer),
        digest: [byte; 32],
        signatures: vec![sig(0)],
    }
}

fn sig(signer: u32) -> QcSignature {
    QcSignature {
        signer: PartyId(signer),
        signature: QcSignatureBytes([signer as u8; 64]),
    }
}

fn decode_nonce(tx: &TxEnvelope) -> u64 {
    tx.nonce()
}

fn decode_max_fee_per_gas(tx: &TxEnvelope) -> u128 {
    tx.max_fee_per_gas()
}
