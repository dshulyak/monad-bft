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
use monad_types::Epoch;

use super::*;
use crate::{DkgLocalKeyMaterial, DkgTransactionContext};

#[test]
fn encodes_post_pc_qc_contract_calldata() {
    let qc = PCQc {
        dealer: PartyId(7),
        digest: [0x11; 32],
        signatures: vec![sig(0)],
    };
    let call = ChainCall::PostPCQc { qc: qc.clone() };
    let calldata = contract_calldata(Epoch(9), &call, Address::ZERO).unwrap();
    assert_eq!(
        calldata,
        DkgContract::postPcQcCall {
            epoch: 9,
            qc: pc_qc_to_contract(&qc),
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
    let calldata = contract_calldata(Epoch(9), &call, Address::ZERO).unwrap();
    assert_eq!(
        calldata,
        DkgContract::submitResultCall {
            epoch: 9,
            result: dkg_result_to_contract(&qc),
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
    service.finalized_block(Epoch(2), Vec::new(), false);
    assert!(local_rx.try_recv().is_err());

    service.finalized_block(Epoch(2), Vec::new(), true);
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
    service.finalized_block(Epoch(2), Vec::new(), true);

    service.submit(Epoch(2), pc_call(qc));
    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(first.is_eip1559());
    service.finalized_block(Epoch(2), Vec::new(), false);
    let second = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(first, second);
    assert_eq!(decode_nonce(&first), 5);
    assert_eq!(nonce_reads.load(Ordering::SeqCst), 2);

    service.finalized_block(Epoch(2), vec![event], false);
    service.finalized_block(Epoch(2), Vec::new(), false);
    assert!(local_rx.try_recv().is_err());
}

#[test]
fn registration_retries_same_transaction_until_finalized_state_confirms_it() {
    let nonce_reads = Arc::new(AtomicUsize::new(0));
    let (mut service, local_rx) = test_submitter(5, Arc::clone(&nonce_reads));
    let registration = DkgLocalKeyMaterial::derive([0x01; 32])
        .registration_bytes(service.signer_address().into_array(), 2)
        .unwrap();

    service.submit_registration(Epoch(2), registration.clone());
    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    service.retry_registration(Epoch(2));
    let second = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(second, first);
    assert_eq!(decode_nonce(&second), 5);
    assert_eq!(nonce_reads.load(Ordering::SeqCst), 2);

    service.confirm_registration(Epoch(2), &registration);
    service.retry_registration(Epoch(2));
    assert!(local_rx.try_recv().is_err());
}

#[test]
fn serializes_artifacts_without_leaving_a_nonce_gap() {
    let nonce_reads = Arc::new(AtomicUsize::new(0));
    let (mut service, local_rx) = test_submitter(11, Arc::clone(&nonce_reads));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), Vec::new(), true);

    let first_qc = pc_qc(1, 1);
    let second_qc = pc_qc(2, 2);
    for qc in [first_qc.clone(), second_qc] {
        service.submit(Epoch(2), pc_call(qc));
    }

    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(local_rx.try_recv().is_err());

    service.finalized_block(
        Epoch(2),
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
fn reprepares_active_artifact_after_finalized_nonce_advances() {
    let nonce = Arc::new(AtomicU64::new(5));
    let (mut service, local_rx) =
        test_submitter_with_nonce(Arc::clone(&nonce), Arc::new(AtomicUsize::new(0)));
    service.start_session(Epoch(2));
    service.finalized_block(Epoch(2), Vec::new(), true);
    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));

    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    nonce.store(6, Ordering::SeqCst);
    service.finalized_block(Epoch(2), Vec::new(), false);
    let second = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    assert_eq!(decode_nonce(&first), 5);
    assert_eq!(decode_nonce(&second), 6);
    assert_ne!(first, second);
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
    service.finalized_block(Epoch(2), Vec::new(), true);
    service.submit(Epoch(2), pc_call(pc_qc(1, 1)));

    let first = local_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(decode_max_fee_per_gas(&first), 151);

    base_fee.store(200, Ordering::SeqCst);
    service.finalized_block(Epoch(2), Vec::new(), false);
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
        vec![ChainEvent::PCQc {
            record_id: RecordId(9),
            qc: qc.clone(),
        }],
        true,
    );
    service.submit(Epoch(2), pc_call(qc));

    assert!(local_rx.try_recv().is_err());
}

struct TestChain {
    nonce: Arc<AtomicU64>,
    base_fee: Arc<AtomicU64>,
    reads: Arc<AtomicUsize>,
    transactions: flume::Sender<TxEnvelope>,
}

impl DkgChain for TestChain {
    fn transaction_context(
        &self,
        _address: Address,
    ) -> Result<DkgTransactionContext, crate::DkgError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
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
    let (transactions, receiver) = flume::unbounded();
    let chain = Arc::new(TestChain {
        nonce,
        base_fee,
        reads,
        transactions,
    });
    let config = DkgChainConfig::new([0x01; 32], Address::repeat_byte(0x22), 0x4eaf);
    (TxSubmitter::new(&config, chain).unwrap(), receiver)
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
