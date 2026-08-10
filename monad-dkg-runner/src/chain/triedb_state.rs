//! Triedb/eth-call implementation of a DKG recovery snapshot read.
//!
//! Recovery orchestration lives in `monad-dkg-runner`; this module only maps
//! one requested finalized state boundary to protocol chain events.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Signature, TxKind, U256};
use alloy_sol_types::SolCall;
use dkg_core::{RecordId, SessionId};
use dkg_protocol::{ChainEvent, RegistrationCall};
use monad_chain_config::{
    ETHEREUM_MAINNET_CHAIN_ID, HIVE_CHAIN_ID, MONAD_DEVNET_CHAIN_ID, MONAD_MAINNET_CHAIN_ID,
    MONAD_TESTNET_CHAIN_ID,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_ethcall::{CallResult, ChainId, EthCallResult};
use monad_execution_state_read::{
    ExecutionStateReadExt, ExecutionStateReadExtError, FinalizedEthCallRequest,
};
use monad_types::{Epoch, SeqNum};
use monad_validator::signature_collection::SignatureCollection;
use thiserror::Error;

use super::{ContractCodecError, ContractRecordPage, DkgContract};
use crate::DkgError;

const DKG_ETH_CALL_GAS_LIMIT: u64 = 5_000_000;
const MAX_RECORD_PAGE_SIZE: usize = 16;
const RECORD_PAGE_SIGNATURE_BUDGET: usize = 512;

#[derive(Debug, Error)]
pub(super) enum TriedbStateError {
    #[error("unsupported DKG eth-call chain ID {chain_id}")]
    UnsupportedChainId { chain_id: u64 },
    #[error(transparent)]
    StateRead(#[from] ExecutionStateReadExtError),
    #[error("DKG state at block {block} is not available yet")]
    NotAvailable { block: u64 },
    #[error("DKG contract {contract} has no code at block {block}")]
    ContractMissing { contract: Address, block: u64 },
    #[error("DKG {kind} count exceeds usize")]
    CountOverflow { kind: &'static str },
    #[error(transparent)]
    Contract(#[from] ContractCodecError),
    #[error("DKG record total changed from {expected} to {actual} within one finalized snapshot")]
    RecordTotalChanged { expected: u64, actual: u64 },
    #[error("failed to decode DKG contract call {signature} at block {block}")]
    CallDecode {
        signature: &'static str,
        block: u64,
        #[source]
        source: alloy_sol_types::Error,
    },
    #[error("DKG state eth-call failed at block {block}: {message} ({error_code:?})")]
    CallFailed {
        block: u64,
        message: String,
        error_code: EthCallResult,
    },
    #[error("DKG state eth-call reverted at block {block} ({trace_len} bytes)")]
    CallReverted { block: u64, trace_len: usize },
    #[error("invalid DKG contract record page at start {start}, next {next}, total {total}")]
    InvalidRecordPage { start: u64, next: u64, total: u64 },
}

impl TriedbStateError {
    pub(super) fn into_dkg_error(self, operation: &'static str) -> DkgError {
        match self {
            Self::NotAvailable { block } => DkgError::ChainDataUnavailable {
                block: SeqNum(block),
            },
            source => DkgError::operation(operation, source),
        }
    }
}

pub(super) struct TriedbDkgStateReader {
    chain_id: ChainId,
    numeric_chain_id: u64,
    execution_delay: SeqNum,
}

#[derive(Default)]
struct RecordSnapshot {
    total: Option<u64>,
    next: u64,
    events: Vec<ChainEvent>,
}

impl RecordSnapshot {
    fn accept(
        &mut self,
        page: ContractRecordPage,
        epoch: Epoch,
        party_count: usize,
        limit: u32,
    ) -> Result<bool, TriedbStateError> {
        let start = self.next;
        let ContractRecordPage {
            total,
            next,
            pcQcs,
            bveQcs,
            results,
        } = page;
        if let Some(expected) = self.total {
            if total != expected {
                return Err(TriedbStateError::RecordTotalChanged {
                    expected,
                    actual: total,
                });
            }
        } else {
            let count = usize::try_from(total)
                .map_err(|_| TriedbStateError::CountOverflow { kind: "record" })?;
            self.events.reserve(count);
            self.total = Some(total);
        }
        if next < start
            || next > total
            || next - start > u64::from(limit)
            || (next == start && start != total)
        {
            return Err(TriedbStateError::InvalidRecordPage { start, next, total });
        }

        let expected_count =
            usize::try_from(next - start).map_err(|_| TriedbStateError::CountOverflow {
                kind: "record page",
            })?;
        let mut page_events = Vec::with_capacity(expected_count);
        for record in pcQcs {
            page_events.push(
                record
                    .qc
                    .into_chain_event(RecordId(record.sequence), party_count)
                    .map_err(|_| TriedbStateError::InvalidRecordPage { start, next, total })?,
            );
        }
        for record in bveQcs {
            page_events.push(
                record
                    .qc
                    .into_chain_event(RecordId(record.sequence), party_count)
                    .map_err(|_| TriedbStateError::InvalidRecordPage { start, next, total })?,
            );
        }
        for record in results {
            let event = record
                .result
                .into_chain_event(RecordId(record.sequence), SessionId(epoch.0), party_count)
                .map_err(|_| TriedbStateError::InvalidRecordPage { start, next, total })?;
            page_events.push(event);
        }
        page_events.sort_unstable_by_key(|event| event.record_id());
        if page_events.len() != expected_count
            || page_events.iter().enumerate().any(|(offset, event)| {
                event.record_id().0
                    != start + u64::try_from(offset).expect("record page length fits in u64")
            })
        {
            return Err(TriedbStateError::InvalidRecordPage { start, next, total });
        }
        self.events.extend(page_events);
        self.next = next;
        Ok(next == total)
    }
}

impl TriedbDkgStateReader {
    pub(super) fn new(
        numeric_chain_id: u64,
        execution_delay: SeqNum,
    ) -> Result<Self, TriedbStateError> {
        let chain_id = parse_chain_id(numeric_chain_id)?;
        Ok(Self {
            chain_id,
            numeric_chain_id,
            execution_delay,
        })
    }

    fn state_context<ST, SCT>(
        &self,
        state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
        block: SeqNum,
        contract: Address,
    ) -> Result<u64, TriedbStateError>
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        let required_head = SeqNum(block.0.saturating_add(self.execution_delay.0));
        if state_read
            .raw_read_latest_finalized_block()
            .is_none_or(|latest| latest < required_head)
        {
            return Err(TriedbStateError::NotAvailable { block: block.0 });
        }
        let header = match state_read.get_finalized_block_header(block) {
            Ok(header) => header,
            Err(ExecutionStateReadExtError::NotAvailableYet) => {
                return Err(TriedbStateError::NotAvailable { block: block.0 })
            }
            Err(err) => return Err(err.into()),
        };
        let account = match state_read.get_finalized_account(block, contract) {
            Ok(account) => account,
            Err(ExecutionStateReadExtError::NotAvailableYet) => {
                return Err(TriedbStateError::NotAvailable { block: block.0 })
            }
            Err(err) => return Err(err.into()),
        };
        if account.is_none_or(|account| account.code_hash.is_none()) {
            return Err(TriedbStateError::ContractMissing {
                contract,
                block: block.0,
            });
        }
        Ok(DKG_ETH_CALL_GAS_LIMIT.min(header.0.gas_limit))
    }

    pub(super) fn read_registrations<ST, SCT>(
        &self,
        state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
        block: SeqNum,
        contract: Address,
        epoch: Epoch,
        parties: &[Address],
    ) -> Result<Vec<Option<RegistrationCall>>, TriedbStateError>
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        let gas_limit = self.state_context(state_read, block, contract)?;

        let mut registrations = Vec::with_capacity(parties.len());
        for &party in parties {
            let registration = self.call(
                state_read,
                block,
                contract,
                gas_limit,
                DkgContract::registrationOfCall {
                    epoch: epoch.0,
                    party,
                },
            )?;
            registrations.push(
                registration
                    .exists
                    .then(|| registration.registration.into_registration(party))
                    .transpose()?,
            );
        }

        Ok(registrations)
    }

    pub(super) fn read<ST, SCT>(
        &self,
        state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
        block: SeqNum,
        contract: Address,
        epoch: Epoch,
        party_count: usize,
    ) -> Result<Vec<ChainEvent>, TriedbStateError>
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        let gas_limit = match self.state_context(state_read, block, contract) {
            Ok(gas_limit) => gas_limit,
            Err(TriedbStateError::ContractMissing { .. }) => {
                return Ok(Vec::new());
            }
            Err(err) => return Err(err),
        };

        let limit = u32::try_from(
            (RECORD_PAGE_SIGNATURE_BUDGET / party_count.max(1)).clamp(1, MAX_RECORD_PAGE_SIZE),
        )
        .expect("record page size fits in u32");
        let mut snapshot = RecordSnapshot::default();
        loop {
            let page = self.call(
                state_read,
                block,
                contract,
                gas_limit,
                DkgContract::recordsCall {
                    epoch: epoch.0,
                    start: snapshot.next,
                    limit,
                },
            )?;
            if snapshot.accept(page, epoch, party_count, limit)? {
                break;
            }
        }
        Ok(snapshot.events)
    }

    fn call<ST, SCT, C: SolCall>(
        &self,
        state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
        block: SeqNum,
        contract: Address,
        gas_limit: u64,
        call: C,
    ) -> Result<C::Return, TriedbStateError>
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        let transaction = TxEip1559 {
            chain_id: self.numeric_chain_id,
            nonce: 0,
            gas_limit,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(contract),
            value: U256::ZERO,
            access_list: Default::default(),
            input: call.abi_encode().into(),
        };
        let transaction: TxEnvelope = transaction
            .into_signed(Signature::new(U256::ZERO, U256::ZERO, false))
            .into();
        match state_read.eth_call(FinalizedEthCallRequest {
            chain_id: self.chain_id,
            transaction,
            sender: Address::ZERO,
            block,
            gas_specified: false,
        })? {
            CallResult::Success(success) => {
                C::abi_decode_returns(&success.output_data).map_err(|source| {
                    TriedbStateError::CallDecode {
                        signature: C::SIGNATURE,
                        block: block.0,
                        source,
                    }
                })
            }
            CallResult::Failure(failure) => Err(TriedbStateError::CallFailed {
                block: block.0,
                message: failure.message,
                error_code: failure.error_code,
            }),
            CallResult::Revert(revert) => Err(TriedbStateError::CallReverted {
                block: block.0,
                trace_len: revert.trace.len(),
            }),
        }
    }
}

fn parse_chain_id(chain_id: u64) -> Result<ChainId, TriedbStateError> {
    match chain_id {
        ETHEREUM_MAINNET_CHAIN_ID => Ok(ChainId::EthereumMainnet),
        MONAD_MAINNET_CHAIN_ID => Ok(ChainId::MonadMainnet),
        MONAD_TESTNET_CHAIN_ID => Ok(ChainId::MonadTestnet),
        MONAD_DEVNET_CHAIN_ID => Ok(ChainId::MonadDevnet),
        HIVE_CHAIN_ID => Ok(ChainId::HiveNet),
        chain_id => Err(TriedbStateError::UnsupportedChainId { chain_id }),
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;

    #[test]
    fn maps_supported_chain_ids() {
        assert_eq!(
            parse_chain_id(MONAD_DEVNET_CHAIN_ID).unwrap(),
            ChainId::MonadDevnet
        );
        assert!(parse_chain_id(42).is_err());
    }

    #[test]
    fn record_snapshot_accepts_typed_pages_in_sequence_order() {
        let mut snapshot = RecordSnapshot::default();
        assert!(!snapshot
            .accept(
                ContractRecordPage {
                    total: 3,
                    next: 2,
                    pcQcs: vec![pc_record(1)],
                    bveQcs: vec![bve_record(0)],
                    results: Vec::new(),
                },
                Epoch(7),
                4,
                2,
            )
            .unwrap());
        assert!(snapshot
            .accept(
                ContractRecordPage {
                    total: 3,
                    next: 3,
                    pcQcs: vec![pc_record(2)],
                    bveQcs: Vec::new(),
                    results: Vec::new(),
                },
                Epoch(7),
                4,
                2,
            )
            .unwrap());
        assert_eq!(
            snapshot
                .events
                .iter()
                .map(ChainEvent::record_id)
                .collect::<Vec<_>>(),
            vec![RecordId(0), RecordId(1), RecordId(2)]
        );
    }

    #[test]
    fn record_snapshot_accepts_an_empty_first_page() {
        let mut snapshot = RecordSnapshot::default();
        assert!(snapshot
            .accept(
                ContractRecordPage {
                    total: 0,
                    next: 0,
                    pcQcs: Vec::new(),
                    bveQcs: Vec::new(),
                    results: Vec::new(),
                },
                Epoch(7),
                4,
                1,
            )
            .unwrap());
        assert!(snapshot.events.is_empty());
    }

    #[test]
    fn record_snapshot_rejects_gaps_and_changed_totals() {
        let mut snapshot = RecordSnapshot::default();
        let gap = snapshot.accept(
            ContractRecordPage {
                total: 2,
                next: 2,
                pcQcs: vec![pc_record(0)],
                bveQcs: Vec::new(),
                results: Vec::new(),
            },
            Epoch(7),
            4,
            2,
        );
        assert!(matches!(
            gap,
            Err(TriedbStateError::InvalidRecordPage { .. })
        ));

        let mut snapshot = RecordSnapshot::default();
        snapshot
            .accept(
                ContractRecordPage {
                    total: 2,
                    next: 1,
                    pcQcs: vec![pc_record(0)],
                    bveQcs: Vec::new(),
                    results: Vec::new(),
                },
                Epoch(7),
                4,
                1,
            )
            .unwrap();
        let changed = snapshot.accept(
            ContractRecordPage {
                total: 3,
                next: 2,
                pcQcs: Vec::new(),
                bveQcs: vec![bve_record(1)],
                results: Vec::new(),
            },
            Epoch(7),
            4,
            1,
        );
        assert!(matches!(
            changed,
            Err(TriedbStateError::RecordTotalChanged {
                expected: 2,
                actual: 3
            })
        ));
    }

    fn pc_record(sequence: u64) -> DkgContract::SequencedPcQc {
        DkgContract::SequencedPcQc {
            sequence,
            qc: DkgContract::PcQc {
                dealer: 0,
                digest: B256::repeat_byte(0x11),
                signatures: vec![signature(0)],
            },
        }
    }

    fn bve_record(sequence: u64) -> DkgContract::SequencedBveQc {
        DkgContract::SequencedBveQc {
            sequence,
            qc: DkgContract::BveQc {
                dealer: 1,
                digest: B256::repeat_byte(0x22),
                commitmentDigest: B256::repeat_byte(0x33),
                signatures: vec![signature(1)],
            },
        }
    }

    fn signature(signer: u32) -> DkgContract::QcSignature {
        DkgContract::QcSignature {
            signer,
            r: B256::repeat_byte(0x44),
            s: B256::repeat_byte(0x55),
        }
    }
}
