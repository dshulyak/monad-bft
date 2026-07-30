//! Triedb/eth-call implementation of a DKG recovery snapshot read.
//!
//! Recovery orchestration lives in `monad-dkg-runner`; this module only maps
//! one requested finalized state boundary to protocol chain events.

use std::collections::BTreeSet;

use crate::{DkgLocalRegistrationState, DkgRegistration};
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
use alloy_sol_types::SolCall;
use dkg_core::RecordId;
use dkg_protocol::ChainEvent;
use monad_chain_config::{
    ETHEREUM_MAINNET_CHAIN_ID, HIVE_CHAIN_ID, MONAD_DEVNET_CHAIN_ID, MONAD_MAINNET_CHAIN_ID,
    MONAD_TESTNET_CHAIN_ID,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_ethcall::{CallResult, ChainId, EthCallResult};
use monad_execution_state_read::{
    ExecutionStateRead, ExecutionStateReadExt, ExecutionStateReadExtError, FinalizedEthCallRequest,
};
use monad_types::{Epoch, SeqNum};
use monad_validator::signature_collection::SignatureCollection;
use thiserror::Error;

use super::bindings::{record_to_chain_event, registration_from_contract, DkgContract};

const DKG_ETH_CALL_GAS_LIMIT: u64 = 5_000_000;

#[derive(Debug, Error)]
pub(super) enum TriedbStateError {
    #[error("unsupported DKG eth-call chain ID {chain_id}")]
    UnsupportedChainId { chain_id: u64 },
    #[error(transparent)]
    StateRead(#[from] ExecutionStateReadExtError),
    #[error("DKG contract {contract} has no code at block {block}")]
    ContractMissing { contract: Address, block: u64 },
    #[error("DKG {kind} count exceeds usize")]
    CountOverflow { kind: &'static str },
    #[error("DKG contract has {count} registrations; maximum supported is 256")]
    TooManyRegistrations { count: usize },
    #[error("duplicate DKG registered party {address}")]
    DuplicateRegistration { address: Address },
    #[error("DKG registration for {address} is empty")]
    EmptyRegistration { address: Address },
    #[error("DKG contract supports at most 256 parties; got {count}")]
    TooManyParties { count: usize },
    #[error("DKG result epoch {actual} does not match requested epoch {expected}")]
    ResultEpochMismatch { expected: u64, actual: u64 },
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
    #[error("invalid DKG contract record at sequence {sequence}")]
    InvalidRecord { sequence: u64 },
}

pub(super) struct TriedbDkgStateReader {
    chain_id: ChainId,
    numeric_chain_id: u64,
    execution_delay: SeqNum,
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

    fn is_stable_finalized_state<ST, SCT>(
        &self,
        state_read: &impl ExecutionStateRead<ST, SCT>,
        block: SeqNum,
    ) -> bool
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        let required_head = SeqNum(block.0.saturating_add(self.execution_delay.0));
        state_read
            .raw_read_latest_finalized_block()
            .is_some_and(|latest| latest >= required_head)
    }

    fn state_context<ST, SCT>(
        &self,
        state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
        block: SeqNum,
        contract: Address,
    ) -> Result<Option<u64>, TriedbStateError>
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        if !self.is_stable_finalized_state(state_read, block) {
            return Ok(None);
        }
        let header = match state_read.get_finalized_block_header(block) {
            Ok(header) => header,
            Err(ExecutionStateReadExtError::NotAvailableYet) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let account = match state_read.get_finalized_account(block, contract) {
            Ok(account) => account,
            Err(ExecutionStateReadExtError::NotAvailableYet) => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        if account.is_none_or(|account| account.code_hash.is_none()) {
            return Err(TriedbStateError::ContractMissing {
                contract,
                block: block.0,
            });
        }
        Ok(Some(DKG_ETH_CALL_GAS_LIMIT.min(header.0.gas_limit)))
    }

    pub(super) fn read_registrations<ST, SCT>(
        &self,
        state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
        block: SeqNum,
        contract: Address,
        epoch: Epoch,
    ) -> Result<Option<Vec<DkgRegistration>>, TriedbStateError>
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        let Some(gas_limit) = self.state_context(state_read, block, contract)? else {
            return Ok(None);
        };

        let count = self.call(
            state_read,
            block,
            contract,
            gas_limit,
            DkgContract::registeredPartyCountCall { epoch: epoch.0 },
        )?;
        let count = usize::try_from(count).map_err(|_| TriedbStateError::CountOverflow {
            kind: "registered-party",
        })?;
        if count > 256 {
            return Err(TriedbStateError::TooManyRegistrations { count });
        }

        let mut seen = BTreeSet::new();
        let mut registrations = Vec::with_capacity(count);
        for index in 0..count {
            let address = self.call(
                state_read,
                block,
                contract,
                gas_limit,
                DkgContract::registeredPartyCall {
                    epoch: epoch.0,
                    index: U256::from(index),
                },
            )?;
            if !seen.insert(address) {
                return Err(TriedbStateError::DuplicateRegistration { address });
            }

            let registration = self.call(
                state_read,
                block,
                contract,
                gas_limit,
                DkgContract::registrationOfCall {
                    epoch: epoch.0,
                    party: address,
                },
            )?;
            if !registration.exists {
                return Err(TriedbStateError::EmptyRegistration { address });
            }
            registrations.push(DkgRegistration {
                address,
                bytes: registration_from_contract(address, &registration.registration),
            });
        }

        Ok(Some(registrations))
    }

    pub(super) fn read_local_registration<ST, SCT>(
        &self,
        state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
        block: SeqNum,
        contract: Address,
        epoch: Epoch,
        party: Address,
    ) -> Result<Option<DkgLocalRegistrationState>, TriedbStateError>
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        let Some(gas_limit) = self.state_context(state_read, block, contract)? else {
            return Ok(None);
        };

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

        Ok(Some(DkgLocalRegistrationState {
            registration: registration
                .exists
                .then(|| registration_from_contract(party, &registration.registration)),
        }))
    }

    pub(super) fn read<ST, SCT>(
        &self,
        state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
        block: SeqNum,
        contract: Address,
        epoch: Epoch,
        party_count: usize,
    ) -> Result<Option<Vec<ChainEvent>>, TriedbStateError>
    where
        ST: CertificateSignatureRecoverable,
        SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
    {
        if party_count > 256 {
            return Err(TriedbStateError::TooManyParties { count: party_count });
        }
        let gas_limit = match self.state_context(state_read, block, contract) {
            Ok(Some(gas_limit)) => gas_limit,
            Ok(None) => return Ok(None),
            Err(TriedbStateError::ContractMissing { .. }) => {
                return Ok(Some(Vec::new()));
            }
            Err(err) => return Err(err),
        };

        let count = self.call(
            state_read,
            block,
            contract,
            gas_limit,
            DkgContract::recordCountCall { epoch: epoch.0 },
        )?;
        let count = usize::try_from(count)
            .map_err(|_| TriedbStateError::CountOverflow { kind: "record" })?;
        let mut events = Vec::with_capacity(count);
        for index in 0..count {
            let record = self.call(
                state_read,
                block,
                contract,
                gas_limit,
                DkgContract::recordAtCall {
                    epoch: epoch.0,
                    index: U256::from(index),
                },
            )?;
            let event = record_to_chain_event(RecordId(index as u64), record, party_count)
                .map_err(|_| TriedbStateError::InvalidRecord {
                    sequence: index as u64,
                })?;
            if let ChainEvent::DkgResultRecorded { qc, .. } = &event {
                if qc.epoch.0 != epoch.0 {
                    return Err(TriedbStateError::ResultEpochMismatch {
                        expected: epoch.0,
                        actual: qc.epoch.0,
                    });
                }
            }
            events.push(event);
        }
        Ok(Some(events))
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
        let input = call.abi_encode();
        let transaction = TxEip1559 {
            chain_id: self.numeric_chain_id,
            nonce: 0,
            gas_limit,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(contract),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::from(input),
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
    use super::*;

    #[test]
    fn maps_supported_chain_ids() {
        assert_eq!(
            parse_chain_id(MONAD_DEVNET_CHAIN_ID).unwrap(),
            ChainId::MonadDevnet
        );
        assert!(parse_chain_id(42).is_err());
    }
}
