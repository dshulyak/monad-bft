//! Finalized contract reads, event delivery, and transaction submission.

use alloy_primitives::Address;
use bytes::Bytes;
use dkg_protocol::{ChainCall, ChainEvent};
use monad_types::{Epoch, SeqNum};

use crate::DkgError;

mod bindings;
mod recovery;
mod submitter;

pub(crate) use recovery::{read_chain, ChainEventBatch, ChainEventReader, ChainEventSession};
pub(crate) use submitter::TxSubmitter;

const DEFAULT_TX_GAS_LIMIT: u64 = 5_000_000;
const DEFAULT_TX_MAX_PRIORITY_FEE_PER_GAS: u128 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgRegistration {
    pub address: Address,
    pub bytes: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DkgLocalRegistrationState {
    pub registration: Option<Bytes>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DkgTransactionContext {
    pub nonce: u64,
    pub base_fee_per_gas: u64,
}

/// Raw signed transaction bytes prepared for insertion into the local txpool.
pub type DkgLocalTransaction = Bytes;

/// The only boundary between the DKG manager and chain-specific I/O.
///
/// The manager owns recovery timing, retry, ordering, and delivery into the
/// protocol engine. Implementations only read a requested chain boundary or
/// finalized block and submit transactions through the host node.
pub trait DkgChain: Send + Sync + 'static {
    /// Reads all recovery-relevant DKG state at exactly `block`.
    ///
    /// `None` means the execution state for the requested block is not available
    /// yet. Returned events must use the same record identities as live logs.
    fn read_recovery_state(
        &self,
        _block: SeqNum,
        _contract: Address,
        _epoch: Epoch,
        _party_count: usize,
    ) -> Result<Option<Vec<ChainEvent>>, DkgError> {
        Err(DkgError::Unsupported("DKG recovery reads"))
    }

    /// Reads the complete registration set at exactly `block`.
    ///
    /// `None` means the execution state for the requested block is not
    /// available yet. The manager validates and intersects these records with
    /// the finalized validator set before constructing the protocol engine.
    fn read_registered_parties(
        &self,
        _block: SeqNum,
        _contract: Address,
        _epoch: Epoch,
    ) -> Result<Option<Vec<DkgRegistration>>, DkgError> {
        Err(DkgError::Unsupported("DKG registration reads"))
    }

    /// Reads this node's registration at exactly `block`.
    ///
    /// This lightweight read drives pre-boundary registration retries without
    /// loading every party's registration on each finalized block.
    fn read_local_registration(
        &self,
        _block: SeqNum,
        _contract: Address,
        _epoch: Epoch,
        _party: Address,
    ) -> Result<Option<DkgLocalRegistrationState>, DkgError> {
        Err(DkgError::Unsupported("DKG local registration reads"))
    }

    /// Reads DKG events from exactly one finalized block.
    ///
    /// `None` means the block or its receipts are not available yet. The
    /// manager retries and delivers successful reads to the protocol engine.
    fn read_finalized_events(
        &self,
        _block: SeqNum,
        _contract: Address,
        _epoch: Epoch,
        _party_count: usize,
    ) -> Result<Option<Vec<ChainEvent>>, DkgError> {
        Err(DkgError::Unsupported("DKG finalized-event reads"))
    }

    /// Reads the signer nonce and the latest proposed block's base fee.
    ///
    /// The base-fee boundary matches RPC's `latest` block tag. Implementations
    /// may use a finalized account boundary for the nonce so retries never skip
    /// an unfinalized transaction.
    fn transaction_context(&self, _address: Address) -> Result<DkgTransactionContext, DkgError> {
        Err(DkgError::Unsupported("DKG transaction context reads"))
    }

    fn submit_transaction(&self, _transaction: DkgLocalTransaction) -> Result<(), DkgError> {
        Err(DkgError::Unsupported("DKG transaction submission"))
    }
}

#[derive(Clone)]
pub struct DkgChainConfig {
    pub signing_key: [u8; 32],
    pub local_keys: crate::DkgLocalKeyMaterial,
    pub contract: Address,
    pub chain_id: u64,
    pub gas_limit: u64,
    pub max_priority_fee_per_gas: u128,
}

impl DkgChainConfig {
    pub fn new(signing_key: [u8; 32], contract: Address, chain_id: u64) -> Self {
        Self {
            signing_key,
            local_keys: crate::DkgLocalKeyMaterial::derive(signing_key),
            contract,
            chain_id,
            gas_limit: DEFAULT_TX_GAS_LIMIT,
            max_priority_fee_per_gas: DEFAULT_TX_MAX_PRIORITY_FEE_PER_GAS,
        }
    }
}

pub(crate) fn chain_call_kind(call: &ChainCall) -> &'static str {
    match call {
        ChainCall::PostPCQc { .. } => "post_pc_qc",
        ChainCall::PostBveQc { .. } => "post_bve_qc",
        ChainCall::PostDkgResult { .. } => "post_dkg_result",
        ChainCall::PostRegistration { .. } => "post_registration",
    }
}

pub(crate) fn chain_event_kind(event: &ChainEvent) -> &'static str {
    match event {
        ChainEvent::PCQc { .. } => "pc_qc",
        ChainEvent::BveQcFinalized { .. } => "bve_qc_finalized",
        ChainEvent::DkgResultRecorded { .. } => "dkg_result_recorded",
    }
}
