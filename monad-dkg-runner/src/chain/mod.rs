//! Finalized contract reads, event delivery, and transaction submission.

use alloy_consensus::TxEnvelope;
use alloy_primitives::Address;
use dkg_protocol::{ChainCall, ChainEvent, RegistrationCall};
use monad_types::{Epoch, SeqNum};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::DkgError;

mod bindings;
mod recovery;
mod submitter;
mod triedb;
mod triedb_state;

pub use triedb::new_triedb_manager;

pub(crate) use recovery::{ChainEventBatch, ChainEventReader, ChainEventSession, ChainRead};
pub(crate) use submitter::TxSubmitter;

const DEFAULT_TX_GAS_LIMIT: u64 = 5_000_000;
const DEFAULT_TX_MAX_PRIORITY_FEE_PER_GAS: u128 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DkgTransactionContext {
    pub nonce: u64,
    pub base_fee_per_gas: u64,
}

/// The only boundary between the DKG manager and chain-specific I/O.
///
/// The manager owns recovery timing, retry, ordering, and delivery into the
/// protocol engine. Implementations only read a requested chain boundary or
/// finalized block and submit transactions through the host node.
pub(crate) trait DkgChain: Send + Sync + 'static {
    /// Reads registrations for the requested parties at exactly `block`.
    ///
    /// `None` means the execution state is not available yet. The returned
    /// registrations must be in request order and omit unregistered parties.
    fn read_registrations(
        &self,
        block: SeqNum,
        epoch: Epoch,
        parties: &[Address],
    ) -> Result<Option<Vec<RegistrationCall>>, DkgError>;

    /// Reads either the recovery snapshot or one finalized block.
    ///
    /// `None` means the requested state or receipts are not available yet.
    fn read_events(&self, read: ChainRead) -> Result<Option<Vec<ChainEvent>>, DkgError>;

    /// Reads the signer nonce at `block` and the latest proposed block's base fee.
    ///
    /// The base-fee boundary matches RPC's `latest` block tag. Aligning the
    /// nonce with the event scan prevents a transaction that has
    /// finalized but whose event has not yet been scanned from being submitted
    /// again at a new nonce.
    fn transaction_context(
        &self,
        block: SeqNum,
        address: Address,
    ) -> Result<DkgTransactionContext, DkgError>;

    fn submit_transaction(&self, transaction: TxEnvelope) -> Result<(), DkgError>;
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DkgChainConfig {
    pub signing_key: [u8; 32],
    pub local_keys: crate::DkgLocalKeyMaterial,
    #[zeroize(skip)]
    pub contract: Address,
    #[zeroize(skip)]
    pub chain_id: u64,
    #[zeroize(skip)]
    pub gas_limit: u64,
    #[zeroize(skip)]
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
