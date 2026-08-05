use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use alloy_consensus::{SignableTransaction, Transaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, FixedBytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use dkg_crypto::BLS_G2_SERIALIZED_BYTES;
use dkg_protocol::{encode_registration, ChainCall, ChainEvent, RegistrationCall};
use monad_eth_types::buffered_base_fee_per_gas;
use monad_types::{Epoch, SeqNum};
use tracing::{info, warn};
use zeroize::Zeroize;

use super::{chain_call_kind, ContractRegistration, DkgChain, DkgChainConfig, DkgContract};
use crate::DkgError;

use self::reliable::{Attempt, PreparedState, ReliableSubmitter, SubmissionStrategy};

mod reliable;

type TxKey = (Epoch, ChainTxId);
type ReliableTxSubmitter = ReliableSubmitter<TxSubmission, TxKey, ChainCall>;

pub(crate) struct TxSubmitter {
    reliable: ReliableTxSubmitter,
    active_epochs: BTreeSet<Epoch>,
    recovered_epochs: BTreeSet<Epoch>,
}

impl TxSubmitter {
    pub(crate) fn new(config: &DkgChainConfig, chain: Arc<dyn DkgChain>) -> Result<Self, DkgError> {
        let mut key = FixedBytes::<32>::from(config.signing_key);
        let signer = PrivateKeySigner::from_bytes(&key)
            .map_err(|err| DkgError::operation("construct DKG transaction signer", err));
        key.0.zeroize();
        let signer = signer?;

        let submission = TxSubmission {
            config: TxConfig {
                contract: config.contract,
                chain_id: config.chain_id,
                gas_limit: config.gas_limit,
                max_priority_fee_per_gas: config.max_priority_fee_per_gas,
            },
            signer,
            chain,
            context_blocks: BTreeMap::new(),
        };
        Ok(Self {
            reliable: ReliableSubmitter::new(submission),
            active_epochs: BTreeSet::new(),
            recovered_epochs: BTreeSet::new(),
        })
    }

    pub(crate) fn signer_address(&self) -> Address {
        self.reliable.strategy().signer.address()
    }

    pub(crate) fn submit_registration(
        &mut self,
        epoch: Epoch,
        block: SeqNum,
        registration: RegistrationCall,
    ) {
        let submission = self.reliable.strategy_mut();
        submission.context_blocks.insert(epoch, block);
        let contract = submission.config.contract;
        self.submit(
            epoch,
            ChainCall::PostRegistration {
                registration,
                dkg: dkg_core::Address(contract.into_array()),
            },
        );
    }

    pub(crate) fn start_session(&mut self, epoch: Epoch) {
        if self.active_epochs.contains(&epoch)
            || self
                .active_epochs
                .last()
                .is_some_and(|latest| *latest > epoch)
        {
            return;
        }
        self.active_epochs.insert(epoch);
        while self.active_epochs.len() > crate::MAX_RETAINED_DKG_SESSIONS {
            self.active_epochs.pop_first();
        }
        let latest = *self
            .active_epochs
            .last()
            .expect("started DKG transaction epoch");
        self.reliable.retain(|(pending_epoch, id)| {
            self.active_epochs.contains(pending_epoch)
                || (*pending_epoch > latest && matches!(id, ChainTxId::Registration { .. }))
        });
        self.recovered_epochs
            .retain(|recovered| self.active_epochs.contains(recovered));
        self.reliable
            .strategy_mut()
            .context_blocks
            .retain(|epoch, _| self.active_epochs.contains(epoch) || *epoch > latest);
    }

    pub(crate) fn submit(&mut self, epoch: Epoch, call: ChainCall) {
        let key = (epoch, ChainTxId::from(&call));
        let immediate = matches!(&call, ChainCall::PostRegistration { .. });
        if !immediate && !self.active_epochs.contains(&epoch) {
            return;
        }

        if !self.reliable.enqueue(key.clone(), call) {
            return;
        }
        if immediate || self.recovered_epochs.contains(&epoch) {
            self.submit_keys([key]);
        }
    }

    pub(crate) fn retry_registration(&mut self, epoch: Epoch, block: SeqNum) {
        self.reliable
            .strategy_mut()
            .context_blocks
            .insert(epoch, block);
        let keys = self.reliable.pending_keys(|(pending_epoch, id)| {
            *pending_epoch == epoch && matches!(id, ChainTxId::Registration { .. })
        });
        self.submit_keys(keys);
    }

    pub(crate) fn confirm_registration(&mut self, epoch: Epoch, registration: &RegistrationCall) {
        let id = ChainTxId::from(registration);
        self.reliable.confirm((epoch, id));
    }

    pub(crate) fn cancel_registration(&mut self, epoch: Epoch) {
        self.reliable.remove_where(|(pending_epoch, id)| {
            *pending_epoch == epoch && matches!(id, ChainTxId::Registration { .. })
        });
    }

    pub(crate) fn finalized_block(
        &mut self,
        epoch: Epoch,
        block: SeqNum,
        events: Vec<ChainEvent>,
        recovery_complete_after: bool,
    ) {
        if !self.active_epochs.contains(&epoch) {
            return;
        }
        self.reliable
            .strategy_mut()
            .context_blocks
            .insert(epoch, block);
        for event in events {
            let id = ChainTxId::from(&event);
            self.reliable.confirm((epoch, id));
        }
        if recovery_complete_after {
            self.recovered_epochs.insert(epoch);
        }
        if self.recovered_epochs.contains(&epoch) {
            let keys = self
                .reliable
                .pending_keys(|(pending_epoch, _)| *pending_epoch == epoch);
            self.submit_keys(keys);
        }
    }

    fn submit_keys(&mut self, keys: impl IntoIterator<Item = TxKey>) {
        let keys = keys.into_iter().collect::<Vec<_>>();
        loop {
            match self.reliable.attempt(keys.clone()) {
                Attempt::Idle => return,
                // This handles a finalized no-op/revert that consumed the nonce but
                // emitted no event, such as a duplicate BVE witness for one pair.
                Attempt::Retired {
                    key: (epoch, _),
                    value,
                } => info!(
                    epoch = epoch.0,
                    call_kind = chain_call_kind(&value),
                    "retired finalized DKG transaction without a matching event"
                ),
                Attempt::RefreshFailed { key, error } => {
                    let (epoch, _) = &key;
                    let call_kind = self
                        .reliable
                        .pending(&key)
                        .map(chain_call_kind)
                        .expect("failed refreshed submission remains pending");
                    match error {
                        TxSubmissionError::MissingContext => warn!(
                            epoch = epoch.0,
                            call_kind, "missing DKG transaction context block; will retry"
                        ),
                        TxSubmissionError::ChainContext { block, source } => warn!(
                            ?source,
                            block = block.0,
                            call_kind,
                            "failed to read DKG transaction context; will retry"
                        ),
                        TxSubmissionError::Operation(source) => warn!(
                            ?source,
                            epoch = epoch.0,
                            call_kind,
                            "failed to prepare DKG chain tx; will retry"
                        ),
                    }
                    return;
                }
                Attempt::Submitted { key } => {
                    let (epoch, _) = &key;
                    let call_kind = self
                        .reliable
                        .pending(&key)
                        .map(chain_call_kind)
                        .expect("submitted transaction remains pending");
                    let prepared = self
                        .reliable
                        .prepared(&key)
                        .expect("submitted transaction remains prepared");
                    info!(
                        epoch = epoch.0,
                        call_kind,
                        nonce = prepared.transaction.nonce(),
                        latest_base_fee_per_gas = prepared.latest_base_fee_per_gas,
                        max_fee_per_gas = prepared.transaction.max_fee_per_gas(),
                        max_priority_fee_per_gas = self
                            .reliable
                            .strategy()
                            .config
                            .max_priority_fee_per_gas,
                        tx_hash = %prepared.transaction.tx_hash(),
                        "queued DKG transaction for local txpool insertion"
                    );
                    return;
                }
                Attempt::SubmitFailed { key, error } => {
                    let (epoch, _) = &key;
                    let call_kind = self
                        .reliable
                        .pending(&key)
                        .map(chain_call_kind)
                        .expect("failed submission remains pending");
                    let prepared = self
                        .reliable
                        .prepared(&key)
                        .expect("failed submission remains prepared");
                    warn!(
                        ?error,
                        epoch = epoch.0,
                        call_kind,
                        nonce = prepared.transaction.nonce(),
                        tx_hash = %prepared.transaction.tx_hash(),
                        "failed to queue DKG chain tx; will retry"
                    );
                    return;
                }
            }
        }
    }
}

struct TxSubmission {
    config: TxConfig,
    signer: PrivateKeySigner,
    chain: Arc<dyn DkgChain>,
    context_blocks: BTreeMap<Epoch, SeqNum>,
}

struct PreparedTx {
    transaction: TxEnvelope,
    latest_base_fee_per_gas: u64,
}

#[derive(Debug)]
enum TxSubmissionError {
    MissingContext,
    ChainContext { block: SeqNum, source: DkgError },
    Operation(DkgError),
}

impl SubmissionStrategy<TxKey, ChainCall> for TxSubmission {
    type Prepared = PreparedTx;
    type Error = TxSubmissionError;

    fn refresh(
        &self,
        key: &TxKey,
        call: &ChainCall,
        prepared: Option<&Self::Prepared>,
    ) -> Result<PreparedState<Self::Prepared>, Self::Error> {
        // An active retry stays at its epoch's event-scan boundary. New work
        // uses the newest boundary so overlapping sessions observe consumed nonces.
        let block = if prepared.is_some() {
            self.context_blocks.get(&key.0).copied()
        } else {
            self.context_blocks.values().copied().max()
        }
        .ok_or(TxSubmissionError::MissingContext)?;
        let context = self
            .chain
            .transaction_context(block, self.signer.address())
            .map_err(|source| TxSubmissionError::ChainContext { block, source })?;
        let max_fee_per_gas = buffered_base_fee_per_gas(u128::from(context.base_fee_per_gas))
            .saturating_add(self.config.max_priority_fee_per_gas);

        if let Some(prepared) = prepared {
            if prepared.transaction.nonce() < context.nonce {
                return Ok(PreparedState::Obsolete);
            }
            // An overlapping epoch may retry against an older context block;
            // do not replace its prepared transaction with a stale lower nonce.
            if prepared.transaction.nonce() != context.nonce
                || prepared.transaction.max_fee_per_gas() >= max_fee_per_gas
            {
                return Ok(PreparedState::Current);
            }
        }

        let transaction = self
            .config
            .prepare(&self.signer, context.nonce, max_fee_per_gas, key.0, call)
            .map_err(TxSubmissionError::Operation)?;
        Ok(PreparedState::Replace(PreparedTx {
            transaction,
            latest_base_fee_per_gas: context.base_fee_per_gas,
        }))
    }

    fn submit(&self, prepared: &Self::Prepared) -> Result<(), Self::Error> {
        self.chain
            .submit_transaction(prepared.transaction.clone())
            .map_err(TxSubmissionError::Operation)
    }
}

struct TxConfig {
    contract: Address,
    chain_id: u64,
    gas_limit: u64,
    max_priority_fee_per_gas: u128,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ChainTxId {
    Registration {
        digest: [u8; 32],
    },
    PcQc {
        dealer: u32,
        digest: [u8; 32],
    },
    BveQc {
        dealer: u32,
        commitment_digest: [u8; 32],
        digest: [u8; 32],
    },
    DkgResult {
        g2x: [u8; BLS_G2_SERIALIZED_BYTES],
    },
}

impl From<&RegistrationCall> for ChainTxId {
    fn from(registration: &RegistrationCall) -> Self {
        Self::Registration {
            digest: *blake3::hash(&encode_registration(registration)).as_bytes(),
        }
    }
}

impl From<&ChainCall> for ChainTxId {
    fn from(call: &ChainCall) -> Self {
        match call {
            ChainCall::PostPCQc { qc } => Self::PcQc {
                dealer: qc.dealer.0,
                digest: qc.digest,
            },
            ChainCall::PostBveQc { qc } => Self::BveQc {
                dealer: qc.dealer.0,
                commitment_digest: qc.commitment_digest,
                digest: qc.digest,
            },
            ChainCall::PostDkgResult { qc } => Self::DkgResult { g2x: qc.g2x.0 },
            ChainCall::PostRegistration { registration, .. } => registration.into(),
        }
    }
}

impl From<&ChainEvent> for ChainTxId {
    fn from(event: &ChainEvent) -> Self {
        match event {
            ChainEvent::PCQc { qc, .. } => Self::PcQc {
                dealer: qc.dealer.0,
                digest: qc.digest,
            },
            ChainEvent::BveQcFinalized { qc, .. } => Self::BveQc {
                dealer: qc.dealer.0,
                commitment_digest: qc.commitment_digest,
                digest: qc.digest,
            },
            ChainEvent::DkgResultRecorded { qc, .. } => Self::DkgResult { g2x: qc.g2x.0 },
        }
    }
}

impl TxConfig {
    fn prepare(
        &self,
        signer: &PrivateKeySigner,
        nonce: u64,
        max_fee_per_gas: u128,
        epoch: Epoch,
        call: &ChainCall,
    ) -> Result<TxEnvelope, DkgError> {
        if let ChainCall::PostRegistration { dkg, .. } = call {
            if dkg.0 != self.contract.into_array() {
                return Err(DkgError::RegistrationContractMismatch {
                    expected: self.contract,
                    actual: Address::from(dkg.0),
                });
            }
        }

        let transaction = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            to: TxKind::Call(self.contract),
            value: U256::ZERO,
            access_list: Default::default(),
            input: self.calldata(epoch, call, signer.address())?.into(),
        };
        let signature = signer
            .sign_hash_sync(&transaction.signature_hash())
            .map_err(|err| DkgError::operation("sign DKG transaction", err))?;
        Ok(TxEnvelope::Eip1559(transaction.into_signed(signature)))
    }

    fn calldata(
        &self,
        epoch: Epoch,
        call: &ChainCall,
        signer: Address,
    ) -> Result<Vec<u8>, DkgError> {
        match call {
            ChainCall::PostPCQc { qc } => Ok(DkgContract::postPcQcCall {
                epoch: epoch.0,
                qc: qc.into(),
            }
            .abi_encode()),
            ChainCall::PostBveQc { qc } => Ok(DkgContract::postBveQcCall {
                epoch: epoch.0,
                qc: qc.into(),
            }
            .abi_encode()),
            ChainCall::PostDkgResult { qc } if qc.epoch.0 == epoch.0 => {
                Ok(DkgContract::submitResultCall {
                    epoch: epoch.0,
                    result: qc.into(),
                }
                .abi_encode())
            }
            ChainCall::PostDkgResult { qc } => Err(DkgError::ResultEpochMismatch {
                expected: epoch.0,
                actual: qc.epoch.0,
            }),
            ChainCall::PostRegistration { registration, .. } => Ok(DkgContract::registerCall {
                epoch: epoch.0,
                registration: ContractRegistration::try_from((registration, signer)).map_err(
                    |source| DkgError::operation("encode typed DKG registration", source),
                )?,
            }
            .abi_encode()),
        }
    }
}

#[cfg(test)]
#[path = "submitter_tests.rs"]
mod tests;
