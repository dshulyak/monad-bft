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
use monad_types::{Epoch, Nonce, SeqNum};
use tracing::{info, warn};
use zeroize::Zeroize;

use super::{chain_call_kind, ContractRegistration, DkgChain, DkgChainConfig, DkgContract};
use crate::DkgError;

type TxKey = (Epoch, ChainTxId);

pub(crate) struct TxSubmitter {
    submission: TxSubmission,
    pending: BTreeMap<TxKey, ChainCall>,
    prepared: Option<(TxKey, PreparedTx)>,
    finalized: BTreeSet<TxKey>,
    latest_context_block: Option<SeqNum>,
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
        };
        Ok(Self {
            submission,
            pending: BTreeMap::new(),
            prepared: None,
            finalized: BTreeSet::new(),
            latest_context_block: None,
        })
    }

    pub(crate) fn signer_address(&self) -> Address {
        self.submission.signer.address()
    }

    pub(crate) fn submit_registration(
        &mut self,
        epoch: Epoch,
        block: SeqNum,
        registration: RegistrationCall,
    ) {
        self.observe_context(block);
        let contract = self.submission.config.contract;
        let key = self.enqueue(
            epoch,
            ChainCall::PostRegistration {
                registration,
                dkg: dkg_core::Address(contract.into_array()),
            },
        );
        self.submit_keys(key, block);
    }

    pub(crate) fn submit(&mut self, epoch: Epoch, call: ChainCall) {
        let key = self.enqueue(epoch, call);
        let Some(block) = self.latest_context_block else {
            return;
        };
        self.submit_keys(key, block);
    }

    pub(crate) fn retry_registration(&mut self, epoch: Epoch, block: SeqNum) {
        self.observe_context(block);
        let keys = self
            .pending
            .keys()
            .filter(|(pending_epoch, id)| {
                *pending_epoch == epoch && matches!(id, ChainTxId::Registration { .. })
            })
            .cloned()
            .collect::<Vec<_>>();
        self.submit_keys(keys, block);
    }

    pub(crate) fn confirm_registration(&mut self, epoch: Epoch, registration: &RegistrationCall) {
        let id = ChainTxId::from(registration);
        self.confirm((epoch, id));
    }

    pub(crate) fn cancel_registration(&mut self, epoch: Epoch) {
        self.pending.retain(|(pending_epoch, id), _| {
            !(*pending_epoch == epoch && matches!(id, ChainTxId::Registration { .. }))
        });
        self.clear_orphaned_prepared();
    }

    pub(crate) fn retire_epoch(&mut self, epoch: Epoch) {
        self.pending
            .retain(|(pending_epoch, _), _| *pending_epoch != epoch);
        self.finalized
            .retain(|(finalized_epoch, _)| *finalized_epoch != epoch);
        self.clear_orphaned_prepared();
    }

    pub(crate) fn finalized_block(&mut self, epoch: Epoch, block: SeqNum, events: Vec<ChainEvent>) {
        self.observe_context(block);
        for event in events {
            let id = ChainTxId::from(&event);
            self.confirm((epoch, id));
        }
        let keys = self
            .pending
            .keys()
            .filter(|(pending_epoch, _)| *pending_epoch == epoch)
            .cloned()
            .collect::<Vec<_>>();
        // Advance an active retry with its own epoch's scan. A newer overlapping
        // epoch must not make it read a nonce from the wrong chain boundary.
        self.submit_keys(keys, block);
    }

    fn enqueue(&mut self, epoch: Epoch, call: ChainCall) -> Option<TxKey> {
        let key = (epoch, ChainTxId::from(&call));
        if self.finalized.contains(&key) || self.pending.contains_key(&key) {
            return None;
        }
        self.pending.insert(key.clone(), call);
        Some(key)
    }

    fn submit_keys(&mut self, keys: impl IntoIterator<Item = TxKey>, context_block: SeqNum) {
        let keys = keys.into_iter().collect::<Vec<_>>();
        loop {
            let key = match &self.prepared {
                Some((key, _)) if keys.contains(key) => key.clone(),
                Some(_) => return,
                None => match keys.iter().find(|key| self.pending.contains_key(key)) {
                    Some(key) => (*key).clone(),
                    None => return,
                },
            };
            let call = self
                .pending
                .get(&key)
                .expect("selected DKG submission remains pending");
            match self
                .submission
                .refresh(context_block, &key, call, &mut self.prepared)
            {
                Ok(TxRefresh::Ready) => {
                    debug_assert!(self.prepared.is_some());
                }
                Ok(TxRefresh::Obsolete) => {
                    self.prepared = None;
                    let call = self
                        .pending
                        .remove(&key)
                        .expect("obsolete DKG submission remains pending");
                    self.finalized.insert(key.clone());
                    // A finalized no-op/revert can consume the nonce without an
                    // event, such as a duplicate BVE witness for one pair.
                    info!(
                        epoch = key.0 .0,
                        call_kind = chain_call_kind(&call),
                        "retired finalized DKG transaction without a matching event"
                    );
                    continue;
                }
                Err(error) => {
                    let call_kind = chain_call_kind(call);
                    match error {
                        TxSubmissionError::ChainContext { block, source } => warn!(
                            ?source,
                            block = block.0,
                            call_kind,
                            "failed to read DKG transaction context; will retry"
                        ),
                        TxSubmissionError::Operation(source) => warn!(
                            ?source,
                            epoch = key.0 .0,
                            call_kind,
                            "failed to prepare DKG chain tx; will retry"
                        ),
                    }
                    return;
                }
            }

            let prepared = self
                .prepared
                .as_ref()
                .filter(|(prepared_key, _)| prepared_key == &key)
                .map(|(_, prepared)| prepared)
                .expect("refreshed DKG submission is prepared");
            let call_kind = self
                .pending
                .get(&key)
                .map(chain_call_kind)
                .expect("prepared DKG submission remains pending");
            match self.submission.submit(prepared) {
                Ok(()) => {
                    info!(
                        epoch = key.0.0,
                        call_kind,
                        nonce = prepared.transaction.nonce(),
                        latest_base_fee_per_gas = prepared.latest_base_fee_per_gas,
                        max_fee_per_gas = prepared.transaction.max_fee_per_gas(),
                        max_priority_fee_per_gas = self.submission.config.max_priority_fee_per_gas,
                        tx_hash = %prepared.transaction.tx_hash(),
                        "queued DKG transaction for local txpool insertion"
                    );
                    return;
                }
                Err(error) => {
                    warn!(
                        ?error,
                        epoch = key.0.0,
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

    fn observe_context(&mut self, block: SeqNum) {
        self.latest_context_block = Some(
            self.latest_context_block
                .map_or(block, |latest| latest.max(block)),
        );
    }

    fn confirm(&mut self, key: TxKey) {
        self.finalized.insert(key.clone());
        self.pending.remove(&key);
        if self
            .prepared
            .as_ref()
            .is_some_and(|(prepared_key, _)| prepared_key == &key)
        {
            self.prepared = None;
        }
    }

    fn clear_orphaned_prepared(&mut self) {
        if self
            .prepared
            .as_ref()
            .is_some_and(|(key, _)| !self.pending.contains_key(key))
        {
            self.prepared = None;
        }
    }
}

struct TxSubmission {
    config: TxConfig,
    signer: PrivateKeySigner,
    chain: Arc<dyn DkgChain>,
}

struct PreparedTx {
    transaction: TxEnvelope,
    latest_base_fee_per_gas: u64,
}

enum TxRefresh {
    Ready,
    Obsolete,
}

#[derive(Debug)]
enum TxSubmissionError {
    ChainContext { block: SeqNum, source: DkgError },
    Operation(DkgError),
}

impl TxSubmission {
    fn refresh(
        &self,
        block: SeqNum,
        key: &TxKey,
        call: &ChainCall,
        prepared: &mut Option<(TxKey, PreparedTx)>,
    ) -> Result<TxRefresh, TxSubmissionError> {
        let context = self
            .chain
            .transaction_context(block, self.signer.address())
            .map_err(|source| TxSubmissionError::ChainContext { block, source })?;
        let max_fee_per_gas = buffered_base_fee_per_gas(u128::from(context.base_fee_per_gas))
            .saturating_add(self.config.max_priority_fee_per_gas);

        if let Some((_, prepared)) = prepared.as_ref() {
            if prepared.transaction.nonce() < context.nonce {
                return Ok(TxRefresh::Obsolete);
            }
            // An overlapping epoch may retry against an older context block;
            // do not replace its prepared transaction with a stale lower nonce.
            if prepared.transaction.nonce() != context.nonce
                || prepared.transaction.max_fee_per_gas() >= max_fee_per_gas
            {
                return Ok(TxRefresh::Ready);
            }
        }

        let transaction = self
            .config
            .prepare(&self.signer, context.nonce, max_fee_per_gas, key.0, call)
            .map_err(TxSubmissionError::Operation)?;
        *prepared = Some((
            key.clone(),
            PreparedTx {
                transaction,
                latest_base_fee_per_gas: context.base_fee_per_gas,
            },
        ));
        Ok(TxRefresh::Ready)
    }

    fn submit(&self, prepared: &PreparedTx) -> Result<(), TxSubmissionError> {
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
        session_id: [u8; 32],
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
            ChainCall::PostDkgResult { qc } => Self::DkgResult {
                session_id: qc.session_id,
                g2x: qc.g2x.0,
            },
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
            ChainEvent::DkgResultRecorded { qc, .. } => Self::DkgResult {
                session_id: qc.session_id,
                g2x: qc.g2x.0,
            },
        }
    }
}

impl TxConfig {
    fn prepare(
        &self,
        signer: &PrivateKeySigner,
        nonce: Nonce,
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
                expected: epoch,
                actual: Epoch(qc.epoch.0),
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
