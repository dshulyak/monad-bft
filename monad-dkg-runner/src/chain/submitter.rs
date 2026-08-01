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
use dkg_protocol::{ChainCall, ChainEvent};
use monad_eth_types::buffered_base_fee_per_gas;
use monad_types::{Epoch, SeqNum};
use tracing::{info, warn};

use super::{
    bindings::{
        bve_qc_to_contract, dkg_result_to_contract, pc_qc_to_contract, registration_to_contract,
        DkgContract,
    },
    chain_call_kind, DkgChain, DkgChainConfig,
};
use crate::DkgError;

pub(crate) struct TxSubmitter {
    config: DkgChainConfig,
    signer: PrivateKeySigner,
    chain: Arc<dyn DkgChain>,
    pending: BTreeMap<(Epoch, ChainTxId), PendingTx>,
    finalized: BTreeSet<(Epoch, ChainTxId)>,
    active_epochs: BTreeSet<Epoch>,
    recovered_epochs: BTreeSet<Epoch>,
    context_blocks: BTreeMap<Epoch, SeqNum>,
}

impl TxSubmitter {
    pub(crate) fn new(config: &DkgChainConfig, chain: Arc<dyn DkgChain>) -> Result<Self, DkgError> {
        let config = config.clone();
        let key = FixedBytes::<32>::from(config.signing_key);
        let signer = PrivateKeySigner::from_bytes(&key)
            .map_err(|err| DkgError::operation("construct DKG transaction signer", err))?;

        Ok(Self {
            config,
            signer,
            chain,
            pending: BTreeMap::new(),
            finalized: BTreeSet::new(),
            active_epochs: BTreeSet::new(),
            recovered_epochs: BTreeSet::new(),
            context_blocks: BTreeMap::new(),
        })
    }

    pub(crate) fn signer_address(&self) -> Address {
        self.signer.address()
    }

    pub(crate) fn submit_registration(&mut self, epoch: Epoch, block: SeqNum, bytes: Vec<u8>) {
        self.context_blocks.insert(epoch, block);
        self.submit(
            epoch,
            ChainCall::PostRegistration {
                bytes,
                dkg: dkg_core::Address(self.config.contract.into_array()),
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
        self.pending.retain(|(pending_epoch, id), _| {
            self.active_epochs.contains(pending_epoch)
                || (*pending_epoch > latest && matches!(id, ChainTxId::Registration { .. }))
        });
        self.finalized.retain(|(finalized_epoch, id)| {
            self.active_epochs.contains(finalized_epoch)
                || (*finalized_epoch > latest && matches!(id, ChainTxId::Registration { .. }))
        });
        self.recovered_epochs
            .retain(|recovered| self.active_epochs.contains(recovered));
        self.context_blocks
            .retain(|epoch, _| self.active_epochs.contains(epoch) || *epoch > latest);
    }

    pub(crate) fn submit(&mut self, epoch: Epoch, call: ChainCall) {
        let key = (epoch, ChainTxId::from_call(&call));
        let immediate = matches!(&call, ChainCall::PostRegistration { .. });
        if !immediate && !self.active_epochs.contains(&epoch) {
            return;
        }

        if self.finalized.contains(&key) || self.pending.contains_key(&key) {
            return;
        }

        self.pending.insert(
            key.clone(),
            PendingTx {
                call,
                prepared: None,
            },
        );
        if immediate || self.recovered_epochs.contains(&epoch) {
            self.submit_keys([key]);
        }
    }

    pub(crate) fn retry_registration(&mut self, epoch: Epoch, block: SeqNum) {
        self.context_blocks.insert(epoch, block);
        let keys = self
            .pending
            .keys()
            .filter(|(pending_epoch, id)| {
                *pending_epoch == epoch && matches!(id, ChainTxId::Registration { .. })
            })
            .cloned()
            .collect::<Vec<_>>();
        self.submit_keys(keys);
    }

    pub(crate) fn confirm_registration(&mut self, epoch: Epoch, bytes: &[u8]) {
        let id = ChainTxId::registration(bytes);
        self.finalized.insert((epoch, id.clone()));
        self.pending.remove(&(epoch, id));
    }

    pub(crate) fn cancel_registration(&mut self, epoch: Epoch) {
        self.pending.retain(|(pending_epoch, id), _| {
            *pending_epoch != epoch || !matches!(id, ChainTxId::Registration { .. })
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
        self.context_blocks.insert(epoch, block);
        for event in events {
            let id = ChainTxId::from_event(&event);
            self.finalized.insert((epoch, id.clone()));
            self.pending.remove(&(epoch, id));
        }
        if recovery_complete_after {
            self.recovered_epochs.insert(epoch);
        }
        if self.recovered_epochs.contains(&epoch) {
            let keys = self
                .pending
                .keys()
                .filter(|(pending_epoch, _)| *pending_epoch == epoch)
                .cloned()
                .collect::<Vec<_>>();
            self.submit_keys(keys);
        }
    }

    fn submit_keys(&mut self, keys: impl IntoIterator<Item = (Epoch, ChainTxId)>) {
        let keys = keys.into_iter().collect::<Vec<_>>();
        if keys.is_empty() {
            return;
        }

        let active = self
            .pending
            .iter()
            .find_map(|(key, pending)| pending.prepared.is_some().then_some(key.clone()));
        let key = match active {
            Some(active) if keys.contains(&active) => active,
            Some(_) => return,
            None => {
                let Some(key) = keys.iter().find(|key| self.pending.contains_key(key)) else {
                    return;
                };
                key.clone()
            }
        };

        let (epoch, id) = key;
        let prepared = self
            .pending
            .get(&(epoch, id.clone()))
            .expect("selected pending DKG chain tx")
            .prepared
            .as_ref();
        // New work must see nonces consumed by overlapping sessions, while an
        // active retry stays at its own event-scan boundary until its outcome is known.
        let block = prepared
            .and_then(|_| self.context_blocks.get(&epoch).copied())
            .or_else(|| self.context_blocks.values().copied().max());
        let Some(block) = block else {
            warn!(
                epoch = epoch.0,
                "missing DKG transaction context block; will retry"
            );
            return;
        };
        let config = &self.config;
        let signer = &self.signer;
        let transaction_context = match self.chain.transaction_context(block, signer.address()) {
            Ok(context) => context,
            Err(err) => {
                warn!(
                    ?err,
                    block = block.0,
                    "failed to read DKG transaction context; will retry"
                );
                return;
            }
        };
        let chain_nonce = transaction_context.nonce;
        let max_fee_per_gas =
            buffered_base_fee_per_gas(u128::from(transaction_context.base_fee_per_gas))
                .saturating_add(config.max_priority_fee_per_gas);
        // A consumed nonce with no matching event is a finalized no-op/revert
        // (for example, a second BVE witness for the same submitter/dealer pair).
        if prepared.is_some_and(|prepared| prepared.nonce() < chain_nonce) {
            let call_kind = chain_call_kind(
                &self
                    .pending
                    .get(&(epoch, id.clone()))
                    .expect("selected pending DKG chain tx")
                    .call,
            );
            self.pending.remove(&(epoch, id.clone()));
            self.finalized.insert((epoch, id));
            info!(
                epoch = epoch.0,
                call_kind,
                chain_nonce,
                "retired finalized DKG transaction without a matching event"
            );
            self.submit_keys(keys);
            return;
        }
        let pending = self
            .pending
            .get_mut(&(epoch, id.clone()))
            .expect("selected pending DKG chain tx");
        if pending.prepared.as_ref().is_some_and(|prepared| {
            prepared.nonce() == chain_nonce && prepared.max_fee_per_gas() < max_fee_per_gas
        }) {
            pending.prepared = None;
        }
        let call_kind = chain_call_kind(&pending.call);
        if pending.prepared.is_none() {
            match prepare_chain_call(
                config,
                signer,
                chain_nonce,
                max_fee_per_gas,
                epoch,
                &pending.call,
            ) {
                Ok(prepared) => pending.prepared = Some(prepared),
                Err(err) => {
                    warn!(
                        ?err,
                        epoch = epoch.0,
                        call_kind,
                        "failed to prepare DKG chain tx; will retry"
                    );
                    return;
                }
            }
        }

        let prepared = pending.prepared.as_ref().expect("prepared above");
        match self.chain.submit_transaction(prepared.clone()) {
            Ok(()) => {
                info!(
                    epoch = epoch.0,
                    call_kind,
                    nonce = prepared.nonce(),
                    latest_base_fee_per_gas = transaction_context.base_fee_per_gas,
                    max_fee_per_gas = prepared.max_fee_per_gas(),
                    max_priority_fee_per_gas = config.max_priority_fee_per_gas,
                    tx_hash = %prepared.tx_hash(),
                    "queued DKG transaction for local txpool insertion"
                );
            }
            Err(err) => {
                warn!(
                    ?err,
                    epoch = epoch.0,
                    call_kind,
                    nonce = prepared.nonce(),
                    tx_hash = %prepared.tx_hash(),
                    "failed to queue DKG chain tx; will retry"
                );
            }
        }
    }
}

struct PendingTx {
    call: ChainCall,
    prepared: Option<TxEnvelope>,
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

impl ChainTxId {
    fn registration(bytes: &[u8]) -> Self {
        Self::Registration {
            digest: *blake3::hash(bytes).as_bytes(),
        }
    }

    fn from_call(call: &ChainCall) -> Self {
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
            ChainCall::PostRegistration { bytes, .. } => Self::registration(bytes),
        }
    }

    fn from_event(event: &ChainEvent) -> Self {
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

fn prepare_chain_call(
    config: &DkgChainConfig,
    signer: &PrivateKeySigner,
    nonce: u64,
    max_fee_per_gas: u128,
    epoch: Epoch,
    call: &ChainCall,
) -> Result<TxEnvelope, DkgError> {
    if let ChainCall::PostRegistration { dkg, .. } = call {
        if dkg.0 != config.contract.into_array() {
            return Err(DkgError::RegistrationContractMismatch {
                expected: config.contract,
                actual: Address::from(dkg.0),
            });
        }
    }
    let calldata = contract_calldata(epoch, call, signer.address())?;
    let transaction = TxEip1559 {
        chain_id: config.chain_id,
        nonce,
        gas_limit: config.gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas: config.max_priority_fee_per_gas,
        to: TxKind::Call(config.contract),
        value: U256::ZERO,
        access_list: Default::default(),
        input: calldata.into(),
    };
    let signature = signer
        .sign_hash_sync(&transaction.signature_hash())
        .map_err(|err| DkgError::operation("sign DKG transaction", err))?;
    Ok(TxEnvelope::Eip1559(transaction.into_signed(signature)))
}

fn contract_calldata(epoch: Epoch, call: &ChainCall, signer: Address) -> Result<Vec<u8>, DkgError> {
    match call {
        ChainCall::PostPCQc { qc } => Ok(DkgContract::postPcQcCall {
            epoch: epoch.0,
            qc: pc_qc_to_contract(qc),
        }
        .abi_encode()),
        ChainCall::PostBveQc { qc } => Ok(DkgContract::postBveQcCall {
            epoch: epoch.0,
            qc: bve_qc_to_contract(qc),
        }
        .abi_encode()),
        ChainCall::PostDkgResult { qc } if qc.epoch.0 == epoch.0 => {
            Ok(DkgContract::submitResultCall {
                epoch: epoch.0,
                result: dkg_result_to_contract(qc),
            }
            .abi_encode())
        }
        ChainCall::PostDkgResult { qc } => Err(DkgError::ResultEpochMismatch {
            expected: epoch.0,
            actual: qc.epoch.0,
        }),
        ChainCall::PostRegistration { bytes, .. } => Ok(DkgContract::registerCall {
            epoch: epoch.0,
            registration: registration_to_contract(bytes, signer)
                .map_err(|source| DkgError::operation("encode typed DKG registration", source))?,
        }
        .abi_encode()),
    }
}

#[cfg(test)]
#[path = "submitter_tests.rs"]
mod tests;
