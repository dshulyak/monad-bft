use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, FixedBytes, TxHash, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use dkg_protocol::{ChainCall, ChainEvent};
use monad_eth_types::buffered_base_fee_per_gas;
use monad_types::Epoch;
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
    signer_address: Address,
    chain: Arc<dyn DkgChain>,
    pending: BTreeMap<(Epoch, ChainTxId), PendingTx>,
    finalized: BTreeSet<(Epoch, ChainTxId)>,
    ready_epochs: BTreeSet<Epoch>,
}

impl TxSubmitter {
    pub(crate) fn new(config: &DkgChainConfig, chain: Arc<dyn DkgChain>) -> Result<Self, DkgError> {
        let config = config.clone();
        let key = FixedBytes::<32>::from(config.signing_key);
        let signer = PrivateKeySigner::from_bytes(&key)
            .map_err(|err| DkgError::operation("construct DKG transaction signer", err))?;
        let signer_address = signer.address();

        Ok(Self {
            config,
            signer,
            signer_address,
            chain,
            pending: BTreeMap::new(),
            finalized: BTreeSet::new(),
            ready_epochs: BTreeSet::new(),
        })
    }

    pub(crate) fn signer_address(&self) -> Address {
        self.signer_address
    }

    pub(crate) fn submit_registration(&mut self, epoch: Epoch, bytes: Vec<u8>) {
        self.submit(
            epoch,
            ChainCall::PostRegistration {
                bytes,
                dkg: dkg_core::Address(self.config.contract.into_array()),
            },
        );
    }

    pub(crate) fn start_session(&mut self, epoch: Epoch) {
        self.ready_epochs.remove(&epoch);
    }

    pub(crate) fn submit(&mut self, epoch: Epoch, call: ChainCall) {
        let key = (epoch, ChainTxId::from_call(&call));
        let immediate = matches!(&call, ChainCall::PostRegistration { .. });

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
        if immediate || self.ready_epochs.contains(&epoch) {
            self.submit_keys([key]);
        }
    }

    pub(crate) fn retry_registration(&mut self, epoch: Epoch) {
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
        events: Vec<ChainEvent>,
        recovery_complete_after: bool,
    ) {
        for event in events {
            let id = ChainTxId::from_event(&event);
            self.finalized.insert((epoch, id.clone()));
            self.pending.remove(&(epoch, id));
        }
        if recovery_complete_after {
            self.ready_epochs.insert(epoch);
        }
        if self.ready_epochs.contains(&epoch) {
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

        let config = &self.config;
        let signer = &self.signer;
        let signer_address = self.signer_address;
        let transaction_context = match self.chain.transaction_context(signer_address) {
            Ok(context) => context,
            Err(err) => {
                warn!(?err, "failed to read DKG transaction context; will retry");
                return;
            }
        };
        let chain_nonce = transaction_context.nonce;
        let max_fee_per_gas =
            buffered_base_fee_per_gas(u128::from(transaction_context.base_fee_per_gas))
                .saturating_add(config.max_priority_fee_per_gas);

        for pending in self.pending.values_mut() {
            if pending.prepared.as_ref().is_some_and(|prepared| {
                prepared.nonce < chain_nonce
                    || (prepared.nonce == chain_nonce && prepared.max_fee_per_gas < max_fee_per_gas)
            }) {
                pending.prepared = None;
            }
        }

        let active = self
            .pending
            .iter()
            .find_map(|(key, pending)| pending.prepared.is_some().then_some(key.clone()));
        let key = match active {
            Some(active) if keys.contains(&active) => active,
            Some(_) => return,
            None => {
                let Some(key) = keys.into_iter().find(|key| self.pending.contains_key(key)) else {
                    return;
                };
                key
            }
        };

        let (epoch, id) = key;
        let pending = self
            .pending
            .get_mut(&(epoch, id.clone()))
            .expect("selected pending DKG chain tx");
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
        match self.chain.submit_transaction(prepared.tx.clone()) {
            Ok(()) => {
                info!(
                    epoch = epoch.0,
                    call_kind,
                    nonce = prepared.nonce,
                    latest_base_fee_per_gas = transaction_context.base_fee_per_gas,
                    max_fee_per_gas = prepared.max_fee_per_gas,
                    max_priority_fee_per_gas = config.max_priority_fee_per_gas,
                    tx_hash = %prepared.tx_hash,
                    "queued DKG transaction for local txpool insertion"
                );
            }
            Err(err) => {
                warn!(
                    ?err,
                    epoch = epoch.0,
                    call_kind,
                    nonce = prepared.nonce,
                    tx_hash = %prepared.tx_hash,
                    "failed to queue DKG chain tx; will retry"
                );
            }
        }
    }
}

struct PendingTx {
    call: ChainCall,
    prepared: Option<PreparedTx>,
}

struct PreparedTx {
    nonce: u64,
    max_fee_per_gas: u128,
    tx_hash: TxHash,
    tx: TxEnvelope,
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
        g2x: Vec<u8>,
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
            ChainCall::PostDkgResult { qc } => Self::DkgResult {
                g2x: qc.g2x.0.to_vec(),
            },
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
            ChainEvent::DkgResultRecorded { qc, .. } => Self::DkgResult {
                g2x: qc.g2x.0.to_vec(),
            },
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
) -> Result<PreparedTx, DkgError> {
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
    let tx = TxEnvelope::Eip1559(transaction.into_signed(signature));
    Ok(PreparedTx {
        nonce,
        max_fee_per_gas,
        tx_hash: *tx.tx_hash(),
        tx,
    })
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
