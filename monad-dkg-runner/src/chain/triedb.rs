use std::{path::PathBuf, sync::Arc};

use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, Bloom, Log, B256};
use alloy_sol_types::SolEvent;
use dkg_core::RecordId;
use dkg_protocol::{ChainEvent, RegistrationCall};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_execution_state_read::{
    ExecutionStateReadExt, ExecutionStateReadExtError, ExecutionStateReadThreadClient,
};
use monad_types::{Epoch, NodeId, SeqNum};
use monad_validator::signature_collection::SignatureCollection;
use thiserror::Error;

use crate::{DkgChainConfig, DkgError, DkgManager};

use super::{
    triedb_state::TriedbDkgStateReader, BveQcPosted, ChainRead, ContractCodecError, DkgChain,
    DkgResultPosted, DkgTransactionContext, PcQcPosted,
};
#[cfg(test)]
use super::{ContractBveQc, ContractDkgResult, ContractPcQc};

pub fn new_triedb_manager<ST, SCT>(
    self_id: NodeId<CertificateSignaturePubKey<ST>>,
    storage_root: PathBuf,
    chain_config: DkgChainConfig,
    state_read: ExecutionStateReadThreadClient<ST, SCT>,
    execution_delay: SeqNum,
) -> Result<(DkgManager<ST>, flume::Receiver<TxEnvelope>), DkgError>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>> + Send + Sync + 'static,
{
    let (transactions, transaction_rx) = flume::unbounded();
    let state_reader = TriedbDkgStateReader::new(chain_config.chain_id, execution_delay)
        .map_err(|source| DkgError::operation("open DKG Triedb chain", source))?;
    let chain = Arc::new(TriedbDkgChain {
        state_read,
        state_reader,
        contract: chain_config.contract,
        transactions,
    });
    let manager = DkgManager::new(self_id, storage_root, chain_config, chain)?;
    Ok((manager, transaction_rx))
}

struct TriedbDkgChain<ST, SCT>
where
    ST: CertificateSignatureRecoverable,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
{
    state_read: ExecutionStateReadThreadClient<ST, SCT>,
    state_reader: TriedbDkgStateReader,
    contract: Address,
    transactions: flume::Sender<TxEnvelope>,
}

impl<ST, SCT> DkgChain for TriedbDkgChain<ST, SCT>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>> + Send + Sync + 'static,
{
    fn read_registrations(
        &self,
        block: SeqNum,
        epoch: Epoch,
        parties: &[Address],
    ) -> Result<Vec<RegistrationCall>, DkgError> {
        let mut state = self.state_read.clone();
        self.state_reader
            .read_registrations(&mut state, block, self.contract, epoch, parties)
            .map_err(|source| source.into_dkg_error("read DKG registrations"))
    }

    fn read_events(&self, read: ChainRead) -> Result<Vec<ChainEvent>, DkgError> {
        let session = read.session();
        match read {
            ChainRead::Snapshot(_) => self
                .state_reader
                .read(
                    &mut self.state_read.clone(),
                    read.block(),
                    self.contract,
                    session.epoch,
                    session.party_count,
                )
                .map_err(|source| source.into_dkg_error("read DKG chain events")),
            ChainRead::Block(block, _) => read_dkg_events(
                &mut self.state_read.clone(),
                block,
                &DkgLogMatcher::new(self.contract),
                session.epoch,
                session.party_count,
            ),
        }
    }

    fn transaction_context(
        &self,
        block: SeqNum,
        address: Address,
    ) -> Result<DkgTransactionContext, DkgError> {
        let mut state_read = self.state_read.clone();
        let latest_header = state_read.get_latest_block_header().map_err(|source| {
            DkgError::operation("read latest DKG transaction base fee", source)
        })?;
        let nonce = state_read
            .get_finalized_account(block, address)
            .map_err(|source| DkgError::operation("read finalized DKG nonce", source))?
            .map_or(0, |account| account.nonce);
        Ok(DkgTransactionContext {
            nonce,
            base_fee_per_gas: latest_header.0.base_fee_per_gas.unwrap_or_default(),
        })
    }

    fn submit_transaction(&self, transaction: TxEnvelope) -> Result<(), DkgError> {
        self.transactions
            .send(transaction)
            .map_err(|_| DkgError::ChannelClosed("submitting a local DKG transaction"))
    }
}

fn read_dkg_events<ST, SCT>(
    state_read: &mut impl ExecutionStateReadExt<ST, SCT>,
    block: SeqNum,
    matcher: &DkgLogMatcher,
    epoch: Epoch,
    party_count: usize,
) -> Result<Vec<ChainEvent>, DkgError>
where
    ST: CertificateSignatureRecoverable,
    SCT: SignatureCollection<NodeIdPubKey = CertificateSignaturePubKey<ST>>,
{
    let read_error = |source| match source {
        ExecutionStateReadExtError::NotAvailableYet => DkgError::ChainDataUnavailable { block },
        source => DkgError::operation("read finalized DKG events", source),
    };
    let header = state_read
        .get_finalized_block_header(block)
        .map_err(read_error)?;
    if !matcher.maybe_matches_bloom(header.0.logs_bloom) {
        return Ok(Vec::new());
    }
    let receipts = state_read
        .get_finalized_receipts(block)
        .map_err(read_error)?;
    let mut events = Vec::new();
    for receipt in receipts {
        if !matcher.maybe_matches_bloom(*receipt.receipt.logs_bloom()) {
            continue;
        }
        for log in receipt.receipt.logs() {
            if let Some(event) = matcher
                .match_log(log, epoch, party_count)
                .map_err(|source| DkgError::operation("decode DKG chain event", source))?
            {
                events.push(event);
            }
        }
    }
    Ok(events)
}

#[derive(Debug, Error)]
enum DkgLogError {
    #[error("decode DKG contract event failed: {0}")]
    Decode(#[from] alloy_sol_types::Error),
    #[error(transparent)]
    Contract(#[from] ContractCodecError),
}

struct DkgLogMatcher {
    contract: Address,
    blooms: [Bloom; 3],
}

impl DkgLogMatcher {
    fn new(contract: Address) -> Self {
        let blooms = Self::topics().map(|topic| {
            let mut bloom = Bloom::ZERO;
            bloom.accrue_raw_log(contract, &[topic]);
            bloom
        });
        Self { contract, blooms }
    }

    fn topics() -> [B256; 3] {
        [
            PcQcPosted::SIGNATURE_HASH,
            BveQcPosted::SIGNATURE_HASH,
            DkgResultPosted::SIGNATURE_HASH,
        ]
    }

    fn maybe_matches_bloom(&self, bloom: Bloom) -> bool {
        self.blooms.iter().any(|expected| bloom.contains(expected))
    }

    fn match_log(
        &self,
        log: &Log,
        epoch: Epoch,
        party_count: usize,
    ) -> Result<Option<ChainEvent>, DkgLogError> {
        if log.address != self.contract {
            return Ok(None);
        }

        let Some(topic) = log.topics().first().copied() else {
            return Ok(None);
        };
        match topic {
            PcQcPosted::SIGNATURE_HASH => {
                let event = PcQcPosted::decode_log(log)?;
                if event.epoch != epoch.0 {
                    return Ok(None);
                }
                let record_id = RecordId(event.sequence);
                event
                    .to_chain_event(record_id, party_count)
                    .map(Some)
                    .map_err(Into::into)
            }
            BveQcPosted::SIGNATURE_HASH => {
                let event = BveQcPosted::decode_log(log)?;
                if event.epoch != epoch.0 {
                    return Ok(None);
                }
                let record_id = RecordId(event.sequence);
                event
                    .to_chain_event(record_id, party_count)
                    .map(Some)
                    .map_err(Into::into)
            }
            DkgResultPosted::SIGNATURE_HASH => {
                let event = DkgResultPosted::decode_log(log)?;
                if event.epoch != epoch.0 {
                    return Ok(None);
                }
                let record_id = RecordId(event.sequence);
                event
                    .to_chain_event(record_id, party_count)
                    .map(Some)
                    .map_err(Into::into)
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use dkg_core::{PartyId, SessionId};
    use dkg_crypto::{BlsG2SerializedBytes, BLS_G2_SERIALIZED_BYTES};
    use dkg_protocol::{BveQc, ChainCall, DkgDoneQc, PCQc, QcSignature, QcSignatureBytes};

    use super::*;

    #[test]
    fn matcher_rejects_wrong_contract_epoch_or_session_witness() {
        let contract = Address::repeat_byte(0xD0);
        let matcher = DkgLogMatcher::new(contract);
        let call = ChainCall::PostPCQc {
            qc: PCQc {
                dealer: PartyId(1),
                digest: [0x11; 32],
                signatures: vec![signature(0)],
            },
        };
        assert!(matcher
            .match_log(
                &log_for_call(Address::repeat_byte(0xD1), Epoch(9), 0, &call),
                Epoch(9),
                4,
            )
            .unwrap()
            .is_none());
        assert!(matcher
            .match_log(&log_for_call(contract, Epoch(8), 0, &call), Epoch(9), 4)
            .unwrap()
            .is_none());

        let ChainCall::PostPCQc { qc } = &call else {
            unreachable!()
        };
        let mut qc = ContractPcQc::from(qc);
        qc.signatures[0].signer = 4;
        let log = Log {
            address: contract,
            data: PcQcPosted {
                epoch: 9,
                sequence: 0,
                dealer: qc.dealer,
                digest: qc.digest,
                signatures: qc.signatures,
            }
            .encode_log_data(),
        };
        assert!(matcher.match_log(&log, Epoch(9), 4).is_err());
    }

    #[test]
    fn matcher_bloom_requires_contract_and_a_dkg_event_topic() {
        let contract = Address::repeat_byte(0xA5);
        let matcher = DkgLogMatcher::new(contract);

        for topic in DkgLogMatcher::topics() {
            let mut matching = Bloom::ZERO;
            matching.accrue_raw_log(contract, &[topic]);
            assert!(matcher.maybe_matches_bloom(matching));
        }

        let mut wrong_topic = Bloom::ZERO;
        wrong_topic.accrue_raw_log(contract, &[B256::repeat_byte(0x11)]);
        assert!(!matcher.maybe_matches_bloom(wrong_topic));

        let mut wrong_contract = Bloom::ZERO;
        wrong_contract.accrue_raw_log(Address::repeat_byte(0xB6), &[PcQcPosted::SIGNATURE_HASH]);
        assert!(!matcher.maybe_matches_bloom(wrong_contract));
    }

    #[test]
    fn matcher_decodes_all_contract_record_types() {
        let contract = Address::repeat_byte(0xD0);
        let matcher = DkgLogMatcher::new(contract);
        let calls = [
            ChainCall::PostPCQc {
                qc: PCQc {
                    dealer: PartyId(1),
                    digest: [0x11; 32],
                    signatures: vec![signature(0), signature(2)],
                },
            },
            ChainCall::PostBveQc {
                qc: BveQc {
                    dealer: PartyId(2),
                    digest: [0x22; 32],
                    commitment_digest: [0x33; 32],
                    signatures: vec![signature(1), signature(3)],
                },
            },
            ChainCall::PostDkgResult {
                qc: DkgDoneQc {
                    epoch: SessionId(9),
                    g2x: BlsG2SerializedBytes([0x44; BLS_G2_SERIALIZED_BYTES]),
                    signatures: vec![signature(0), signature(1), signature(2)],
                },
            },
        ];

        for (index, call) in calls.into_iter().enumerate() {
            let record_id = RecordId(index as u64);
            let expected = match &call {
                ChainCall::PostPCQc { qc } => ChainEvent::PCQc {
                    record_id,
                    qc: qc.clone(),
                },
                ChainCall::PostBveQc { qc } => ChainEvent::BveQcFinalized {
                    record_id,
                    qc: qc.clone(),
                },
                ChainCall::PostDkgResult { qc } => ChainEvent::DkgResultRecorded {
                    record_id,
                    qc: qc.clone(),
                },
                ChainCall::PostRegistration { .. } => {
                    panic!("registration is not a DKG record event")
                }
            };
            let event = matcher
                .match_log(
                    &log_for_call(contract, Epoch(9), index as u64, &call),
                    Epoch(9),
                    4,
                )
                .expect("contract log should decode")
                .expect("contract log should match");
            assert_eq!(event, expected);
        }
    }

    fn log_for_call(contract: Address, epoch: Epoch, sequence: u64, call: &ChainCall) -> Log {
        let data = match call {
            ChainCall::PostPCQc { qc } => {
                let qc = ContractPcQc::from(qc);
                PcQcPosted {
                    epoch: epoch.0,
                    sequence,
                    dealer: qc.dealer,
                    digest: qc.digest,
                    signatures: qc.signatures,
                }
                .encode_log_data()
            }
            ChainCall::PostBveQc { qc } => {
                let qc = ContractBveQc::from(qc);
                BveQcPosted {
                    epoch: epoch.0,
                    sequence,
                    dealer: qc.dealer,
                    digest: qc.digest,
                    commitmentDigest: qc.commitmentDigest,
                    signatures: qc.signatures,
                }
                .encode_log_data()
            }
            ChainCall::PostDkgResult { qc } => {
                let result = ContractDkgResult::from(qc);
                DkgResultPosted {
                    epoch: epoch.0,
                    sequence,
                    g2x: result.g2x,
                    signatures: result.signatures,
                }
                .encode_log_data()
            }
            ChainCall::PostRegistration { .. } => panic!("registration is not a DKG record event"),
        };
        Log {
            address: contract,
            data,
        }
    }

    fn signature(signer: u32) -> QcSignature {
        QcSignature {
            signer: PartyId(signer),
            signature: QcSignatureBytes([signer as u8; 64]),
        }
    }
}
