//! Finalized contract reads, event delivery, and transaction submission.

use std::collections::BTreeMap;

use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, B256};
use alloy_sol_types::sol;
use dkg_core::{PartyId, RecordId, SessionId};
use dkg_crypto::{BlsG2SerializedBytes, SecpPointBytes, SecpScalarBytes, BLS_G2_SERIALIZED_BYTES};
use dkg_protocol::{
    BveQc, ChainCall, ChainEvent, DkgDoneQc, PCQc, QcSignature, QcSignatureBytes, RegistrationCall,
};
use monad_types::{Epoch, SeqNum};
use thiserror::Error;
use tracing::info;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::DkgError;

use self::recovery::SessionScan;

mod recovery;
mod submitter;
mod triedb;
mod triedb_state;

pub use triedb::new_triedb_runner;

pub(crate) use submitter::TxSubmitter;

sol!("../dkg-contracts/src/DkgContract.sol");

use DkgContract::{
    BveQc as ContractBveQc, BveQcPosted, DkgResult as ContractDkgResult, DkgResultPosted,
    PcQc as ContractPcQc, PcQcPosted, QcSignature as ContractQcSignature,
    RecordPage as ContractRecordPage, Registration as ContractRegistration,
    SecpPoint as ContractSecpPoint,
};

const COMPRESSED_SECP_POINT_BYTES: usize = 33;

#[derive(Debug, Error)]
pub enum ContractCodecError {
    #[error("typed DKG registration address {actual} does not match signer {expected}")]
    RegistrationAddress { expected: Address, actual: Address },
    #[error("typed DKG registration contains invalid QC verifier {address}")]
    InvalidQcVerifier { address: Address },
    #[error("typed DKG QC has {count} signatures, expected 1..={maximum}")]
    SignatureCount { count: usize, maximum: usize },
    #[error("typed DKG QC signer {signer} is outside the {party_count}-party session")]
    SignerOutOfRange { signer: u32, party_count: usize },
    #[error("typed DKG QC signers are not strictly increasing at signer {signer}")]
    NonCanonicalSigners { signer: u32 },
}

impl TryFrom<(&RegistrationCall, Address)> for ContractRegistration {
    type Error = ContractCodecError;

    fn try_from((registration, signer): (&RegistrationCall, Address)) -> Result<Self, Self::Error> {
        let encoded = Address::from(registration.address.0);
        if encoded != signer {
            return Err(ContractCodecError::RegistrationAddress {
                expected: signer,
                actual: encoded,
            });
        }

        Ok(Self {
            qcVerifier: Address::from(<[u8; 20]>::from(registration.qc_verifier)),
            receiverPublicKey: registration.receiver_public_key.0.into(),
            receiverKeyImage: registration.receiver_key_image.0.into(),
            proofU0: registration.proof_u0.0.into(),
            proofV0: registration.proof_v0.0.into(),
            proofZ: B256::from(registration.proof_z.0),
        })
    }
}

impl ContractRegistration {
    pub(super) fn into_registration(
        self,
        address: Address,
    ) -> Result<RegistrationCall, ContractCodecError> {
        let qc_verifier = self
            .qcVerifier
            .into_array()
            .try_into()
            .map_err(|_| ContractCodecError::InvalidQcVerifier {
                address: self.qcVerifier,
            })?;
        Ok(RegistrationCall {
            address: dkg_core::Address(address.into_array()),
            qc_verifier,
            receiver_public_key: SecpPointBytes(self.receiverPublicKey.into()),
            receiver_key_image: SecpPointBytes(self.receiverKeyImage.into()),
            proof_u0: SecpPointBytes(self.proofU0.into()),
            proof_v0: SecpPointBytes(self.proofV0.into()),
            proof_z: SecpScalarBytes(self.proofZ.0),
        })
    }
}

impl From<&PCQc> for ContractPcQc {
    fn from(qc: &PCQc) -> Self {
        Self {
            dealer: qc.dealer.0,
            digest: B256::from(qc.digest),
            signatures: ContractQcSignature::encode_all(&qc.signatures),
        }
    }
}

impl From<&BveQc> for ContractBveQc {
    fn from(qc: &BveQc) -> Self {
        Self {
            dealer: qc.dealer.0,
            digest: B256::from(qc.digest),
            commitmentDigest: B256::from(qc.commitment_digest),
            signatures: ContractQcSignature::encode_all(&qc.signatures),
        }
    }
}

impl From<&DkgDoneQc> for ContractDkgResult {
    fn from(qc: &DkgDoneQc) -> Self {
        Self {
            g2x: std::array::from_fn(|index| {
                let start = index * 32;
                B256::from_slice(&qc.g2x.0[start..start + 32])
            }),
            signatures: ContractQcSignature::encode_all(&qc.signatures),
        }
    }
}

impl PcQcPosted {
    pub(super) fn to_chain_event(
        &self,
        record_id: RecordId,
        party_count: usize,
    ) -> Result<ChainEvent, ContractCodecError> {
        ContractPcQc {
            dealer: self.dealer,
            digest: self.digest,
            signatures: self.signatures.clone(),
        }
        .into_chain_event(record_id, party_count)
    }
}

impl BveQcPosted {
    pub(super) fn to_chain_event(
        &self,
        record_id: RecordId,
        party_count: usize,
    ) -> Result<ChainEvent, ContractCodecError> {
        ContractBveQc {
            dealer: self.dealer,
            digest: self.digest,
            commitmentDigest: self.commitmentDigest,
            signatures: self.signatures.clone(),
        }
        .into_chain_event(record_id, party_count)
    }
}

impl DkgResultPosted {
    pub(super) fn to_chain_event(
        &self,
        record_id: RecordId,
        party_count: usize,
    ) -> Result<ChainEvent, ContractCodecError> {
        ContractDkgResult {
            g2x: self.g2x,
            signatures: self.signatures.clone(),
        }
        .into_chain_event(record_id, SessionId(self.epoch), party_count)
    }
}

impl ContractPcQc {
    pub(super) fn into_chain_event(
        self,
        record_id: RecordId,
        party_count: usize,
    ) -> Result<ChainEvent, ContractCodecError> {
        Ok(ChainEvent::PCQc {
            record_id,
            qc: PCQc {
                dealer: PartyId(self.dealer),
                digest: self.digest.0,
                signatures: ContractQcSignature::decode_all(self.signatures, party_count)?,
            },
        })
    }
}

impl ContractBveQc {
    pub(super) fn into_chain_event(
        self,
        record_id: RecordId,
        party_count: usize,
    ) -> Result<ChainEvent, ContractCodecError> {
        Ok(ChainEvent::BveQcFinalized {
            record_id,
            qc: BveQc {
                dealer: PartyId(self.dealer),
                digest: self.digest.0,
                commitment_digest: self.commitmentDigest.0,
                signatures: ContractQcSignature::decode_all(self.signatures, party_count)?,
            },
        })
    }
}

impl ContractDkgResult {
    pub(super) fn into_chain_event(
        self,
        record_id: RecordId,
        epoch: SessionId,
        party_count: usize,
    ) -> Result<ChainEvent, ContractCodecError> {
        let mut point = [0_u8; BLS_G2_SERIALIZED_BYTES];
        for (chunk, limb) in point.chunks_exact_mut(32).zip(self.g2x) {
            chunk.copy_from_slice(limb.as_slice());
        }
        Ok(ChainEvent::DkgResultRecorded {
            record_id,
            qc: DkgDoneQc {
                epoch,
                g2x: BlsG2SerializedBytes(point),
                signatures: ContractQcSignature::decode_all(self.signatures, party_count)?,
            },
        })
    }
}

impl From<[u8; COMPRESSED_SECP_POINT_BYTES]> for ContractSecpPoint {
    fn from(point: [u8; COMPRESSED_SECP_POINT_BYTES]) -> Self {
        Self {
            prefix: point[0],
            x: B256::from_slice(&point[1..]),
        }
    }
}

impl From<ContractSecpPoint> for [u8; COMPRESSED_SECP_POINT_BYTES] {
    fn from(point: ContractSecpPoint) -> Self {
        let mut bytes = [0; COMPRESSED_SECP_POINT_BYTES];
        bytes[0] = point.prefix;
        bytes[1..].copy_from_slice(point.x.as_slice());
        bytes
    }
}

impl From<QcSignature> for ContractQcSignature {
    fn from(signature: QcSignature) -> Self {
        Self {
            signer: signature.signer.0,
            r: B256::from_slice(&signature.signature.0[..32]),
            s: B256::from_slice(&signature.signature.0[32..]),
        }
    }
}

impl ContractQcSignature {
    fn encode_all(signatures: &[QcSignature]) -> Vec<Self> {
        let mut signatures = signatures.to_vec();
        signatures.sort_unstable_by_key(|signature| signature.signer.0);
        signatures.into_iter().map(Into::into).collect()
    }

    fn decode_all(
        signatures: Vec<Self>,
        party_count: usize,
    ) -> Result<Vec<QcSignature>, ContractCodecError> {
        if signatures.is_empty() || signatures.len() > party_count {
            return Err(ContractCodecError::SignatureCount {
                count: signatures.len(),
                maximum: party_count,
            });
        }

        let mut previous = None;
        signatures
            .into_iter()
            .map(|signature| {
                let signer = signature.signer;
                if usize::try_from(signer).map_or(true, |signer| signer >= party_count) {
                    return Err(ContractCodecError::SignerOutOfRange {
                        signer,
                        party_count,
                    });
                }
                if previous.is_some_and(|previous| signer <= previous) {
                    return Err(ContractCodecError::NonCanonicalSigners { signer });
                }
                previous = Some(signer);
                let mut bytes = [0_u8; 64];
                bytes[..32].copy_from_slice(signature.r.as_slice());
                bytes[32..].copy_from_slice(signature.s.as_slice());
                Ok(QcSignature {
                    signer: PartyId(signer),
                    signature: QcSignatureBytes(bytes),
                })
            })
            .collect()
    }
}

const DEFAULT_TX_GAS_LIMIT: u64 = 5_000_000;
const DEFAULT_TX_MAX_PRIORITY_FEE_PER_GAS: u128 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DkgTransactionContext {
    pub nonce: u64,
    pub base_fee_per_gas: u64,
}

/// The only boundary between the DKG runner and chain-specific I/O.
///
/// The runner owns recovery timing, retry, ordering, and delivery into the
/// protocol engine. Implementations only read a requested chain boundary or
/// finalized block and submit transactions through the host node.
pub(crate) trait DkgChain: Send + Sync + 'static {
    /// Reads registrations for the requested parties at exactly `block`.
    ///
    /// The returned registrations must be in request order and omit
    /// unregistered parties. Returns [`DkgError::ChainDataUnavailable`] when
    /// the execution state has not reached the requested block.
    fn read_registrations(
        &self,
        block: SeqNum,
        epoch: Epoch,
        parties: &[Address],
    ) -> Result<Vec<RegistrationCall>, DkgError>;

    /// Reads either the recovery snapshot or one finalized block. Returns
    /// [`DkgError::ChainDataUnavailable`] when its state or receipts are not
    /// available yet.
    fn read_events(&self, read: ChainRead) -> Result<Vec<ChainEvent>, DkgError>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChainEventSession {
    pub epoch: Epoch,
    pub party_count: usize,
    pub recovery_block: SeqNum,
}

#[derive(Debug)]
pub(crate) struct ChainEventBatch {
    pub session: ChainEventSession,
    pub block: SeqNum,
    pub events: Vec<ChainEvent>,
    pub recovery_complete_after: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChainRead {
    Snapshot(ChainEventSession),
    Block(SeqNum, ChainEventSession),
}

impl ChainRead {
    pub(crate) fn session(self) -> ChainEventSession {
        match self {
            Self::Snapshot(session) | Self::Block(_, session) => session,
        }
    }

    pub(crate) fn block(self) -> SeqNum {
        match self {
            Self::Snapshot(session) => session.recovery_block,
            Self::Block(block, _) => block,
        }
    }
}

#[derive(Default)]
pub(crate) struct ChainEventReader {
    finalized: Option<SeqNum>,
    scans: BTreeMap<Epoch, SessionScan>,
}

impl ChainEventReader {
    pub(crate) fn notify_finalized(&mut self, block: SeqNum) {
        self.finalized = Some(self.finalized.map_or(block, |latest| latest.max(block)));
    }

    pub(crate) fn start_session(&mut self, session: ChainEventSession) {
        self.scans
            .insert(session.epoch, SessionScan::new(session, self.finalized));
        while self.scans.len() > crate::MAX_RETAINED_DKG_SESSIONS {
            let (epoch, _) = self.scans.pop_first().expect("excess scan");
            info!(epoch = epoch.0, "retired old DKG chain cursor");
        }
        info!(
            epoch = session.epoch.0,
            party_count = session.party_count,
            recovery_block = session.recovery_block.0,
            "started DKG chain recovery"
        );
    }

    pub(crate) fn next_read(&self) -> Option<ChainRead> {
        self.scans.values().find_map(|scan| {
            let latest = self
                .finalized
                .unwrap_or(scan.recovery_block())
                .max(scan.recovery_block());
            scan.next(latest)
        })
    }

    pub(crate) fn complete(&mut self, read: ChainRead, events: Vec<ChainEvent>) -> ChainEventBatch {
        let session = read.session();
        let scan = self
            .scans
            .get_mut(&session.epoch)
            .expect("blocking DKG read keeps its cursor alive");
        let recovery_complete_after = scan.advance(read);
        if recovery_complete_after {
            info!(
                epoch = session.epoch.0,
                through_block = read.block().0,
                "completed DKG chain recovery"
            );
        }
        ChainEventBatch {
            session,
            block: read.block(),
            events,
            recovery_complete_after,
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

#[cfg(test)]
mod bindings_tests {
    use super::*;
    use crate::DkgLocalKeyMaterial;

    #[test]
    fn registration_boundary_round_trips_protocol_encoding() {
        let address = Address::repeat_byte(0xA5);
        let registration = DkgLocalKeyMaterial::derive([0x11; 32])
            .registration(address.into_array(), 7)
            .unwrap();

        let contract = ContractRegistration::try_from((&registration, address)).unwrap();

        assert_eq!(contract.into_registration(address).unwrap(), registration);
    }

    #[test]
    fn registration_boundary_rejects_zero_qc_verifier() {
        let address = Address::repeat_byte(0xA5);
        let registration = DkgLocalKeyMaterial::derive([0x11; 32])
            .registration(address.into_array(), 7)
            .unwrap();
        let mut contract = ContractRegistration::try_from((&registration, address)).unwrap();
        contract.qcVerifier = Address::ZERO;

        assert!(matches!(
            contract.into_registration(address),
            Err(ContractCodecError::InvalidQcVerifier {
                address: Address::ZERO
            })
        ));
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod recovery_tests;
