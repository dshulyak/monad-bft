use alloy_primitives::{Address, B256};
use alloy_sol_types::sol;
use dkg_core::{PartyId, RecordId, SessionId};
use dkg_crypto::{BlsG2SerializedBytes, SecpPointBytes, SecpScalarBytes, BLS_G2_SERIALIZED_BYTES};
use dkg_protocol::{
    BveQc, ChainEvent, DkgDoneQc, PCQc, QcSignature, QcSignatureBytes, RegistrationCall,
};
use thiserror::Error;

sol! {
    struct ContractSecpPoint {
        uint8 prefix;
        bytes32 x;
    }

    struct ContractRegistration {
        ContractSecpPoint qcVerifyingKey;
        ContractSecpPoint receiverPublicKey;
        ContractSecpPoint receiverKeyImage;
        ContractSecpPoint proofU0;
        ContractSecpPoint proofV0;
        bytes32 proofZ;
    }

    struct ContractQcSignature {
        uint32 signer;
        bytes32 r;
        bytes32 s;
    }

    struct ContractPcQc {
        uint32 dealer;
        bytes32 digest;
        ContractQcSignature[] signatures;
    }

    struct ContractBveQc {
        uint32 dealer;
        bytes32 digest;
        bytes32 commitmentDigest;
        ContractQcSignature[] signatures;
    }

    struct ContractDkgResult {
        uint64 epoch;
        bytes32[6] g2x;
        ContractQcSignature[] signatures;
    }

    enum ContractRecordKind {
        PcQc,
        BveQc,
        DkgResult
    }

    struct ContractDkgRecord {
        ContractRecordKind kind;
        uint32 dealer;
        bytes32 digest;
        bytes32 commitmentDigest;
        uint64 resultEpoch;
        bytes32[6] g2x;
        ContractQcSignature[] signatures;
    }

    interface DkgContract {
        function register(uint64 epoch, ContractRegistration registration);
        function postPcQc(uint64 epoch, ContractPcQc qc);
        function postBveQc(uint64 epoch, ContractBveQc qc);
        function submitResult(uint64 epoch, ContractDkgResult result);
        function registrationOf(uint64 epoch, address party)
            external view returns (bool exists, ContractRegistration registration);
        function recordCount(uint64 epoch) external view returns (uint256);
        function recordAt(uint64 epoch, uint256 index)
            external view returns (ContractDkgRecord record);
    }

    event PcQcPosted(
        uint64 indexed epoch,
        uint64 indexed sequence,
        uint32 indexed dealer,
        bytes32 digest,
        ContractQcSignature[] signatures
    );
    event BveQcPosted(
        uint64 indexed epoch,
        uint64 indexed sequence,
        uint32 indexed dealer,
        bytes32 digest,
        bytes32 commitmentDigest,
        ContractQcSignature[] signatures
    );
    event DkgResultPosted(
        uint64 indexed epoch,
        uint64 indexed sequence,
        bytes32[6] g2x,
        ContractQcSignature[] signatures
    );
}

const COMPRESSED_SECP_POINT_BYTES: usize = 33;

#[derive(Debug, Error)]
pub(super) enum ContractCodecError {
    #[error("typed DKG registration address {actual} does not match signer {expected}")]
    RegistrationAddress { expected: Address, actual: Address },
    #[error("typed DKG QC has {count} signatures, expected 1..={maximum}")]
    SignatureCount { count: usize, maximum: usize },
    #[error("typed DKG QC signer {signer} is outside the {party_count}-party session")]
    SignerOutOfRange { signer: u32, party_count: usize },
    #[error("typed DKG QC signers are not strictly increasing at signer {signer}")]
    NonCanonicalSigners { signer: u32 },
    #[error("typed DKG record has an invalid kind")]
    InvalidRecordKind,
}

pub(super) fn registration_to_contract(
    registration: &RegistrationCall,
    signer: Address,
) -> Result<ContractRegistration, ContractCodecError> {
    let encoded = Address::from(registration.address.0);
    if encoded != signer {
        return Err(ContractCodecError::RegistrationAddress {
            expected: signer,
            actual: encoded,
        });
    }

    Ok(ContractRegistration {
        qcVerifyingKey: point_to_contract(registration.qc_verifying_key.0),
        receiverPublicKey: point_to_contract(registration.receiver_public_key.0),
        receiverKeyImage: point_to_contract(registration.receiver_key_image.0),
        proofU0: point_to_contract(registration.proof_u0.0),
        proofV0: point_to_contract(registration.proof_v0.0),
        proofZ: B256::from(registration.proof_z.0),
    })
}

pub(super) fn registration_from_contract(
    address: Address,
    registration: &ContractRegistration,
) -> RegistrationCall {
    RegistrationCall {
        address: dkg_core::Address(address.into_array()),
        qc_verifying_key: dkg_protocol::QcVerifyingKeyBytes(point_from_contract(
            &registration.qcVerifyingKey,
        )),
        receiver_public_key: SecpPointBytes(point_from_contract(&registration.receiverPublicKey)),
        receiver_key_image: SecpPointBytes(point_from_contract(&registration.receiverKeyImage)),
        proof_u0: SecpPointBytes(point_from_contract(&registration.proofU0)),
        proof_v0: SecpPointBytes(point_from_contract(&registration.proofV0)),
        proof_z: SecpScalarBytes(registration.proofZ.0),
    }
}

pub(super) fn pc_qc_to_contract(qc: &PCQc) -> ContractPcQc {
    ContractPcQc {
        dealer: qc.dealer.0,
        digest: B256::from(qc.digest),
        signatures: signatures_to_contract(&qc.signatures),
    }
}

pub(super) fn bve_qc_to_contract(qc: &BveQc) -> ContractBveQc {
    ContractBveQc {
        dealer: qc.dealer.0,
        digest: B256::from(qc.digest),
        commitmentDigest: B256::from(qc.commitment_digest),
        signatures: signatures_to_contract(&qc.signatures),
    }
}

pub(super) fn dkg_result_to_contract(qc: &DkgDoneQc) -> ContractDkgResult {
    ContractDkgResult {
        epoch: qc.epoch.0,
        g2x: std::array::from_fn(|index| {
            let start = index * 32;
            B256::from_slice(&qc.g2x.0[start..start + 32])
        }),
        signatures: signatures_to_contract(&qc.signatures),
    }
}

pub(super) fn pc_chain_event(
    record_id: RecordId,
    dealer: u32,
    digest: B256,
    signatures: Vec<ContractQcSignature>,
    party_count: usize,
) -> Result<ChainEvent, ContractCodecError> {
    Ok(ChainEvent::PCQc {
        record_id,
        qc: PCQc {
            dealer: PartyId(dealer),
            digest: digest.0,
            signatures: signatures_from_contract(signatures, party_count)?,
        },
    })
}

pub(super) fn bve_chain_event(
    record_id: RecordId,
    dealer: u32,
    digest: B256,
    commitment_digest: B256,
    signatures: Vec<ContractQcSignature>,
    party_count: usize,
) -> Result<ChainEvent, ContractCodecError> {
    Ok(ChainEvent::BveQcFinalized {
        record_id,
        qc: BveQc {
            dealer: PartyId(dealer),
            digest: digest.0,
            commitment_digest: commitment_digest.0,
            signatures: signatures_from_contract(signatures, party_count)?,
        },
    })
}

pub(super) fn result_chain_event(
    record_id: RecordId,
    epoch: u64,
    g2x: [B256; 6],
    signatures: Vec<ContractQcSignature>,
    party_count: usize,
) -> Result<ChainEvent, ContractCodecError> {
    let mut point = [0_u8; BLS_G2_SERIALIZED_BYTES];
    for (chunk, limb) in point.chunks_exact_mut(32).zip(g2x) {
        chunk.copy_from_slice(limb.as_slice());
    }
    Ok(ChainEvent::DkgResultRecorded {
        record_id,
        qc: DkgDoneQc {
            epoch: SessionId(epoch),
            g2x: BlsG2SerializedBytes(point),
            signatures: signatures_from_contract(signatures, party_count)?,
        },
    })
}

pub(super) fn record_to_chain_event(
    record_id: RecordId,
    record: ContractDkgRecord,
    party_count: usize,
) -> Result<ChainEvent, ContractCodecError> {
    match record.kind {
        ContractRecordKind::PcQc => pc_chain_event(
            record_id,
            record.dealer,
            record.digest,
            record.signatures,
            party_count,
        ),
        ContractRecordKind::BveQc => bve_chain_event(
            record_id,
            record.dealer,
            record.digest,
            record.commitmentDigest,
            record.signatures,
            party_count,
        ),
        ContractRecordKind::DkgResult => result_chain_event(
            record_id,
            record.resultEpoch,
            record.g2x,
            record.signatures,
            party_count,
        ),
        ContractRecordKind::__Invalid => Err(ContractCodecError::InvalidRecordKind),
    }
}

fn point_to_contract(point: [u8; COMPRESSED_SECP_POINT_BYTES]) -> ContractSecpPoint {
    ContractSecpPoint {
        prefix: point[0],
        x: B256::from_slice(&point[1..]),
    }
}

fn point_from_contract(point: &ContractSecpPoint) -> [u8; COMPRESSED_SECP_POINT_BYTES] {
    let mut bytes = [0; COMPRESSED_SECP_POINT_BYTES];
    bytes[0] = point.prefix;
    bytes[1..].copy_from_slice(point.x.as_slice());
    bytes
}

fn signatures_to_contract(signatures: &[QcSignature]) -> Vec<ContractQcSignature> {
    let mut signatures = signatures.to_vec();
    signatures.sort_unstable_by_key(|signature| signature.signer.0);
    signatures
        .into_iter()
        .map(|signature| ContractQcSignature {
            signer: signature.signer.0,
            r: B256::from_slice(&signature.signature.0[..32]),
            s: B256::from_slice(&signature.signature.0[32..]),
        })
        .collect()
}

fn signatures_from_contract(
    signatures: Vec<ContractQcSignature>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DkgLocalKeyMaterial;

    #[test]
    fn registration_boundary_round_trips_protocol_encoding() {
        let address = Address::repeat_byte(0xA5);
        let registration = DkgLocalKeyMaterial::derive([0x11; 32])
            .registration(address.into_array(), 7)
            .unwrap();

        let contract = registration_to_contract(&registration, address).unwrap();

        assert_eq!(registration_from_contract(address, &contract), registration);
    }
}
