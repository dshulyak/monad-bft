use dkg_core::{Address, PartyId, PartySet, PartySetError, SessionId};
use dkg_crypto::{
    BlstBackend, BveConfig, K256SecpBackend, Matrix, MatrixShapeError, NonIdentitySecpPoint,
};
use dkg_protocol::{
    DkgEngine, DkgEngineError, DkgEngineParams, DkgSetupContext, DkgSetupError, DkgThresholdError,
    DkgThresholds, QcVerifyingKeyBytes, SecretKeys, VirtualTopology, VirtualTopologyError,
};
use monad_types::Epoch;
use thiserror::Error;

use crate::session::DkgRegisteredKeyMaterial;

pub(crate) type ResearchBls = BlstBackend;
pub(crate) type ResearchSecp = K256SecpBackend;
pub(crate) type ResearchEngine = DkgEngine<ResearchBls, ResearchSecp>;
pub(crate) const DKG_OUTPUT_COUNT: usize = 2;

#[derive(Debug, Error)]
pub(crate) enum EngineBuildError {
    #[error("derive DKG thresholds failed: {0}")]
    Threshold(#[source] DkgThresholdError),
    #[error("DKG {field} has {actual} entries, expected {expected}")]
    MaterialLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("build DKG party set failed: {0}")]
    PartySet(#[source] PartySetError),
    #[error("build DKG topology failed: {0}")]
    Topology(#[source] VirtualTopologyError),
    #[error("assemble DKG setup failed: {0}")]
    Setup(#[source] DkgSetupError),
    #[error("initialize research DKG engine failed: {0:?}")]
    Engine(DkgEngineError),
    #[error("local DKG party {party} is outside key material with {party_count} entries")]
    PartyOutOfRange { party: u32, party_count: usize },
    #[error("local DKG receiver secret does not match registered public key")]
    ReceiverKeyMismatch,
    #[error("local DKG QC signing key does not match registered verifying key")]
    QcKeyMismatch,
    #[error("shape DKG receiver public matrix failed: {0}")]
    ReceiverMatrix(#[source] MatrixShapeError),
}

pub(crate) fn build_engine(
    epoch: Epoch,
    self_party: PartyId,
    parties: Vec<PartyId>,
    key_material: DkgRegisteredKeyMaterial,
    seed: [u8; 32],
) -> Result<ResearchEngine, EngineBuildError> {
    let party_count = parties.len();
    let material = assemble_registered_material(key_material, self_party, party_count)?;
    let thresholds = DkgThresholds::derive(party_count, DKG_OUTPUT_COUNT)
        .map_err(EngineBuildError::Threshold)?;
    let party_set = PartySet::new(parties).map_err(EngineBuildError::PartySet)?;
    let topology = VirtualTopology::new(party_set, vec![1; party_count])
        .map_err(EngineBuildError::Topology)?;
    let setup = DkgSetupContext::assemble(
        self_party,
        SessionId(epoch.0),
        topology,
        thresholds,
        material.qc_verifying_keys,
        material.receiver_publics,
        material.addresses,
    )
    .map_err(EngineBuildError::Setup)?;
    ResearchEngine::from_setup(
        setup,
        DkgEngineParams {
            output_count: DKG_OUTPUT_COUNT,
            bve: BveConfig::default(),
        },
        material.local_keys,
        seed,
    )
    .map_err(EngineBuildError::Engine)
}

struct AssembledKeyMaterial {
    local_keys: SecretKeys<ResearchSecp>,
    receiver_publics: Matrix<NonIdentitySecpPoint<ResearchSecp>>,
    qc_verifying_keys: Vec<QcVerifyingKeyBytes>,
    addresses: Vec<Address>,
}

fn assemble_registered_material(
    material: DkgRegisteredKeyMaterial,
    self_party: PartyId,
    party_count: usize,
) -> Result<AssembledKeyMaterial, EngineBuildError> {
    let DkgRegisteredKeyMaterial {
        local,
        receiver_public_keys,
        qc_verifying_keys,
        addresses,
    } = material;
    for (name, actual) in [
        ("receiver public keys", receiver_public_keys.len()),
        ("QC verifying keys", qc_verifying_keys.len()),
        ("addresses", addresses.len()),
    ] {
        if actual != party_count {
            return Err(EngineBuildError::MaterialLength {
                field: name,
                actual,
                expected: party_count,
            });
        }
    }
    let local_index = self_party.0 as usize;
    let expected_receiver =
        receiver_public_keys
            .get(local_index)
            .ok_or(EngineBuildError::PartyOutOfRange {
                party: self_party.0,
                party_count,
            })?;
    if expected_receiver != &local.receiver_public_key {
        return Err(EngineBuildError::ReceiverKeyMismatch);
    }
    if local.qc_verifying_key != qc_verifying_keys[local_index] {
        return Err(EngineBuildError::QcKeyMismatch);
    }
    let receiver_publics = Matrix::from_vec(party_count, 1, receiver_public_keys)
        .map_err(EngineBuildError::ReceiverMatrix)?;
    Ok(AssembledKeyMaterial {
        local_keys: local.secret_keys,
        receiver_publics,
        qc_verifying_keys,
        addresses,
    })
}
