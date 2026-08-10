use std::{collections::HashSet, path::Path};

use alloy_primitives::Address;
use dkg_crypto::{secp::signature::SignatureError, K256SecpBackend};
use dkg_protocol::{
    decode_registration, encode_registration, verify_party_registration, PartyRegistration,
    RegistrationCall, RegistrationCodecError,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId, Stake};
use thiserror::Error;

use crate::{
    recovery::{RecoveryWal, RecoveryWalConfig, RecoveryWalError},
    DkgLocalKeyMaterial, DkgValidator,
};

#[derive(Debug, Error)]
pub(crate) enum RegistrationError {
    #[error("multiple validators map to DKG address {address}")]
    DuplicateValidatorAddress { address: Address },
    #[error("no finalized validator has a DKG registration")]
    NoEligibleValidator,
    #[error("registration snapshot has {actual} entries for {expected} validators")]
    RegistrationCountMismatch { expected: usize, actual: usize },
    #[error(transparent)]
    Wal(#[from] RecoveryWalError),
    #[error("decode local DKG keys failed: {0}")]
    LocalKeys(#[source] crate::DkgError),
    #[error("persisted DKG registration receiver key does not match the local key")]
    ReceiverKeyMismatch,
    #[error("persisted DKG registration QC verifier does not match the local signer")]
    QcVerifierMismatch,
    #[error("decode DKG registration for {address} failed: {source}")]
    Decode {
        address: Address,
        #[source]
        source: RegistrationCodecError,
    },
    #[error(
        "DKG registration getter address {requested} does not match encoded address {encoded}"
    )]
    AddressMismatch {
        requested: Address,
        encoded: Address,
    },
    #[error("verify DKG registration for {address} failed: {source}")]
    Verification {
        address: Address,
        #[source]
        source: SignatureError,
    },
    #[error("invalid DKG receiver proof for {address} at epoch {epoch}")]
    InvalidReceiverProof { address: Address, epoch: Epoch },
}

pub(crate) struct RegisteredSession<ST>
where
    ST: CertificateSignatureRecoverable,
{
    pub parties: Vec<RegisteredParty<ST>>,
    pub local_keys: dkg_protocol::SecretKeys<K256SecpBackend>,
}

pub(crate) struct RegisteredParty<ST>
where
    ST: CertificateSignatureRecoverable,
{
    pub node_id: NodeId<CertificateSignaturePubKey<ST>>,
    pub stake: Stake,
    pub registration: PartyRegistration<K256SecpBackend>,
}

pub(crate) fn assemble_registered_session<ST>(
    epoch: Epoch,
    self_id: NodeId<CertificateSignaturePubKey<ST>>,
    validators: Vec<DkgValidator<ST>>,
    local_keys: &DkgLocalKeyMaterial,
    registrations: Vec<Option<RegistrationCall>>,
) -> Result<RegisteredSession<ST>, RegistrationError>
where
    ST: CertificateSignatureRecoverable,
{
    let mut validator_addresses = HashSet::with_capacity(validators.len());
    for validator in &validators {
        if !validator_addresses.insert(validator.address) {
            return Err(RegistrationError::DuplicateValidatorAddress {
                address: validator.address,
            });
        }
    }
    if registrations.len() != validators.len() {
        return Err(RegistrationError::RegistrationCountMismatch {
            expected: validators.len(),
            actual: registrations.len(),
        });
    }

    // Party IDs are compact ranks in the finalized validator-set order. Missing
    // registrations are filtered without changing the relative validator order.
    let eligible = validators
        .into_iter()
        .zip(registrations)
        .filter_map(|(validator, registration)| registration.map(|record| (validator, record)))
        .map(|(validator, registration)| {
            verify_registration(validator.address, registration, epoch)
                .map(|registration| (validator, registration))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if eligible.is_empty() {
        return Err(RegistrationError::NoEligibleValidator);
    }

    let local = local_keys.decode().map_err(RegistrationError::LocalKeys)?;
    if let Some((_, registration)) = eligible
        .iter()
        .find(|(validator, _)| validator.node_id == self_id)
    {
        if registration.receiver.public_key != local.receiver_public_key {
            return Err(RegistrationError::ReceiverKeyMismatch);
        }
        if registration.qc_verifier != local.qc_verifier {
            return Err(RegistrationError::QcVerifierMismatch);
        }
    }
    let parties = eligible
        .into_iter()
        .map(|(validator, registration)| RegisteredParty {
            node_id: validator.node_id,
            stake: validator.stake,
            registration,
        })
        .collect();
    Ok(RegisteredSession {
        parties,
        local_keys: local.secret_keys,
    })
}

pub(crate) fn load_or_create_local_registration(
    storage_root: &Path,
    epoch: Epoch,
    address: Address,
    local_keys: &DkgLocalKeyMaterial,
    finalized: Option<&RegistrationCall>,
) -> Result<RegistrationCall, RegistrationError> {
    let (mut wal, mut recovery) =
        RecoveryWal::open(storage_root, epoch, RecoveryWalConfig::default())?;
    let bytes = recovery.load_or_create_registration(&mut wal, || match finalized {
        Some(registration) => Ok(encode_registration(registration)),
        None => local_keys
            .registration(address, epoch)
            .map(|registration| encode_registration(&registration)),
    })?;
    let registration = decode_verified_registration(address, epoch, &bytes)?;

    let local = local_keys.decode().map_err(RegistrationError::LocalKeys)?;
    if registration.receiver.public_key != local.receiver_public_key {
        return Err(RegistrationError::ReceiverKeyMismatch);
    }

    if registration.qc_verifier != local.qc_verifier {
        return Err(RegistrationError::QcVerifierMismatch);
    }
    Ok(RegistrationCall::from_party(&registration))
}

fn verify_registration(
    expected_address: Address,
    registration: RegistrationCall,
    epoch: Epoch,
) -> Result<PartyRegistration<K256SecpBackend>, RegistrationError> {
    let registration = registration
        .into_party()
        .map_err(|source| RegistrationError::Decode {
            address: expected_address,
            source,
        })?;
    verify_decoded_registration(expected_address, epoch, registration)
}

fn decode_verified_registration(
    address: Address,
    epoch: Epoch,
    bytes: &[u8],
) -> Result<PartyRegistration<K256SecpBackend>, RegistrationError> {
    let requested = address;
    let registration = decode_registration::<K256SecpBackend>(bytes).map_err(|source| {
        RegistrationError::Decode {
            address: requested,
            source,
        }
    })?;
    verify_decoded_registration(address, epoch, registration)
}

fn verify_decoded_registration(
    address: Address,
    epoch: Epoch,
    registration: PartyRegistration<K256SecpBackend>,
) -> Result<PartyRegistration<K256SecpBackend>, RegistrationError> {
    let requested = address;
    if Address::from(registration.address.0) != address {
        return Err(RegistrationError::AddressMismatch {
            requested,
            encoded: Address::from(registration.address.0),
        });
    }
    if !verify_party_registration::<K256SecpBackend>(&registration, epoch.0).map_err(|source| {
        RegistrationError::Verification {
            address: requested,
            source,
        }
    })? {
        return Err(RegistrationError::InvalidReceiverProof {
            address: requested,
            epoch,
        });
    }
    Ok(registration)
}
