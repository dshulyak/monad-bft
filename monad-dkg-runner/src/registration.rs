use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use alloy_primitives::Address;
use dkg_crypto::{secp::signature::SignatureError, K256SecpBackend};
use dkg_protocol::{
    decode_registration, encode_registration, verify_party_registration, PartyRegistration,
    RegistrationCall, RegistrationCodecError,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId};
use thiserror::Error;

use crate::{
    recovery::{RecoveryWal, RecoveryWalConfig, RecoveryWalError},
    DkgLocalKeyMaterial, DkgRegisteredKeyMaterial, DkgValidator,
};

#[derive(Debug, Error)]
pub(crate) enum RegistrationError {
    #[error("multiple validators map to DKG address {address}")]
    DuplicateValidatorAddress { address: Address },
    #[error("duplicate DKG registration for {address}")]
    DuplicateRegistration { address: Address },
    #[error("no finalized validator has a DKG registration")]
    NoEligibleValidator,
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
    InvalidReceiverProof { address: Address, epoch: u64 },
}

pub(crate) struct RegisteredSession<ST>
where
    ST: CertificateSignatureRecoverable,
{
    pub validators: Vec<NodeId<CertificateSignaturePubKey<ST>>>,
    pub key_material: DkgRegisteredKeyMaterial,
}

pub(crate) fn assemble_registered_session<ST>(
    epoch: Epoch,
    self_id: NodeId<CertificateSignaturePubKey<ST>>,
    validators: Vec<DkgValidator<ST>>,
    local_keys: &DkgLocalKeyMaterial,
    registrations: Vec<RegistrationCall>,
) -> Result<RegisteredSession<ST>, RegistrationError>
where
    ST: CertificateSignatureRecoverable,
{
    let mut validator_addresses = HashSet::with_capacity(validators.len());
    for validator in &validators {
        if !validator_addresses.insert(validator.address) {
            return Err(RegistrationError::DuplicateValidatorAddress {
                address: Address::from(validator.address),
            });
        }
    }

    let mut registrations_by_address = HashMap::new();
    for record in registrations {
        let address = record.address.0;
        // Registrations outside the finalized validator set cannot participate
        // in this session. Ignore them before decoding so unrelated malformed
        // records cannot abort bootstrap for the selected validators.
        if !validator_addresses.contains(&address) {
            continue;
        }
        if registrations_by_address.contains_key(&address) {
            return Err(RegistrationError::DuplicateRegistration {
                address: Address::from(address),
            });
        }
        registrations_by_address.insert(address, record);
    }

    // Party IDs are compact ranks in the finalized validator-set order. Missing
    // registrations are filtered without changing the relative validator order.
    let eligible = validators
        .into_iter()
        .filter_map(|validator| {
            registrations_by_address
                .remove(&validator.address)
                .map(|registration| (validator.node_id, registration))
        })
        .map(|(node_id, registration)| {
            verify_registration(registration, epoch).map(|registration| (node_id, registration))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if eligible.is_empty() {
        return Err(RegistrationError::NoEligibleValidator);
    }

    let local = local_keys.decode().map_err(RegistrationError::LocalKeys)?;
    if let Some((_, registration)) = eligible.iter().find(|(node_id, _)| *node_id == self_id) {
        if registration.receiver.public_key != local.receiver_public_key {
            return Err(RegistrationError::ReceiverKeyMismatch);
        }
        if registration.qc_verifier != local.qc_verifier {
            return Err(RegistrationError::QcVerifierMismatch);
        }
    }
    let validators = eligible.iter().map(|(node_id, _)| *node_id).collect();
    let registrations = eligible
        .into_iter()
        .map(|(_, registration)| registration)
        .collect();
    Ok(RegisteredSession {
        validators,
        key_material: DkgRegisteredKeyMaterial {
            local_keys: local.secret_keys,
            registrations,
        },
    })
}

pub(crate) fn load_or_create_local_registration(
    storage_root: &Path,
    epoch: Epoch,
    address: [u8; 20],
    local_keys: &DkgLocalKeyMaterial,
    finalized: Option<&RegistrationCall>,
) -> Result<RegistrationCall, RegistrationError> {
    let (mut wal, mut recovery) =
        RecoveryWal::open(storage_root, epoch, RecoveryWalConfig::default())?;
    let bytes = recovery.load_or_create_registration(&mut wal, || match finalized {
        Some(registration) => Ok(encode_registration(registration)),
        None => local_keys
            .registration(address, epoch.0)
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
    registration: RegistrationCall,
    epoch: Epoch,
) -> Result<PartyRegistration<K256SecpBackend>, RegistrationError> {
    let address = registration.address.0;
    let registration = registration
        .into_party()
        .map_err(|source| RegistrationError::Decode {
            address: Address::from(address),
            source,
        })?;
    verify_decoded_registration(address, epoch, registration)
}

fn decode_verified_registration(
    address: [u8; 20],
    epoch: Epoch,
    bytes: &[u8],
) -> Result<PartyRegistration<K256SecpBackend>, RegistrationError> {
    let requested = Address::from(address);
    let registration = decode_registration::<K256SecpBackend>(bytes).map_err(|source| {
        RegistrationError::Decode {
            address: requested,
            source,
        }
    })?;
    verify_decoded_registration(address, epoch, registration)
}

fn verify_decoded_registration(
    address: [u8; 20],
    epoch: Epoch,
    registration: PartyRegistration<K256SecpBackend>,
) -> Result<PartyRegistration<K256SecpBackend>, RegistrationError> {
    let requested = Address::from(address);
    if registration.address.0 != address {
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
            epoch: epoch.0,
        });
    }
    Ok(registration)
}
