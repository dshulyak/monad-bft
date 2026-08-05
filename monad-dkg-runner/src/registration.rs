use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

use alloy_primitives::Address;
use dkg_crypto::{K256SecpBackend, ReceiverKeyRegistrationError};
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
    #[error("persisted DKG registration QC key does not match the local key")]
    QcKeyMismatch,
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
        source: ReceiverKeyRegistrationError,
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
    let mut validators_by_address = BTreeMap::new();
    for validator in validators {
        if validators_by_address
            .insert(validator.address, validator.node_id)
            .is_some()
        {
            return Err(RegistrationError::DuplicateValidatorAddress {
                address: Address::from(validator.address),
            });
        }
    }

    let mut registrations_by_address = HashMap::new();
    for record in registrations {
        let address = record.address.0;
        if registrations_by_address.contains_key(&address) {
            return Err(RegistrationError::DuplicateRegistration {
                address: Address::from(address),
            });
        }
        let registration = verify_registration(record, epoch)?;
        registrations_by_address.insert(address, registration);
    }

    let eligible = validators_by_address
        .into_iter()
        .filter_map(|(address, node_id)| {
            registrations_by_address
                .remove(&address)
                .map(|registration| (address, node_id, registration))
        })
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Err(RegistrationError::NoEligibleValidator);
    }

    let local = local_keys.decode().map_err(RegistrationError::LocalKeys)?;
    if let Some((_, _, registration)) = eligible.iter().find(|(_, node_id, _)| *node_id == self_id)
    {
        if registration.receiver.public_key != local.receiver_public_key {
            return Err(RegistrationError::ReceiverKeyMismatch);
        }
        if registration.qc_verifying_key != local.qc_verifying_key {
            return Err(RegistrationError::QcKeyMismatch);
        }
    }
    let validators = eligible.iter().map(|(_, node_id, _)| *node_id).collect();
    let registrations = eligible
        .into_iter()
        .map(|(_, _, registration)| registration)
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

    if registration.qc_verifying_key != local.qc_verifying_key {
        return Err(RegistrationError::QcKeyMismatch);
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
