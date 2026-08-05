use std::error::Error as StdError;

use alloy_primitives::Address;
#[cfg(test)]
use dkg_core::PartyId;
use dkg_crypto::{
    K256SecpBackend, NonIdentitySecpPoint, NonZeroSecpScalar, SecpBackend, SecpScalarBytes,
};
use dkg_protocol::{
    PartyRegistration, QcSigningKey, QcVerifyingKeyBytes, RegistrationCall, SecretKeys,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
#[cfg(test)]
use monad_types::Epoch;
use monad_types::{NodeId, SeqNum};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod chain;
mod record;
mod recovery;
mod registration;
mod reliable;
mod runner;
mod session;
mod wal;

const MAX_RETAINED_DKG_SESSIONS: usize = 2;
const RECEIVER_KEY_DERIVATION: &str = "monad/dkg/receiver-key";
const QC_KEY_DERIVATION: &str = "monad/dkg/qc-signing-key";

#[cfg(test)]
mod registration_tests;

pub use chain::{new_triedb_runner, DkgChainConfig};
pub use runner::{DeliveryOutbound, DkgRunner, DkgRunnerHandle, DkgRunnerInbox};

#[derive(Debug, Error)]
pub enum DkgError {
    #[error("{operation} failed")]
    Operation {
        operation: &'static str,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("{0} is not supported")]
    Unsupported(&'static str),
    #[error("DKG channel closed while {0}")]
    ChannelClosed(&'static str),
    #[error("DKG requires at least {minimum} validators, received {actual}")]
    InsufficientValidators { actual: usize, minimum: usize },
    #[error("registration contract {actual} does not match configured DKG contract {expected}")]
    RegistrationContractMismatch { expected: Address, actual: Address },
    #[error("DKG result epoch {actual} does not match submission epoch {expected}")]
    ResultEpochMismatch { expected: u64, actual: u64 },
    #[error("duplicate validator in DKG party map")]
    DuplicateValidator,
    #[error("finalized DKG registration for {address} conflicts with the recovery WAL")]
    FinalizedRegistrationConflict { address: Address },
    #[error("no active DKG session for epoch {epoch}")]
    NoActiveSession { epoch: u64 },
    #[error("DKG chain data at block {block:?} is not available yet")]
    ChainDataUnavailable { block: SeqNum },
}

impl DkgError {
    pub fn operation(
        operation: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Operation {
            operation,
            source: Box::new(source),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct DkgLocalKeyMaterial {
    pub receiver_secret_key: [u8; 32],
    pub qc_signing_key: [u8; 32],
}

impl DkgLocalKeyMaterial {
    /// Derives independent protocol keys from a node-owned secret seed.
    pub fn derive(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        Self {
            receiver_secret_key: derive_valid_key(&seed, RECEIVER_KEY_DERIVATION, |bytes| {
                K256SecpBackend::scalar_from_bytes(SecpScalarBytes(*bytes))
                    .ok()
                    .is_some_and(|scalar| NonZeroSecpScalar::<K256SecpBackend>::new(scalar).is_ok())
            }),
            qc_signing_key: derive_valid_key(&seed, QC_KEY_DERIVATION, |bytes| {
                QcSigningKey::from_bytes(*bytes).is_ok()
            }),
        }
    }

    /// Encodes the public registration corresponding to these local keys.
    pub fn registration(
        &self,
        address: [u8; 20],
        epoch: u64,
    ) -> Result<RegistrationCall, DkgError> {
        let local = self.decode()?;
        let registration = PartyRegistration::from_local_keys(
            dkg_core::Address(address),
            epoch,
            &local.secret_keys,
        )
        .map_err(|err| DkgError::operation("build DKG registration", err))?;
        Ok(RegistrationCall::from_party(&registration))
    }

    pub(crate) fn decode(&self) -> Result<DecodedLocalKeyMaterial, DkgError> {
        let receiver_secret_key =
            K256SecpBackend::scalar_from_bytes(SecpScalarBytes(self.receiver_secret_key))
                .map_err(|err| DkgError::operation("decode DKG receiver secret", err))?;
        let receiver_secret_key = NonZeroSecpScalar::<K256SecpBackend>::new(receiver_secret_key)
            .map_err(|err| DkgError::operation("validate DKG receiver secret", err))?;
        let receiver_public_key =
            NonIdentitySecpPoint::new(K256SecpBackend::generator_mul(receiver_secret_key.scalar()))
                .map_err(|err| DkgError::operation("derive DKG receiver public key", err))?;
        let qc_signing_key = QcSigningKey::from_bytes(self.qc_signing_key)
            .map_err(|err| DkgError::operation("decode DKG QC signing key", err))?;
        let qc_verifying_key = qc_signing_key
            .verifying_key_bytes()
            .map_err(|err| DkgError::operation("derive DKG QC verifying key", err))?;
        Ok(DecodedLocalKeyMaterial {
            secret_keys: SecretKeys {
                receiver_secret_key: Some(receiver_secret_key),
                qc_signing_key,
            },
            receiver_public_key,
            qc_verifying_key,
        })
    }
}

fn derive_valid_key(
    seed: &[u8; 32],
    domain: &'static str,
    valid: impl Fn(&[u8; 32]) -> bool,
) -> [u8; 32] {
    for counter in 0u32.. {
        let mut input = Zeroizing::new([0u8; 36]);
        input[..32].copy_from_slice(seed);
        input[32..].copy_from_slice(&counter.to_le_bytes());
        let candidate = Zeroizing::new(blake3::derive_key(domain, input.as_ref()));
        if valid(&candidate) {
            return *candidate;
        }
    }
    unreachable!("u32 key-derivation counter exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DkgValidator<ST>
where
    ST: CertificateSignatureRecoverable,
{
    pub node_id: NodeId<CertificateSignaturePubKey<ST>>,
    pub address: [u8; 20],
}

pub(crate) struct DkgRegisteredKeyMaterial {
    pub(crate) local_keys: SecretKeys<K256SecpBackend>,
    pub(crate) registrations: Vec<PartyRegistration<K256SecpBackend>>,
}

pub(crate) struct DecodedLocalKeyMaterial {
    pub(crate) secret_keys: SecretKeys<K256SecpBackend>,
    pub(crate) receiver_public_key: NonIdentitySecpPoint<K256SecpBackend>,
    pub(crate) qc_verifying_key: QcVerifyingKeyBytes,
}

#[cfg(test)]
pub(crate) fn test_registered_key_material(
    self_party: PartyId,
    party_count: usize,
    epoch: Epoch,
) -> DkgRegisteredKeyMaterial {
    let keys = (0..party_count)
        .map(|index| DkgLocalKeyMaterial::derive([index as u8 + 1; 32]))
        .collect::<Vec<_>>();
    let registrations = keys
        .iter()
        .enumerate()
        .map(|(index, keys)| {
            keys.registration([index as u8 + 1; 20], epoch.0)
                .expect("test DKG registration")
                .into_party::<K256SecpBackend>()
                .expect("test DKG registration validates")
        })
        .collect::<Vec<_>>();
    let local = &keys[self_party.0 as usize];
    DkgRegisteredKeyMaterial {
        local_keys: local.decode().expect("test DKG keys decode").secret_keys,
        registrations,
    }
}

pub fn recovery_epochs(root: &std::path::Path) -> Result<Vec<monad_types::Epoch>, DkgError> {
    recovery::recovery_epochs(root)
        .map_err(|err| DkgError::operation("list DKG recovery epochs", err))
}

pub const DKG_FAILPOINT_NAMES: [&str; 7] = [
    "dkg.chain.call_buffered",
    "dkg.chain.event_buffered",
    "dkg.network.outgoing_persisted",
    "dkg.peer.engine_applied",
    "dkg.peer.input_persisted",
    "dkg.registration.loaded",
    "dkg.session.seed_persisted",
];

#[cfg(test)]
#[test]
fn registers_all_dkg_failpoints() {
    let registered = failpoint::Registry::global()
        .list()
        .into_iter()
        .filter_map(|point| point.name.starts_with("dkg.").then_some(point.name))
        .collect::<Vec<_>>();
    assert_eq!(registered, DKG_FAILPOINT_NAMES);
}
