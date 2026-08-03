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
use monad_types::NodeId;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const RECEIVER_KEY_DERIVATION: &str = "monad/dkg/receiver-key";
const QC_KEY_DERIVATION: &str = "monad/dkg/qc-signing-key";

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
    ) -> Result<RegistrationCall, crate::DkgError> {
        let local = self.decode()?;
        let registration = PartyRegistration::from_local_keys(
            dkg_core::Address(address),
            epoch,
            &local.secret_keys,
        )
        .map_err(|err| crate::DkgError::operation("build DKG registration", err))?;
        Ok(RegistrationCall::from_party(&registration))
    }

    pub(crate) fn decode(&self) -> Result<DecodedLocalKeyMaterial, crate::DkgError> {
        let receiver_secret_key =
            K256SecpBackend::scalar_from_bytes(SecpScalarBytes(self.receiver_secret_key))
                .map_err(|err| crate::DkgError::operation("decode DKG receiver secret", err))?;
        let receiver_secret_key = NonZeroSecpScalar::<K256SecpBackend>::new(receiver_secret_key)
            .map_err(|err| crate::DkgError::operation("validate DKG receiver secret", err))?;
        let receiver_public_key =
            NonIdentitySecpPoint::new(K256SecpBackend::generator_mul(receiver_secret_key.scalar()))
                .map_err(|err| crate::DkgError::operation("derive DKG receiver public key", err))?;
        let qc_signing_key = QcSigningKey::from_bytes(self.qc_signing_key)
            .map_err(|err| crate::DkgError::operation("decode DKG QC signing key", err))?;
        let qc_verifying_key = qc_signing_key
            .verifying_key_bytes()
            .map_err(|err| crate::DkgError::operation("derive DKG QC verifying key", err))?;
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
