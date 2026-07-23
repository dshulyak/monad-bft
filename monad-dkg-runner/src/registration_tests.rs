use alloy_primitives::Address;
use bytes::Bytes;
use monad_crypto::{
    certificate_signature::{CertificateKeyPair, CertificateSignaturePubKey},
    NopKeyPair, NopSignature,
};
use monad_types::{Epoch, NodeId};

use crate::{
    registration::{
        assemble_registered_session, load_or_create_local_registration, RegistrationError,
    },
    DkgLocalKeyMaterial, DkgRegistration, DkgValidator,
};

const EPOCH: Epoch = Epoch(17);

#[test]
fn assembles_registered_parties_in_canonical_address_order() {
    let nodes = test_nodes(4);
    let keys = test_keys(4);
    let addresses = [[4; 20], [1; 20], [3; 20], [2; 20]];
    let validators = nodes
        .iter()
        .zip(addresses)
        .map(|(node_id, address)| DkgValidator::<NopSignature> {
            node_id: *node_id,
            address,
        })
        .collect();
    let registrations = addresses
        .into_iter()
        .zip(keys.iter())
        .rev()
        .map(|(address, keys)| registration(address, keys))
        .collect();

    let session = assemble_registered_session(EPOCH, validators, keys[0], registrations).unwrap();

    assert_eq!(
        session.key_material.addresses,
        vec![
            dkg_core::Address([1; 20]),
            dkg_core::Address([2; 20]),
            dkg_core::Address([3; 20]),
            dkg_core::Address([4; 20])
        ]
    );
    assert_eq!(
        session.validators,
        vec![nodes[1], nodes[3], nodes[2], nodes[0]]
    );
}

#[test]
fn intersects_registrations_with_finalized_validators() {
    let nodes = test_nodes(5);
    let keys = test_keys(5);
    let validators = (0..4)
        .map(|index| DkgValidator::<NopSignature> {
            node_id: nodes[index],
            address: [index as u8 + 1; 20],
        })
        .collect();
    let registrations = [0usize, 1, 2, 4]
        .into_iter()
        .map(|index| registration([index as u8 + 1; 20], &keys[index]))
        .collect();

    let session = assemble_registered_session(EPOCH, validators, keys[0], registrations).unwrap();

    assert_eq!(session.validators, vec![nodes[0], nodes[1], nodes[2]]);
    assert_eq!(
        session.key_material.addresses,
        vec![
            dkg_core::Address([1; 20]),
            dkg_core::Address([2; 20]),
            dkg_core::Address([3; 20])
        ]
    );
}

#[test]
fn rejects_mismatched_encoded_address() {
    let nodes = test_nodes(1);
    let keys = test_keys(1);
    let validators = vec![DkgValidator::<NopSignature> {
        node_id: nodes[0],
        address: [1; 20],
    }];
    let state = vec![DkgRegistration {
        address: Address::from([2; 20]),
        bytes: keys[0].registration_bytes([1; 20], EPOCH.0).unwrap().into(),
    }];
    assert!(matches!(
        assemble_registered_session(EPOCH, validators, keys[0], state).err(),
        Some(RegistrationError::AddressMismatch { .. })
    ));
}

#[test]
fn local_key_derivation_is_stable_and_domain_separated() {
    let first = DkgLocalKeyMaterial::derive([7; 32]);
    let second = DkgLocalKeyMaterial::derive([7; 32]);
    assert!(first == second);
    assert_ne!(first.receiver_secret_key, first.qc_signing_key);
    assert!(first != DkgLocalKeyMaterial::derive([8; 32]));
}

#[test]
fn encoded_registration_is_reused_from_recovery_wal() {
    let directory = tempfile::tempdir().unwrap();
    let keys = DkgLocalKeyMaterial::derive([7; 32]);
    let first =
        load_or_create_local_registration(directory.path(), EPOCH, [1; 20], keys, None).unwrap();
    let second =
        load_or_create_local_registration(directory.path(), EPOCH, [1; 20], keys, None).unwrap();

    assert_eq!(first, second);
}

fn registration(address: [u8; 20], keys: &DkgLocalKeyMaterial) -> DkgRegistration {
    DkgRegistration {
        address: Address::from(address),
        bytes: Bytes::from(keys.registration_bytes(address, EPOCH.0).unwrap()),
    }
}

fn test_keys(count: usize) -> Vec<DkgLocalKeyMaterial> {
    (0..count)
        .map(|index| DkgLocalKeyMaterial::derive([index as u8 + 1; 32]))
        .collect()
}

fn test_nodes(count: u8) -> Vec<NodeId<CertificateSignaturePubKey<NopSignature>>> {
    (0..count)
        .map(|seed| {
            let mut bytes = [seed.saturating_add(1); 32];
            NodeId::new(NopKeyPair::from_bytes(&mut bytes).unwrap().pubkey())
        })
        .collect()
}
