use dkg_protocol::DkgMessageKind;
use monad_crypto::{certificate_signature::PubKey, NopPubKey, NopSignature};

use super::*;

type TestSig = NopSignature;

fn node(byte: u8) -> NodeId<CertificateSignaturePubKey<TestSig>> {
    NodeId::new(NopPubKey::from_bytes(&[byte; 32]).expect("test pubkey is valid"))
}

#[test]
fn peer_map_authenticates_configured_validators() {
    let sender = node(1);
    let receiver = node(2);
    let peers = DkgPeerMap::<TestSig>::new_ordered(vec![sender, receiver]).unwrap();

    assert_eq!(peers.party_id(&sender), Some(PartyId(0)));
    assert_eq!(peers.party_id(&receiver), Some(PartyId(1)));
    assert_eq!(peers.party_id(&node(3)), None);
}

#[test]
fn delivery_envelope_round_trips() {
    let message_id = DkgMessageId::single(DkgMessageKey::BveProposal { dealer: PartyId(1) });
    let encoded: Bytes =
        DeliveryEnvelope::data(Epoch(8), message_id.clone(), Bytes::from_static(b"message")).into();

    let decoded: DeliveryEnvelope = encoded.as_ref().try_into().unwrap();
    assert_eq!(decoded.epoch, Epoch(8));
    let DeliveryMessage::Data {
        message_id: decoded_id,
        payload,
    } = decoded.message
    else {
        panic!("expected reliable DKG data");
    };
    assert_eq!(decoded_id, message_id);
    assert_eq!(payload, Bytes::from_static(b"message"));
}

#[test]
fn acknowledgement_envelope_is_one_shot_control_traffic() {
    let message_id = DkgMessageId::single(DkgMessageKey::BveProposal { dealer: PartyId(1) });
    let encoded: Bytes = DeliveryEnvelope::ack(Epoch(8), message_id.clone()).into();

    let decoded: DeliveryEnvelope = encoded.as_ref().try_into().unwrap();
    assert_eq!(decoded.epoch, Epoch(8));
    let DeliveryMessage::Ack(decoded_id) = decoded.message else {
        panic!("expected DKG acknowledgement");
    };
    assert_eq!(decoded_id, message_id);
}

#[test]
fn transport_acknowledgements_do_not_replace_sync_responses() {
    assert!(requires_transport_ack(DkgDeliveryPolicy::Durable));
    assert!(!requires_transport_ack(DkgDeliveryPolicy::Retry));
    assert!(!requires_transport_ack(DkgDeliveryPolicy::Once));
}

#[test]
fn delivery_groups_use_typed_protocol_kind() {
    let dealer = PartyId(2);
    let peer = PartyId(3);
    assert_eq!(
        delivery_abort_group_for_peer_payload(DkgMessageKind::PcProposal, dealer, peer),
        Some(DeliveryAbortGroup::CommitmentQc(dealer))
    );
    assert_eq!(
        delivery_abort_group_for_peer_payload(DkgMessageKind::PcAck, peer, dealer),
        Some(DeliveryAbortGroup::CommitmentQc(dealer))
    );
    assert_eq!(
        delivery_abort_group_for_peer_payload(DkgMessageKind::BveProposal, dealer, peer),
        Some(DeliveryAbortGroup::BveQc(dealer))
    );
    assert_eq!(
        delivery_abort_group_for_peer_payload(DkgMessageKind::BveApprovalBatch, peer, dealer),
        Some(DeliveryAbortGroup::Vss)
    );
    assert_eq!(
        delivery_abort_group_for_peer_payload(
            DkgMessageKind::BveRetrievalRequest,
            PartyId(0),
            PartyId(1),
        ),
        Some(DeliveryAbortGroup::Extraction)
    );
    assert_eq!(
        delivery_abort_group_for_peer_payload(
            DkgMessageKind::BveRetrievalResponse,
            PartyId(0),
            PartyId(1),
        ),
        None
    );
    assert_eq!(
        delivery_abort_group_for_peer_payload(DkgMessageKind::Ladder, dealer, peer),
        None
    );
}

#[test]
fn vss_evidence_obsoletes_only_qc_scopes() {
    assert!(DkgObsolescence::obsolete(
        &DeliveryAbortGroup::CommitmentQc(PartyId(0)),
        &DeliveryAbortGroup::Vss,
    ));
    assert!(DkgObsolescence::obsolete(
        &DeliveryAbortGroup::BveQc(PartyId(1)),
        &DeliveryAbortGroup::Vss,
    ));
    assert!(!DkgObsolescence::obsolete(
        &DeliveryAbortGroup::Extraction,
        &DeliveryAbortGroup::Vss,
    ));
}
