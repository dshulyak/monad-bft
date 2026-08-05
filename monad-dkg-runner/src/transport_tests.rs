use dkg_protocol::{DkgMessageId, DkgMessageKey, DkgMessageKind};
use monad_crypto::{certificate_signature::PubKey, NopPubKey, NopSignature};

use super::*;

type TestSig = NopSignature;

fn unwrap_delivered(
    inbound: DeliveryInbound<TestSig>,
) -> (NodeId<CertificateSignaturePubKey<TestSig>>, Bytes) {
    (inbound.sender, inbound.payload)
}

fn node(byte: u8) -> NodeId<CertificateSignaturePubKey<TestSig>> {
    NodeId::new(NopPubKey::from_bytes(&[byte; 32]).expect("test pubkey is valid"))
}

#[test]
fn configured_validator_sender_is_delivered() {
    let epoch = Epoch(8);
    let now = Instant::now();
    let sender = node(1);
    let receiver = node(2);
    let id = DkgMessageId::single(DkgMessageKey::PcAck {
        dealer: PartyId(2),
        signer: PartyId(1),
    });
    let mut sender_delivery = DeliveryEngine::<TestSig>::new(epoch, []);
    let receiver_delivery = DeliveryEngine::<TestSig>::new(epoch, [sender, receiver]);
    let outbound = sender_delivery
        .schedule_reliable(id, [receiver], Bytes::from_static(b"pc-ack"), None, now)
        .unwrap();

    let (_, payload) = unwrap_delivered(
        receiver_delivery
            .handle_network_message(sender, outbound[0].payload.clone())
            .expect("payload delivered from configured validator"),
    );
    assert_eq!(payload, Bytes::from_static(b"pc-ack"));

    let rejected = DeliveryEngine::<TestSig>::new(epoch, [receiver]);
    assert!(rejected
        .handle_network_message(sender, outbound[0].payload.clone())
        .is_none());
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
fn send_once_does_not_schedule_a_retry() {
    let epoch = Epoch(8);
    let sender = node(1);
    let receiver = node(2);
    let sender_delivery = DeliveryEngine::<TestSig>::new(epoch, []);
    let receiver_delivery = DeliveryEngine::<TestSig>::new(epoch, [sender]);

    let outbound = sender_delivery.schedule_once(receiver, Bytes::from_static(b"response"));

    assert_eq!(outbound.to, receiver);
    assert!(sender_delivery.next_timer().is_none());
    let (_, payload) = unwrap_delivered(
        receiver_delivery
            .handle_network_message(sender, outbound.payload)
            .unwrap(),
    );
    assert_eq!(payload, Bytes::from_static(b"response"));
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
