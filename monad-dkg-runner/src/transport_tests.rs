use dkg_protocol::{DkgMessageId, DkgMessageKey, DkgMessageKind};
use monad_crypto::{certificate_signature::PubKey, NopPubKey, NopSignature};

use super::*;

type TestSig = NopSignature;

fn unwrap_delivered(
    inbound: DeliveryInbound<TestSig>,
) -> (NodeId<CertificateSignaturePubKey<TestSig>>, Bytes) {
    match inbound {
        DeliveryInbound::Delivered { sender, payload } => (sender, payload),
        DeliveryInbound::TransportAck { .. } => panic!("expected delivered payload"),
    }
}

fn node(byte: u8) -> NodeId<CertificateSignaturePubKey<TestSig>> {
    NodeId::new(NopPubKey::from_bytes(&[byte; 32]).expect("test pubkey is valid"))
}

fn key(value: u32) -> DkgMessageKey {
    DkgMessageKey::Ladder {
        sender: PartyId(value),
        level: 1,
    }
}

fn message_id(value: u32) -> DkgMessageId {
    DkgMessageId::single(key(value))
}

fn send_command(
    message_id: DkgMessageId,
    to: NodeId<CertificateSignaturePubKey<TestSig>>,
    payload: &'static [u8],
    abort_group: Option<DeliveryAbortGroup>,
) -> DkgSend<TestSig> {
    DkgSend {
        message_id,
        to,
        payload: Bytes::from_static(payload),
        abort_group,
    }
}

#[test]
fn transport_ack_stops_one_way_message_after_runner_completion() {
    let epoch = Epoch(7);
    let message_id = message_id(1);
    let ack_key = key(1);
    let now = Instant::now();
    let sender = node(1);
    let receiver = node(2);
    let mut sender_delivery = DeliveryEngine::<TestSig>::new(epoch);
    let receiver_delivery = DeliveryEngine::<TestSig>::new(epoch);

    let outbound = sender_delivery.send(
        send_command(message_id.clone(), receiver, b"ladder", None),
        now,
    );
    assert_eq!(outbound.len(), 1);
    assert_delay_with_jitter(
        sender_delivery.next_timer().unwrap().duration_since(now),
        DKG_RETRY_INITIAL,
    );

    let (delivered_by, payload) = unwrap_delivered(
        receiver_delivery
            .handle_network_message(sender, outbound[0].payload.clone())
            .expect("payload delivered"),
    );
    assert_eq!(delivered_by, sender);
    assert_eq!(payload, Bytes::from_static(b"ladder"));

    let ack = receiver_delivery.finish_inbound(sender, Some(ack_key));
    match sender_delivery
        .handle_network_message(receiver, ack.unwrap().payload)
        .expect("transport acknowledgement delivered")
    {
        DeliveryInbound::TransportAck { sender, key } => {
            assert_eq!(sender, receiver);
            assert_eq!(key, ack_key);
        }
        DeliveryInbound::Delivered { .. } => panic!("expected transport acknowledgement"),
    }
    sender_delivery.complete(&message_id, receiver);
    assert!(sender_delivery.outbox.is_empty());
}

#[test]
fn configured_validator_sender_is_delivered_without_transport_ack() {
    let epoch = Epoch(8);
    let now = Instant::now();
    let sender = node(1);
    let receiver = node(2);
    let id = DkgMessageId::single(DkgMessageKey::PcAck {
        dealer: PartyId(2),
        signer: PartyId(1),
    });
    let mut sender_delivery = DeliveryEngine::<TestSig>::new(epoch);
    let receiver_delivery =
        DeliveryEngine::<TestSig>::with_inbound_validators(epoch, vec![sender, receiver]);
    let outbound = sender_delivery.send(send_command(id, receiver, b"pc-ack", None), now);

    let (_, payload) = unwrap_delivered(
        receiver_delivery
            .handle_network_message(sender, outbound[0].payload.clone())
            .expect("payload delivered from configured validator"),
    );
    assert_eq!(payload, Bytes::from_static(b"pc-ack"));
    assert!(receiver_delivery.finish_inbound(sender, None).is_none());

    let rejected = DeliveryEngine::<TestSig>::with_inbound_validators(epoch, vec![receiver]);
    assert!(rejected
        .handle_network_message(sender, outbound[0].payload.clone())
        .is_none());
}

#[test]
fn transport_ack_cannot_complete_message_with_protocol_evidence() {
    let epoch = Epoch(8);
    let now = Instant::now();
    let sender = node(1);
    let receiver = node(2);
    let key = DkgMessageKey::PcAck {
        dealer: PartyId(2),
        signer: PartyId(1),
    };
    let mut sender_delivery = DeliveryEngine::<TestSig>::new(epoch);
    let receiver_delivery = DeliveryEngine::<TestSig>::new(epoch);

    sender_delivery.send(
        send_command(DkgMessageId::single(key), receiver, b"pc-ack", None),
        now,
    );
    let ack = receiver_delivery.finish_inbound(sender, Some(key));
    assert!(sender_delivery
        .handle_network_message(receiver, ack.unwrap().payload)
        .is_none());
    assert_eq!(sender_delivery.outstanding_delivery_count(), 1);
}

#[test]
fn application_completion_stops_request_without_transport_ack() {
    let epoch = Epoch(8);
    let id = DkgMessageId::single(DkgMessageKey::BveRetrievalRequest {
        dealer: PartyId(3),
        requester: PartyId(1),
        responder: PartyId(2),
    });
    let now = Instant::now();
    let receiver = node(2);
    let mut delivery = DeliveryEngine::<TestSig>::new(epoch);
    delivery.send(
        send_command(
            id.clone(),
            receiver,
            b"request",
            Some(DeliveryAbortGroup::Extraction),
        ),
        now,
    );
    assert_eq!(
        delivery.handle_timer(delivery.next_timer().unwrap()).len(),
        1
    );
    delivery.complete(&id, receiver);
    assert_eq!(delivery.outstanding_delivery_count(), 0);
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
}

#[test]
fn one_message_id_reuses_one_outbox_message_for_multiple_peers() {
    let epoch = Epoch(9);
    let id = message_id(4);
    let now = Instant::now();
    let peers = [node(2), node(3), node(4)];
    let mut delivery = DeliveryEngine::<TestSig>::new(epoch);
    for peer in peers {
        assert_eq!(
            delivery
                .send(send_command(id.clone(), peer, b"message", None), now)
                .len(),
            1
        );
    }
    assert_eq!(delivery.outbox.len(), 1);
    assert_eq!(delivery.outstanding_delivery_count(), 3);
    assert!(delivery
        .send(send_command(id.clone(), peers[0], b"message", None), now)
        .is_empty());
    delivery.complete(&id, peers[0]);
    assert_eq!(delivery.outstanding_delivery_count(), 2);
}

#[test]
fn abort_groups_stop_only_matching_deliveries() {
    let now = Instant::now();
    let mut delivery = DeliveryEngine::<TestSig>::new(Epoch(10));
    for (value, group) in [
        (9, DeliveryAbortGroup::Extraction),
        (10, DeliveryAbortGroup::BveQc(PartyId(1))),
        (11, DeliveryAbortGroup::BveQc(PartyId(2))),
    ] {
        delivery.send(
            send_command(
                message_id(value),
                node(value as u8),
                b"message",
                Some(group),
            ),
            now,
        );
    }
    delivery.abort_group(DeliveryAbortGroup::BveQc(PartyId(1)));
    assert_eq!(delivery.outbox.len(), 2);
    delivery.abort_group(DeliveryAbortGroup::Extraction);
    assert_eq!(delivery.outbox.len(), 1);
}

#[test]
fn vss_abort_stops_all_qc_scoped_deliveries() {
    let now = Instant::now();
    let mut delivery = DeliveryEngine::<TestSig>::new(Epoch(11));
    for (value, group) in [
        (12, DeliveryAbortGroup::CommitmentQc(PartyId(0))),
        (13, DeliveryAbortGroup::BveQc(PartyId(1))),
        (14, DeliveryAbortGroup::Extraction),
    ] {
        delivery.send(
            send_command(
                message_id(value),
                node(value as u8),
                b"message",
                Some(group),
            ),
            now,
        );
    }
    delivery.abort_group(DeliveryAbortGroup::Vss);
    assert_eq!(delivery.outbox.len(), 1);
    assert_eq!(
        delivery.outbox.values().next().unwrap().abort_group,
        Some(DeliveryAbortGroup::Extraction)
    );
}

#[test]
fn retries_use_linear_backoff_capped_at_thirty_seconds() {
    let now = Instant::now();
    let mut delivery = DeliveryEngine::<TestSig>::new(Epoch(11));
    delivery.send(
        send_command(message_id(11), node(2), b"retry-me", None),
        now,
    );

    let mut due = delivery.next_timer().expect("initial retry scheduled");
    assert_delay_with_jitter(due.duration_since(now), DKG_RETRY_INITIAL);
    assert_eq!(delivery.handle_timer(due).len(), 1);
    let last_due = due;
    due = delivery.next_timer().expect("second retry scheduled");
    assert_delay_with_jitter(
        due.duration_since(last_due),
        DKG_RETRY_INITIAL + DKG_RETRY_STEP,
    );

    for _ in 0..80 {
        let due = delivery.next_timer().expect("retry remains scheduled");
        delivery.handle_timer(due);
    }
    let recipient = delivery
        .outbox
        .values()
        .next()
        .unwrap()
        .recipients
        .values()
        .next()
        .unwrap();
    assert_eq!(recipient.retry_delay, DKG_RETRY_MAX);
}

fn assert_delay_with_jitter(delay: Duration, base: Duration) {
    let max_jitter = (base / 5).min(Duration::from_millis(500));
    assert!(delay >= base && delay <= base + max_jitter);
}
