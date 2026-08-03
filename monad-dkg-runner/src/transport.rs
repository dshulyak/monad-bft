//! Retry scheduling for DKG messages until the protocol reports completion.

use std::{
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap},
    time::{Duration, Instant},
};

use alloy_rlp::{RlpDecodable, RlpEncodable};
use bytes::Bytes;
use dkg_core::PartyId;
use dkg_protocol::{DkgMessageCodecError, DkgMessageId, DkgMessageKey, DkgMessageKind};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId};
use rand::Rng;
use thiserror::Error;
use tracing::warn;

pub(crate) enum DeliveryInbound<ST: CertificateSignatureRecoverable> {
    Delivered {
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        payload: Bytes,
    },
    TransportAck {
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        key: DkgMessageKey,
    },
}

const DKG_RETRY_INITIAL: Duration = Duration::from_secs(2);
const DKG_RETRY_STEP: Duration = Duration::from_secs(2);
const DKG_RETRY_MAX: Duration = Duration::from_secs(30);
pub(crate) struct DkgSend<ST: CertificateSignatureRecoverable> {
    pub(crate) message_id: DkgMessageId,
    pub(crate) to: NodeId<CertificateSignaturePubKey<ST>>,
    pub(crate) payload: Bytes,
    pub(crate) abort_group: Option<DeliveryAbortGroup>,
}

pub struct DeliveryOutbound<ST: CertificateSignatureRecoverable> {
    pub to: NodeId<CertificateSignaturePubKey<ST>>,
    pub payload: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum DeliveryAbortGroup {
    Vss,
    Extraction,
    CommitmentQc(PartyId),
    BveQc(PartyId),
    DoneQc,
}

impl DeliveryAbortGroup {
    fn is_aborted_by(self, group: Self) -> bool {
        self == group
            || matches!(group, Self::Vss) && matches!(self, Self::CommitmentQc(_) | Self::BveQc(_))
    }
}

pub(crate) struct DeliveryEngine<ST: CertificateSignatureRecoverable> {
    epoch: Epoch,
    inbound_validators: Option<BTreeSet<NodeId<CertificateSignaturePubKey<ST>>>>,
    outbox: HashMap<DkgMessageId, OutboxMessage<ST>>,
    aborted_groups: BTreeSet<DeliveryAbortGroup>,
}

impl<ST> DeliveryEngine<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    pub(crate) fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            inbound_validators: None,
            outbox: HashMap::new(),
            aborted_groups: BTreeSet::new(),
        }
    }

    pub(crate) fn with_inbound_validators(
        epoch: Epoch,
        validators: Vec<NodeId<CertificateSignaturePubKey<ST>>>,
    ) -> Self {
        let mut engine = Self::new(epoch);
        engine.inbound_validators = Some(validators.into_iter().collect());
        engine
    }

    pub(crate) fn next_timer(&self) -> Option<Instant> {
        self.outbox
            .values()
            .flat_map(|message| message.recipients.values())
            .map(|recipient| recipient.next_retry)
            .min()
    }

    pub(crate) fn handle_network_message(
        &self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        payload: Bytes,
    ) -> Option<DeliveryInbound<ST>> {
        match DkgWireMessage::decode(payload.as_ref()) {
            Ok(DkgWireMessage::Data { epoch, payload }) if epoch == self.epoch => {
                if self
                    .inbound_validators
                    .as_ref()
                    .is_some_and(|validators| !validators.contains(&sender))
                {
                    warn!(
                        epoch = self.epoch.0,
                        sender = ?sender,
                        "dropping DKG delivery from non-validator"
                    );
                    return None;
                }
                Some(DeliveryInbound::Delivered { sender, payload })
            }
            Ok(DkgWireMessage::TransportAck { epoch, key })
                if epoch == self.epoch && self.expects_transport_ack(sender, key) =>
            {
                Some(DeliveryInbound::TransportAck { sender, key })
            }
            Ok(_) => None,
            Err(err) => {
                warn!(?err, ?sender, "dropping malformed DKG delivery message");
                None
            }
        }
    }

    pub(crate) fn finish_inbound(
        &self,
        to: NodeId<CertificateSignaturePubKey<ST>>,
        transport_ack: Option<DkgMessageKey>,
    ) -> Option<DeliveryOutbound<ST>> {
        let key = transport_ack?;
        Some(DeliveryOutbound {
            to,
            payload: DkgWireMessage::TransportAck {
                epoch: self.epoch,
                key,
            }
            .encode(),
        })
    }

    pub(crate) fn handle_timer(&mut self, now: Instant) -> Vec<DeliveryOutbound<ST>> {
        let mut out = Vec::new();
        for message in self.outbox.values_mut() {
            for (&to, recipient) in &mut message.recipients {
                if recipient.next_retry <= now {
                    out.push(DeliveryOutbound {
                        to,
                        payload: message.wire_payload.clone(),
                    });
                    recipient.retry_delay = recipient
                        .retry_delay
                        .saturating_add(DKG_RETRY_STEP)
                        .min(DKG_RETRY_MAX);
                    recipient.next_retry =
                        now + recipient.retry_delay + retry_jitter(recipient.retry_delay);
                }
            }
        }
        out
    }

    pub(crate) fn send(&mut self, send: DkgSend<ST>, now: Instant) -> Vec<DeliveryOutbound<ST>> {
        if send.abort_group.is_some_and(|group| {
            self.aborted_groups
                .iter()
                .any(|aborted| group.is_aborted_by(*aborted))
        }) {
            return Vec::new();
        }

        let message_id = send.message_id;
        let to = send.to;
        let next_retry = now + DKG_RETRY_INITIAL + retry_jitter(DKG_RETRY_INITIAL);
        let recipient = OutboxRecipient {
            next_retry,
            retry_delay: DKG_RETRY_INITIAL,
        };

        let wire = DkgWireMessage::Data {
            epoch: self.epoch,
            payload: send.payload,
        }
        .encode();
        match self.outbox.entry(message_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(OutboxMessage {
                    wire_payload: wire.clone(),
                    abort_group: send.abort_group,
                    recipients: BTreeMap::from([(to, recipient)]),
                });
            }
            Entry::Occupied(mut entry) => {
                let message = entry.get_mut();
                if message.wire_payload != wire || message.abort_group != send.abort_group {
                    warn!(message_id = ?message_id, "dropping inconsistent duplicate DKG message id");
                    return Vec::new();
                }
                if message.recipients.contains_key(&to) {
                    warn!(message_id = ?message_id, "dropping duplicate queued DKG message recipient");
                    return Vec::new();
                }
                message.recipients.insert(to, recipient);
            }
        }

        vec![DeliveryOutbound { to, payload: wire }]
    }

    fn expects_transport_ack(
        &self,
        from: NodeId<CertificateSignaturePubKey<ST>>,
        key: DkgMessageKey,
    ) -> bool {
        if !key.requires_transport_ack() {
            return false;
        }
        self.outbox
            .get(&DkgMessageId::single(key))
            .is_some_and(|message| message.recipients.contains_key(&from))
    }

    pub(crate) fn abort_group(&mut self, group: DeliveryAbortGroup) {
        self.aborted_groups.insert(group);
        self.outbox.retain(|_, message| {
            !message
                .abort_group
                .is_some_and(|message_group| message_group.is_aborted_by(group))
        });
    }

    pub(crate) fn complete(
        &mut self,
        message_id: &DkgMessageId,
        to: NodeId<CertificateSignaturePubKey<ST>>,
    ) {
        let remove_message = self.outbox.get_mut(message_id).is_some_and(|message| {
            message.recipients.remove(&to).is_some() && message.recipients.is_empty()
        });
        if remove_message {
            self.outbox.remove(message_id);
        }
    }

    #[cfg(test)]
    fn outstanding_delivery_count(&self) -> usize {
        self.outbox
            .values()
            .map(|message| message.recipients.len())
            .sum()
    }
}

struct OutboxMessage<ST: CertificateSignatureRecoverable> {
    wire_payload: Bytes,
    abort_group: Option<DeliveryAbortGroup>,
    recipients: BTreeMap<NodeId<CertificateSignaturePubKey<ST>>, OutboxRecipient>,
}

struct OutboxRecipient {
    next_retry: Instant,
    retry_delay: Duration,
}

fn retry_jitter(retry_delay: Duration) -> Duration {
    let max_jitter = retry_delay / 5;
    let max_jitter_ms = max_jitter.as_millis().min(500) as u64;
    Duration::from_millis(rand::thread_rng().gen_range(0..=max_jitter_ms))
}

pub(crate) fn delivery_abort_group_for_peer_payload(
    kind: DkgMessageKind,
    source: PartyId,
    target: PartyId,
) -> Option<DeliveryAbortGroup> {
    match kind {
        DkgMessageKind::PcProposal => Some(DeliveryAbortGroup::CommitmentQc(source)),
        DkgMessageKind::PcAck => Some(DeliveryAbortGroup::CommitmentQc(target)),
        DkgMessageKind::BveProposal => Some(DeliveryAbortGroup::BveQc(source)),
        // One approval batch can cover several dealers, so only the enclosing
        // phase can safely abort the whole delivery.
        DkgMessageKind::BveApprovalBatch => Some(DeliveryAbortGroup::Vss),
        DkgMessageKind::BveRetrievalRequest | DkgMessageKind::PcRetrievalRequest => {
            Some(DeliveryAbortGroup::Extraction)
        }
        // A completed peer must still be able to serve a recovering peer after
        // its own extraction phase has ended.
        DkgMessageKind::BveRetrievalResponse | DkgMessageKind::PcRetrievalResponse => None,
        DkgMessageKind::Done => Some(DeliveryAbortGroup::DoneQc),
        _ => None,
    }
}

const DATA_TAG: u8 = 100;
const TRANSPORT_ACK_TAG: u8 = 101;

#[derive(Debug, Error)]
enum WireError {
    #[error("RLP decode failed: {0}")]
    Rlp(#[from] alloy_rlp::Error),
    #[error("unknown DKG wire message tag {0}")]
    UnknownTag(u8),
    #[error("invalid DKG transport acknowledgement: {0}")]
    MessageKey(#[from] DkgMessageCodecError),
}

enum DkgWireMessage {
    Data { epoch: Epoch, payload: Bytes },
    TransportAck { epoch: Epoch, key: DkgMessageKey },
}

pub(crate) fn delivery_epoch(payload: &[u8]) -> Option<Epoch> {
    match DkgWireMessage::decode(payload) {
        Ok(DkgWireMessage::Data { epoch, .. } | DkgWireMessage::TransportAck { epoch, .. }) => {
            Some(epoch)
        }
        Err(err) => {
            warn!(?err, "dropping malformed DKG delivery message");
            None
        }
    }
}

#[derive(RlpEncodable, RlpDecodable)]
struct WireEnvelope {
    tag: u8,
    epoch: u64,
    payload: Bytes,
}

impl DkgWireMessage {
    fn encode(&self) -> Bytes {
        let wire = match self {
            Self::Data { epoch, payload } => WireEnvelope {
                tag: DATA_TAG,
                epoch: epoch.0,
                payload: payload.clone(),
            },
            Self::TransportAck { epoch, key } => WireEnvelope {
                tag: TRANSPORT_ACK_TAG,
                epoch: epoch.0,
                payload: Bytes::copy_from_slice(&key.encode()),
            },
        };
        alloy_rlp::encode(wire).into()
    }

    fn decode(data: &[u8]) -> Result<Self, WireError> {
        let wire = alloy_rlp::decode_exact::<WireEnvelope>(data)?;
        Ok(match wire.tag {
            DATA_TAG => Self::Data {
                epoch: Epoch(wire.epoch),
                payload: wire.payload,
            },
            TRANSPORT_ACK_TAG => Self::TransportAck {
                epoch: Epoch(wire.epoch),
                key: DkgMessageKey::decode(&wire.payload)?,
            },
            tag => return Err(WireError::UnknownTag(tag)),
        })
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
