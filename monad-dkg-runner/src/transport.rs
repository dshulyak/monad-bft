//! Retry scheduling for DKG messages until the protocol makes them obsolete.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use alloy_rlp::{RlpDecodable, RlpEncodable};
use bytes::Bytes;
use dkg_core::PartyId;
use dkg_protocol::{DkgMessageId, DkgMessageKind};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId};
use tracing::warn;

use crate::reliable::{
    EnqueueError, ObsolescencePolicy, OnceScheduler, RetryConfig, RetryScheduler, ScheduledSend,
};

pub(crate) struct DeliveryInbound<ST: CertificateSignatureRecoverable> {
    pub(crate) sender: NodeId<CertificateSignaturePubKey<ST>>,
    pub(crate) payload: Bytes,
}

const DKG_RETRY: RetryConfig = RetryConfig::new(
    Duration::from_secs(2),
    Duration::from_secs(2),
    Duration::from_secs(30),
    Duration::from_millis(500),
);

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

struct DkgObsolescence;

impl ObsolescencePolicy for DkgObsolescence {
    type Scope = DeliveryAbortGroup;
    type Evidence = DeliveryAbortGroup;

    fn obsolete(scope: &Self::Scope, evidence: &Self::Evidence) -> bool {
        scope.is_aborted_by(*evidence)
    }
}

pub(crate) struct DeliveryEngine<ST: CertificateSignatureRecoverable> {
    epoch: Epoch,
    inbound_validators: Option<BTreeSet<NodeId<CertificateSignaturePubKey<ST>>>>,
    scheduler: RetryScheduler<
        NodeId<CertificateSignaturePubKey<ST>>,
        DkgMessageId,
        Bytes,
        DkgObsolescence,
    >,
}

impl<ST> DeliveryEngine<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    pub(crate) fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            inbound_validators: None,
            scheduler: RetryScheduler::new(DKG_RETRY),
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
        self.scheduler.next_timer()
    }

    pub(crate) fn handle_network_message(
        &self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        payload: Bytes,
    ) -> Option<DeliveryInbound<ST>> {
        match decode_wire(payload.as_ref()) {
            Ok(WireEnvelope { epoch, payload }) if epoch == self.epoch.0 => {
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
                Some(DeliveryInbound { sender, payload })
            }
            Ok(_) => None,
            Err(err) => {
                warn!(?err, ?sender, "dropping malformed DKG delivery message");
                None
            }
        }
    }

    pub(crate) fn handle_timer(&mut self, now: Instant) -> Vec<DeliveryOutbound<ST>> {
        self.scheduler
            .retry_due(now)
            .into_iter()
            .map(delivery_outbound)
            .collect()
    }

    pub(crate) fn schedule_reliable(
        &mut self,
        message_id: DkgMessageId,
        recipients: impl IntoIterator<Item = NodeId<CertificateSignaturePubKey<ST>>>,
        payload: Bytes,
        abort_group: Option<DeliveryAbortGroup>,
        now: Instant,
    ) -> Result<Vec<DeliveryOutbound<ST>>, EnqueueError> {
        self.scheduler
            .enqueue(
                message_id,
                recipients,
                encode_wire(self.epoch, payload),
                abort_group,
                now,
            )
            .map(|sends| sends.into_iter().map(delivery_outbound).collect())
    }

    pub(crate) fn schedule_once(
        &self,
        to: NodeId<CertificateSignaturePubKey<ST>>,
        payload: Bytes,
    ) -> DeliveryOutbound<ST> {
        delivery_outbound(OnceScheduler::schedule(
            to,
            encode_wire(self.epoch, payload),
        ))
    }

    pub(crate) fn complete(&mut self, message_id: &DkgMessageId) {
        self.scheduler.complete(message_id);
    }

    pub(crate) fn abort_group(&mut self, group: DeliveryAbortGroup) {
        self.scheduler.observe(group);
    }
}

fn delivery_outbound<ST: CertificateSignatureRecoverable>(
    send: ScheduledSend<NodeId<CertificateSignaturePubKey<ST>>, Bytes>,
) -> DeliveryOutbound<ST> {
    DeliveryOutbound {
        to: send.to,
        payload: send.payload,
    }
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
        DkgMessageKind::BveRetrievalResponse
        | DkgMessageKind::PcRetrievalResponse
        | DkgMessageKind::Ladder
        | DkgMessageKind::LowerConversion
        | DkgMessageKind::OpenPower => None,
        DkgMessageKind::Done => Some(DeliveryAbortGroup::DoneQc),
    }
}

pub(crate) fn delivery_epoch(payload: &[u8]) -> Option<Epoch> {
    match decode_wire(payload) {
        Ok(wire) => Some(Epoch(wire.epoch)),
        Err(err) => {
            warn!(?err, "dropping malformed DKG delivery message");
            None
        }
    }
}

#[derive(RlpEncodable, RlpDecodable)]
struct WireEnvelope {
    epoch: u64,
    payload: Bytes,
}

fn encode_wire(epoch: Epoch, payload: Bytes) -> Bytes {
    alloy_rlp::encode(WireEnvelope {
        epoch: epoch.0,
        payload,
    })
    .into()
}

fn decode_wire(data: &[u8]) -> Result<WireEnvelope, alloy_rlp::Error> {
    alloy_rlp::decode_exact(data)
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
