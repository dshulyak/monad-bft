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
    EnqueueError, ObsolescencePolicy, RetryConfig, RetryScheduler, ScheduledSend,
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

impl<ST: CertificateSignatureRecoverable>
    From<ScheduledSend<NodeId<CertificateSignaturePubKey<ST>>, Bytes>> for DeliveryOutbound<ST>
{
    fn from(send: ScheduledSend<NodeId<CertificateSignaturePubKey<ST>>, Bytes>) -> Self {
        Self {
            to: send.to,
            payload: send.payload,
        }
    }
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
    inbound_validators: BTreeSet<NodeId<CertificateSignaturePubKey<ST>>>,
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
    pub(crate) fn new(
        epoch: Epoch,
        validators: impl IntoIterator<Item = NodeId<CertificateSignaturePubKey<ST>>>,
    ) -> Self {
        Self {
            epoch,
            inbound_validators: validators.into_iter().collect(),
            scheduler: RetryScheduler::new(DKG_RETRY),
        }
    }

    pub(crate) fn next_timer(&self) -> Option<Instant> {
        self.scheduler.next_timer()
    }

    pub(crate) fn handle_network_message(
        &self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        payload: Bytes,
    ) -> Option<DeliveryInbound<ST>> {
        let wire: Result<WireEnvelope, _> = payload.as_ref().try_into();
        match wire {
            Ok(WireEnvelope { epoch, payload }) if epoch == self.epoch.0 => {
                if !self.inbound_validators.contains(&sender) {
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
            .map(Into::into)
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
                WireEnvelope {
                    epoch: self.epoch.0,
                    payload,
                }
                .into(),
                abort_group,
                now,
            )
            .map(|sends| sends.into_iter().map(Into::into).collect())
    }

    pub(crate) fn schedule_once(
        &self,
        to: NodeId<CertificateSignaturePubKey<ST>>,
        payload: Bytes,
    ) -> DeliveryOutbound<ST> {
        ScheduledSend {
            to,
            payload: WireEnvelope {
                epoch: self.epoch.0,
                payload,
            }
            .into(),
        }
        .into()
    }

    pub(crate) fn complete(&mut self, message_id: &DkgMessageId) {
        self.scheduler.complete(message_id);
    }

    pub(crate) fn abort_group(&mut self, group: DeliveryAbortGroup) {
        self.scheduler.observe(group);
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
    let wire: Result<WireEnvelope, _> = payload.try_into();
    match wire {
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

impl From<WireEnvelope> for Bytes {
    fn from(wire: WireEnvelope) -> Self {
        alloy_rlp::encode(wire).into()
    }
}

impl TryFrom<&[u8]> for WireEnvelope {
    type Error = alloy_rlp::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        alloy_rlp::decode_exact(data)
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
