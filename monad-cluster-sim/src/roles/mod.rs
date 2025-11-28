pub mod bootnode;
pub mod fullnode;
pub mod validator;

use std::{
    collections::HashMap,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_executor_glue::Message;
use monad_raptorcast::RaptorCastEvent;
use monad_secp::SecpSignature;
use monad_types::{Deserializable, NodeId, Serializable};
use rand::{thread_rng, Rng};

pub type SignatureType = SecpSignature;
pub type PubKeyType = CertificateSignaturePubKey<SignatureType>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Validator,
    Bootnode,
    Fullnode { dedicated: bool, prioritized: bool },
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Validator => write!(f, "validator"),
            NodeType::Bootnode => write!(f, "bootnode"),
            NodeType::Fullnode {
                dedicated,
                prioritized,
            } => {
                if *dedicated {
                    write!(f, "dedicated_fullnode")
                } else if *prioritized {
                    write!(f, "prioritized_fullnode")
                } else {
                    write!(f, "fullnode")
                }
            }
        }
    }
}

#[derive(Debug, Clone, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
pub struct MockMessage {
    pub timestamp: u64,
    pub data: bytes::Bytes,
}

impl MockMessage {
    pub fn new_with_timestamp(message_len: usize) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut data = bytes::BytesMut::with_capacity(message_len);
        data.resize(message_len, 0);

        let timestamp_bytes = timestamp.to_le_bytes();
        if data.len() >= 8 {
            data[0..8].copy_from_slice(&timestamp_bytes);
        }

        if data.len() > 8 {
            let mut rng = thread_rng();
            rng.fill(&mut data[8..]);
        }

        Self {
            timestamp,
            data: data.freeze(),
        }
    }
}

impl Message for MockMessage {
    type NodeIdPubKey = PubKeyType;
    type Event = MockEvent<Self::NodeIdPubKey>;

    fn event(self, from: NodeId<Self::NodeIdPubKey>) -> Self::Event {
        MockEvent {
            from,
            message: self,
        }
    }
}

impl Serializable<bytes::Bytes> for MockMessage {
    fn serialize(&self) -> bytes::Bytes {
        self.data.clone()
    }
}

impl Deserializable<bytes::Bytes> for MockMessage {
    type ReadError = std::io::Error;

    fn deserialize(message: &bytes::Bytes) -> Result<Self, Self::ReadError> {
        if message.len() < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too short",
            ));
        }
        let timestamp = u64::from_le_bytes(message[..8].try_into().unwrap());
        Ok(Self {
            timestamp,
            data: message.clone(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct MockEvent<P: monad_crypto::certificate_signature::PubKey> {
    pub from: NodeId<P>,
    pub message: MockMessage,
}

pub enum RouterEvent<P: monad_crypto::certificate_signature::PubKey> {
    Message(MockEvent<P>),
    ControlEvent,
}

impl<ST> From<RaptorCastEvent<MockEvent<CertificateSignaturePubKey<ST>>, ST>>
    for RouterEvent<CertificateSignaturePubKey<ST>>
where
    ST: CertificateSignatureRecoverable,
{
    fn from(value: RaptorCastEvent<MockEvent<CertificateSignaturePubKey<ST>>, ST>) -> Self {
        match value {
            RaptorCastEvent::Message(event) => RouterEvent::Message(event),
            RaptorCastEvent::PeerManagerResponse(_) => {
                tracing::debug!("received peer manager response");
                RouterEvent::ControlEvent
            }
            RaptorCastEvent::SecondaryRaptorcastPeersUpdate(round, peers) => {
                tracing::debug!(round = ?round, peer_count = peers.len(), "received secondary raptorcast peers update");
                RouterEvent::ControlEvent
            }
        }
    }
}

#[derive(Default)]
pub struct LatencyMetrics {
    pub total_messages_received: u64,
    pub total_messages_sent: u64,
    pub last_latency_us: u64,
    pub min_latency_us: u64,
    pub max_latency_us: u64,
    pub total_latency_sum_us: u64,
}

pub const GAUGE_LATENCY_LAST_US: &str = "raptorcast.latency.last_us";
pub const GAUGE_LATENCY_MIN_US: &str = "raptorcast.latency.min_us";
pub const GAUGE_LATENCY_MAX_US: &str = "raptorcast.latency.max_us";
pub const GAUGE_LATENCY_AVG_US: &str = "raptorcast.latency.avg_us";
pub const GAUGE_MESSAGES_RECEIVED: &str = "raptorcast.messages.received";
pub const GAUGE_MESSAGES_SENT: &str = "raptorcast.messages.sent";
pub const GAUGE_UPTIME_US: &str = "raptorcast.uptime_us";

impl LatencyMetrics {
    pub fn new() -> Self {
        Self {
            total_messages_received: 0,
            total_messages_sent: 0,
            last_latency_us: 0,
            min_latency_us: u64::MAX,
            max_latency_us: 0,
            total_latency_sum_us: 0,
        }
    }

    pub fn record_received(&mut self, latency_ns: u64) {
        let latency_us = latency_ns / 1_000;
        self.total_messages_received += 1;
        self.last_latency_us = latency_us;
        self.min_latency_us = self.min_latency_us.min(latency_us);
        self.max_latency_us = self.max_latency_us.max(latency_us);
        self.total_latency_sum_us += latency_us;
    }

    pub fn record_sent(&mut self) {
        self.total_messages_sent += 1;
    }

    pub fn avg_latency_us(&self) -> u64 {
        if self.total_messages_received > 0 {
            self.total_latency_sum_us / self.total_messages_received
        } else {
            0
        }
    }

    pub fn metrics(&self) -> Vec<(&'static str, u64)> {
        vec![
            (GAUGE_LATENCY_LAST_US, self.last_latency_us),
            (
                GAUGE_LATENCY_MIN_US,
                if self.min_latency_us == u64::MAX {
                    0
                } else {
                    self.min_latency_us
                },
            ),
            (GAUGE_LATENCY_MAX_US, self.max_latency_us),
            (GAUGE_LATENCY_AVG_US, self.avg_latency_us()),
            (GAUGE_MESSAGES_RECEIVED, self.total_messages_received),
            (GAUGE_MESSAGES_SENT, self.total_messages_sent),
        ]
    }
}

pub fn send_metrics(
    meter: &opentelemetry::metrics::Meter,
    gauge_cache: &mut HashMap<&'static str, opentelemetry::metrics::Gauge<u64>>,
    latency_metrics: &LatencyMetrics,
    raptorcast_metrics: monad_executor::ExecutorMetricsChain,
    process_start: &Instant,
) {
    for (k, v) in latency_metrics
        .metrics()
        .into_iter()
        .chain(raptorcast_metrics.into_inner())
        .chain(std::iter::once((
            GAUGE_UPTIME_US,
            process_start.elapsed().as_micros() as u64,
        )))
    {
        let gauge = gauge_cache
            .entry(k)
            .or_insert_with(|| meter.u64_gauge(k).build());
        gauge.record(v, &[]);
    }
}

pub type MultiRouterType = monad_router_multi::MultiRouter<
    SignatureType,
    MockMessage,
    MockMessage,
    RouterEvent<PubKeyType>,
    monad_peer_discovery::discovery::PeerDiscovery<SignatureType>,
    monad_raptorcast::auth::WireAuthProtocol,
>;
