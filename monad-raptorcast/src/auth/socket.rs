// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{collections::HashSet, net::SocketAddr};

use bytes::Bytes;
use monad_crypto::certificate_signature::PubKey;
use monad_dataplane::{
    auth::{AuthenticatedUdpSocket, CommandQueueFull, AUTHENTICATED_HEADER_SIZE},
    RecvUdpMsg,
};
use monad_executor::{ExecutorMetrics, ExecutorMetricsChain, Gauge};
use monad_peer_score::IdentityScore;
use monad_types::{NodeId, UdpPriority};
use tracing::{debug, warn};

use super::{
    framing::{AuthPacketFramer, LeanUdpFramer},
    metrics::{
        init_direct_udp_executor_metrics, init_socket_executor_metrics,
        GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_READ,
        GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_WRITTEN,
        GAUGE_RAPTORCAST_AUTH_DIRECT_UDP_BYTES_READ,
        GAUGE_RAPTORCAST_AUTH_DIRECT_UDP_BYTES_WRITTEN,
    },
};

const RECEIVE_BATCH_SIZE: usize = 128;

#[derive(Clone)]
pub struct AuthRecvMsg<P: PubKey> {
    pub src_addr: SocketAddr,
    pub payload: Bytes,
    pub stride: u16,
    pub sender: NodeId<P>,
}

/// Raptorcast framing and accounting around an authenticated dataplane handle.
pub struct AuthenticatedSocketHandle<P: PubKey> {
    socket: AuthenticatedUdpSocket<P>,
    metrics: ExecutorMetrics,
    bytes_written: Gauge,
    bytes_read: Gauge,
    receive_buffer: Vec<RecvUdpMsg<P>>,
}

impl<P: PubKey> AuthenticatedSocketHandle<P> {
    pub fn new(socket: AuthenticatedUdpSocket<P>) -> Self {
        let mut metrics = init_socket_executor_metrics();
        let bytes_written = metrics
            .gauge(GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_WRITTEN)
            .clone();
        let bytes_read = metrics
            .gauge(GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_READ)
            .clone();
        Self {
            socket,
            metrics,
            bytes_written,
            bytes_read,
            receive_buffer: Vec::with_capacity(RECEIVE_BATCH_SIZE),
        }
    }
    fn with_direct_metrics(mut self) -> Self {
        self.metrics = init_direct_udp_executor_metrics();
        self.bytes_written = self
            .metrics
            .gauge(GAUGE_RAPTORCAST_AUTH_DIRECT_UDP_BYTES_WRITTEN)
            .clone();
        self.bytes_read = self
            .metrics
            .gauge(GAUGE_RAPTORCAST_AUTH_DIRECT_UDP_BYTES_READ)
            .clone();
        self
    }
    pub fn segment_size(&self, mtu: u16) -> u16 {
        monad_dataplane::udp::segment_size_for_mtu(mtu) - AUTHENTICATED_HEADER_SIZE
    }
    pub fn write(
        &mut self,
        public_key: &P,
        addr: SocketAddr,
        msg: Bytes,
        stride: u16,
        priority: UdpPriority,
    ) {
        let _ = self.try_write(public_key, addr, msg, stride, priority);
    }
    fn try_write(
        &mut self,
        public_key: &P,
        addr: SocketAddr,
        msg: Bytes,
        stride: u16,
        priority: UdpPriority,
    ) -> Result<(), CommandQueueFull> {
        let bytes = msg.len();
        self.socket
            .write(*public_key, addr, msg, stride, priority)?;
        self.bytes_written.add(bytes as u64);
        Ok(())
    }
    pub fn set_priority_identities(&self, identities: HashSet<P>) {
        self.socket.set_priority_identities(identities);
    }
    pub fn set_prioritize(&self, enabled: bool) {
        self.socket.set_prioritize(enabled);
    }
    fn received(&mut self, message: RecvUdpMsg<P>) -> Option<AuthRecvMsg<P>> {
        // Discard raw packets buffered before authentication was installed.
        let sender = NodeId::new(message.sender?);
        self.bytes_read.add(message.payload.len() as u64);
        Some(AuthRecvMsg {
            src_addr: message.src_addr,
            payload: message.payload,
            stride: message.stride,
            sender,
        })
    }
    pub async fn recv(&mut self) -> AuthRecvMsg<P> {
        loop {
            let message = self.socket.recv().await;
            if let Some(message) = self.received(message) {
                return message;
            }
        }
    }
    pub async fn recv_many(&mut self, messages: &mut Vec<AuthRecvMsg<P>>, limit: usize) {
        assert!(limit > 0 && limit <= RECEIVE_BATCH_SIZE);
        let before = messages.len();
        while messages.len() == before {
            self.socket.recv_many(&mut self.receive_buffer, limit).await;
            let mut batch = std::mem::take(&mut self.receive_buffer);
            for message in batch.drain(..) {
                if let Some(message) = self.received(message) {
                    messages.push(message);
                }
            }
            self.receive_buffer = batch;
        }
    }
    pub fn connect(
        &mut self,
        public_key: &P,
        addr: SocketAddr,
        attempts: u64,
    ) -> Result<(), CommandQueueFull> {
        self.socket.connect(*public_key, addr, attempts)
    }
    pub fn metrics(&self) -> ExecutorMetricsChain<'_> {
        self.socket.metrics().push(&self.metrics)
    }
}

pub struct FramedAuthenticatedSocketHandle<P, F>
where
    P: PubKey,
    F: AuthPacketFramer<P, Decoded = Bytes>,
{
    socket: AuthenticatedSocketHandle<P>,
    framer: F,
}
impl<P, F> FramedAuthenticatedSocketHandle<P, F>
where
    P: PubKey,
    F: AuthPacketFramer<P, Decoded = Bytes>,
{
    pub fn new(socket: AuthenticatedSocketHandle<P>, framer: F) -> Self {
        Self {
            socket: socket.with_direct_metrics(),
            framer,
        }
    }
    pub async fn recv(&mut self) -> AuthRecvMsg<P> {
        loop {
            let msg = self.socket.recv().await;
            match self.framer.deframe(msg.sender.pubkey(), msg.payload) {
                Ok(Some(payload)) => return AuthRecvMsg { payload, ..msg },
                Ok(None) => {}
                Err(err) => {
                    debug!(addr=?msg.src_addr, error=?err, "failed to decode authenticated packet")
                }
            }
        }
    }
    /// Queue framed plaintext. Framing and command admission can fail locally.
    #[allow(clippy::result_unit_err)]
    pub fn write_buffered(
        &mut self,
        public_key: &P,
        addr: SocketAddr,
        plaintext: Bytes,
        priority: UdpPriority,
    ) -> Result<(), ()> {
        let packets = self
            .framer
            .frame(plaintext)
            .map_err(|err| warn!(error=?err, "failed to encode message"))?;
        for packet in packets {
            if packet.is_empty() {
                continue;
            }
            let stride = packet.len().try_into().map_err(|_| ())?;
            self.socket
                .try_write(public_key, addr, packet, stride, priority)
                .map_err(|_| ())?;
        }
        Ok(())
    }
    pub fn connect(
        &mut self,
        key: &P,
        addr: SocketAddr,
        attempts: u64,
    ) -> Result<(), CommandQueueFull> {
        self.socket.connect(key, addr, attempts)
    }
    pub fn set_priority_identities(&self, identities: HashSet<P>) {
        self.socket.set_priority_identities(identities);
    }
    pub fn metrics(&self) -> ExecutorMetricsChain<'_> {
        self.socket.metrics().chain(self.framer.metrics())
    }
}
impl<P, S> FramedAuthenticatedSocketHandle<P, LeanUdpFramer<NodeId<P>, S>>
where
    P: PubKey,
    S: IdentityScore<Identity = NodeId<P>>,
{
    pub fn set_dedicated_identities(&mut self, identities: impl IntoIterator<Item = NodeId<P>>) {
        self.framer.set_dedicated_identities(identities);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        pin::pin,
        sync::Arc,
        time::Duration,
    };

    use bytes::Bytes;
    use futures::poll;
    use monad_dataplane::{
        auth::{AuthenticatedUdpSocket, Config, WireAuthProtocol, DEFAULT_RETRY_ATTEMPTS},
        DataplaneBuilder, UnicastMsg,
    };
    use monad_peer_discovery::NameRecord;
    use monad_secp::KeyPair;
    use monad_types::UdpPriority;
    use tracing_subscriber::EnvFilter;

    use super::{AuthenticatedSocketHandle, FramedAuthenticatedSocketHandle};
    use crate::auth::{
        framing::AuthPacketFramer, metrics::GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_WRITTEN,
    };

    struct PanicFramer;

    impl AuthPacketFramer<monad_secp::PubKey> for PanicFramer {
        type Decoded = Bytes;
        type Error = Infallible;

        fn frame(&mut self, _payload: Bytes) -> Result<impl Iterator<Item = Bytes>, Self::Error> {
            Ok(std::iter::empty())
        }

        fn deframe(
            &mut self,
            _public_key: monad_secp::PubKey,
            _packet: Bytes,
        ) -> Result<Option<Self::Decoded>, Self::Error> {
            unreachable!("framer should not be called for unauthenticated messages");
        }
    }

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
    }

    fn keypair(seed: u8) -> KeyPair {
        KeyPair::from_bytes(&mut [seed; 32]).unwrap()
    }

    struct PeerNode {
        socket: AuthenticatedSocketHandle<monad_secp::PubKey>,
        auth_addr: SocketAddr,
        public_key: monad_secp::PubKey,
        _tcp_socket: monad_dataplane::TcpSocketHandle,
        _control: monad_dataplane::DataplaneControl,
        dataplane_metrics: monad_executor::ExecutorMetrics,
    }

    impl PeerNode {
        fn new(seed: u8) -> Self {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

            let udp_sockets = vec![(
                monad_dataplane::UdpSocketId::AuthenticatedRaptorcast,
                bind_addr,
            )];

            let mut dp = DataplaneBuilder::new(1000)
                .with_tcp_sockets([(monad_dataplane::TcpSocketId::Raptorcast, bind_addr)])
                .with_udp_sockets(udp_sockets)
                .build_with_identity::<monad_secp::PubKey>();

            let tcp_socket = dp
                .tcp_sockets
                .take(monad_dataplane::TcpSocketId::Raptorcast)
                .expect("tcp socket");
            let authenticated_socket = dp
                .udp_sockets
                .take(monad_dataplane::UdpSocketId::AuthenticatedRaptorcast)
                .expect("authenticated socket");
            let control = dp.control.clone();

            let auth_addr = authenticated_socket.local_addr();
            let keypair = keypair(seed);
            let public_key = keypair.pubkey();
            let auth_protocol = WireAuthProtocol::new(
                &monad_dataplane::auth::metrics::UDP_METRICS,
                Config::default(),
                Arc::new(keypair),
            );
            let socket =
                AuthenticatedSocketHandle::new(monad_dataplane::auth::AuthenticatedUdpSocket::new(
                    authenticated_socket,
                    auth_protocol,
                ));

            Self {
                socket,
                auth_addr,
                public_key,
                _tcp_socket: tcp_socket,
                _control: control,
                dataplane_metrics: dp.metrics().clone(),
            }
        }

        fn connect(&mut self, peer_public: &monad_secp::PubKey, peer_addr: SocketAddr) {
            self.socket
                .connect(peer_public, peer_addr, DEFAULT_RETRY_ATTEMPTS)
                .expect("connect failed");
        }
    }

    async fn exchange_handshake(peer1: &mut PeerNode, peer2: &mut PeerNode) {
        let probe = Bytes::from_static(b"handshake ready");
        peer1.socket.write(
            &peer2.public_key,
            peer2.auth_addr,
            probe.clone(),
            probe.len() as u16,
            UdpPriority::High,
        );
        let message = tokio::time::timeout(Duration::from_secs(3), peer2.socket.recv())
            .await
            .expect("handshake and buffered delivery timeout");
        assert_eq!(message.sender.pubkey(), peer1.public_key);
        assert_eq!(message.payload, probe);
    }

    #[tokio::test]
    async fn authenticates_dataplane_batches_in_order_and_preserves_cancelled_receives() {
        let mut alice = PeerNode::new(1);
        let mut bob = PeerNode::new(2);
        alice.connect(&bob.public_key, bob.auth_addr);
        exchange_handshake(&mut alice, &mut bob).await;
        let received = bob
            .dataplane_metrics
            .metric_handles()
            .into_iter()
            .find(|(name, _, _)| *name == "monad.dataplane.udp.total_messages_received")
            .unwrap()
            .1;
        let baseline = received.get();
        for value in 0..144_u64 {
            alice.socket.write(
                &bob.public_key,
                bob.auth_addr,
                Bytes::copy_from_slice(&value.to_le_bytes()),
                8,
                UdpPriority::Regular,
            );
        }
        // Stage a complete dataplane batch so the assertion measures batch
        // dequeueing rather than relying on the relative timing of UDP sends.
        tokio::time::timeout(Duration::from_secs(2), async {
            while received.get() < baseline + 144 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let mut messages = Vec::new();
        while messages.len() < 144 {
            let before = messages.len();
            tokio::time::timeout(
                Duration::from_secs(2),
                bob.socket.recv_many(&mut messages, 128),
            )
            .await
            .unwrap();
            assert!(messages.len() - before <= 128);
        }
        assert_eq!(messages.len(), 144);
        for (value, message) in messages.drain(..).enumerate() {
            assert_eq!(message.sender.pubkey(), alice.public_key);
            assert_eq!(message.payload.as_ref(), &(value as u64).to_le_bytes());
        }
        assert!(poll!(pin!(bob.socket.recv_many(&mut messages, 128))).is_pending());
        assert!(messages.is_empty());
        alice.socket.write(
            &bob.public_key,
            bob.auth_addr,
            Bytes::from_static(b"after cancellation"),
            18,
            UdpPriority::Regular,
        );
        let message = tokio::time::timeout(Duration::from_secs(2), bob.socket.recv())
            .await
            .unwrap();
        assert_eq!(message.payload.as_ref(), b"after cancellation");
    }

    #[tokio::test]
    async fn test_e2e_bidirectional() {
        init_tracing();

        let mut alice = PeerNode::new(1);
        let mut bob = PeerNode::new(2);

        let bob_addr = bob.auth_addr;
        let alice_addr = alice.auth_addr;

        alice.connect(&bob.public_key, bob_addr);

        exchange_handshake(&mut alice, &mut bob).await;

        alice.socket.write(
            &bob.public_key,
            bob_addr,
            Bytes::from_static(b"hello from alice"),
            16,
            UdpPriority::Regular,
        );

        let received_bob = tokio::time::timeout(Duration::from_secs(2), bob.socket.recv())
            .await
            .expect("timeout waiting for bob");
        assert_eq!(&received_bob.payload[..], b"hello from alice");
        assert_eq!(received_bob.src_addr, alice_addr);

        bob.socket.write(
            &alice.public_key,
            alice_addr,
            Bytes::from_static(b"hello from bob"),
            14,
            UdpPriority::Regular,
        );

        let received_alice = tokio::time::timeout(Duration::from_secs(2), alice.socket.recv())
            .await
            .expect("timeout waiting for alice");
        assert_eq!(&received_alice.payload[..], b"hello from bob");
        assert_eq!(received_alice.src_addr, bob_addr);
    }

    #[tokio::test]
    async fn normal_send_reuses_session_at_supplied_address() {
        let mut alice = PeerNode::new(1);
        let mut bob = PeerNode::new(2);

        alice.connect(&bob.public_key, bob.auth_addr);
        exchange_handshake(&mut alice, &mut bob).await;

        alice.socket.write(
            &bob.public_key,
            bob.auth_addr,
            Bytes::from_static(b"existing session"),
            16,
            UdpPriority::Regular,
        );

        let received = tokio::time::timeout(Duration::from_secs(2), bob.socket.recv())
            .await
            .expect("timeout waiting for bob");
        assert_eq!(received.payload, b"existing session"[..]);
    }

    #[tokio::test]
    async fn test_write_to_name_record_tracks_authenticated_bytes() {
        init_tracing();

        let mut alice = PeerNode::new(1);
        let mut bob = PeerNode::new(2);

        alice.connect(&bob.public_key, bob.auth_addr);
        exchange_handshake(&mut alice, &mut bob).await;

        let SocketAddr::V4(bob_auth_addr) = bob.auth_addr else {
            panic!("test uses IPv4 addresses");
        };
        let bob_name_record = NameRecord::new_with_ports(
            *bob_auth_addr.ip(),
            bob_auth_addr.port(),
            None,
            bob_auth_addr.port(),
            None,
            None,
            1,
        );
        let payload = Bytes::from_static(b"authenticated path");
        let before = alice.socket.bytes_written.get();

        alice.socket.write(
            &bob.public_key,
            SocketAddr::V4(bob_name_record.authenticated_udp_socket()),
            payload.clone(),
            payload.len() as u16,
            UdpPriority::Regular,
        );

        let authenticated_bytes = alice
            .socket
            .metrics()
            .into_inner()
            .into_iter()
            .find_map(|(name, value, _)| {
                (name == GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_WRITTEN.name)
                    .then_some(value)
            })
            .unwrap_or_default();
        assert_eq!(authenticated_bytes - before, payload.len() as u64);
    }

    #[tokio::test]
    async fn legacy_name_record_port_does_not_enable_plaintext_fallback() {
        let mut alice = PeerNode::new(1);
        let mut bob = PeerNode::new(2);
        let legacy = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        legacy.set_nonblocking(true).unwrap();
        let SocketAddr::V4(auth_addr) = bob.auth_addr else {
            panic!("test uses IPv4");
        };
        let record = NameRecord::new_with_ports(
            *auth_addr.ip(),
            auth_addr.port(),
            Some(legacy.local_addr().unwrap().port()),
            auth_addr.port(),
            None,
            None,
            1,
        );
        alice.socket.write(
            &bob.public_key,
            SocketAddr::V4(record.authenticated_udp_socket()),
            Bytes::from_static(b"buffered"),
            8,
            UdpPriority::Regular,
        );
        let message = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                _ = alice.socket.recv() => panic!("unexpected sender input"),
                result = bob.socket.recv() => result,
            }
        })
        .await
        .unwrap();
        assert_eq!(message.payload, b"buffered"[..]);
        assert_eq!(message.sender, monad_types::NodeId::new(alice.public_key));
        assert_eq!(
            legacy.recv_from(&mut [0; 1024]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn plaintext_datagrams_are_rejected_on_the_authenticated_socket() {
        let mut bob = PeerNode::new(2);
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"plaintext", bob.auth_addr).unwrap();
        let rejected = bob
            .dataplane_metrics
            .metric_handles()
            .into_iter()
            .find(|(name, _, _)| *name == "monad.dataplane.udp.auth.packets_rejected")
            .unwrap()
            .1;
        tokio::time::timeout(Duration::from_secs(1), async {
            while rejected.get() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("dataplane rejects plaintext without application polling");
        assert!(poll!(pin!(bob.socket.recv())).is_pending());
        // Handshake and decryption must also progress with neither application
        // polling a receive future. The ciphertext never reaches this thread.
        let mut alice = PeerNode::new(1);
        alice.socket.write(
            &bob.public_key,
            bob.auth_addr,
            Bytes::from_static(b"authenticated"),
            13,
            UdpPriority::Regular,
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let decrypts = bob
                    .socket
                    .metrics()
                    .into_inner()
                    .into_iter()
                    .find(|(name, _, _)| {
                        *name == monad_dataplane::auth::metrics::UDP_METRICS.api_decrypt.name
                    })
                    .unwrap()
                    .1;
                if decrypts > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("dataplane decrypts before the receiver is polled");
        let buffered = alice
            .socket
            .metrics()
            .into_inner()
            .into_iter()
            .find(|(name, _, _)| {
                *name
                    == monad_dataplane::auth::metrics::UDP_METRICS
                        .initiator_messages_sent_from_buffer
                        .name
            })
            .unwrap()
            .1;
        assert_eq!(
            buffered, 0,
            "plaintext must wait outside WireAuth's encrypt-on-handshake buffer"
        );
        let message = bob.socket.recv().await;
        assert_eq!(message.payload.as_ref(), b"authenticated");
        assert_eq!(message.sender.pubkey(), alice.public_key);
    }

    #[tokio::test]
    async fn test_write_to_name_record_segments_authenticated_payload_by_stride() {
        init_tracing();

        let mut alice = PeerNode::new(1);
        let mut bob = PeerNode::new(2);

        alice.connect(&bob.public_key, bob.auth_addr);
        exchange_handshake(&mut alice, &mut bob).await;

        let SocketAddr::V4(bob_auth_addr) = bob.auth_addr else {
            panic!("test uses IPv4 addresses");
        };
        let bob_name_record = NameRecord::new_with_ports(
            *bob_auth_addr.ip(),
            bob_auth_addr.port(),
            None,
            bob_auth_addr.port(),
            None,
            None,
            1,
        );

        alice.socket.write(
            &bob.public_key,
            SocketAddr::V4(bob_name_record.authenticated_udp_socket()),
            Bytes::from_static(b"helloworld"),
            5,
            UdpPriority::Regular,
        );

        let first = tokio::time::timeout(Duration::from_secs(2), bob.socket.recv())
            .await
            .expect("timeout waiting for first chunk");
        let second = tokio::time::timeout(Duration::from_secs(2), bob.socket.recv())
            .await
            .expect("timeout waiting for second chunk");

        assert_eq!(&first.payload[..], b"hello");
        assert_eq!(&second.payload[..], b"world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_timer_deadline() {
        init_tracing();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let mut dp = DataplaneBuilder::new(1000)
            .with_udp_sockets([(
                monad_dataplane::UdpSocketId::AuthenticatedRaptorcast,
                bind_addr,
            )])
            .build_with_identity::<monad_secp::PubKey>();

        let authenticated_socket = dp
            .udp_sockets
            .take(monad_dataplane::UdpSocketId::AuthenticatedRaptorcast)
            .expect("authenticated socket");

        let local_keypair = keypair(1);
        let config = Config {
            handshake_rate_reset_interval: Duration::from_millis(10),
            initiation_timeout: Duration::from_millis(4),
            session_timeout_jitter: Duration::ZERO,
            ..Default::default()
        };

        let auth_protocol = WireAuthProtocol::new(
            &monad_dataplane::auth::metrics::UDP_METRICS,
            config,
            Arc::new(local_keypair),
        );
        let mut handle = AuthenticatedSocketHandle::new(
            monad_dataplane::auth::AuthenticatedUdpSocket::new(authenticated_socket, auth_protocol),
        );

        let ticks = |handle: &AuthenticatedSocketHandle<monad_secp::PubKey>| {
            handle
                .metrics()
                .into_inner()
                .into_iter()
                .find(|(name, _, _)| {
                    *name == monad_dataplane::auth::metrics::UDP_METRICS.api_tick.name
                })
                .unwrap()
                .1
        };
        let initial = ticks(&handle);
        tokio::time::timeout(Duration::from_secs(1), async {
            while ticks(&handle) == initial {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("dataplane must tick with no application receives");
        let remote_keypair = keypair(2);
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 19004));
        let initial = ticks(&handle);
        handle
            .connect(&remote_keypair.pubkey(), remote_addr, 1)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while ticks(&handle) == initial {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("dataplane must service new handshake deadline without receive polling");
    }

    #[tokio::test]
    async fn test_framed_socket_rejects_unauthenticated_messages() {
        init_tracing();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let mut recv_dp = DataplaneBuilder::new(1000)
            .with_udp_sockets([(
                monad_dataplane::UdpSocketId::AuthenticatedRaptorcast,
                bind_addr,
            )])
            .build_with_identity::<monad_secp::PubKey>();
        let recv_socket = recv_dp
            .udp_sockets
            .take(monad_dataplane::UdpSocketId::AuthenticatedRaptorcast)
            .expect("recv socket");
        let recv_addr = recv_socket.local_addr();

        let mut send_dp = DataplaneBuilder::new(1000)
            .with_udp_sockets([(monad_dataplane::UdpSocketId::Raptorcast, bind_addr)])
            .build();
        let send_socket = send_dp
            .udp_sockets
            .take(monad_dataplane::UdpSocketId::Raptorcast)
            .expect("send socket");

        let auth_socket = AuthenticatedSocketHandle::new(AuthenticatedUdpSocket::with_key(
            recv_socket,
            Arc::new(keypair(1)),
        ));
        let mut framed_socket = FramedAuthenticatedSocketHandle::new(auth_socket, PanicFramer);

        send_socket.write_unicast_with_priority(
            UnicastMsg {
                msgs: vec![(recv_addr, Bytes::from_static(b"hello"))],
                stride: 5,
            },
            UdpPriority::Regular,
        );

        let result = tokio::time::timeout(Duration::from_millis(100), framed_socket.recv()).await;
        assert!(
            result.is_err(),
            "unauthenticated input must not reach the framer"
        );
        let rejected = recv_dp
            .metrics()
            .metric_handles()
            .into_iter()
            .find(|(name, _, _)| *name == "monad.dataplane.udp.auth.packets_rejected")
            .unwrap()
            .1;
        assert!(rejected.get() > 0);
    }
}
