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

use std::{
    future::Future,
    net::SocketAddr,
    task::{Context, Poll},
};

use bytes::Bytes;
use monad_crypto::certificate_signature::PubKey;
use monad_dataplane::{RecvUdpMsg, UdpSocketHandle};
use monad_executor::{ExecutorMetrics, ExecutorMetricsChain, Gauge};
use monad_peer_score::IdentityScore;
use monad_types::{NodeId, UdpPriority};
use thiserror::Error;
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
    priority_queue::{RecvMany, RECEIVE_BATCH_SIZE},
    protocol::AuthenticationProtocol,
};

// Allow two retries so a cookie-challenged handshake can resend its initiation.

#[derive(Clone)]
pub struct AuthRecvMsg<P: PubKey> {
    pub src_addr: SocketAddr,
    pub payload: Bytes,
    pub stride: u16,
    pub sender: Option<NodeId<P>>,
}

pub struct AuthenticatedSocketHandle<AP: AuthenticationProtocol<PublicKey: PubKey>> {
    socket: monad_dataplane::auth::AuthenticatedUdpSocket<AP>,
    metrics: ExecutorMetrics,
    bytes_written: Gauge,
    bytes_read: Gauge,
    receive_buffer: Vec<RecvUdpMsg<AP::PublicKey>>,
}
impl<AP: AuthenticationProtocol<PublicKey: PubKey>> Unpin for AuthenticatedSocketHandle<AP> {}
impl<AP: AuthenticationProtocol<PublicKey: PubKey>> RecvMany for AuthenticatedSocketHandle<AP> {
    type Item = Result<AuthRecvMsg<AP::PublicKey>, AP::Error>;
    fn poll_recv_many(
        &mut self,
        cx: &mut Context<'_>,
        messages: &mut Vec<Self::Item>,
        limit: usize,
    ) -> Poll<Option<()>> {
        std::pin::pin!(self.recv_many(messages, limit))
            .poll(cx)
            .map(|_| Some(()))
    }
}
impl<AP: AuthenticationProtocol<PublicKey: PubKey>> AuthenticatedSocketHandle<AP> {
    pub fn new(socket: UdpSocketHandle<AP::PublicKey>, protocol: AP) -> Self {
        let mut metrics = init_socket_executor_metrics();
        let bytes_written = metrics
            .gauge(GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_WRITTEN)
            .clone();
        let bytes_read = metrics
            .gauge(GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_READ)
            .clone();
        Self {
            socket: monad_dataplane::auth::AuthenticatedUdpSocket::new(socket, protocol),
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
        monad_dataplane::udp::segment_size_for_mtu(mtu) - AP::HEADER_SIZE
    }
    pub fn write(
        &mut self,
        public_key: &AP::PublicKey,
        addr: SocketAddr,
        msg: Bytes,
        stride: u16,
        priority: UdpPriority,
    ) {
        let _ = self.try_write(public_key, addr, msg, stride, priority);
    }
    fn try_write(
        &mut self,
        public_key: &AP::PublicKey,
        addr: SocketAddr,
        msg: Bytes,
        stride: u16,
        priority: UdpPriority,
    ) -> Result<(), monad_dataplane::auth::CommandQueueFull> {
        let bytes = msg.len();
        self.socket
            .write(*public_key, addr, msg, stride, priority)?;
        self.bytes_written.add(bytes as u64);
        Ok(())
    }
    pub fn set_priority_identities(&self, identities: std::collections::HashSet<AP::PublicKey>) {
        self.socket.set_priority_identities(identities);
    }
    pub fn set_prioritize(&self, enabled: bool) {
        self.socket.set_prioritize(enabled);
    }
    fn received(
        &mut self,
        message: RecvUdpMsg<AP::PublicKey>,
    ) -> Option<AuthRecvMsg<AP::PublicKey>> {
        // Never expose raw packets queued before authentication was installed.
        if AP::HEADER_SIZE > 0 && message.sender.is_none() {
            return None;
        }
        self.bytes_read.add(message.payload.len() as u64);
        Some(AuthRecvMsg {
            src_addr: message.src_addr,
            payload: message.payload,
            stride: message.stride,
            sender: message.sender.map(NodeId::new),
        })
    }
    pub async fn recv(&mut self) -> Result<AuthRecvMsg<AP::PublicKey>, AP::Error> {
        loop {
            let message = self.socket.recv().await;
            if let Some(message) = self.received(message) {
                return Ok(message);
            }
        }
    }
    pub async fn recv_many(
        &mut self,
        messages: &mut Vec<Result<AuthRecvMsg<AP::PublicKey>, AP::Error>>,
        limit: usize,
    ) {
        assert!(limit > 0 && limit <= RECEIVE_BATCH_SIZE);
        self.socket.recv_many(&mut self.receive_buffer, limit).await;
        let mut batch = std::mem::take(&mut self.receive_buffer);
        for message in batch.drain(..) {
            if let Some(message) = self.received(message) {
                messages.push(Ok(message));
            }
        }
        self.receive_buffer = batch;
    }
    pub fn connect(
        &mut self,
        public_key: &AP::PublicKey,
        addr: SocketAddr,
        attempts: u64,
    ) -> Result<(), monad_dataplane::auth::CommandQueueFull> {
        self.socket.connect(*public_key, addr, attempts)
    }
    /// Protocol control and timers are serviced independently by the dataplane.
    pub fn flush(&mut self) {}
    pub fn metrics(&self) -> ExecutorMetricsChain<'_> {
        self.socket.metrics().push(&self.metrics)
    }
}

pub struct FramedAuthenticatedSocketHandle<AP, F>
where
    AP: AuthenticationProtocol<PublicKey: PubKey>,
    F: AuthPacketFramer<AP::PublicKey, Decoded = Bytes>,
{
    socket: AuthenticatedSocketHandle<AP>,
    framer: F,
    receive_buffer: Vec<Result<AuthRecvMsg<AP::PublicKey>, AP::Error>>,
}

// Neither the socket nor the framer is structurally pinned by this handle.
impl<AP, F> Unpin for FramedAuthenticatedSocketHandle<AP, F>
where
    AP: AuthenticationProtocol<PublicKey: PubKey>,
    F: AuthPacketFramer<AP::PublicKey, Decoded = Bytes>,
{
}

impl<AP, F> RecvMany for FramedAuthenticatedSocketHandle<AP, F>
where
    AP: AuthenticationProtocol<PublicKey: PubKey>,
    F: AuthPacketFramer<AP::PublicKey, Decoded = Bytes>,
{
    type Item = Result<AuthRecvMsg<AP::PublicKey>, FramedRecvError<AP::Error>>;

    fn poll_recv_many(
        &mut self,
        cx: &mut Context<'_>,
        messages: &mut Vec<Self::Item>,
        limit: usize,
    ) -> Poll<Option<()>> {
        assert!(limit > 0 && limit <= RECEIVE_BATCH_SIZE);
        std::task::ready!(self
            .socket
            .poll_recv_many(cx, &mut self.receive_buffer, limit));
        for message in self.receive_buffer.drain(..) {
            match message {
                Err(error) => messages.push(Err(FramedRecvError::Auth(error))),
                Ok(msg) => {
                    let Some(sender) = msg.sender else {
                        messages.push(Err(FramedRecvError::MissingAuthPublicKey));
                        continue;
                    };
                    match self.framer.deframe(sender.pubkey(), msg.payload) {
                        Ok(Some(payload)) => messages.push(Ok(AuthRecvMsg {
                            src_addr: msg.src_addr,
                            payload,
                            sender: Some(sender),
                            stride: msg.stride,
                        })),
                        Ok(None) => {}
                        Err(err) => {
                            debug!(addr=?msg.src_addr, error=?err, "failed to decode authenticated packet")
                        }
                    }
                }
            }
        }
        Poll::Ready(Some(()))
    }
}

#[derive(Debug, Error)]
pub enum FramedRecvError<E: std::fmt::Debug> {
    #[error("authenticated socket error: {0:?}")]
    Auth(E),
    #[error("received unauthenticated message on framed socket")]
    MissingAuthPublicKey,
}

impl<AP, F> FramedAuthenticatedSocketHandle<AP, F>
where
    AP: AuthenticationProtocol<PublicKey: PubKey>,
    F: AuthPacketFramer<AP::PublicKey, Decoded = Bytes>,
{
    pub fn new(socket: AuthenticatedSocketHandle<AP>, framer: F) -> Self {
        Self {
            socket: socket.with_direct_metrics(),
            framer,
            receive_buffer: Vec::with_capacity(RECEIVE_BATCH_SIZE),
        }
    }

    pub async fn recv(&mut self) -> Result<AuthRecvMsg<AP::PublicKey>, FramedRecvError<AP::Error>> {
        loop {
            let msg = self.socket.recv().await.map_err(FramedRecvError::Auth)?;
            let Some(sender) = msg.sender else {
                return Err(FramedRecvError::MissingAuthPublicKey);
            };

            match self.framer.deframe(sender.pubkey(), msg.payload) {
                Ok(Some(payload)) => {
                    return Ok(AuthRecvMsg {
                        src_addr: msg.src_addr,
                        payload,
                        sender: Some(sender),
                        stride: msg.stride,
                    });
                }
                Ok(None) => continue,
                Err(err) => {
                    debug!(addr=?msg.src_addr, error=?err, "failed to decode authenticated packet");
                    continue;
                }
            }
        }
    }

    /// Queues framed plaintext for asynchronous authenticated delivery.
    /// Returns `Err(())` if framing or command-queue admission fails.
    #[allow(clippy::result_unit_err)]
    pub fn write_buffered(
        &mut self,
        public_key: &AP::PublicKey,
        addr: SocketAddr,
        plaintext: Bytes,
        priority: UdpPriority,
    ) -> Result<(), ()> {
        let packets = match self.framer.frame(plaintext) {
            Ok(packets) => packets,
            Err(err) => {
                warn!(error=?err, "failed to encode message");
                return Err(());
            }
        };

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
        remote_public_key: &AP::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), monad_dataplane::auth::CommandQueueFull> {
        self.socket
            .connect(remote_public_key, remote_addr, retry_attempts)
    }

    pub fn flush(&mut self) {
        self.socket.flush();
    }
    pub fn set_priority_identities(&self, identities: std::collections::HashSet<AP::PublicKey>) {
        self.socket.set_priority_identities(identities);
    }

    pub fn metrics(&self) -> ExecutorMetricsChain<'_> {
        self.socket.metrics().chain(self.framer.metrics())
    }
}

impl<AP, S> FramedAuthenticatedSocketHandle<AP, LeanUdpFramer<NodeId<AP::PublicKey>, S>>
where
    AP: AuthenticationProtocol<PublicKey: PubKey>,
    S: IdentityScore<Identity = NodeId<AP::PublicKey>>,
{
    pub fn set_dedicated_identities(
        &mut self,
        identities: impl IntoIterator<Item = NodeId<AP::PublicKey>>,
    ) {
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
    use monad_dataplane::{DataplaneBuilder, UnicastMsg};
    use monad_peer_discovery::NameRecord;
    use monad_secp::KeyPair;
    use monad_types::UdpPriority;
    use monad_wireauth::{Config, DEFAULT_RETRY_ATTEMPTS};
    use tracing_subscriber::EnvFilter;

    use super::{AuthenticatedSocketHandle, FramedAuthenticatedSocketHandle, FramedRecvError};
    use crate::auth::{
        framing::AuthPacketFramer,
        metrics::GAUGE_RAPTORCAST_AUTH_AUTHENTICATED_UDP_BYTES_WRITTEN,
        protocol::{NoopAuthProtocol, WireAuthProtocol},
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
        socket: AuthenticatedSocketHandle<WireAuthProtocol>,
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
                &crate::auth::metrics::UDP_METRICS,
                Config::default(),
                Arc::new(keypair),
            );
            let socket = AuthenticatedSocketHandle::new(authenticated_socket, auth_protocol);

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
            self.socket.flush();
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
            .expect("handshake and buffered delivery timeout")
            .expect("authenticated probe");
        assert_eq!(message.sender.unwrap().pubkey(), peer1.public_key);
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
            let message = message.unwrap();
            assert_eq!(message.sender.unwrap().pubkey(), alice.public_key);
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
            .unwrap()
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
            .expect("timeout waiting for bob")
            .expect("bob received");
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
            .expect("timeout waiting for alice")
            .expect("alice received");
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
            .expect("timeout waiting for bob")
            .expect("bob received");
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
                result = alice.socket.recv() => panic!("unexpected sender input: {:?}", result.err()),
                result = bob.socket.recv() => result.unwrap(),
            }
        }).await.unwrap();
        assert_eq!(message.payload, b"buffered"[..]);
        assert_eq!(
            message.sender,
            Some(monad_types::NodeId::new(alice.public_key))
        );
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
                        *name == crate::auth::metrics::UDP_METRICS.api_decrypt.name
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
                    == crate::auth::metrics::UDP_METRICS
                        .initiator_messages_sent_from_buffer
                        .name
            })
            .unwrap()
            .1;
        assert_eq!(
            buffered, 0,
            "plaintext must wait outside WireAuth's encrypt-on-handshake buffer"
        );
        let message = bob.socket.recv().await.unwrap();
        assert_eq!(message.payload.as_ref(), b"authenticated");
        assert_eq!(message.sender.unwrap().pubkey(), alice.public_key);
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
            .expect("timeout waiting for first chunk")
            .expect("bob received first chunk");
        let second = tokio::time::timeout(Duration::from_secs(2), bob.socket.recv())
            .await
            .expect("timeout waiting for second chunk")
            .expect("bob received second chunk");

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
            &crate::auth::metrics::UDP_METRICS,
            config,
            Arc::new(local_keypair),
        );
        let mut handle = AuthenticatedSocketHandle::new(authenticated_socket, auth_protocol);

        let ticks = |handle: &AuthenticatedSocketHandle<WireAuthProtocol>| {
            handle
                .metrics()
                .into_inner()
                .into_iter()
                .find(|(name, _, _)| *name == crate::auth::metrics::UDP_METRICS.api_tick.name)
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

        let auth_socket = AuthenticatedSocketHandle::new(
            recv_socket,
            NoopAuthProtocol::<monad_secp::PubKey>::new(),
        );
        let mut framed_socket = FramedAuthenticatedSocketHandle::new(auth_socket, PanicFramer);

        send_socket.write_unicast_with_priority(
            UnicastMsg {
                msgs: vec![(recv_addr, Bytes::from_static(b"hello"))],
                stride: 5,
            },
            UdpPriority::Regular,
        );

        let result = tokio::time::timeout(Duration::from_secs(2), framed_socket.recv())
            .await
            .expect("timeout waiting for framed recv");
        assert!(matches!(result, Err(FramedRecvError::MissingAuthPublicKey)));
    }
}
