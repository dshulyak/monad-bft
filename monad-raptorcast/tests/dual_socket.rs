use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use monad_dataplane::{DataplaneBuilder, UnicastMsg};
use monad_raptorcast::{
    authenticated_socket::{AuthenticatedSocketHandle, DualSocketHandle},
    authentication::WireAuthProtocol,
    AUTHENTICATED_RAPTORCAST_SOCKET, RAPTORCAST_SOCKET,
};
use monad_secp::KeyPair;
use monad_types::UdpPriority;
use monad_wireauth::{Config, DEFAULT_RETRY_ATTEMPTS};
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

fn keypair(seed: u8) -> KeyPair {
    KeyPair::from_bytes(&mut [seed; 32]).unwrap()
}

struct PeerNode {
    socket: DualSocketHandle<WireAuthProtocol>,
    auth_addr: SocketAddr,
    public_key: monad_secp::PubKey,
    _tcp_socket: monad_dataplane::TcpSocketHandle,
    _control: monad_dataplane::DataplaneControl,
}

impl PeerNode {
    fn new(auth_port: u16, non_auth_port: u16, seed: u8) -> Self {
        let auth_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port));
        let non_auth_addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            non_auth_port,
        ));

        let dp = DataplaneBuilder::new(&auth_addr, 1000)
            .extend_udp_sockets(vec![
                monad_dataplane::UdpSocketConfig {
                    socket_addr: auth_addr,
                    label: AUTHENTICATED_RAPTORCAST_SOCKET.to_string(),
                },
                monad_dataplane::UdpSocketConfig {
                    socket_addr: non_auth_addr,
                    label: RAPTORCAST_SOCKET.to_string(),
                },
            ])
            .build();

        assert!(dp.block_until_ready(Duration::from_secs(1)));
        let (tcp_socket, mut udp_dataplane, control) = dp.split();

        let authenticated_socket = udp_dataplane
            .take_socket(AUTHENTICATED_RAPTORCAST_SOCKET)
            .expect("authenticated socket");
        let non_authenticated_socket = udp_dataplane
            .take_socket(RAPTORCAST_SOCKET)
            .expect("non-authenticated socket");

        let keypair = keypair(seed);
        let public_key = keypair.pubkey();
        let config = Config::default();
        let auth_protocol = WireAuthProtocol::new(config, &Arc::new(keypair));
        let authenticated_handle =
            AuthenticatedSocketHandle::new(authenticated_socket, auth_protocol);
        let socket = DualSocketHandle::new(authenticated_handle, non_authenticated_socket);

        Self {
            socket,
            auth_addr,
            public_key,
            _tcp_socket: tcp_socket,
            _control: control,
        }
    }

    fn connect(&mut self, peer_public: &monad_secp::PubKey, peer_addr: SocketAddr) {
        self.socket
            .connect(peer_public, peer_addr, DEFAULT_RETRY_ATTEMPTS)
            .expect("connect failed");
        self.socket.flush();
    }

    fn write_message(&mut self, dest: SocketAddr, message: &[u8]) {
        self.socket.write_unicast_with_priority(
            UnicastMsg {
                msgs: vec![(dest, Bytes::copy_from_slice(message))],
                stride: message.len() as u16,
            },
            UdpPriority::Regular,
        );
    }
}

async fn exchange_handshake(peer1: &mut PeerNode, peer2: &mut PeerNode) {
    let timeout = Duration::from_secs(3);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        tokio::select! {
            result1 = tokio::time::timeout(Duration::from_millis(100), peer1.socket.recv()) => {
                if let Ok(Ok(msg)) = result1 {
                    tracing::info!(src=?msg.src_addr, len=msg.payload.len(), "peer1 received");
                }
            }
            result2 = tokio::time::timeout(Duration::from_millis(100), peer2.socket.recv()) => {
                if let Ok(Ok(msg)) = result2 {
                    tracing::info!(src=?msg.src_addr, len=msg.payload.len(), "peer2 received");
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if peer1.socket.is_connected_socket_and_public_key(&peer2.auth_addr, &peer2.public_key) {
                    tracing::info!("handshake complete");
                    break;
                }
            }
        }
    }
}

#[tokio::test]
async fn test_e2e_bidirectional() {
    init_tracing();

    let mut alice = PeerNode::new(18001, 19001, 1);
    let mut bob = PeerNode::new(18002, 19002, 2);

    let bob_addr = bob.auth_addr;
    let alice_addr = alice.auth_addr;

    alice.connect(&bob.public_key, bob_addr);

    exchange_handshake(&mut alice, &mut bob).await;

    alice.write_message(bob_addr, b"hello from alice");

    let received_bob = tokio::time::timeout(Duration::from_secs(2), bob.socket.recv())
        .await
        .expect("timeout waiting for bob")
        .expect("bob received");
    assert_eq!(&received_bob.payload[..], b"hello from alice");
    assert_eq!(received_bob.src_addr, alice_addr);

    bob.write_message(alice_addr, b"hello from bob");

    let received_alice = tokio::time::timeout(Duration::from_secs(2), alice.socket.recv())
        .await
        .expect("timeout waiting for alice")
        .expect("alice received");
    assert_eq!(&received_alice.payload[..], b"hello from bob");
    assert_eq!(received_alice.src_addr, bob_addr);
}
