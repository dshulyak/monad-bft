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

mod common;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use common::find_udp_free_port;
use monad_dataplane::{DataplaneBuilder, DataplaneControl, UdpSocketConfig};
use monad_peer_score::{create_scorer, ScoreConfig, StdClock};
use monad_raptorcast::auth::{AuthenticatedSocketHandle, LeanUdpSocketHandle, WireAuthProtocol};
use monad_secp::KeyPair;
use monad_types::{NodeId, UdpPriority};
use monad_wireauth::Config;

const SOCKET_LABEL: &str = "lean_udp";
const DEFAULT_RETRY_ATTEMPTS: u64 = 3;

fn keypair(seed: u8) -> KeyPair {
    KeyPair::from_bytes(&mut [seed; 32]).unwrap()
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

struct LeanPeerNode {
    socket: LeanUdpSocketHandle<WireAuthProtocol, NodeId<monad_secp::PubKey>, StdClock>,
    addr: SocketAddr,
    public_key: monad_secp::PubKey,
    _control: DataplaneControl,
}

impl LeanPeerNode {
    fn new(seed: u8) -> Self {
        let port = find_udp_free_port();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port));

        let dp = DataplaneBuilder::new(&addr, 1000)
            .extend_udp_sockets(vec![UdpSocketConfig {
                socket_addr: addr,
                label: SOCKET_LABEL.to_string(),
            }])
            .build();

        assert!(dp.block_until_ready(Duration::from_secs(1)));
        let (_tcp_socket, mut udp_dataplane, control) = dp.split();

        let udp_socket = udp_dataplane.take_socket(SOCKET_LABEL).expect("udp socket");

        let keypair = keypair(seed);
        let public_key = keypair.pubkey();
        let config = Config::default();
        let auth_protocol = WireAuthProtocol::new(config, Arc::new(keypair));
        let auth_socket = AuthenticatedSocketHandle::new(udp_socket, auth_protocol);

        let (_, score_reader) =
            create_scorer::<NodeId<monad_secp::PubKey>, StdClock>(ScoreConfig::default(), StdClock);

        let socket = LeanUdpSocketHandle::new(
            auth_socket,
            score_reader,
            monad_leanudp::Config::default(),
            0.0,
        );

        Self {
            socket,
            addr,
            public_key,
            _control: control,
        }
    }

    fn connect(&mut self, peer_public: &monad_secp::PubKey, peer_addr: SocketAddr) {
        self.socket
            .connect(peer_public, peer_addr, DEFAULT_RETRY_ATTEMPTS)
            .expect("connect failed");
        self.socket.flush();
    }
}

async fn exchange_handshake(peer1: &mut LeanPeerNode, peer2: &mut LeanPeerNode) {
    let timeout = Duration::from_secs(3);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        tokio::select! {
            _ = tokio::time::timeout(Duration::from_millis(50), peer1.socket.recv()) => {}
            _ = tokio::time::timeout(Duration::from_millis(50), peer2.socket.recv()) => {}
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                if peer1.socket.is_connected_socket_and_public_key(&peer2.addr, &peer2.public_key) {
                    return;
                }
            }
        }

        peer1.socket.flush();
        peer2.socket.flush();
    }
}

fn create_test_tx() -> alloy_consensus::TxEnvelope {
    use monad_eth_testutil::{make_legacy_tx, S1};
    const BASE_FEE: u128 = 100_000_000_000;
    make_legacy_tx(S1, BASE_FEE, 21000, 0, 0)
}

fn encode_tx(tx: &alloy_consensus::TxEnvelope) -> bytes::Bytes {
    use alloy_rlp::Encodable;
    let mut buf = bytes::BytesMut::new();
    tx.encode(&mut buf);
    buf.freeze()
}

fn decode_tx(payload: &bytes::Bytes) -> alloy_consensus::TxEnvelope {
    use alloy_rlp::Decodable;
    alloy_consensus::TxEnvelope::decode(&mut payload.as_ref()).expect("decode tx")
}

#[tokio::test(flavor = "current_thread")]
async fn test_lean_udp_tx_exchange() {
    init_tracing();

    let mut alice = LeanPeerNode::new(1);
    let mut bob = LeanPeerNode::new(2);

    let bob_addr = bob.addr;
    let bob_pubkey = bob.public_key;
    let alice_pubkey = alice.public_key;

    alice.connect(&bob_pubkey, bob_addr);

    exchange_handshake(&mut alice, &mut bob).await;

    let tx = create_test_tx();
    let tx_hash = tx.tx_hash();

    alice
        .socket
        .send(bob_addr, encode_tx(&tx), UdpPriority::Regular);
    alice.socket.flush();

    let received = tokio::time::timeout(Duration::from_secs(2), bob.socket.recv())
        .await
        .expect("timeout waiting for bob to receive")
        .expect("bob recv error");

    assert_eq!(received.public_key, alice_pubkey);
    let decoded_tx = decode_tx(&received.payload);
    assert_eq!(decoded_tx.tx_hash(), tx_hash);

    let tx2 = create_test_tx();
    let tx2_hash = tx2.tx_hash();

    bob.socket
        .send(alice.addr, encode_tx(&tx2), UdpPriority::Regular);
    bob.socket.flush();

    let received2 = tokio::time::timeout(Duration::from_secs(2), alice.socket.recv())
        .await
        .expect("timeout waiting for alice to receive")
        .expect("alice recv error");

    assert_eq!(received2.public_key, bob_pubkey);
    let decoded_tx2 = decode_tx(&received2.payload);
    assert_eq!(decoded_tx2.tx_hash(), tx2_hash);
}
