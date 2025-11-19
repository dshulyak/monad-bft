use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::ParseIntError,
    sync::Arc,
    time::Duration,
};

use alloy_rlp::{RlpDecodable, RlpEncodable};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable, PubKey,
};
use monad_executor::Executor;
use monad_executor_glue::{Message, RouterCommand};
use monad_peer_discovery::MonadNameRecord;
use monad_raptorcast::RaptorCastEvent;
use monad_secp::{KeyPair, SecpSignature};
use monad_types::{Deserializable, Epoch, NodeId, Serializable, Stake};
use tracing_subscriber::EnvFilter;

const UP_BANDWIDTH_MBPS: u64 = 1_000;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

fn keypair(seed: u8) -> KeyPair {
    KeyPair::from_bytes(&mut [seed; 32]).unwrap()
}

fn find_free_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind");
    socket.local_addr().expect("failed to get addr").port()
}

#[derive(Clone, Copy, RlpEncodable, RlpDecodable)]
struct MockMessage {
    id: u32,
    message_len: usize,
}

impl MockMessage {
    fn new(id: u32, message_len: usize) -> Self {
        Self { id, message_len }
    }
}

impl Message for MockMessage {
    type NodeIdPubKey = CertificateSignaturePubKey<SecpSignature>;
    type Event = MockEvent<Self::NodeIdPubKey>;

    fn event(self, from: NodeId<Self::NodeIdPubKey>) -> Self::Event {
        MockEvent((from, self.id))
    }
}

impl Serializable<Bytes> for MockMessage {
    fn serialize(&self) -> Bytes {
        let mut message = BytesMut::zeroed(self.message_len);
        let id_bytes = self.id.to_le_bytes();
        message[0] = id_bytes[0];
        message[1] = id_bytes[1];
        message[2] = id_bytes[2];
        message[3] = id_bytes[3];
        message.into()
    }
}

impl Deserializable<Bytes> for MockMessage {
    type ReadError = ParseIntError;

    fn deserialize(message: &Bytes) -> Result<Self, Self::ReadError> {
        Ok(Self::new(
            u32::from_le_bytes(message[..4].try_into().unwrap()),
            message.len(),
        ))
    }
}

#[derive(Clone, Copy, Debug)]
struct MockEvent<P: PubKey>((NodeId<P>, u32));

impl<ST> From<RaptorCastEvent<MockEvent<CertificateSignaturePubKey<ST>>, ST>>
    for MockEvent<CertificateSignaturePubKey<ST>>
where
    ST: CertificateSignatureRecoverable,
{
    fn from(value: RaptorCastEvent<MockEvent<CertificateSignaturePubKey<ST>>, ST>) -> Self {
        match value {
            RaptorCastEvent::Message(event) => event,
            RaptorCastEvent::PeerManagerResponse(_) => unimplemented!(),
            RaptorCastEvent::SecondaryRaptorcastPeersUpdate { .. } => unimplemented!(),
        }
    }
}

struct ValidatorChannels {
    cmd_tx: tokio::sync::mpsc::UnboundedSender<RouterCommand<SecpSignature, MockMessage>>,
    event_rx:
        tokio::sync::mpsc::UnboundedReceiver<MockEvent<CertificateSignaturePubKey<SecpSignature>>>,
}

#[derive(Clone)]
struct ValidatorInfo {
    keypair: Arc<KeyPair>,
    nodeid: NodeId<CertificateSignaturePubKey<SecpSignature>>,
    pubkey: monad_secp::PubKey,
    tcp_addr: SocketAddrV4,
    non_auth_addr: SocketAddrV4,
}

impl ValidatorInfo {
    fn new(seed: u8) -> Self {
        let kp = keypair(seed);
        let nodeid = NodeId::new(kp.pubkey());
        let pubkey = kp.pubkey();
        let tcp_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), find_free_port());
        let non_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), find_free_port());
        Self {
            keypair: Arc::new(kp),
            nodeid,
            pubkey,
            tcp_addr,
            non_auth_addr,
        }
    }

    fn create_name_record(&self) -> MonadNameRecord<SecpSignature> {
        let name_record = monad_peer_discovery::NameRecord::new_with_all_ports(
            Ipv4Addr::new(127, 0, 0, 1),
            self.tcp_addr.port(),
            self.non_auth_addr.port(),
            Some(self.tcp_addr.port()),
            Some(self.tcp_addr.port()),
            1,
        );
        MonadNameRecord::new(name_record, &*self.keypair)
    }
}

fn create_raptorcast_config(
    keypair: Arc<KeyPair>,
) -> monad_raptorcast::config::RaptorCastConfig<SecpSignature> {
    monad_raptorcast::config::RaptorCastConfig {
        shared_key: keypair,
        mtu: monad_dataplane::udp::DEFAULT_MTU,
        udp_message_max_age_ms: u64::MAX,
        primary_instance: Default::default(),
        secondary_instance: monad_node_config::FullNodeRaptorCastConfig {
            enable_publisher: false,
            enable_client: false,
            raptor10_fullnode_redundancy_factor: 2f32,
            full_nodes_prioritized: monad_node_config::FullNodeConfig { identities: vec![] },
            round_span: monad_types::Round(10),
            invite_lookahead: monad_types::Round(5),
            max_invite_wait: monad_types::Round(3),
            deadline_round_dist: monad_types::Round(3),
            init_empty_round_span: monad_types::Round(1),
            max_group_size: 10,
            max_num_group: 5,
            invite_future_dist_min: monad_types::Round(1),
            invite_future_dist_max: monad_types::Round(5),
            invite_accept_heartbeat_ms: 100,
        },
    }
}

fn spawn_tcp_validator(
    keypair: Arc<KeyPair>,
    tcp_addr: SocketAddrV4,
    non_auth_addr: SocketAddrV4,
    tcp_addresses: HashMap<NodeId<CertificateSignaturePubKey<SecpSignature>>, SocketAddrV4>,
    name_records: HashMap<
        NodeId<CertificateSignaturePubKey<SecpSignature>>,
        MonadNameRecord<SecpSignature>,
    >,
) -> ValidatorChannels {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::task::spawn_local(async move {
        let builder = monad_peer_discovery::mock::NopDiscoveryBuilder {
            known_addresses: tcp_addresses,
            name_records,
            ..Default::default()
        };
        let pd = monad_peer_discovery::driver::PeerDiscoveryDriver::new(builder);
        let shared_pd = Arc::new(std::sync::Mutex::new(pd));

        const TCP_SOCKET: &str = "tcp";

        let dp = monad_dataplane::DataplaneBuilder::new(UP_BANDWIDTH_MBPS)
            .extend_tcp_sockets(vec![monad_dataplane::TcpSocketConfig {
                socket_addr: SocketAddr::V4(tcp_addr),
                label: TCP_SOCKET.to_string(),
            }])
            .extend_udp_sockets(vec![
                monad_dataplane::UdpSocketConfig {
                    socket_addr: SocketAddr::V4(tcp_addr),
                    label: monad_raptorcast::AUTHENTICATED_RAPTORCAST_SOCKET.to_string(),
                },
                monad_dataplane::UdpSocketConfig {
                    socket_addr: SocketAddr::V4(non_auth_addr),
                    label: monad_raptorcast::RAPTORCAST_SOCKET.to_string(),
                },
            ])
            .build();
        assert!(dp.block_until_ready(Duration::from_secs(1)));

        let (mut tcp_dataplane, mut udp_dataplane, control) = dp.split();
        let tcp_socket = tcp_dataplane.take_socket(TCP_SOCKET).unwrap();
        let (tcp_reader, tcp_writer) = tcp_socket.split();
        let authenticated_socket = udp_dataplane
            .take_socket(monad_raptorcast::AUTHENTICATED_RAPTORCAST_SOCKET)
            .expect("authenticated socket");
        let non_authenticated_socket = udp_dataplane
            .take_socket(monad_raptorcast::RAPTORCAST_SOCKET)
            .expect("non-authenticated socket");

        let tcp_sig_auth =
            monad_raptorcast::auth::SignatureBasedTcpAuth::<SecpSignature>::new(keypair.clone());
        let tcp_sig_handle = monad_raptorcast::auth::AuthenticatedTcpSocketHandle::new(
            tcp_reader,
            tcp_writer,
            tcp_sig_auth,
        );
        let dual_tcp_socket: monad_raptorcast::auth::DualTcpSocketHandle<
            monad_raptorcast::auth::SignatureBasedTcpAuth<SecpSignature>,
            monad_raptorcast::auth::SignatureBasedTcpAuth<SecpSignature>,
        > = monad_raptorcast::auth::DualTcpSocketHandle::new(tcp_sig_handle, None);

        let config = create_raptorcast_config(keypair.clone());
        let wireauth_config = monad_wireauth::Config::default();
        let udp_auth_protocol =
            monad_raptorcast::auth::WireAuthProtocol::new(wireauth_config, &keypair);

        let mut validator_rc = monad_raptorcast::RaptorCast::<
            SecpSignature,
            MockMessage,
            MockMessage,
            MockEvent<CertificateSignaturePubKey<SecpSignature>>,
            monad_peer_discovery::mock::NopDiscovery<SecpSignature>,
            _,
            _,
            _,
        >::new(
            config,
            monad_raptorcast::raptorcast_secondary::SecondaryRaptorCastModeConfig::None,
            dual_tcp_socket,
            Some(authenticated_socket),
            non_authenticated_socket,
            control,
            shared_pd,
            Epoch(0),
            udp_auth_protocol,
        );

        let mut cmd_rx = cmd_rx;

        loop {
            tokio::select! {
                Some(cmd) = cmd_rx.recv() => {
                    validator_rc.exec(vec![cmd]);
                }
                Some(event) = validator_rc.next() => {
                    if event_tx.send(event).is_err() {
                        break;
                    }
                }
            }
        }
    });

    ValidatorChannels { cmd_tx, event_rx }
}

#[tokio::test(flavor = "current_thread")]
async fn test_tcp_signature_point_to_point() {
    init_tracing();

    const NUM_NODES: usize = 3;

    let validator_infos: Vec<_> = (1..=NUM_NODES as u8).map(ValidatorInfo::new).collect();

    let name_records: HashMap<_, _> = validator_infos
        .iter()
        .map(|v| (v.nodeid, v.create_name_record()))
        .collect();

    let tcp_addresses: HashMap<_, _> = validator_infos
        .iter()
        .map(|v| (v.nodeid, v.tcp_addr))
        .collect();

    tokio::task::LocalSet::new()
        .run_until(async {
            let validators: Vec<_> = validator_infos
                .iter()
                .map(|v| {
                    spawn_tcp_validator(
                        v.keypair.clone(),
                        v.tcp_addr,
                        v.non_auth_addr,
                        tcp_addresses.clone(),
                        name_records.clone(),
                    )
                })
                .collect();

            let epoch = Epoch(0);
            let validator_set: Vec<_> = validator_infos
                .iter()
                .map(|v| (v.nodeid, Stake::ONE))
                .collect();

            for v in &validators {
                v.cmd_tx
                    .send(RouterCommand::AddEpochValidatorSet {
                        epoch,
                        validator_set: validator_set.clone(),
                    })
                    .unwrap();
            }

            tokio::time::sleep(Duration::from_millis(100)).await;

            let sender_idx = 0;
            let sender_nodeid = validator_infos[sender_idx].nodeid;
            let receiver_idx = 1;

            let message = MockMessage::new(42, 1000);
            validators[sender_idx]
                .cmd_tx
                .send(RouterCommand::Publish {
                    target: monad_types::RouterTarget::TcpPointToPoint {
                        to: validator_infos[receiver_idx].nodeid,
                        completion: None,
                    },
                    message,
                })
                .unwrap();

            let (cmd_txs, mut event_rxs): (Vec<_>, Vec<_>) = validators
                .into_iter()
                .map(|v| (v.cmd_tx, v.event_rx))
                .unzip();

            let event = tokio::time::timeout(MESSAGE_TIMEOUT, event_rxs[receiver_idx].recv())
                .await
                .expect("timeout waiting for message")
                .expect("channel closed");

            let MockEvent((from, msg_id)) = event;
            assert_eq!(from, sender_nodeid);
            assert_eq!(msg_id, 42);
        })
        .await;
}
