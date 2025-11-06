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
use monad_peer_discovery::{MonadNameRecord, NameRecord};
use monad_raptorcast::RaptorCastEvent;
use monad_secp::{KeyPair, SecpSignature};
use monad_types::{Deserializable, Epoch, NodeId, Serializable, Stake};
use tracing_subscriber::EnvFilter;

type SignatureType = SecpSignature;
type PubKeyType = CertificateSignaturePubKey<SignatureType>;

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
    type NodeIdPubKey = PubKeyType;
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
            RaptorCastEvent::PeerManagerResponse(_) => {
                unimplemented!()
            }
            RaptorCastEvent::SecondaryRaptorcastPeersUpdate { .. } => {
                unimplemented!()
            }
        }
    }
}

struct ValidatorChannels {
    cmd_tx: tokio::sync::mpsc::UnboundedSender<RouterCommand<SignatureType, MockMessage>>,
    event_rx: tokio::sync::mpsc::UnboundedReceiver<MockEvent<PubKeyType>>,
    ready_rx: tokio::sync::oneshot::Receiver<()>,
}

fn spawn_noop_validator(
    keypair: KeyPair,
    auth_addr: SocketAddrV4,
    known_addresses: HashMap<NodeId<PubKeyType>, SocketAddrV4>,
    name_records: HashMap<NodeId<PubKeyType>, MonadNameRecord<SignatureType>>,
) -> ValidatorChannels {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    tokio::task::spawn_local(async move {
        let mut builder = monad_peer_discovery::mock::NopDiscoveryBuilder::default();
        builder.known_addresses = known_addresses;
        builder.name_records = name_records;

        let pd = monad_peer_discovery::driver::PeerDiscoveryDriver::new(builder);
        let shared_pd = Arc::new(std::sync::Mutex::new(pd));

        let up_bandwidth_mbps = 1_000;
        let non_auth_addr = SocketAddr::new((*auth_addr.ip()).into(), auth_addr.port() + 1);
        let dp =
            monad_dataplane::DataplaneBuilder::new(&SocketAddr::V4(auth_addr), up_bandwidth_mbps)
                .extend_udp_sockets(vec![
                    monad_dataplane::UdpSocketConfig {
                        socket_addr: SocketAddr::V4(auth_addr),
                        label: monad_raptorcast::AUTHENTICATED_RAPTORCAST_SOCKET.to_string(),
                    },
                    monad_dataplane::UdpSocketConfig {
                        socket_addr: non_auth_addr,
                        label: monad_raptorcast::RAPTORCAST_SOCKET.to_string(),
                    },
                ])
                .build();
        assert!(dp.block_until_ready(Duration::from_secs(1)));
        let (tcp_socket, mut udp_dataplane, control) = dp.split();
        let authenticated_socket = udp_dataplane
            .take_socket(monad_raptorcast::AUTHENTICATED_RAPTORCAST_SOCKET)
            .expect("authenticated socket");
        let non_authenticated_socket = udp_dataplane
            .take_socket(monad_raptorcast::RAPTORCAST_SOCKET)
            .expect("non-authenticated socket");
        let (tcp_reader, tcp_writer) = tcp_socket.split();

        let config = monad_raptorcast::config::RaptorCastConfig {
            shared_key: Arc::new(keypair),
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
        };

        let auth_protocol = monad_raptorcast::authentication::NoopAuthProtocol::new();

        let mut validator_rc = monad_raptorcast::RaptorCast::<
            SignatureType,
            MockMessage,
            MockMessage,
            MockEvent<PubKeyType>,
            monad_peer_discovery::mock::NopDiscovery<SignatureType>,
            _,
        >::new(
            config,
            monad_raptorcast::raptorcast_secondary::SecondaryRaptorCastModeConfig::None,
            tcp_reader,
            tcp_writer,
            authenticated_socket,
            non_authenticated_socket,
            control,
            shared_pd,
            Epoch(0),
            auth_protocol,
        );

        let mut cmd_rx = cmd_rx;
        let _ = ready_tx.send(());

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

    ValidatorChannels {
        cmd_tx,
        event_rx,
        ready_rx,
    }
}

fn spawn_wireauth_validator(
    keypair: KeyPair,
    auth_addr: SocketAddrV4,
    known_addresses: HashMap<NodeId<PubKeyType>, SocketAddrV4>,
    name_records: HashMap<NodeId<PubKeyType>, MonadNameRecord<SignatureType>>,
    peers_to_check: Vec<(SocketAddrV4, monad_secp::PubKey)>,
) -> ValidatorChannels {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    tokio::task::spawn_local(async move {
        let mut builder = monad_peer_discovery::mock::NopDiscoveryBuilder::default();
        builder.known_addresses = known_addresses;
        builder.name_records = name_records;

        let pd = monad_peer_discovery::driver::PeerDiscoveryDriver::new(builder);
        let shared_pd = Arc::new(std::sync::Mutex::new(pd));

        let up_bandwidth_mbps = 1_000;
        let non_auth_addr = SocketAddr::new((*auth_addr.ip()).into(), auth_addr.port() + 1);
        let dp =
            monad_dataplane::DataplaneBuilder::new(&SocketAddr::V4(auth_addr), up_bandwidth_mbps)
                .extend_udp_sockets(vec![
                    monad_dataplane::UdpSocketConfig {
                        socket_addr: SocketAddr::V4(auth_addr),
                        label: monad_raptorcast::AUTHENTICATED_RAPTORCAST_SOCKET.to_string(),
                    },
                    monad_dataplane::UdpSocketConfig {
                        socket_addr: non_auth_addr,
                        label: monad_raptorcast::RAPTORCAST_SOCKET.to_string(),
                    },
                ])
                .build();
        assert!(dp.block_until_ready(Duration::from_secs(1)));
        let (tcp_socket, mut udp_dataplane, control) = dp.split();
        let authenticated_socket = udp_dataplane
            .take_socket(monad_raptorcast::AUTHENTICATED_RAPTORCAST_SOCKET)
            .expect("authenticated socket");
        let non_authenticated_socket = udp_dataplane
            .take_socket(monad_raptorcast::RAPTORCAST_SOCKET)
            .expect("non-authenticated socket");
        let (tcp_reader, tcp_writer) = tcp_socket.split();

        let config = monad_raptorcast::config::RaptorCastConfig {
            shared_key: Arc::new(keypair),
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
        };

        let wireauth_config = monad_wireauth::Config::default();
        let auth_protocol = monad_raptorcast::authentication::WireAuthProtocol::new(
            wireauth_config,
            &config.shared_key,
        );

        let mut validator_rc = monad_raptorcast::RaptorCast::<
            SignatureType,
            MockMessage,
            MockMessage,
            MockEvent<PubKeyType>,
            monad_peer_discovery::mock::NopDiscovery<SignatureType>,
            _,
        >::new(
            config,
            monad_raptorcast::raptorcast_secondary::SecondaryRaptorCastModeConfig::None,
            tcp_reader,
            tcp_writer,
            authenticated_socket,
            non_authenticated_socket,
            control,
            shared_pd,
            Epoch(0),
            auth_protocol,
        );

        let mut cmd_rx = cmd_rx;
        let mut ready_tx = Some(ready_tx);
        let mut check_interval = tokio::time::interval(Duration::from_millis(100));

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
                _ = check_interval.tick() => {
                    if let Some(tx) = ready_tx.take() {
                        let all_connected = peers_to_check.iter().all(|(addr, pubkey)| {
                            validator_rc.is_connected_to(&SocketAddr::V4(*addr), pubkey)
                        });

                        if all_connected {
                            let _ = tx.send(());
                        } else {
                            ready_tx = Some(tx);
                        }
                    }
                }
            }
        }
    });

    ValidatorChannels {
        cmd_tx,
        event_rx,
        ready_rx,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wireauth_message_exchange() {
    init_tracing();

    let local = tokio::task::LocalSet::new();

    local
        .run_until(async {
            let auth_port1 = find_free_port();
            let auth_port2 = find_free_port();

            let validator1_keypair = keypair(1);
            let validator1_nodeid = NodeId::new(validator1_keypair.pubkey());
            let validator1_pubkey = validator1_keypair.pubkey();
            let validator1_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port1);

            let validator2_keypair = keypair(2);
            let validator2_nodeid = NodeId::new(validator2_keypair.pubkey());
            let validator2_pubkey = validator2_keypair.pubkey();
            let validator2_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port2);

            let name_record1 = NameRecord::new_with_authentication(
                Ipv4Addr::new(127, 0, 0, 1),
                8000,
                validator1_auth_addr.port() + 1,
                validator1_auth_addr.port(),
                1,
            );
            let monad_name_record1 = MonadNameRecord::new(name_record1, &validator1_keypair);

            let name_record2 = NameRecord::new_with_authentication(
                Ipv4Addr::new(127, 0, 0, 1),
                8002,
                validator2_auth_addr.port() + 1,
                validator2_auth_addr.port(),
                1,
            );
            let monad_name_record2 = MonadNameRecord::new(name_record2, &validator2_keypair);

            let mut name_records = HashMap::new();
            name_records.insert(validator1_nodeid, monad_name_record1);
            name_records.insert(validator2_nodeid, monad_name_record2);

            let known_addresses = HashMap::from([
                (
                    validator1_nodeid,
                    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), validator1_auth_addr.port() + 1),
                ),
                (
                    validator2_nodeid,
                    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), validator2_auth_addr.port() + 1),
                ),
            ]);

            let validator1 = spawn_wireauth_validator(
                validator1_keypair,
                validator1_auth_addr,
                known_addresses.clone(),
                name_records.clone(),
                vec![(validator2_auth_addr, validator2_pubkey)],
            );

            let validator2 = spawn_wireauth_validator(
                validator2_keypair,
                validator2_auth_addr,
                known_addresses.clone(),
                name_records.clone(),
                vec![(validator1_auth_addr, validator1_pubkey)],
            );

            let epoch = Epoch(0);
            let validator_set = vec![
                (validator1_nodeid, Stake::ONE),
                (validator2_nodeid, Stake::ONE),
            ];

            validator1
                .cmd_tx
                .send(RouterCommand::AddEpochValidatorSet {
                    epoch,
                    validator_set: validator_set.clone(),
                })
                .unwrap();

            validator2
                .cmd_tx
                .send(RouterCommand::AddEpochValidatorSet {
                    epoch,
                    validator_set: validator_set.clone(),
                })
                .unwrap();

            let ready_timeout = Duration::from_secs(5);
            tokio::time::timeout(ready_timeout, validator1.ready_rx)
                .await
                .expect("validator1 connection timeout")
                .expect("validator1 ready channel closed");

            tokio::time::timeout(ready_timeout, validator2.ready_rx)
                .await
                .expect("validator2 connection timeout")
                .expect("validator2 ready channel closed");

            let message = MockMessage::new(42, 1000);
            validator1
                .cmd_tx
                .send(RouterCommand::PublishWithPriority {
                    target: monad_types::RouterTarget::PointToPoint(validator2_nodeid),
                    message,
                    priority: monad_types::UdpPriority::Regular,
                })
                .unwrap();

            let timeout = Duration::from_secs(5);
            let mut validator2_event_rx = validator2.event_rx;
            let event = tokio::time::timeout(timeout, validator2_event_rx.recv())
                .await
                .expect("timeout waiting for message")
                .expect("channel closed");

            let MockEvent((from, msg_id)) = event;
            assert_eq!(from, validator1_nodeid);
            assert_eq!(msg_id, 42);

            let message = MockMessage::new(43, 1000);
            validator2
                .cmd_tx
                .send(RouterCommand::PublishWithPriority {
                    target: monad_types::RouterTarget::PointToPoint(validator1_nodeid),
                    message,
                    priority: monad_types::UdpPriority::Regular,
                })
                .unwrap();

            let mut validator1_event_rx = validator1.event_rx;
            let event = tokio::time::timeout(timeout, validator1_event_rx.recv())
                .await
                .expect("timeout waiting for message")
                .expect("channel closed");

            let MockEvent((from, msg_id)) = event;
            assert_eq!(from, validator2_nodeid);
            assert_eq!(msg_id, 43);
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wireauth_three_node_raptorcast() {
    init_tracing();

    let local = tokio::task::LocalSet::new();

    local
        .run_until(async {
            let auth_port1 = find_free_port();
            let auth_port2 = find_free_port();
            let auth_port3 = find_free_port();

            let validator1_keypair = keypair(1);
            let validator1_nodeid = NodeId::new(validator1_keypair.pubkey());
            let validator1_pubkey = validator1_keypair.pubkey();
            let validator1_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port1);

            let validator2_keypair = keypair(2);
            let validator2_nodeid = NodeId::new(validator2_keypair.pubkey());
            let validator2_pubkey = validator2_keypair.pubkey();
            let validator2_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port2);

            let validator3_keypair = keypair(3);
            let validator3_nodeid = NodeId::new(validator3_keypair.pubkey());
            let validator3_pubkey = validator3_keypair.pubkey();
            let validator3_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port3);

            let name_record1 = NameRecord::new_with_authentication(
                Ipv4Addr::new(127, 0, 0, 1),
                8000,
                validator1_auth_addr.port() + 1,
                validator1_auth_addr.port(),
                1,
            );
            let monad_name_record1 = MonadNameRecord::new(name_record1, &validator1_keypair);

            let name_record2 = NameRecord::new_with_authentication(
                Ipv4Addr::new(127, 0, 0, 1),
                8002,
                validator2_auth_addr.port() + 1,
                validator2_auth_addr.port(),
                1,
            );
            let monad_name_record2 = MonadNameRecord::new(name_record2, &validator2_keypair);

            let name_record3 = NameRecord::new_with_authentication(
                Ipv4Addr::new(127, 0, 0, 1),
                8004,
                validator3_auth_addr.port() + 1,
                validator3_auth_addr.port(),
                1,
            );
            let monad_name_record3 = MonadNameRecord::new(name_record3, &validator3_keypair);

            let mut name_records = HashMap::new();
            name_records.insert(validator1_nodeid, monad_name_record1);
            name_records.insert(validator2_nodeid, monad_name_record2);
            name_records.insert(validator3_nodeid, monad_name_record3);

            let known_addresses = HashMap::from([
                (
                    validator1_nodeid,
                    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), validator1_auth_addr.port() + 1),
                ),
                (
                    validator2_nodeid,
                    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), validator2_auth_addr.port() + 1),
                ),
                (
                    validator3_nodeid,
                    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), validator3_auth_addr.port() + 1),
                ),
            ]);

            let validator1 = spawn_wireauth_validator(
                validator1_keypair,
                validator1_auth_addr,
                known_addresses.clone(),
                name_records.clone(),
                vec![
                    (validator2_auth_addr, validator2_pubkey),
                    (validator3_auth_addr, validator3_pubkey),
                ],
            );

            let validator2 = spawn_wireauth_validator(
                validator2_keypair,
                validator2_auth_addr,
                known_addresses.clone(),
                name_records.clone(),
                vec![
                    (validator1_auth_addr, validator1_pubkey),
                    (validator3_auth_addr, validator3_pubkey),
                ],
            );

            let validator3 = spawn_wireauth_validator(
                validator3_keypair,
                validator3_auth_addr,
                known_addresses.clone(),
                name_records.clone(),
                vec![
                    (validator1_auth_addr, validator1_pubkey),
                    (validator2_auth_addr, validator2_pubkey),
                ],
            );

            let epoch = Epoch(0);
            let validator_set = vec![
                (validator1_nodeid, Stake::ONE),
                (validator2_nodeid, Stake::ONE),
                (validator3_nodeid, Stake::ONE),
            ];

            validator1
                .cmd_tx
                .send(RouterCommand::AddEpochValidatorSet {
                    epoch,
                    validator_set: validator_set.clone(),
                })
                .unwrap();

            validator2
                .cmd_tx
                .send(RouterCommand::AddEpochValidatorSet {
                    epoch,
                    validator_set: validator_set.clone(),
                })
                .unwrap();

            validator3
                .cmd_tx
                .send(RouterCommand::AddEpochValidatorSet {
                    epoch,
                    validator_set: validator_set.clone(),
                })
                .unwrap();

            let ready_timeout = Duration::from_secs(5);
            tokio::time::timeout(ready_timeout, validator1.ready_rx)
                .await
                .expect("validator1 connection timeout")
                .expect("validator1 ready channel closed");

            tokio::time::timeout(ready_timeout, validator2.ready_rx)
                .await
                .expect("validator2 connection timeout")
                .expect("validator2 ready channel closed");

            tokio::time::timeout(ready_timeout, validator3.ready_rx)
                .await
                .expect("validator3 connection timeout")
                .expect("validator3 ready channel closed");

            let message = MockMessage::new(100, 10000);
            validator1
                .cmd_tx
                .send(RouterCommand::Publish {
                    target: monad_types::RouterTarget::Raptorcast(epoch),
                    message,
                })
                .unwrap();

            let timeout = Duration::from_secs(5);
            let mut validator2_event_rx = validator2.event_rx;
            let event2 = tokio::time::timeout(timeout, validator2_event_rx.recv())
                .await
                .expect("timeout waiting for validator2")
                .expect("channel closed");

            let MockEvent((from, msg_id)) = event2;
            assert_eq!(from, validator1_nodeid);
            assert_eq!(msg_id, 100);

            let mut validator3_event_rx = validator3.event_rx;
            let event3 = tokio::time::timeout(timeout, validator3_event_rx.recv())
                .await
                .expect("timeout waiting for validator3")
                .expect("channel closed");

            let MockEvent((from, msg_id)) = event3;
            assert_eq!(from, validator1_nodeid);
            assert_eq!(msg_id, 100);
        })
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wireauth_mixed_three_node() {
    init_tracing();

    let local = tokio::task::LocalSet::new();

    local
        .run_until(async {
            let auth_port1 = find_free_port();
            let auth_port2 = find_free_port();
            let auth_port3 = find_free_port();

            let validator1_keypair = keypair(1);
            let validator1_nodeid = NodeId::new(validator1_keypair.pubkey());
            let validator1_pubkey = validator1_keypair.pubkey();
            let validator1_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port1);

            let validator2_keypair = keypair(2);
            let validator2_nodeid = NodeId::new(validator2_keypair.pubkey());
            let validator2_pubkey = validator2_keypair.pubkey();
            let validator2_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port2);

            let validator3_keypair = keypair(3);
            let validator3_nodeid = NodeId::new(validator3_keypair.pubkey());
            let validator3_auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), auth_port3);

            let name_record1 = NameRecord::new_with_authentication(
                Ipv4Addr::new(127, 0, 0, 1),
                8000,
                validator1_auth_addr.port() + 1,
                validator1_auth_addr.port(),
                1,
            );
            let monad_name_record1 = MonadNameRecord::new(name_record1, &validator1_keypair);

            let name_record2 = NameRecord::new_with_authentication(
                Ipv4Addr::new(127, 0, 0, 1),
                8002,
                validator2_auth_addr.port() + 1,
                validator2_auth_addr.port(),
                1,
            );
            let monad_name_record2 = MonadNameRecord::new(name_record2, &validator2_keypair);

            let name_record3 = NameRecord::new(
                Ipv4Addr::new(127, 0, 0, 1),
                validator3_auth_addr.port() + 1,
                1,
            );
            let monad_name_record3 = MonadNameRecord::new(name_record3, &validator3_keypair);

            let mut name_records = HashMap::new();
            name_records.insert(validator1_nodeid, monad_name_record1);
            name_records.insert(validator2_nodeid, monad_name_record2);
            name_records.insert(validator3_nodeid, monad_name_record3);

            let known_addresses = HashMap::from([
                (
                    validator1_nodeid,
                    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), validator1_auth_addr.port() + 1),
                ),
                (
                    validator2_nodeid,
                    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), validator2_auth_addr.port() + 1),
                ),
                (
                    validator3_nodeid,
                    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), validator3_auth_addr.port() + 1),
                ),
            ]);

            let validator1 = spawn_wireauth_validator(
                validator1_keypair,
                validator1_auth_addr,
                known_addresses.clone(),
                name_records.clone(),
                vec![(validator2_auth_addr, validator2_pubkey)],
            );

            let validator2 = spawn_wireauth_validator(
                validator2_keypair,
                validator2_auth_addr,
                known_addresses.clone(),
                name_records.clone(),
                vec![(validator1_auth_addr, validator1_pubkey)],
            );

            let validator3 = spawn_noop_validator(
                validator3_keypair,
                validator3_auth_addr,
                known_addresses.clone(),
                name_records.clone(),
            );

            let epoch = Epoch(0);
            let validator_set = vec![
                (validator1_nodeid, Stake::ONE),
                (validator2_nodeid, Stake::ONE),
                (validator3_nodeid, Stake::ONE),
            ];

            validator1
                .cmd_tx
                .send(RouterCommand::AddEpochValidatorSet {
                    epoch,
                    validator_set: validator_set.clone(),
                })
                .unwrap();

            validator2
                .cmd_tx
                .send(RouterCommand::AddEpochValidatorSet {
                    epoch,
                    validator_set: validator_set.clone(),
                })
                .unwrap();

            validator3
                .cmd_tx
                .send(RouterCommand::AddEpochValidatorSet {
                    epoch,
                    validator_set: validator_set.clone(),
                })
                .unwrap();

            let ready_timeout = Duration::from_secs(5);
            tokio::time::timeout(ready_timeout, validator1.ready_rx)
                .await
                .expect("validator1 connection timeout")
                .expect("validator1 ready channel closed");

            tokio::time::timeout(ready_timeout, validator2.ready_rx)
                .await
                .expect("validator2 connection timeout")
                .expect("validator2 ready channel closed");

            tokio::time::timeout(ready_timeout, validator3.ready_rx)
                .await
                .expect("validator3 connection timeout")
                .expect("validator3 ready channel closed");

            let message = MockMessage::new(200, 10000);
            validator1
                .cmd_tx
                .send(RouterCommand::Publish {
                    target: monad_types::RouterTarget::Raptorcast(epoch),
                    message,
                })
                .unwrap();

            let timeout = Duration::from_secs(5);
            let mut validator2_event_rx = validator2.event_rx;
            let event2 = tokio::time::timeout(timeout, validator2_event_rx.recv())
                .await
                .expect("timeout waiting for validator2")
                .expect("channel closed");

            let MockEvent((from, msg_id)) = event2;
            assert_eq!(from, validator1_nodeid);
            assert_eq!(msg_id, 200);

            let mut validator3_event_rx = validator3.event_rx;
            let event3 = tokio::time::timeout(timeout, validator3_event_rx.recv())
                .await
                .expect("timeout waiting for validator3")
                .expect("channel closed");

            let MockEvent((from, msg_id)) = event3;
            assert_eq!(from, validator1_nodeid);
            assert_eq!(msg_id, 200);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_wireauth_ten_node_mixed() {
    init_tracing();

    let local = tokio::task::LocalSet::new();

    local
        .run_until(async {
            let mut validators = Vec::new();
            let mut validator_infos = Vec::new();

            for i in 1..=10 {
                let keypair = keypair(i);
                let nodeid = NodeId::new(keypair.pubkey());
                let pubkey = keypair.pubkey();
                let auth_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), find_free_port());

                validator_infos.push((keypair, nodeid, pubkey, auth_addr));
            }

            let mut name_records = HashMap::new();
            let mut known_addresses = HashMap::new();

            for (keypair, nodeid, _pubkey, auth_addr) in &validator_infos {
                let name_record = if validator_infos
                    .iter()
                    .position(|(_, id, _, _)| id == nodeid)
                    .unwrap()
                    < 5
                {
                    NameRecord::new_with_authentication(
                        Ipv4Addr::new(127, 0, 0, 1),
                        8000 + (nodeid.pubkey().bytes()[0] as u16),
                        auth_addr.port() + 1,
                        auth_addr.port(),
                        1,
                    )
                } else {
                    NameRecord::new(Ipv4Addr::new(127, 0, 0, 1), auth_addr.port() + 1, 1)
                };
                let monad_name_record = MonadNameRecord::new(name_record, keypair);
                name_records.insert(*nodeid, monad_name_record);
                let non_auth_addr =
                    SocketAddrV4::new(*auth_addr.ip(), auth_addr.port() + 1);
                known_addresses.insert(*nodeid, non_auth_addr);
            }

            let validator_infos_for_peers: Vec<_> = validator_infos
                .iter()
                .map(|(_, _, pk, addr)| (*addr, *pk))
                .collect();

            for (i, (keypair, nodeid, _pubkey, auth_addr)) in validator_infos.into_iter().enumerate()
            {
                let peers_to_check: Vec<_> = if i < 5 {
                    validator_infos_for_peers
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j < 5 && *j != i)
                        .map(|(_, (addr, pk))| (*addr, *pk))
                        .collect()
                } else {
                    vec![]
                };

                let validator = if i < 5 {
                    spawn_wireauth_validator(
                        keypair,
                        auth_addr,
                        known_addresses.clone(),
                        name_records.clone(),
                        peers_to_check,
                    )
                } else {
                    spawn_noop_validator(
                        keypair,
                        auth_addr,
                        known_addresses.clone(),
                        name_records.clone(),
                    )
                };

                validators.push((nodeid, validator));
            }

            let epoch = Epoch(0);
            let validator_set: Vec<_> = validators
                .iter()
                .map(|(nodeid, _)| (*nodeid, Stake::ONE))
                .collect();

            for (_nodeid, validator) in &validators {
                validator
                    .cmd_tx
                    .send(RouterCommand::AddEpochValidatorSet {
                        epoch,
                        validator_set: validator_set.clone(),
                    })
                    .unwrap();
            }

            let ready_timeout = Duration::from_secs(5);
            for (_nodeid, validator) in validators.iter_mut() {
                tokio::time::timeout(ready_timeout, &mut validator.ready_rx)
                    .await
                    .expect("connection timeout")
                    .expect("ready channel closed");
            }

            let cmd_txs: Vec<_> = validators
                .iter()
                .map(|(_nodeid, validator)| validator.cmd_tx.clone())
                .collect();

            let mut event_rxs: Vec<_> = validators
                .into_iter()
                .map(|(nodeid, validator)| (nodeid, validator.event_rx))
                .collect();

            let timeout = Duration::from_secs(10);

            for sender_idx in 0..10 {
                let message = MockMessage::new(1000 + sender_idx as u32, 2_000_000);
                cmd_txs[sender_idx]
                    .send(RouterCommand::Publish {
                        target: monad_types::RouterTarget::Raptorcast(epoch),
                        message,
                    })
                    .unwrap();

                for receiver_idx in 0..10 {
                    let event = tokio::time::timeout(timeout, event_rxs[receiver_idx].1.recv())
                        .await
                        .expect("timeout waiting for message")
                        .expect("channel closed");

                    let MockEvent((_from, msg_id)) = event;
                    assert_eq!(
                        msg_id,
                        1000 + sender_idx as u32,
                        "receiver {} expected message {} from sender {}, got {}",
                        receiver_idx,
                        1000 + sender_idx as u32,
                        sender_idx,
                        msg_id
                    );
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
}
