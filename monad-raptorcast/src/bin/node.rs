#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::{
    collections::BTreeMap,
    env,
    net::{SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_dataplane::DataplaneBuilder;
use monad_executor::Executor;
use monad_executor_glue::{Message, RouterCommand};
use monad_node_config::{fullnode_raptorcast::FullNodeRaptorCastConfig, FullNodeConfig};
use monad_peer_discovery::{
    driver::PeerDiscoveryDriver,
    mock::{NopDiscovery, NopDiscoveryBuilder},
    MonadNameRecord, NameRecord,
};
use monad_raptorcast::{
    authentication::WireAuthProtocol,
    config::{RaptorCastConfig, RaptorCastConfigPrimary},
    raptorcast_secondary::SecondaryRaptorCastModeConfig,
    RaptorCast, RaptorCastEvent,
};
use monad_secp::{KeyPair, SecpSignature};
use monad_types::{Deserializable, Epoch, NodeId, RouterTarget, Serializable, Stake};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tracing_manytrace::{ManytraceLayer, TracingExtension};
use tracing_subscriber::{layer::SubscriberExt, Layer};

type SignatureType = SecpSignature;
type PubKeyType = CertificateSignaturePubKey<SignatureType>;

fn parse_duration(s: &str) -> Result<Duration, String> {
    // If it's just a number, treat it as seconds
    if s.chars().all(|c| c.is_ascii_digit()) {
        let value = s.parse::<u64>().map_err(|e| e.to_string())?;
        return Ok(Duration::from_secs(value));
    }

    let parts: Vec<&str> = s.split(' ').collect();
    if parts.len() != 2 {
        return Err(
            "Expected format: '<number>' for seconds or '<number> <unit>' (e.g., '5 seconds')"
                .to_string(),
        );
    }

    let value = parts[0].parse::<u64>().map_err(|e| e.to_string())?;

    let duration = match parts[1] {
        "s" | "sec" | "secs" | "second" | "seconds" => Duration::from_secs(value),
        "ms" | "millisecond" | "milliseconds" => Duration::from_millis(value),
        "us" | "microsecond" | "microseconds" => Duration::from_micros(value),
        "m" | "min" | "mins" | "minute" | "minutes" => Duration::from_secs(value * 60),
        "h" | "hour" | "hours" => Duration::from_secs(value * 3600),
        _ => return Err(format!("Unknown duration unit: {}", parts[1])),
    };

    Ok(duration)
}

fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim();

    // If it's just a number, treat it as bytes
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s.parse::<usize>().map_err(|e| e.to_string());
    }

    let (num_part, unit_part): (String, String) =
        s.chars().partition(|c| c.is_ascii_digit() || *c == '.');

    let value = num_part.parse::<f64>().map_err(|e| e.to_string())?;

    let multiplier = match unit_part.to_uppercase().as_str() {
        "" | "B" => 1.0,
        "K" | "KB" => 1024.0,
        "M" | "MB" => 1024.0 * 1024.0,
        "G" | "GB" => 1024.0 * 1024.0 * 1024.0,
        "T" | "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "KI" | "KIB" => 1024.0,
        "MI" | "MIB" => 1024.0 * 1024.0,
        "GI" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "TI" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return Err(format!("Unknown size unit: {}", unit_part)),
    };

    Ok((value * multiplier) as usize)
}

#[derive(Parser)]
#[command(name = "node")]
#[command(about = "Monad RaptorCast Node", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(long)]
        cluster: String,
        #[arg(long)]
        cluster_size: Option<usize>,
        #[arg(long, default_value = "manytrace.sock")]
        manytrace_socket: String,
    },
    Producer {
        #[arg(long)]
        cluster: String,
        #[arg(long)]
        cluster_size: Option<usize>,
        #[arg(long, value_parser = parse_duration)]
        interval: Duration,
        #[arg(long, value_parser = parse_size)]
        size: usize,
        #[arg(long, default_value = "manytrace.sock")]
        manytrace_socket: String,
    },
    Generate {
        #[arg(long)]
        output: String,
        #[arg(long)]
        count: usize,
        #[arg(long, default_value = "127.0.0.1")]
        ip: String,
        #[arg(long, default_value = "30000")]
        port: u16,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParticipantConfig {
    public_key: String,
    private_key: String,
    tcp_addr: SocketAddrV4,
    udp_addr: SocketAddrV4,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClusterConfig {
    participants: Vec<ParticipantConfig>,
}

#[derive(Debug, Clone, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
struct MockMessage {
    timestamp: u64,
    data: bytes::Bytes,
}

impl MockMessage {
    fn new_with_timestamp(message_len: usize) -> Self {
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
struct MockEvent<P: monad_crypto::certificate_signature::PubKey> {
    from: NodeId<P>,
    message: MockMessage,
}

impl<ST> From<RaptorCastEvent<MockEvent<CertificateSignaturePubKey<ST>>, ST>>
    for MockEvent<CertificateSignaturePubKey<ST>>
where
    ST: CertificateSignatureRecoverable,
{
    fn from(value: RaptorCastEvent<MockEvent<CertificateSignaturePubKey<ST>>, ST>) -> Self {
        match value {
            RaptorCastEvent::Message(event) => event,
            RaptorCastEvent::PeerManagerResponse(_) => unimplemented!(),
        }
    }
}

fn create_raptorcast_config(keypair: Arc<KeyPair>) -> RaptorCastConfig<SignatureType> {
    RaptorCastConfig {
        shared_key: keypair,
        mtu: monad_dataplane::udp::DEFAULT_MTU,
        udp_message_max_age_ms: 5000,
        primary_instance: RaptorCastConfigPrimary::default(),
        secondary_instance: FullNodeRaptorCastConfig {
            enable_publisher: false,
            enable_client: false,
            full_nodes_prioritized: FullNodeConfig { identities: vec![] },
            raptor10_fullnode_redundancy_factor: 2.0,
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

fn setup_tracing(manytrace_socket: &str) -> Option<agent::Agent> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let manytrace_socket_path = PathBuf::from(manytrace_socket);

    let extension = std::sync::Arc::new(TracingExtension::new());
    if let Ok(agent) = agent::AgentBuilder::new(manytrace_socket_path.to_string_lossy().to_string())
        .register_tracing(Box::new((*extension).clone()))
        .build()
    {
        let layer = ManytraceLayer::new(extension);
        let subscriber = tracing_subscriber::Registry::default()
            .with(layer)
            .with(tracing_subscriber::fmt::layer().with_filter(env_filter));

        tracing::subscriber::set_global_default(subscriber)
            .expect("failed to set tracing subscriber");
        tracing::info!(socket = ?manytrace_socket_path, "manytrace tracing enabled");
        Some(agent)
    } else {
        tracing_subscriber::fmt::fmt()
            .with_env_filter(env_filter)
            .init();
        tracing::info!("manytrace not available, using standard tracing");
        None
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    async_main().await
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let manytrace_socket = match &cli.command {
        Commands::Run {
            manytrace_socket, ..
        } => manytrace_socket.clone(),
        Commands::Producer {
            manytrace_socket, ..
        } => manytrace_socket.clone(),
        Commands::Generate { .. } => "manytrace.sock".to_string(),
    };

    let _agent = setup_tracing(&manytrace_socket);

    match cli.command {
        Commands::Run {
            cluster,
            cluster_size,
            manytrace_socket: _,
        } => run_node(cluster, cluster_size).await,
        Commands::Producer {
            cluster,
            cluster_size,
            interval,
            size,
            manytrace_socket: _,
        } => run_producer(cluster, cluster_size, interval, size).await,
        Commands::Generate {
            output,
            count,
            ip,
            port,
        } => generate_config(output, count, ip, port),
    }
}

const UDP_BW: u64 = 1_000;

async fn run_producer(
    cluster_path: String,
    cluster_size: Option<usize>,
    interval: Duration,
    size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let simnet_index = env::var("SIMNET_INDEX")
        .expect("SIMNET_INDEX environment variable must be set")
        .parse::<usize>()
        .expect("SIMNET_INDEX must be a valid number");

    let index = simnet_index - 1;

    tracing::info!(
        simnet_index = simnet_index,
        index = index,
        "starting producer node with SIMNET_INDEX"
    );

    let config_str = std::fs::read_to_string(cluster_path)?;
    let cluster_config: ClusterConfig = toml::from_str(&config_str)?;

    if index >= cluster_config.participants.len() {
        return Err(format!(
            "Index {} out of range for {} participants",
            index,
            cluster_config.participants.len()
        )
        .into());
    }

    let my_config = &cluster_config.participants[index];
    let private_key_bytes = hex::decode(&my_config.private_key)?;
    let mut privkey_array = [0u8; 32];
    privkey_array.copy_from_slice(&private_key_bytes);
    let keypair = KeyPair::from_bytes(&mut privkey_array)?;

    let my_node_id = NodeId::new(keypair.pubkey());

    let mut routing_info = BTreeMap::new();
    let mut epoch_validators = BTreeMap::new();

    let participants_to_use = if let Some(size) = cluster_size {
        let limited_size = size.min(cluster_config.participants.len());
        tracing::info!(
            cluster_size = size,
            total_participants = cluster_config.participants.len(),
            using_participants = limited_size,
            "limiting validator set size"
        );
        &cluster_config.participants[..limited_size]
    } else {
        &cluster_config.participants[..]
    };

    for participant in participants_to_use {
        let mut participant_privkey = [0u8; 32];
        participant_privkey.copy_from_slice(&hex::decode(&participant.private_key)?);
        let participant_keypair = KeyPair::from_bytes(&mut participant_privkey)?;
        let participant_pubkey = participant_keypair.pubkey();
        let node_id = NodeId::new(participant_pubkey);

        let name_record = NameRecord {
            address: participant.udp_addr,
            seq: 0,
        };
        let monad_name_record =
            MonadNameRecord::<SignatureType>::new(name_record, &participant_keypair);

        routing_info.insert(node_id, monad_name_record);
        epoch_validators.insert(node_id, Stake::ONE);
    }

    let my_name_record = NameRecord {
        address: my_config.udp_addr,
        seq: 0,
    };
    let _my_monad_name_record = MonadNameRecord::<SignatureType>::new(my_name_record, &keypair);

    let server_address = SocketAddr::V4(SocketAddrV4::new(
        std::net::Ipv4Addr::new(0, 0, 0, 0),
        my_config.tcp_addr.port(),
    ));

    let dataplane = DataplaneBuilder::new(&server_address, UDP_BW).build();
    assert!(dataplane.block_until_ready(Duration::from_secs(2)));

    let (dataplane_reader, dataplane_writer) = dataplane.split();

    let mut known_addresses = std::collections::HashMap::new();
    for (node_id, record) in &routing_info {
        known_addresses.insert(*node_id, record.name_record.address);
    }

    let noop_builder = NopDiscoveryBuilder {
        known_addresses,
        pd: std::marker::PhantomData,
    };

    let pd = PeerDiscoveryDriver::new(noop_builder);

    let keypair_arc = Arc::new(keypair);

    let wireauth_config = monad_wireauth_api::Config {
        session_timeout: Duration::from_secs(10),
        session_timeout_jitter: Duration::ZERO,
        keepalive_interval: Duration::from_secs(3),
        keepalive_jitter: Duration::ZERO,
        rekey_interval: Duration::from_secs(60),
        rekey_jitter: Duration::ZERO,
        ..Default::default()
    };

    let auth_protocol = WireAuthProtocol::new(wireauth_config, &keypair_arc);

    let mut raptorcast = RaptorCast::<
        SignatureType,
        MockMessage,
        MockMessage,
        <MockMessage as Message>::Event,
        NopDiscovery<SignatureType>,
        WireAuthProtocol,
    >::new(
        create_raptorcast_config(keypair_arc.clone()),
        SecondaryRaptorCastModeConfig::None,
        dataplane_reader,
        dataplane_writer,
        Arc::new(std::sync::Mutex::new(pd)),
        Epoch(0),
        auth_protocol,
    );

    raptorcast.exec(vec![RouterCommand::AddEpochValidatorSet {
        epoch: Epoch(0),
        validator_set: epoch_validators
            .iter()
            .map(|(id, stake)| (*id, *stake))
            .collect(),
    }]);

    tracing::info!(
        node_id = ?my_node_id,
        tcp_addr = ?server_address,
        udp_addr = ?my_config.udp_addr,
        interval = ?interval,
        message_size = size,
        "started producer node"
    );

    let mut interval_timer = tokio::time::interval(interval);
    interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            maybe_event = raptorcast.next() => {
                if let Some(event) = maybe_event {
                    match MockEvent::from(event) {
                        MockEvent { from, message } => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_nanos() as u64;
                            let latency_ns = now - message.timestamp;
                            let latency_ms = latency_ns as f64 / 1_000_000.0;
                            tracing::info!(
                                from = ?from,
                                latency_ms = latency_ms,
                                message_size = message.data.len(),
                                "message received"
                            );
                        }
                    }
                }
            }
            _ = interval_timer.tick() => {
                let message = MockMessage::new_with_timestamp(size);
                raptorcast.exec(vec![RouterCommand::Publish {
                    target: RouterTarget::Raptorcast(Epoch(0)),
                    message,
                }]);
                tracing::info!(
                    message_size = size,
                    "sent broadcast message"
                );
            }
        }
    }
}

async fn run_node(
    cluster_path: String,
    cluster_size: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let simnet_index = env::var("SIMNET_INDEX")
        .expect("SIMNET_INDEX environment variable must be set")
        .parse::<usize>()
        .expect("SIMNET_INDEX must be a valid number");

    let index = simnet_index - 1;

    tracing::info!(
        simnet_index = simnet_index,
        index = index,
        "starting regular node with SIMNET_INDEX"
    );

    let config_str = std::fs::read_to_string(cluster_path)?;
    let cluster_config: ClusterConfig = toml::from_str(&config_str)?;

    if index >= cluster_config.participants.len() {
        return Err(format!(
            "Index {} out of range for {} participants",
            index,
            cluster_config.participants.len()
        )
        .into());
    }

    let my_config = &cluster_config.participants[index];
    let private_key_bytes = hex::decode(&my_config.private_key)?;
    let mut privkey_array = [0u8; 32];
    privkey_array.copy_from_slice(&private_key_bytes);
    let keypair = KeyPair::from_bytes(&mut privkey_array)?;

    let my_node_id = NodeId::new(keypair.pubkey());

    let mut routing_info = BTreeMap::new();
    let mut epoch_validators = BTreeMap::new();

    let participants_to_use = if let Some(size) = cluster_size {
        let limited_size = size.min(cluster_config.participants.len());
        tracing::info!(
            cluster_size = size,
            total_participants = cluster_config.participants.len(),
            using_participants = limited_size,
            "limiting validator set size"
        );
        &cluster_config.participants[..limited_size]
    } else {
        &cluster_config.participants[..]
    };

    for participant in participants_to_use {
        let mut participant_privkey = [0u8; 32];
        participant_privkey.copy_from_slice(&hex::decode(&participant.private_key)?);
        let participant_keypair = KeyPair::from_bytes(&mut participant_privkey)?;
        let participant_pubkey = participant_keypair.pubkey();
        let node_id = NodeId::new(participant_pubkey);

        let name_record = NameRecord {
            address: participant.udp_addr,
            seq: 0,
        };
        let monad_name_record =
            MonadNameRecord::<SignatureType>::new(name_record, &participant_keypair);

        routing_info.insert(node_id, monad_name_record);
        epoch_validators.insert(node_id, Stake::ONE);
    }

    let my_name_record = NameRecord {
        address: my_config.udp_addr,
        seq: 0,
    };
    let _my_monad_name_record = MonadNameRecord::<SignatureType>::new(my_name_record, &keypair);

    let server_address = SocketAddr::V4(SocketAddrV4::new(
        std::net::Ipv4Addr::new(0, 0, 0, 0),
        my_config.tcp_addr.port(),
    ));

    let dataplane = DataplaneBuilder::new(&server_address, UDP_BW).build();
    assert!(dataplane.block_until_ready(Duration::from_secs(2)));

    let (dataplane_reader, dataplane_writer) = dataplane.split();

    let mut known_addresses = std::collections::HashMap::new();
    for (node_id, record) in &routing_info {
        known_addresses.insert(*node_id, record.name_record.address);
    }

    let noop_builder = NopDiscoveryBuilder {
        known_addresses,
        pd: std::marker::PhantomData,
    };

    let pd = PeerDiscoveryDriver::new(noop_builder);

    let keypair_arc = Arc::new(keypair);

    let wireauth_config = monad_wireauth_api::Config {
        session_timeout: Duration::from_secs(10),
        session_timeout_jitter: Duration::ZERO,
        keepalive_interval: Duration::from_secs(3),
        keepalive_jitter: Duration::ZERO,
        rekey_interval: Duration::from_secs(60),
        rekey_jitter: Duration::ZERO,
        ..Default::default()
    };

    let auth_protocol = WireAuthProtocol::new(wireauth_config, &keypair_arc);

    let mut raptorcast = RaptorCast::<
        SignatureType,
        MockMessage,
        MockMessage,
        <MockMessage as Message>::Event,
        NopDiscovery<SignatureType>,
        WireAuthProtocol,
    >::new(
        create_raptorcast_config(keypair_arc.clone()),
        SecondaryRaptorCastModeConfig::None,
        dataplane_reader,
        dataplane_writer,
        Arc::new(std::sync::Mutex::new(pd)),
        Epoch(0),
        auth_protocol,
    );

    raptorcast.exec(vec![RouterCommand::AddEpochValidatorSet {
        epoch: Epoch(0),
        validator_set: epoch_validators
            .iter()
            .map(|(id, stake)| (*id, *stake))
            .collect(),
    }]);

    tracing::info!(
        node_id = ?my_node_id,
        tcp_addr = ?server_address,
        udp_addr = ?my_config.udp_addr,
        "Started node with raptorcast and discovery"
    );

    loop {
        tokio::select! {
            maybe_event = raptorcast.next() => {
                if let Some(event) = maybe_event {
                    match MockEvent::from(event) {
                        MockEvent { from, message } => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_nanos() as u64;
                            let latency_ns = now - message.timestamp;
                            let latency_ms = latency_ns as f64 / 1_000_000.0;
                            tracing::info!(
                                from = ?from,
                                latency_ms = latency_ms,
                                message_size = message.data.len(),
                                "message received"
                            );
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                tracing::trace!("Heartbeat");
            }
        }
    }
}

fn generate_config(
    output_path: String,
    count: usize,
    base_ip: String,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut participants = Vec::new();

    let base_ip_addr: std::net::Ipv4Addr = base_ip
        .parse()
        .map_err(|_| format!("Invalid IP address: {}", base_ip))?;
    let base_ip_u32 = u32::from(base_ip_addr);

    for i in 0..count {
        let mut privkey = [0u8; 32];
        let idx_bytes = (i as u32).to_le_bytes();
        privkey[0] = idx_bytes[0];
        privkey[1] = idx_bytes[1];
        privkey[2] = idx_bytes[2];
        privkey[3] = idx_bytes[3];
        privkey[31] = 1;

        let keypair = KeyPair::from_bytes(&mut privkey.clone()).unwrap();
        let pubkey = keypair.pubkey();
        let pubkey_bytes = pubkey.bytes();

        let node_ip = std::net::Ipv4Addr::from(base_ip_u32 + i as u32);

        let participant = ParticipantConfig {
            public_key: hex::encode(pubkey_bytes),
            private_key: hex::encode(privkey),
            tcp_addr: SocketAddrV4::new(node_ip, port),
            udp_addr: SocketAddrV4::new(node_ip, port),
        };
        participants.push(participant);
    }

    let cluster_config = ClusterConfig { participants };
    let toml_str = toml::to_string_pretty(&cluster_config)?;
    std::fs::write(&output_path, toml_str)?;

    println!(
        "Generated cluster configuration with {} nodes at {}",
        count, output_path
    );
    println!(
        "IP range: {} - {}",
        base_ip_addr,
        std::net::Ipv4Addr::from(base_ip_u32 + count as u32 - 1)
    );
    println!("Port: {}", port);
    Ok(())
}
