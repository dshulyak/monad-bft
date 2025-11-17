use std::{
    collections::{BTreeMap, HashMap},
    net::{SocketAddr, UdpSocket},
    os::unix::io::AsRawFd,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use byte_unit::Byte;
use bytes::{Bytes, BytesMut};
use clap::Parser;
use monad_raptorcast::packet::build_messages;
use monad_raptorcast::util::{BuildTarget, EpochValidators, NodesView, Redundancy};
use monad_secp::{KeyPair, PubKey, SecpSignature};
use monad_types::{NodeId, Stake};
use secp256k1::rand::{rngs::StdRng, SeedableRng};
use tracing::info;

const UDP_SEGMENT: i32 = 103;
const SOL_UDP: i32 = 17;

extern "C" {
    fn setsockopt(
        socket: i32,
        level: i32,
        name: i32,
        value: *const std::ffi::c_void,
        option_len: u32,
    ) -> i32;
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| e.to_string())
}

fn parse_size(s: &str) -> Result<usize, String> {
    let byte = Byte::parse_str(s, true).map_err(|e| e.to_string())?;
    Ok(byte.as_u64() as usize)
}

#[derive(Parser)]
#[command(name = "raptorspam")]
#[command(about = "spam raptorcast messages with different secp256k1 identities")]
#[command(after_help = "Examples:
  raptorspam 127.0.0.1:9000 0445bad356c9ab26d80fa5c7b69f3d615eec352067751687a0af3491b9b7f44c0cfa91fb4e738378f1558025ff8f32e38cd910c43573836dc39b0e4a129a8d1476 --rate 256MB --message-size 4000
  raptorspam 10.0.0.1:8080 02f3d2b8c9a7e4f1d6a5b3c8e7f2a9d4c6b1e8f5a2d7c3b9e4f1a6d8c2b5e9f3a7 --rate 1GB --interval 2s")]
struct Args {
    #[arg(help = "peer address to send messages to")]
    peer: SocketAddr,

    #[arg(help = "peer public key (hex-encoded secp256k1 public key)")]
    peer_public_key: String,

    #[arg(
        long,
        default_value = "128MB",
        value_parser = parse_size,
        help = "target bandwidth (e.g., 1000MB, 100KB)"
    )]
    rate: usize,

    #[arg(
        long,
        default_value = "1s",
        value_parser = parse_duration,
        help = "measurement interval (e.g., 1s, 100ms)"
    )]
    interval: Duration,

    #[arg(
        long,
        default_value = "2048",
        help = "size of the message payload in bytes"
    )]
    message_size: usize,

    #[arg(
        long,
        default_value = "1200",
        help = "segment size for RaptorCast packets (minimum ~1200 bytes due to protocol overhead)"
    )]
    segment_size: u16,
}

fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    run_raptorcast_spam(
        args.peer,
        &args.peer_public_key,
        args.rate,
        args.interval,
        args.message_size,
        args.segment_size,
    )
}

#[derive(Clone, RlpEncodable, RlpDecodable)]
struct SpamMessage {
    id: u32,
    payload: Vec<u8>,
}

impl SpamMessage {
    fn new(id: u32, size: usize) -> Self {
        let mut payload = vec![0u8; size.saturating_sub(4)];
        let id_bytes = id.to_le_bytes();
        if payload.len() >= 4 {
            payload[0] = id_bytes[0];
            payload[1] = id_bytes[1];
            payload[2] = id_bytes[2];
            payload[3] = id_bytes[3];
        }
        Self { id, payload }
    }

    fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        buf.freeze()
    }
}

fn unix_ts_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_millis() as u64
}

fn run_raptorcast_spam(
    peer: SocketAddr,
    peer_public_key_hex: &str,
    rate: usize,
    interval: Duration,
    message_size: usize,
    segment_size: u16,
) -> std::io::Result<()> {
    let peer_public_key_bytes = hex::decode(peer_public_key_hex).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid peer public key hex: {}", e),
        )
    })?;

    let peer_public_key = PubKey::from_slice(&peer_public_key_bytes).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid peer public key: {}", e),
        )
    })?;

    let peer_node_id = NodeId::new(peer_public_key);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    let port = socket.local_addr()?.port();

    let mut base_rng = StdRng::seed_from_u64(port as u64);

    let keypair = KeyPair::generate(&mut base_rng);
    let known_addresses: HashMap<NodeId<_>, SocketAddr> = [(peer_node_id, peer)]
        .into_iter()
        .collect();

    let mut validators_map = BTreeMap::new();
    validators_map.insert(peer_node_id, Stake::ONE);
    let epoch_validators = EpochValidators::<SecpSignature> {
        validators: validators_map,
    };

    let validators_view = epoch_validators.view_without(vec![]);
    let build_target = BuildTarget::Broadcast(NodesView::Validators(validators_view));

    let message = SpamMessage::new(0, message_size);
    let app_message = message.serialize();

    let packets = build_messages::<SecpSignature>(
        &keypair,
        segment_size,
        app_message.clone(),
        Redundancy::from_u8(1),
        0,
        unix_ts_ms_now(),
        build_target,
        &known_addresses,
    );

    if packets.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "failed to build raptorcast packets",
        ));
    }

    let packet_size = packets[0].1.len();

    info!(
        peer = %peer,
        rate = rate,
        interval = ?interval,
        packet_size = packet_size,
        message_size = message_size,
        num_packets_per_message = packets.len(),
        "starting raptorcast spam with different identities"
    );

    let packets_per_interval = (rate as f64 / packet_size as f64).ceil() as u64;
    let packet_interval_nanos = interval.as_nanos() as u64 / packets_per_interval.max(1);
    let packet_interval = Duration::from_nanos(packet_interval_nanos);

    let gso_size = packet_size as u16;
    let burst_size = if packet_interval < Duration::from_micros(100) {
        ((Duration::from_micros(100).as_nanos() as u64 / packet_interval_nanos.max(1)) as usize)
            .clamp(1, 64)
    } else {
        1
    };

    unsafe {
        let optval = gso_size as i32;
        let ret = setsockopt(
            socket.as_raw_fd(),
            SOL_UDP,
            UDP_SEGMENT,
            &optval as *const _ as *const std::ffi::c_void,
            std::mem::size_of_val(&optval) as u32,
        );
        if ret != 0 {
            info!("gso not supported, falling back to regular sends");
        }
    }

    let mut packet_cache: Vec<Bytes> = Vec::new();
    for i in 0..burst_size {
        let keypair = KeyPair::generate(&mut base_rng);
        let mut validators_map = BTreeMap::new();
        validators_map.insert(peer_node_id, Stake::ONE);
        let epoch_validators = EpochValidators::<SecpSignature> {
            validators: validators_map,
        };
        let validators_view = epoch_validators.view_without(vec![]);
        let build_target = BuildTarget::Broadcast(NodesView::Validators(validators_view));

        let message = SpamMessage::new(i as u32, message_size);
        let app_message = message.serialize();

        let packets = build_messages::<SecpSignature>(
            &keypair,
            segment_size,
            app_message,
            Redundancy::from_u8(1),
            0,
            unix_ts_ms_now(),
            build_target,
            &known_addresses,
        );

        if !packets.is_empty() {
            packet_cache.push(packets[0].1.clone());
        }
    }

    let mut gso_buffer = vec![0u8; packet_size * burst_size];
    for (i, chunk) in gso_buffer.chunks_mut(packet_size).enumerate() {
        if let Some(pkt) = packet_cache.get(i) {
            chunk.copy_from_slice(pkt);
        }
    }

    info!(
        packets_per_interval = packets_per_interval,
        packet_interval = ?packet_interval,
        packet_size = packet_size,
        burst_size = burst_size,
        gso_enabled = true,
        "calculated packet rate"
    );

    let mut packets_sent = 0u64;
    let mut message_id = burst_size as u32;
    let mut next_packet = Instant::now();
    let mut next_stats = Instant::now() + interval;
    let should_sleep = packet_interval >= Duration::from_millis(1);

    loop {
        let now = Instant::now();

        while now >= next_packet {
            match socket.send_to(&gso_buffer, peer) {
                Ok(_) => {
                    packets_sent += burst_size as u64;

                    for (i, chunk) in gso_buffer.chunks_mut(packet_size).enumerate() {
                        let keypair = KeyPair::generate(&mut base_rng);
                        let mut validators_map = BTreeMap::new();
                        validators_map.insert(peer_node_id, Stake::ONE);
                        let epoch_validators = EpochValidators::<SecpSignature> {
                            validators: validators_map,
                        };
                        let validators_view = epoch_validators.view_without(vec![]);
                        let build_target = BuildTarget::Broadcast(NodesView::Validators(validators_view));

                        let message = SpamMessage::new(message_id + i as u32, message_size);
                        let app_message = message.serialize();

                        let packets = build_messages::<SecpSignature>(
                            &keypair,
                            segment_size,
                            app_message,
                            Redundancy::from_u8(1),
                            0,
                            unix_ts_ms_now(),
                            build_target,
                            &known_addresses,
                        );

                        if !packets.is_empty() {
                            chunk.copy_from_slice(&packets[0].1);
                        }
                    }
                    message_id = message_id.wrapping_add(burst_size as u32);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }

            next_packet += packet_interval * burst_size as u32;

            if next_packet <= now {
                next_packet = now;
            }
        }

        if now >= next_stats {
            let rate_mbps =
                (packets_sent * packet_size as u64) as f64 / interval.as_secs_f64() / 1_000_000.0;
            info!(
                packets_sent = packets_sent,
                rate_mbps = format!("{:.2}", rate_mbps),
                "stats"
            );
            packets_sent = 0;
            next_stats = now + interval;
        }

        if should_sleep {
            let sleep_time = next_packet
                .saturating_duration_since(now)
                .min(Duration::from_millis(1));
            std::thread::sleep(sleep_time);
        }
    }
}
