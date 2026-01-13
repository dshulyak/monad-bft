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

//! DoS testing tool for statesync/blocksync/raptorcast endpoints.
//!
//! This tool sends concurrent requests signed by different identities
//! at configurable rates to stress test the TCP/UDP egress queue handling.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use alloy_rlp::{Encodable, encode_list};
use bytes::{Bytes, BytesMut};
use clap::{Parser, ValueEnum};
use eyre::Result;
use monad_blocksync::messages::message::BlockSyncRequestMessage;
use monad_consensus_types::{block::BlockRange, payload::ConsensusBlockBodyId};
use monad_crypto::{certificate_signature::CertificateSignature, hasher::Hash, signing_domain};
use monad_executor_glue::{
    StateSyncNetworkMessage, StateSyncRequest, SELF_STATESYNC_VERSION,
};
use monad_secp::{KeyPair, SecpSignature};
use monad_types::{MonadVersion, SeqNum, GENESIS_BLOCK_ID};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};
use zerocopy::{little_endian::U32 as U32LE, little_endian::U64 as U64LE, Immutable, IntoBytes};

const SIGNATURE_SIZE: usize = 65;
const HEADER_MAGIC: u32 = 0x434e5353; // "SSNC"
const HEADER_VERSION: u32 = 1;

const SERIALIZE_VERSION: u32 = 1;
const COMPRESSION_VERSION_UNCOMPRESSED: u8 = 1;
const MESSAGE_TYPE_APP: u8 = 1;

#[derive(alloy_rlp::RlpEncodable)]
struct NetworkMessageVersion {
    serialize_version: u32,
    compression_version: u8,
}

impl NetworkMessageVersion {
    fn uncompressed() -> Self {
        Self {
            serialize_version: SERIALIZE_VERSION,
            compression_version: COMPRESSION_VERSION_UNCOMPRESSED,
        }
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| e.to_string())
}

#[derive(Parser, Clone)]
#[command(name = "dos", about = "DoS testing tool for statesync/blocksync")]
struct Args {
    /// Target address (ip:port)
    #[arg(short, long)]
    target: SocketAddr,

    /// Protocol to test
    #[arg(short, long, value_enum)]
    protocol: Protocol,

    /// Requests per second per identity (0 = unlimited)
    #[arg(short, long, default_value = "100")]
    rate: u64,

    /// Number of concurrent identities/connections
    #[arg(short, long, default_value = "10")]
    identities: usize,

    /// Test duration
    #[arg(short, long, value_parser = parse_duration, default_value = "60s")]
    duration: Duration,

    /// Don't read responses (causes TCP backpressure)
    #[arg(long, default_value = "false")]
    no_read: bool,

    /// Don't send ACKs for statesync (statesync only)
    #[arg(long, default_value = "false")]
    no_ack: bool,

    /// Request bodies instead of headers (blocksync only)
    #[arg(long, default_value = "false")]
    bodies: bool,

    /// Starting block sequence number (blocksync only)
    #[arg(long, default_value = "1")]
    start_block: u64,

    /// Number of blocks to request per message (blocksync headers only)
    #[arg(long, default_value = "10")]
    num_blocks: u64,

    /// Query mode: send requests sequentially and measure response sizes
    #[arg(long, default_value = "false")]
    query: bool,

    /// Ending block sequence number for range scan (blocksync query mode)
    #[arg(long)]
    end_block: Option<u64>,
}

#[derive(Clone, Copy, ValueEnum, Debug)]
enum Protocol {
    Statesync,
    Blocksync,
}

#[derive(Default)]
struct Stats {
    requests_sent: AtomicU64,
    responses_received: AtomicU64,
    errors: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    max_response_size: AtomicU64,
    max_response_block: AtomicU64,
    connections: AtomicU64,
}

#[repr(C)]
#[derive(IntoBytes, Immutable)]
struct TcpMsgHdr {
    magic: U32LE,
    version: U32LE,
    length: U64LE,
}

impl TcpMsgHdr {
    fn new(length: u64) -> Self {
        Self {
            magic: U32LE::new(HEADER_MAGIC),
            version: U32LE::new(HEADER_VERSION),
            length: U64LE::new(length),
        }
    }
}

fn generate_keypair(seed: u8) -> KeyPair {
    // Seed must be non-zero for valid SECP256K1 key
    let mut key_bytes = [seed.wrapping_add(1); 32];
    // Add some variation to make keys more unique
    key_bytes[0] = seed.wrapping_add(1);
    key_bytes[1] = seed.wrapping_add(2);
    key_bytes[31] = seed.wrapping_add(3);
    KeyPair::from_bytes(&mut key_bytes).expect("valid keypair")
}

fn build_statesync_request() -> StateSyncNetworkMessage {
    StateSyncNetworkMessage::Request(StateSyncRequest {
        version: SELF_STATESYNC_VERSION,
        prefix: 0,
        prefix_bytes: 0,
        target: 1000,
        from: 0,
        until: u64::MAX,
        old_target: 0,
    })
}

fn build_blocksync_request(args: &Args, request_index: u64) -> BlockSyncRequestMessage {
    if args.bodies {
        let mut hash_bytes = [0u8; 32];
        let block_num = args.start_block + request_index;
        hash_bytes[24..32].copy_from_slice(&block_num.to_le_bytes());
        BlockSyncRequestMessage::Payload(ConsensusBlockBodyId(Hash(hash_bytes)))
    } else {
        BlockSyncRequestMessage::Headers(BlockRange {
            last_block_id: GENESIS_BLOCK_ID,
            num_blocks: SeqNum(args.num_blocks),
        })
    }
}

struct WrappedStateSyncMessage<'a> {
    monad_version: &'a MonadVersion,
    msg: &'a StateSyncNetworkMessage,
}

impl Encodable for WrappedStateSyncMessage<'_> {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let enc: [&dyn Encodable; 3] = [self.monad_version, &5u8, self.msg];
        encode_list::<_, dyn Encodable>(&enc, out);
    }

    fn length(&self) -> usize {
        self.monad_version.length() + 1 + self.msg.length() + alloy_rlp::length_of_length(
            self.monad_version.length() + 1 + self.msg.length()
        )
    }
}

struct WrappedBlockSyncMessage<'a> {
    monad_version: &'a MonadVersion,
    msg: &'a BlockSyncRequestMessage,
}

impl Encodable for WrappedBlockSyncMessage<'_> {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let enc: [&dyn Encodable; 3] = [self.monad_version, &2u8, self.msg];
        encode_list::<_, dyn Encodable>(&enc, out);
    }

    fn length(&self) -> usize {
        self.monad_version.length() + 1 + self.msg.length() + alloy_rlp::length_of_length(
            self.monad_version.length() + 1 + self.msg.length()
        )
    }
}

fn sign_and_frame(
    keypair: &KeyPair,
    args: &Args,
    request_index: u64,
) -> Bytes {
    let monad_version = MonadVersion::version();
    let network_version = NetworkMessageVersion::uncompressed();

    // Build the full OutboundRouterMessage in one pass to preserve RLP list structure
    let mut outer_buf = BytesMut::new();
    match args.protocol {
        Protocol::Statesync => {
            let msg = build_statesync_request();
            let wrapped = WrappedStateSyncMessage {
                monad_version: &monad_version,
                msg: &msg,
            };
            let enc: [&dyn Encodable; 3] = [&network_version, &MESSAGE_TYPE_APP, &wrapped];
            encode_list::<_, dyn Encodable>(&enc, &mut outer_buf);
        }
        Protocol::Blocksync => {
            let msg = build_blocksync_request(args, request_index);
            let wrapped = WrappedBlockSyncMessage {
                monad_version: &monad_version,
                msg: &msg,
            };
            let enc: [&dyn Encodable; 3] = [&network_version, &MESSAGE_TYPE_APP, &wrapped];
            encode_list::<_, dyn Encodable>(&enc, &mut outer_buf);
        }
    };

    // Sign the outer RLP-encoded message
    let signature = SecpSignature::sign::<signing_domain::RaptorcastAppMessage>(
        &outer_buf,
        keypair,
    );
    let sig_bytes = <SecpSignature as CertificateSignature>::serialize(&signature);
    assert_eq!(sig_bytes.len(), SIGNATURE_SIZE);

    // Build signed message: [signature | outer_rlp]
    let mut signed = BytesMut::with_capacity(SIGNATURE_SIZE + outer_buf.len());
    signed.extend_from_slice(&sig_bytes);
    signed.extend_from_slice(&outer_buf);

    // Add TCP header
    let header = TcpMsgHdr::new(signed.len() as u64);
    let mut framed = BytesMut::with_capacity(16 + signed.len());
    framed.extend_from_slice(header.as_bytes());
    framed.extend_from_slice(&signed);

    framed.freeze()
}

async fn reader_task(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    stats: Arc<Stats>,
    _no_ack: bool,
) {
    let mut header_buf = [0u8; 16];
    loop {
        // Read TCP header
        if reader.read_exact(&mut header_buf).await.is_err() {
            break;
        }

        // Parse length from header (bytes 8-16, little endian u64)
        let length = u64::from_le_bytes(header_buf[8..16].try_into().unwrap());

        // Read message body
        let mut body = vec![0u8; length as usize];
        if reader.read_exact(&mut body).await.is_err() {
            break;
        }

        let total_size = 16 + length;
        stats.responses_received.fetch_add(1, Ordering::Relaxed);
        stats.bytes_received.fetch_add(total_size, Ordering::Relaxed);

        // Update max response size
        loop {
            let current_max = stats.max_response_size.load(Ordering::Relaxed);
            if total_size <= current_max {
                break;
            }
            if stats
                .max_response_size
                .compare_exchange(current_max, total_size, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        // TODO: If !no_ack and statesync, parse response and send Completion
        // For now, we just read and discard
    }
}

async fn worker(
    id: usize,
    target: SocketAddr,
    keypair: KeyPair,
    args: Args,
    stats: Arc<Stats>,
) {
    let rate_delay = if args.rate > 0 {
        Some(Duration::from_secs_f64(1.0 / args.rate as f64))
    } else {
        None
    };

    loop {
        // Connect
        let stream = match TcpStream::connect(target).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[{}] Connection error: {}", id, e);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        stats.connections.fetch_add(1, Ordering::Relaxed);
        let (reader, mut writer) = stream.into_split();

        // Spawn reader task if needed
        let stats_clone = stats.clone();
        let reader_handle = if !args.no_read {
            Some(tokio::spawn(reader_task(reader, stats_clone, args.no_ack)))
        } else {
            drop(reader);
            None
        };

        // Send loop
        let mut request_index = 0u64;
        loop {
            let msg = sign_and_frame(&keypair, &args, request_index);
            let msg_len = msg.len() as u64;

            if let Err(e) = writer.write_all(&msg).await {
                eprintln!("[{}] Write error: {}", id, e);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                break;
            }

            stats.requests_sent.fetch_add(1, Ordering::Relaxed);
            stats.bytes_sent.fetch_add(msg_len, Ordering::Relaxed);
            request_index += 1;

            // Rate limiting
            if let Some(delay) = rate_delay {
                sleep(delay).await;
            }
        }

        // Cleanup
        if let Some(handle) = reader_handle {
            handle.abort();
        }
        stats.connections.fetch_sub(1, Ordering::Relaxed);

        // Brief pause before reconnecting
        sleep(Duration::from_millis(100)).await;
    }
}

async fn query_worker(
    id: usize,
    target: SocketAddr,
    keypair: KeyPair,
    args: Args,
    stats: Arc<Stats>,
) {
    let start_block = args.start_block;
    let end_block = args.end_block.unwrap_or(start_block + 100);

    for block_num in start_block..=end_block {
        // Connect
        let stream = match TcpStream::connect(target).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[{}] Connection error: {}", id, e);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        stats.connections.fetch_add(1, Ordering::Relaxed);
        let (mut reader, mut writer) = stream.into_split();

        // Build request for this specific block
        let msg = sign_and_frame_block(&keypair, &args, block_num);
        let msg_len = msg.len() as u64;

        if let Err(e) = writer.write_all(&msg).await {
            eprintln!("[{}] Write error for block {}: {}", id, block_num, e);
            stats.errors.fetch_add(1, Ordering::Relaxed);
            stats.connections.fetch_sub(1, Ordering::Relaxed);
            continue;
        }

        stats.requests_sent.fetch_add(1, Ordering::Relaxed);
        stats.bytes_sent.fetch_add(msg_len, Ordering::Relaxed);

        // Read response
        let mut header_buf = [0u8; 16];
        match tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut header_buf)).await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                eprintln!("[{}] Read header error for block {}: {}", id, block_num, e);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                stats.connections.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            Err(_) => {
                eprintln!("[{}] Timeout waiting for response for block {}", id, block_num);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                stats.connections.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
        }

        let length = u64::from_le_bytes(header_buf[8..16].try_into().unwrap());
        let mut body = vec![0u8; length as usize];

        match tokio::time::timeout(Duration::from_secs(30), reader.read_exact(&mut body)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                eprintln!("[{}] Read body error for block {}: {}", id, block_num, e);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                stats.connections.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            Err(_) => {
                eprintln!("[{}] Timeout reading body for block {}", id, block_num);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                stats.connections.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
        }

        let total_size = 16 + length;
        stats.responses_received.fetch_add(1, Ordering::Relaxed);
        stats.bytes_received.fetch_add(total_size, Ordering::Relaxed);

        // Update max response size and block
        loop {
            let current_max = stats.max_response_size.load(Ordering::Relaxed);
            if total_size <= current_max {
                break;
            }
            if stats
                .max_response_size
                .compare_exchange(current_max, total_size, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                stats.max_response_block.store(block_num, Ordering::Relaxed);
                break;
            }
        }

        println!(
            "[{}] Block {} response size: {} bytes",
            id, block_num, total_size
        );

        stats.connections.fetch_sub(1, Ordering::Relaxed);
    }

    println!("[{}] Query complete", id);
}

fn sign_and_frame_block(keypair: &KeyPair, args: &Args, block_num: u64) -> Bytes {
    let monad_version = MonadVersion::version();
    let network_version = NetworkMessageVersion::uncompressed();

    let mut outer_buf = BytesMut::new();
    match args.protocol {
        Protocol::Statesync => {
            let msg = build_statesync_request();
            let wrapped = WrappedStateSyncMessage {
                monad_version: &monad_version,
                msg: &msg,
            };
            let enc: [&dyn Encodable; 3] = [&network_version, &MESSAGE_TYPE_APP, &wrapped];
            encode_list::<_, dyn Encodable>(&enc, &mut outer_buf);
        }
        Protocol::Blocksync => {
            let msg = if args.bodies {
                let mut hash_bytes = [0u8; 32];
                hash_bytes[24..32].copy_from_slice(&block_num.to_le_bytes());
                BlockSyncRequestMessage::Payload(ConsensusBlockBodyId(Hash(hash_bytes)))
            } else {
                BlockSyncRequestMessage::Headers(BlockRange {
                    last_block_id: GENESIS_BLOCK_ID,
                    num_blocks: SeqNum(block_num),
                })
            };
            let wrapped = WrappedBlockSyncMessage {
                monad_version: &monad_version,
                msg: &msg,
            };
            let enc: [&dyn Encodable; 3] = [&network_version, &MESSAGE_TYPE_APP, &wrapped];
            encode_list::<_, dyn Encodable>(&enc, &mut outer_buf);
        }
    };

    let signature =
        SecpSignature::sign::<signing_domain::RaptorcastAppMessage>(&outer_buf, keypair);
    let sig_bytes = <SecpSignature as CertificateSignature>::serialize(&signature);

    let mut signed = BytesMut::with_capacity(SIGNATURE_SIZE + outer_buf.len());
    signed.extend_from_slice(&sig_bytes);
    signed.extend_from_slice(&outer_buf);

    let header = TcpMsgHdr::new(signed.len() as u64);
    let mut framed = BytesMut::with_capacity(16 + signed.len());
    framed.extend_from_slice(header.as_bytes());
    framed.extend_from_slice(&signed);

    framed.freeze()
}

async fn stats_reporter(stats: Arc<Stats>, interval: Duration) {
    let mut last_sent = 0u64;
    let mut last_recv = 0u64;
    let mut last_bytes_sent = 0u64;
    let mut last_bytes_recv = 0u64;
    let start = Instant::now();

    loop {
        sleep(interval).await;

        let sent = stats.requests_sent.load(Ordering::Relaxed);
        let received = stats.responses_received.load(Ordering::Relaxed);
        let errors = stats.errors.load(Ordering::Relaxed);
        let bytes_sent = stats.bytes_sent.load(Ordering::Relaxed);
        let bytes_recv = stats.bytes_received.load(Ordering::Relaxed);
        let max_resp = stats.max_response_size.load(Ordering::Relaxed);
        let conns = stats.connections.load(Ordering::Relaxed);

        let sent_delta = sent - last_sent;
        let recv_delta = received - last_recv;
        let bytes_sent_delta = bytes_sent - last_bytes_sent;
        let bytes_recv_delta = bytes_recv - last_bytes_recv;
        let elapsed = start.elapsed().as_secs_f64();
        let send_rate = sent_delta as f64 / interval.as_secs_f64();
        let recv_rate = recv_delta as f64 / interval.as_secs_f64();
        let send_throughput = bytes_sent_delta as f64 / interval.as_secs_f64() / 1024.0 / 1024.0;
        let recv_throughput = bytes_recv_delta as f64 / interval.as_secs_f64() / 1024.0 / 1024.0;

        println!(
            "[{:.1}s] sent={} ({:.0}/s, {:.2} MB/s) recv={} ({:.0}/s, {:.2} MB/s) max_resp={} err={} conns={}",
            elapsed, sent, send_rate, send_throughput, received, recv_rate, recv_throughput, max_resp, errors, conns
        );

        last_sent = sent;
        last_recv = received;
        last_bytes_sent = bytes_sent;
        last_bytes_recv = bytes_recv;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("DoS testing tool");
    println!("  Target: {}", args.target);
    println!("  Protocol: {:?}", args.protocol);
    println!("  Rate: {} req/s per identity", args.rate);
    println!("  Identities: {}", args.identities);
    println!("  Duration: {:?}", args.duration);
    println!("  No-read: {}", args.no_read);
    println!("  No-ack: {}", args.no_ack);
    if matches!(args.protocol, Protocol::Blocksync) {
        println!("  Bodies: {}", args.bodies);
        println!("  Start block: {}", args.start_block);
        if !args.bodies {
            println!("  Num blocks: {}", args.num_blocks);
        }
    }
    println!("  Query mode: {}", args.query);
    if args.query {
        println!(
            "  Block range: {} - {}",
            args.start_block,
            args.end_block.unwrap_or(args.start_block + 100)
        );
    }
    println!();

    let stats = Arc::new(Stats::default());

    if args.query {
        // Query mode: single worker, sequential requests
        let mut handles = Vec::new();
        for i in 0..args.identities {
            let keypair = generate_keypair(i as u8);
            let stats_clone = stats.clone();
            let args_clone = args.clone();

            handles.push(tokio::spawn(async move {
                query_worker(i, args_clone.target, keypair, args_clone, stats_clone).await;
            }));
        }

        // Wait for all query workers to complete
        for handle in handles {
            let _ = handle.await;
        }
    } else {
        // DoS mode: continuous requests
        let mut handles = Vec::new();
        for i in 0..args.identities {
            let keypair = generate_keypair(i as u8);
            let stats_clone = stats.clone();
            let args_clone = args.clone();

            handles.push(tokio::spawn(async move {
                worker(i, args_clone.target, keypair, args_clone, stats_clone).await;
            }));
        }

        // Spawn stats reporter
        let stats_clone = stats.clone();
        tokio::spawn(async move {
            stats_reporter(stats_clone, Duration::from_secs(1)).await;
        });

        // Wait for duration
        sleep(args.duration).await;
    }

    // Final stats
    let sent = stats.requests_sent.load(Ordering::Relaxed);
    let received = stats.responses_received.load(Ordering::Relaxed);
    let errors = stats.errors.load(Ordering::Relaxed);
    let bytes_sent = stats.bytes_sent.load(Ordering::Relaxed);
    let bytes_recv = stats.bytes_received.load(Ordering::Relaxed);
    let max_resp = stats.max_response_size.load(Ordering::Relaxed);
    let max_block = stats.max_response_block.load(Ordering::Relaxed);
    let duration_secs = args.duration.as_secs_f64();

    println!();
    println!("=== Final Results ===");
    println!("  Requests sent: {}", sent);
    println!("  Responses received: {}", received);
    println!("  Errors: {}", errors);
    println!("  Bytes sent: {:.2} MB", bytes_sent as f64 / 1024.0 / 1024.0);
    println!(
        "  Bytes received: {:.2} MB",
        bytes_recv as f64 / 1024.0 / 1024.0
    );
    println!(
        "  Max response size: {} bytes ({:.2} MB)",
        max_resp,
        max_resp as f64 / 1024.0 / 1024.0
    );
    if args.query && max_block > 0 {
        println!("  Max response block: {}", max_block);
    }
    if !args.query {
        println!("  Avg send rate: {:.0} req/s", sent as f64 / duration_secs);
        println!(
            "  Avg recv rate: {:.0} resp/s",
            received as f64 / duration_secs
        );
        println!(
            "  Avg recv throughput: {:.2} MB/s",
            bytes_recv as f64 / duration_secs / 1024.0 / 1024.0
        );
    }

    Ok(())
}
