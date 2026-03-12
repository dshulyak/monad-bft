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

//! RaptorCast segment builder with two modes:
//! - `inmem`: decode locally in-memory
//! - `remote`: send the same built segments to a target UDP socket

use std::{
    cmp::Reverse,
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use bytes::Bytes;
use clap::{Args as ClapArgs, Parser, Subcommand};
use monad_crypto::{
    certificate_signature::CertificateSignaturePubKey,
    hasher::{Hasher, HasherType},
};
use monad_raptor::r10::CodeParameters;
use monad_secp::{KeyPair, PubKey, SecpSignature};
use monad_types::{Epoch, NodeId};

use crate::{
    decoding::{DecoderCache, DecodingContext, InvalidSymbol, TryDecodeError, TryDecodeStatus},
    packet::build_messages,
    udp::{parse_message, ChunkSignatureVerifier, GroupId, MAX_REDUNDANCY, SIGNATURE_CACHE_SIZE},
    util::{unix_ts_ms_now, BuildTarget, Redundancy},
};

type PubKeyType = CertificateSignaturePubKey<SecpSignature>;

#[derive(Parser, Debug)]
#[command(about = "RaptorCast builder: inmem decode or remote UDP send")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Inmem(InmemArgs),
    Remote(RemoteArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct CommonArgs {
    /// Size of the application message to raptor-encode (bytes).
    #[arg(long, default_value_t = 3 * 1024 * 1024)]
    app_message_bytes: usize,

    /// Redundancy multiplier (must be <= 7).
    #[arg(long, default_value_t = 7.0)]
    redundancy: f32,

    /// Segment size (bytes).
    #[arg(long, default_value_t = 1472)]
    segment_size: u16,

    /// Sort chunks by decreasing LT degree.
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    order_by_degree: bool,
}

#[derive(ClapArgs, Debug)]
struct InmemArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// Max accepted timestamp skew for parse_message.
    #[arg(long, default_value_t = u64::MAX)]
    max_age_ms: u64,
}

#[derive(ClapArgs, Debug)]
struct RemoteArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// Target UDP socket.
    #[arg(long)]
    target: SocketAddr,

    /// Target secp256k1 pubkey (compressed, 33 bytes) as hex.
    #[arg(long)]
    target_secp_pubkey: String,

    /// Send rate in Mbps (spin paced, no sleep).
    #[arg(long, default_value_t = 10.0)]
    rate_mbps: f64,

    /// Keep replaying the segment set until this deadline (seconds).
    #[arg(long, default_value_t = 10)]
    duration_secs: u64,
}

#[derive(Default)]
pub struct DecodeStats {
    parse_errors: usize,
    rejected_by_cache: usize,
    needs_more_symbols: usize,
    recently_decoded: usize,
    decoded: usize,
    duplicate_symbol: usize,
    invalid_symbol_other: usize,
    reconstruct_error: usize,
    hash_mismatch: usize,
    payload_mismatch: usize,
}

struct SegmentMeta {
    chunk_id: u16,
    degree: usize,
    bytes: Bytes,
}

pub struct BuiltTraffic {
    attacker: NodeId<PubKeyType>,
    app_message: Vec<u8>,
    segments: Vec<SegmentMeta>,
    symbol_len: usize,
    num_source_symbols: usize,
    total_wire_bytes: usize,
}

struct SpinPacer {
    bits_per_sec: f64,
    next_send_at: Instant,
}

impl SpinPacer {
    fn new(rate_mbps: f64) -> Result<Self, String> {
        if !rate_mbps.is_finite() || rate_mbps <= 0.0 {
            return Err("rate_mbps must be > 0".to_owned());
        }
        Ok(Self {
            bits_per_sec: rate_mbps * 1_000_000.0,
            next_send_at: Instant::now(),
        })
    }

    fn wait_turn(&mut self) {
        let now = Instant::now();
        if self.next_send_at < now {
            self.next_send_at = now;
        }
        while Instant::now() < self.next_send_at {
            std::hint::spin_loop();
        }
    }

    fn on_send(&mut self, bytes: usize) {
        let secs = (bytes as f64) * 8.0 / self.bits_per_sec;
        let dt = Duration::from_secs_f64(secs.max(0.0));
        if let Some(next) = self.next_send_at.checked_add(dt) {
            self.next_send_at = next;
        } else {
            self.next_send_at = Instant::now();
        }
    }
}

fn decode_hex_0x(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

fn fixed_key(seed: u8) -> KeyPair {
    let mut hasher = HasherType::new();
    hasher.update(seed.to_le_bytes());
    let mut hash = hasher.hash();
    KeyPair::from_bytes(&mut hash.0).expect("fixed key must be valid")
}

fn build_traffic(
    common: &CommonArgs,
    recipient: NodeId<PubKeyType>,
    recipient_addr: SocketAddr,
) -> Result<BuiltTraffic, Box<dyn std::error::Error>> {
    let redundancy = Redundancy::from_f32(common.redundancy)
        .ok_or_else(|| format!("invalid redundancy value: {}", common.redundancy))?;
    if redundancy > MAX_REDUNDANCY {
        return Err(format!(
            "redundancy ({}) must be <= {}",
            redundancy.to_f32(),
            MAX_REDUNDANCY.to_f32()
        )
        .into());
    }

    let attacker_key = fixed_key(1);
    let attacker = NodeId::new(attacker_key.pubkey());

    let mut known = HashMap::new();
    known.insert(recipient, recipient_addr);

    let mut app_message = vec![0u8; common.app_message_bytes];
    for (idx, byte) in app_message.iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(31).wrapping_add(7);
    }

    let messages = build_messages::<SecpSignature>(
        &attacker_key,
        common.segment_size,
        Bytes::from(app_message.clone()),
        redundancy,
        GroupId::Primary(Epoch(0)),
        unix_ts_ms_now(),
        BuildTarget::PointToPoint(&recipient),
        &known,
    );

    let segment_size = usize::from(common.segment_size);
    let mut segments_raw = Vec::<Vec<u8>>::new();
    for (dest, payload) in messages {
        if dest != recipient_addr {
            return Err(format!("unexpected recipient address from builder: {dest}").into());
        }
        if payload.len() % segment_size != 0 {
            return Err(format!(
                "builder payload len {} is not multiple of segment_size {}",
                payload.len(),
                segment_size
            )
            .into());
        }
        for raw in payload.as_ref().chunks(segment_size) {
            segments_raw.push(raw.to_vec());
        }
    }

    let mut signature_verifier =
        ChunkSignatureVerifier::<SecpSignature>::new().with_cache(SIGNATURE_CACHE_SIZE);
    let mut segments = Vec::<SegmentMeta>::with_capacity(segments_raw.len());
    let mut symbol_len = None;

    for raw in segments_raw {
        let parsed = parse_message::<SecpSignature, _>(
            &mut signature_verifier,
            Bytes::from(raw.clone()),
            u64::MAX,
            |_| true,
        )
        .map_err(|err| format!("failed to parse locally built segment: {err:?}"))?;

        symbol_len.get_or_insert(parsed.chunk.len());
        let params = CodeParameters::new(common.app_message_bytes.div_ceil(parsed.chunk.len()))
            .map_err(|e| format!("failed to build CodeParameters: {e}"))?;
        let degree = lt_degree(&params, parsed.chunk_id);

        segments.push(SegmentMeta {
            chunk_id: parsed.chunk_id,
            degree,
            bytes: Bytes::from(raw),
        });
    }

    let symbol_len = symbol_len.ok_or("builder produced no segments")?;
    let num_source_symbols = common.app_message_bytes.div_ceil(symbol_len);

    if common.order_by_degree {
        segments.sort_by_key(|segment| (Reverse(segment.degree), segment.chunk_id));
    }

    let total_wire_bytes = segments.iter().map(|segment| segment.bytes.len()).sum();

    Ok(BuiltTraffic {
        attacker,
        app_message,
        segments,
        symbol_len,
        num_source_symbols,
        total_wire_bytes,
    })
}

fn lt_degree(params: &CodeParameters, encoding_symbol_id: u16) -> usize {
    let mut degree = 0usize;
    params.lt_sequence_op(usize::from(encoding_symbol_id), |_| degree += 1);
    degree
}

pub fn build_inmem_benchmark_traffic(
    app_message_bytes: usize,
    redundancy: f32,
    segment_size: u16,
    order_by_degree: bool,
) -> Result<BuiltTraffic, Box<dyn std::error::Error>> {
    let recipient_key = fixed_key(2);
    let recipient = NodeId::new(recipient_key.pubkey());
    let recipient_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8000);
    let common = CommonArgs {
        app_message_bytes,
        redundancy,
        segment_size,
        order_by_degree,
    };

    build_traffic(&common, recipient, recipient_addr)
}

pub fn run_decode(
    traffic: &BuiltTraffic,
    max_age_ms: u64,
) -> Result<DecodeStats, Box<dyn std::error::Error>> {
    let mut stats = DecodeStats::default();
    let mut signature_verifier =
        ChunkSignatureVerifier::<SecpSignature>::new().with_cache(SIGNATURE_CACHE_SIZE);
    let mut decoder_cache = DecoderCache::default();

    for segment in &traffic.segments {
        let context = DecodingContext::new(None, unix_ts_ms_now());
        let parsed = match parse_message::<SecpSignature, _>(
            &mut signature_verifier,
            segment.bytes.clone(),
            max_age_ms,
            |_| true,
        ) {
            Ok(parsed) => parsed,
            Err(_) => {
                stats.parse_errors += 1;
                continue;
            }
        };

        match decoder_cache.try_decode(&parsed, &context) {
            Ok(TryDecodeStatus::RejectedByCache) => stats.rejected_by_cache += 1,
            Ok(TryDecodeStatus::NeedsMoreSymbols) => stats.needs_more_symbols += 1,
            Ok(TryDecodeStatus::RecentlyDecoded) => stats.recently_decoded += 1,
            Ok(TryDecodeStatus::Decoded {
                author,
                app_message,
            }) => {
                stats.decoded += 1;
                if author != traffic.attacker
                    || app_message.as_ref() != traffic.app_message.as_slice()
                {
                    stats.payload_mismatch += 1;
                }
            }
            Err(TryDecodeError::InvalidSymbol(InvalidSymbol::DuplicateSymbol { .. })) => {
                stats.duplicate_symbol += 1;
            }
            Err(TryDecodeError::InvalidSymbol(_)) => stats.invalid_symbol_other += 1,
            Err(TryDecodeError::UnableToReconstructSourceData) => stats.reconstruct_error += 1,
            Err(TryDecodeError::AppMessageHashMismatch { .. }) => stats.hash_mismatch += 1,
        }
    }

    Ok(stats)
}

pub fn ensure_decode_success(stats: &DecodeStats) -> Result<(), Box<dyn std::error::Error>> {
    if stats.payload_mismatch > 0 {
        return Err("decoded payload mismatch detected".into());
    }
    if stats.decoded == 0 {
        return Err("no successful decode observed; try increasing --redundancy".into());
    }

    Ok(())
}

fn run_inmem(args: InmemArgs) -> Result<(), Box<dyn std::error::Error>> {
    let traffic = build_inmem_benchmark_traffic(
        args.common.app_message_bytes,
        args.common.redundancy,
        args.common.segment_size,
        args.common.order_by_degree,
    )?;

    println!(
        "Built segments: app_message_bytes={} symbol_len={} K={} segments={} total_wire_bytes={} redundancy={} order_by_degree={}",
        args.common.app_message_bytes,
        traffic.symbol_len,
        traffic.num_source_symbols,
        traffic.segments.len(),
        traffic.total_wire_bytes,
        args.common.redundancy,
        args.common.order_by_degree,
    );

    let decode_start = Instant::now();
    let stats = run_decode(&traffic, args.max_age_ms)?;
    let decode_elapsed = decode_start.elapsed();

    println!(
        "Decode stats: parse_errors={} rejected_by_cache={} needs_more_symbols={} recently_decoded={} decoded={} duplicate_symbol={} invalid_symbol_other={} reconstruct_error={} hash_mismatch={} payload_mismatch={}",
        stats.parse_errors,
        stats.rejected_by_cache,
        stats.needs_more_symbols,
        stats.recently_decoded,
        stats.decoded,
        stats.duplicate_symbol,
        stats.invalid_symbol_other,
        stats.reconstruct_error,
        stats.hash_mismatch,
        stats.payload_mismatch,
    );
    println!(
        "Decode elapsed: {} ms ({} us)",
        decode_elapsed.as_millis(),
        decode_elapsed.as_micros()
    );

    ensure_decode_success(&stats)
}

fn run_remote(args: RemoteArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut pacer = SpinPacer::new(args.rate_mbps)?;
    if args.duration_secs == 0 {
        return Err("duration_secs must be > 0".into());
    }

    let pk_bytes = decode_hex_0x(&args.target_secp_pubkey)?;
    let pubkey =
        PubKey::from_slice(&pk_bytes).map_err(|e| format!("invalid target_secp_pubkey: {e}"))?;
    let recipient = NodeId::new(pubkey);

    let traffic = build_traffic(&args.common, recipient, args.target)?;

    println!(
        "Built segments: app_message_bytes={} symbol_len={} K={} segments_per_pass={} total_wire_bytes_per_pass={} redundancy={} order_by_degree={} target={} rate_mbps={} duration_secs={}",
        args.common.app_message_bytes,
        traffic.symbol_len,
        traffic.num_source_symbols,
        traffic.segments.len(),
        traffic.total_wire_bytes,
        args.common.redundancy,
        args.common.order_by_degree,
        args.target,
        args.rate_mbps,
        args.duration_secs,
    );

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let send_start = Instant::now();
    let mut sent_bytes = 0usize;
    let mut sent_segments = 0usize;
    let mut full_passes = 0usize;
    let deadline = send_start + Duration::from_secs(args.duration_secs);

    'outer: loop {
        for segment in &traffic.segments {
            if Instant::now() >= deadline {
                break 'outer;
            }
            pacer.wait_turn();
            if Instant::now() >= deadline {
                break 'outer;
            }

            let sent = sock.send_to(segment.bytes.as_ref(), args.target)?;
            if sent != segment.bytes.len() {
                return Err(format!(
                    "partial udp send: sent {sent} of {} bytes",
                    segment.bytes.len()
                )
                .into());
            }
            pacer.on_send(sent);
            sent_bytes += sent;
            sent_segments += 1;
        }
        full_passes += 1;
    }
    let elapsed = send_start.elapsed();

    println!(
        "Sent: {} segments, {} bytes, full_passes={}, elapsed={} ms",
        sent_segments,
        sent_bytes,
        full_passes,
        elapsed.as_millis()
    );

    Ok(())
}

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inmem(args) => run_inmem(args),
        Command::Remote(args) => run_remote(args),
    }
}
