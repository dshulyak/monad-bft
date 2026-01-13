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

//! Benchmark for blocksync response path to measure serialization/alloc/copy overhead.
//!
//! This simulates the tcp_build_and_send codepath from monad-raptorcast.

use bytes::BytesMut;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use monad_crypto::{
    hasher::{Hasher, HasherType},
    signing_domain::{self, SigningDomain},
};
use monad_secp::{KeyPair, SecpSignature};
use monad_testutil::signing::get_key;

const SIGNATURE_SIZE: usize = 65;
const PAYLOAD_SIZE: usize = 2 * 1024 * 1024; // 2 MB

type SignatureType = SecpSignature;

pub fn criterion_benchmark(c: &mut Criterion) {
    let keypair: KeyPair = get_key::<SignatureType>(42);

    // Pre-allocate a 2MB payload (simulating RLP-encoded blocksync response)
    let payload = vec![0xffu8; PAYLOAD_SIZE];

    let mut group = c.benchmark_group("blocksync_response_path");
    group.throughput(Throughput::Bytes(PAYLOAD_SIZE as u64));

    // 1. Measure just memory allocation
    group.bench_function("01_alloc_only", |b| {
        b.iter(|| {
            let buf = BytesMut::zeroed(SIGNATURE_SIZE + PAYLOAD_SIZE);
            black_box(buf);
        });
    });

    // 2. Measure allocation + copy
    group.bench_function("02_alloc_and_copy", |b| {
        b.iter(|| {
            let mut buf = BytesMut::zeroed(SIGNATURE_SIZE + PAYLOAD_SIZE);
            buf[SIGNATURE_SIZE..].copy_from_slice(&payload);
            black_box(buf);
        });
    });

    // 3. Measure blake3 hash of 2MB
    group.bench_function("03_blake3_hash", |b| {
        b.iter(|| {
            let mut hasher = HasherType::new();
            hasher.update(signing_domain::RaptorcastAppMessage::PREFIX);
            hasher.update(&payload);
            black_box(hasher.hash());
        });
    });

    // 4. Measure secp256k1 signing (includes blake3 hash internally)
    group.bench_function("04_sign_only", |b| {
        b.iter(|| {
            let sig = keypair.sign::<signing_domain::RaptorcastAppMessage>(&payload);
            black_box(sig);
        });
    });

    // 5. Full path: alloc + sign + copy signature + copy payload
    group.bench_function("05_full_path", |b| {
        b.iter(|| {
            // Sign (includes blake3 hash)
            let sig = keypair.sign::<signing_domain::RaptorcastAppMessage>(&payload);
            let sig_bytes = SecpSignature::serialize(&sig);

            // Allocate buffer
            let mut buf = BytesMut::zeroed(SIGNATURE_SIZE + payload.len());

            // Copy signature and payload
            buf[..SIGNATURE_SIZE].copy_from_slice(&sig_bytes);
            buf[SIGNATURE_SIZE..].copy_from_slice(&payload);

            // Freeze (converts to Bytes)
            black_box(buf.freeze());
        });
    });

    // 6. Full path with pre-encoded payload (more realistic - payload already serialized)
    group.bench_function("06_full_path_preencoded", |b| {
        let encoded_payload = payload.clone(); // Simulate already RLP-encoded
        b.iter(|| {
            let sig = keypair.sign::<signing_domain::RaptorcastAppMessage>(&encoded_payload);
            let sig_bytes = SecpSignature::serialize(&sig);

            let mut buf = BytesMut::zeroed(SIGNATURE_SIZE + encoded_payload.len());
            buf[..SIGNATURE_SIZE].copy_from_slice(&sig_bytes);
            buf[SIGNATURE_SIZE..].copy_from_slice(&encoded_payload);

            black_box(buf.freeze());
        });
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
