// Copyright (C) 2026 Category Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use zerocopy::IntoBytes;

use crate::protocol::{
    common::{CipherKey, CipherNonce, SessionIndex},
    messages::DataPacketHeader,
};

/// A sending capability bound to one session generation. Clones share its
/// immutable key and nonce allocator; session management remains with the API.
pub type Writer = Arc<dyn PacketWriter>;

/// Concurrent encryption into a caller-owned complete wire packet, including
/// the protocol header. The output must have the protocol's exact wire size.
pub trait PacketWriter: Send + Sync {
    fn encrypt_into(&self, plaintext: &[u8], output: &mut [u8]) -> Result<(), WriterError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WriterError {
    #[error("sending session has terminated")]
    SessionTerminated,
    #[error("sending nonce exhausted")]
    NonceExhausted,
}

pub(crate) struct SendState {
    key: CipherKey,
    remote_index: SessionIndex,
    nonce: AtomicU64,
    active: AtomicBool,
}

impl SendState {
    pub(crate) fn new(key: CipherKey, remote_index: SessionIndex) -> Self {
        Self {
            key,
            remote_index,
            nonce: AtomicU64::new(0),
            active: AtomicBool::new(true),
        }
    }

    pub(crate) fn check_active(&self) -> Result<(), WriterError> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(WriterError::SessionTerminated)
        }
    }

    pub(crate) fn invalidate(&self) {
        self.active.store(false, Ordering::Release);
    }

    pub(crate) fn encrypt_header(
        &self,
        encrypt: impl FnOnce(&CipherKey, &CipherNonce) -> [u8; 16],
    ) -> Result<DataPacketHeader, WriterError> {
        self.check_active()?;
        // Only uniqueness is shared here; the Arc/channel publishes key material.
        // Failed sends consume their nonce, and exhaustion never wraps to zero.
        let nonce = self
            .nonce
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |nonce| {
                nonce.checked_add(1)
            })
            .map_err(|_| WriterError::NonceExhausted)?;
        Ok(DataPacketHeader {
            receiver_index: self.remote_index.as_u32().into(),
            nonce: nonce.into(),
            tag: encrypt(&self.key, &nonce.into()),
            ..Default::default()
        })
    }
}

impl PacketWriter for SendState {
    fn encrypt_into(&self, plaintext: &[u8], output: &mut [u8]) -> Result<(), WriterError> {
        assert_eq!(output.len(), DataPacketHeader::SIZE + plaintext.len());
        let (header, ciphertext) = output.split_at_mut(DataPacketHeader::SIZE);
        let packet = self.encrypt_header(|key, nonce| {
            crate::protocol::crypto::encrypt_into(key, nonce, plaintext, ciphertext, &[])
        })?;
        header.copy_from_slice(packet.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::FromBytes;

    use super::*;
    use crate::protocol::common::HashOutput;

    fn sender() -> Arc<SendState> {
        Arc::new(SendState::new(
            CipherKey::from(&HashOutput([7; 32])),
            SessionIndex::new(42),
        ))
    }

    #[test]
    fn concurrent_writers_allocate_unique_nonces_and_valid_packets() {
        let state = sender();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let writer: Writer = state.clone();
                std::thread::spawn(move || {
                    (0..128)
                        .map(|_| {
                            let mut output = vec![0; DataPacketHeader::SIZE + 7];
                            writer.encrypt_into(b"payload", &mut output).unwrap();
                            output
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut nonces = Vec::new();
        for thread in threads {
            for mut packet in thread.join().unwrap() {
                let header =
                    DataPacketHeader::read_from_bytes(&packet[..DataPacketHeader::SIZE]).unwrap();
                assert_eq!(header.receiver_index.get(), 42);
                let nonce = header.nonce.get();
                crate::protocol::crypto::decrypt_in_place(
                    &state.key,
                    &nonce.into(),
                    &mut packet[DataPacketHeader::SIZE..],
                    &header.tag,
                    &[],
                )
                .unwrap();
                assert_eq!(&packet[DataPacketHeader::SIZE..], b"payload");
                nonces.push(nonce);
            }
        }
        nonces.sort_unstable();
        assert_eq!(nonces, (0..1024).collect::<Vec<_>>());
    }

    #[test]
    fn direct_and_shared_encryption_use_one_counter() {
        let state = sender();
        let first = state
            .encrypt_header(|key, nonce| {
                crate::protocol::crypto::encrypt_in_place(key, nonce, &mut [], &[])
            })
            .unwrap();
        let writer: Writer = state.clone();
        let mut packet = [0; DataPacketHeader::SIZE];
        writer.encrypt_into(&[], &mut packet).unwrap();
        let second = DataPacketHeader::read_from_bytes(&packet).unwrap();
        let third = state
            .encrypt_header(|key, nonce| {
                crate::protocol::crypto::encrypt_in_place(key, nonce, &mut [], &[])
            })
            .unwrap();
        assert_eq!(
            [first.nonce.get(), second.nonce.get(), third.nonce.get()],
            [0, 1, 2]
        );
    }

    #[test]
    fn invalidation_prevents_retained_writer_from_encrypting() {
        let state = sender();
        let writer: Writer = state.clone();
        state.invalidate();
        let mut packet = [0xa5; DataPacketHeader::SIZE];
        assert_eq!(
            writer.encrypt_into(&[], &mut packet),
            Err(WriterError::SessionTerminated)
        );
        assert_eq!(packet, [0xa5; DataPacketHeader::SIZE]);
        assert_eq!(state.nonce.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn nonce_exhaustion_never_wraps_or_changes_output() {
        let state = sender();
        state.nonce.store(u64::MAX - 1, Ordering::Relaxed);
        let mut packet = [0; DataPacketHeader::SIZE];
        state.encrypt_into(&[], &mut packet).unwrap();
        assert_eq!(
            DataPacketHeader::read_from_bytes(&packet)
                .unwrap()
                .nonce
                .get(),
            u64::MAX - 1
        );
        packet.fill(0xa5);
        assert_eq!(
            state.encrypt_into(&[], &mut packet),
            Err(WriterError::NonceExhausted)
        );
        assert_eq!(packet, [0xa5; DataPacketHeader::SIZE]);
        assert_eq!(state.nonce.load(Ordering::Relaxed), u64::MAX);
    }
}
