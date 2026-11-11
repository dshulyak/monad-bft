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

use std::{net::SocketAddr, time::Instant};

use bytes::Bytes;
use monad_crypto::certificate_signature::PubKey;
pub use monad_dataplane::auth::{AuthenticationProtocol, WireAuthProtocol};
use monad_executor::ExecutorMetricsChain;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NoopHeader;

// TODO(dshulyak): Remove NoopAuthProtocol after migrating its test and simulation users.
pub struct NoopAuthProtocol<P: PubKey> {
    _phantom: std::marker::PhantomData<P>,
    writer: monad_wireauth::Writer,
}

impl<P: PubKey> NoopAuthProtocol<P> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            writer: std::sync::Arc::new(NoopWriter),
        }
    }
}

impl<P: PubKey> Default for NoopAuthProtocol<P> {
    fn default() -> Self {
        Self::new()
    }
}

struct NoopWriter;
impl monad_wireauth::PacketWriter for NoopWriter {
    fn encrypt_into(
        &self,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<(), monad_wireauth::WriterError> {
        output.copy_from_slice(plaintext);
        Ok(())
    }
}

impl<P: PubKey> monad_dataplane::auth::AuthenticationProtocol for NoopAuthProtocol<P> {
    type PublicKey = P;
    type Error = std::convert::Infallible;
    type Header = NoopHeader;

    const HEADER_SIZE: u16 = 0;

    fn into_initializer(self) -> Box<dyn FnOnce() -> Self + Send> {
        Box::new(move || self)
    }

    fn writer_for_peer(
        &mut self,
        _: &Self::PublicKey,
        _: SocketAddr,
        _: usize,
    ) -> Option<monad_wireauth::Writer> {
        Some(self.writer.clone())
    }

    fn connect(
        &mut self,
        _remote_public_key: &Self::PublicKey,
        _remote_addr: SocketAddr,
        _retry_attempts: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn dispatch(
        &mut self,
        packet: &mut [u8],
        _remote_addr: SocketAddr,
    ) -> Result<Option<(Bytes, Option<Self::PublicKey>)>, Self::Error> {
        Ok(Some((Bytes::copy_from_slice(packet), None)))
    }

    fn encrypt_by_public_key(
        &mut self,
        _public_key: &Self::PublicKey,
        _plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        Ok(NoopHeader)
    }

    fn encrypt_by_socket(
        &mut self,
        _socket_addr: &SocketAddr,
        _plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        Ok(NoopHeader)
    }

    fn next_packet(&mut self) -> Option<(SocketAddr, Bytes)> {
        None
    }

    fn tick(&mut self) {}

    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    fn is_connected_public_key(&self, _public_key: &Self::PublicKey) -> bool {
        false
    }

    fn is_connected_socket_and_public_key(
        &self,
        _socket_addr: &SocketAddr,
        _public_key: &Self::PublicKey,
    ) -> bool {
        // Noop can send to an explicit address, but has no session map for key-only sends.
        true
    }

    fn get_socket_by_public_key(&self, _public_key: &Self::PublicKey) -> Option<SocketAddr> {
        None
    }

    fn has_any_session_by_public_key(&self, _public_key: &Self::PublicKey) -> bool {
        false
    }

    fn has_initiator_session_by_public_key(&self, _public_key: &Self::PublicKey) -> bool {
        false
    }

    fn has_initiator_session_by_socket_and_public_key(
        &self,
        _socket_addr: &SocketAddr,
        _public_key: &Self::PublicKey,
    ) -> bool {
        false
    }

    fn metrics(&self) -> ExecutorMetricsChain<'_> {
        ExecutorMetricsChain::default()
    }
}
