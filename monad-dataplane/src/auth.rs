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

//! Authenticated UDP transport owned by the dataplane runtime.
//!
//! Application handles enqueue plaintext and connection requests. Receive tasks
//! decrypt before admission to identity/IP queues; transmit pacing accounts for
//! wire bytes. A selected batch receives sending capabilities from WireAuth;
//! workers encrypt plaintext after pacing into their reusable output buffers.
//! Handshake buffering retains plaintext and priority outside WireAuth's own
//! encrypt-on-establishment buffer. Timers and handshake responses do not depend
//! on application receive polling. Applications supply an address on every send;
//! session management stays on the dataplane thread. Transmit workers receive
//! only immutable sending keys with a shared atomic nonce allocator.

use std::{convert::TryFrom, fmt::Debug, hash::Hash, net::SocketAddr, sync::Arc, time::Instant};

use bytes::Bytes;
use monad_executor::ExecutorMetricsChain;
use monad_wireauth::messages::{DataPacketHeader, Packet};
use zerocopy::{Immutable, IntoBytes};

/// An authenticated sender's grouping key. Transport scheduling does not depend
/// on a particular signature scheme or application node-ID representation.
pub trait Identity: Copy + Debug + Eq + Ord + Hash + Send + Sync + Unpin + 'static {}
impl<T: Copy + Debug + Eq + Ord + Hash + Send + Sync + Unpin + 'static> Identity for T {}

pub trait AuthenticationProtocol: 'static {
    type PublicKey: Identity;
    type Error: std::fmt::Debug + Send + 'static;
    type Header: IntoBytes + Immutable;

    const HEADER_SIZE: u16;

    /// Only the initializer crosses threads. The engine is constructed and used
    /// exclusively on the dataplane thread.
    fn into_initializer(self) -> Box<dyn FnOnce() -> Self + Send>
    where
        Self: Sized;

    fn encrypt_for_peer(
        &mut self,
        key: &Self::PublicKey,
        addr: SocketAddr,
        plaintext: &mut [u8],
    ) -> Option<Self::Header> {
        if !self.is_connected_socket_and_public_key(&addr, key) {
            return None;
        }
        self.encrypt_by_socket(&addr, plaintext).ok()
    }

    fn encrypt_for_peer_into(
        &mut self,
        key: &Self::PublicKey,
        addr: SocketAddr,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Option<Self::Header> {
        ciphertext.copy_from_slice(plaintext);
        self.encrypt_for_peer(key, addr, ciphertext)
    }

    /// Obtain a concurrent sending capability for one selected plaintext packet.
    /// Session selection and send-activity bookkeeping stay on the engine owner.
    fn writer_for_peer(
        &mut self,
        key: &Self::PublicKey,
        addr: SocketAddr,
        plaintext_len: usize,
    ) -> Option<monad_wireauth::Writer>;

    fn connect(
        &mut self,
        remote_public_key: &Self::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), Self::Error>;

    fn dispatch(
        &mut self,
        packet: &mut [u8],
        remote_addr: SocketAddr,
    ) -> Result<Option<(Bytes, Option<Self::PublicKey>)>, Self::Error>;

    fn encrypt_by_public_key(
        &mut self,
        public_key: &Self::PublicKey,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error>;

    fn encrypt_by_socket(
        &mut self,
        socket_addr: &SocketAddr,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error>;

    fn is_connected_public_key(&self, public_key: &Self::PublicKey) -> bool;

    fn is_connected_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &Self::PublicKey,
    ) -> bool;

    fn get_socket_by_public_key(&self, public_key: &Self::PublicKey) -> Option<SocketAddr>;

    fn has_any_session_by_public_key(&self, public_key: &Self::PublicKey) -> bool;

    fn has_initiator_session_by_public_key(&self, public_key: &Self::PublicKey) -> bool;

    fn has_initiator_session_by_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &Self::PublicKey,
    ) -> bool;

    fn next_packet(&mut self) -> Option<(SocketAddr, Bytes)>;

    fn tick(&mut self);

    fn next_deadline(&self) -> Option<Instant>;

    fn metrics(&self) -> ExecutorMetricsChain<'_>;

    fn max_buffered_bytes(&self) -> usize {
        1024 * 1024
    }
}

type WireAuthApi = monad_wireauth::API<
    monad_wireauth::StdContext<secp256k1::rand::rngs::StdRng>,
    Arc<monad_secp::KeyPair>,
>;

pub struct WireAuthProtocol {
    metric_names: &'static monad_wireauth::MetricNames,
    config: monad_wireauth::Config,
    signing_key: Arc<monad_secp::KeyPair>,
    api: std::cell::OnceCell<WireAuthApi>,
}
impl WireAuthProtocol {
    /// Configuration only. Installation creates the engine on its owning thread.
    pub fn new(
        metric_names: &'static monad_wireauth::MetricNames,
        config: monad_wireauth::Config,
        signing_key: Arc<monad_secp::KeyPair>,
    ) -> Self {
        Self {
            metric_names,
            config,
            signing_key,
            api: std::cell::OnceCell::new(),
        }
    }
    fn api(&self) -> &WireAuthApi {
        self.api.get_or_init(|| {
            use secp256k1::rand::SeedableRng;
            let context =
                monad_wireauth::StdContext::with_rng(secp256k1::rand::rngs::StdRng::from_os_rng());
            monad_wireauth::API::new(
                self.metric_names,
                self.config.clone(),
                self.signing_key.clone(),
                context,
            )
        })
    }
    fn api_mut(&mut self) -> &mut WireAuthApi {
        self.api();
        self.api.get_mut().unwrap()
    }
}

impl AuthenticationProtocol for WireAuthProtocol {
    type PublicKey = monad_secp::PubKey;
    type Error = monad_wireauth::Error;
    type Header = monad_wireauth::messages::DataPacketHeader;

    const HEADER_SIZE: u16 = DataPacketHeader::SIZE as u16;

    fn into_initializer(self) -> Box<dyn FnOnce() -> Self + Send> {
        let Self {
            metric_names,
            config,
            signing_key,
            api,
        } = self;
        assert!(
            api.get().is_none(),
            "WireAuth engines cannot move after first use"
        );
        Box::new(move || Self::new(metric_names, config, signing_key))
    }
    fn max_buffered_bytes(&self) -> usize {
        self.config.max_buffered_bytes_per_session
    }
    fn encrypt_for_peer(
        &mut self,
        key: &Self::PublicKey,
        addr: SocketAddr,
        plaintext: &mut [u8],
    ) -> Option<Self::Header> {
        self.api_mut()
            .encrypt_for_peer(key, Some(addr), plaintext)
            .ok()
    }

    fn encrypt_for_peer_into(
        &mut self,
        key: &Self::PublicKey,
        addr: SocketAddr,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Option<Self::Header> {
        self.api_mut()
            .encrypt_for_peer_into(key, Some(addr), plaintext, ciphertext)
            .ok()
    }

    fn writer_for_peer(
        &mut self,
        key: &Self::PublicKey,
        addr: SocketAddr,
        plaintext_len: usize,
    ) -> Option<monad_wireauth::Writer> {
        self.api_mut()
            .writer_for_peer(key, Some(addr), plaintext_len)
            .ok()
    }

    fn connect(
        &mut self,
        remote_public_key: &Self::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), Self::Error> {
        self.api_mut()
            .connect(*remote_public_key, remote_addr, retry_attempts)
    }

    fn dispatch(
        &mut self,
        packet: &mut [u8],
        remote_addr: SocketAddr,
    ) -> Result<Option<(Bytes, Option<Self::PublicKey>)>, Self::Error> {
        match Packet::try_from(packet).map_err(monad_wireauth::Error::from)? {
            Packet::Control(control_packet) => {
                self.api_mut()
                    .dispatch_control(control_packet, remote_addr)?;
                Ok(None)
            }
            Packet::Data(data_packet) => {
                let (plaintext, public_key) = self.api_mut().decrypt(data_packet, remote_addr)?;
                Ok(Some((
                    Bytes::copy_from_slice(plaintext.as_ref()),
                    Some(public_key),
                )))
            }
        }
    }

    fn encrypt_by_public_key(
        &mut self,
        public_key: &Self::PublicKey,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        self.api_mut().encrypt_by_public_key(public_key, plaintext)
    }

    fn encrypt_by_socket(
        &mut self,
        socket_addr: &SocketAddr,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        self.api_mut().encrypt_by_socket(socket_addr, plaintext)
    }

    fn next_packet(&mut self) -> Option<(SocketAddr, Bytes)> {
        self.api_mut().next_packet()
    }

    fn tick(&mut self) {
        self.api_mut().tick();
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.api().next_deadline()
    }

    fn is_connected_public_key(&self, public_key: &Self::PublicKey) -> bool {
        self.api().is_connected_public_key(public_key)
    }

    fn is_connected_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &Self::PublicKey,
    ) -> bool {
        self.api()
            .is_connected_socket_and_public_key(socket_addr, public_key)
    }

    fn get_socket_by_public_key(&self, public_key: &Self::PublicKey) -> Option<SocketAddr> {
        self.api().get_socket_by_public_key(public_key)
    }

    fn has_any_session_by_public_key(&self, public_key: &Self::PublicKey) -> bool {
        self.api().has_any_session_by_public_key(public_key)
    }

    fn has_initiator_session_by_public_key(&self, public_key: &Self::PublicKey) -> bool {
        self.api().has_initiator_session_by_public_key(public_key)
    }

    fn has_initiator_session_by_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &Self::PublicKey,
    ) -> bool {
        self.api()
            .has_initiator_session_by_socket_and_public_key(socket_addr, public_key)
    }

    fn metrics(&self) -> ExecutorMetricsChain<'_> {
        self.api().metrics()
    }
}

use std::{
    collections::{HashMap, HashSet, VecDeque},
    marker::PhantomData,
};

use monad_executor::ExecutorMetrics;
use monad_types::UdpPriority;
use tracing::debug;

use crate::{RecvUdpMsg, UdpMsg, UdpSocketHandle, UdpSocketId};

#[derive(Clone, Copy)]
pub(crate) struct Encryption<I: Identity> {
    pub identity: I,
    pub header_size: u16,
}

// Plaintext and paced packets share one allocation. The encryption identity is
// present on every authenticated plaintext command, even before its session exists.
pub(crate) type Plaintext<I> = Box<UdpMsg<I>>;

pub(crate) type Installation<I> = (
    UdpSocketId,
    BackendInitializer<I>,
    std::sync::mpsc::SyncSender<Vec<ExecutorMetrics>>,
);

pub(crate) enum UdpCommand<I: Identity> {
    Send(Box<UdpMsg<I>>),
    Install(Box<Installation<I>>),
    Connect(Box<(UdpSocketId, I, SocketAddr, u64)>),
    Plaintext(Plaintext<I>),
}

/// The bounded application-to-dataplane command queue has no available slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandQueueFull;
impl std::fmt::Display for CommandQueueFull {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UDP dataplane command queue is full")
    }
}
impl std::error::Error for CommandQueueFull {}

/// Application-side transport proxy. The protocol is moved into the dataplane;
/// this handle only queues addressed plaintext/commands and reads shared metrics.
pub struct AuthenticatedUdpSocket<AP: AuthenticationProtocol> {
    socket: UdpSocketHandle<AP::PublicKey>,
    metrics: Vec<ExecutorMetrics>,
    _protocol: PhantomData<fn() -> AP>,
}

impl<AP: AuthenticationProtocol> AuthenticatedUdpSocket<AP> {
    pub fn new(socket: UdpSocketHandle<AP::PublicKey>, protocol: AP) -> Self {
        let initialize = protocol.into_initializer();
        let pending_limit = socket.writer.max_pending_bytes;
        let backend: BackendInitializer<AP::PublicKey> = Box::new(move || {
            let protocol = initialize();
            let metrics = protocol.metrics().cloned_metrics();
            (
                Box::new(ProtocolBackend {
                    protocol,
                    pending: VecDeque::new(),
                    pending_bytes: HashMap::new(),
                    total_pending: 0,
                    pending_ready: false,
                    pending_limit,
                }),
                metrics,
            )
        });
        let (installed, ready) = std::sync::mpsc::sync_channel(1);
        assert!(
            socket.command(UdpCommand::Install(Box::new((
                socket.writer.socket_id,
                backend,
                installed
            )))),
            "UDP authentication install queue is full"
        );
        let metrics = ready
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("UDP authentication installation did not complete");
        Self {
            socket,
            metrics,
            _protocol: PhantomData,
        }
    }

    pub fn write(
        &self,
        identity: AP::PublicKey,
        address: SocketAddr,
        payload: Bytes,
        stride: u16,
        priority: UdpPriority,
    ) -> Result<(), CommandQueueFull> {
        if payload.is_empty() {
            return Ok(());
        }
        assert!(stride > 0);
        self.socket
            .command(UdpCommand::Plaintext(Box::new(UdpMsg {
                socket_id: self.socket.writer.socket_id,
                dst: address,
                payload,
                stride,
                priority,
                encryption: Some(Encryption {
                    identity,
                    header_size: AP::HEADER_SIZE,
                }),
            })))
            .then_some(())
            .ok_or(CommandQueueFull)
    }
    /// Acceptance queues a connection request; handshake success is asynchronous.
    pub fn connect(
        &self,
        identity: AP::PublicKey,
        address: SocketAddr,
        attempts: u64,
    ) -> Result<(), CommandQueueFull> {
        self.socket
            .command(UdpCommand::Connect(Box::new((
                self.socket.writer.socket_id,
                identity,
                address,
                attempts,
            ))))
            .then_some(())
            .ok_or(CommandQueueFull)
    }

    pub fn set_priority_identities(&self, identities: HashSet<AP::PublicKey>) {
        self.socket.reader.priority.send_if_modified(|current| {
            if current.0 == identities {
                return false;
            }
            current.0 = identities;
            true
        });
    }
    pub fn set_prioritize(&self, enabled: bool) {
        self.socket.reader.priority.send_if_modified(|current| {
            if current.1 == enabled {
                return false;
            }
            current.1 = enabled;
            true
        });
    }

    pub async fn recv(&mut self) -> RecvUdpMsg<AP::PublicKey> {
        self.socket.recv().await
    }
    pub async fn recv_many(
        &mut self,
        messages: &mut Vec<RecvUdpMsg<AP::PublicKey>>,
        limit: usize,
    ) -> usize {
        self.socket.recv_many(messages, limit).await
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr()
    }
    pub fn metrics(&self) -> ExecutorMetricsChain<'_> {
        self.metrics
            .iter()
            .fold(ExecutorMetricsChain::default(), |chain, metrics| {
                chain.push(metrics)
            })
    }
}

pub(crate) type BackendInitializer<I> =
    Box<dyn FnOnce() -> (Box<dyn Backend<I>>, Vec<ExecutorMetrics>) + Send>;

pub(crate) trait Backend<I: Identity> {
    fn receive(
        &mut self,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<Option<(Bytes, Option<I>)>, ()>;
    fn connect(&mut self, key: I, addr: SocketAddr, attempts: u64);
    fn prepare(
        &mut self,
        socket_id: UdpSocketId,
        plaintext: Plaintext<I>,
        output: &mut Vec<Box<UdpMsg<I>>>,
    );
    fn writer(
        &mut self,
        encryption: Encryption<I>,
        addr: SocketAddr,
        plaintext_len: usize,
    ) -> Option<monad_wireauth::Writer>;
    fn deadline(&self) -> Option<Instant>;
    fn tick(&mut self);
    fn drain(&mut self, socket_id: UdpSocketId, output: &mut Vec<Box<UdpMsg<I>>>);
}

struct ProtocolBackend<AP: AuthenticationProtocol> {
    protocol: AP,
    pending: VecDeque<Plaintext<AP::PublicKey>>,
    pending_bytes: HashMap<AP::PublicKey, usize>,
    total_pending: usize,
    pending_ready: bool,
    pending_limit: usize,
}

impl<AP: AuthenticationProtocol> ProtocolBackend<AP> {
    fn route(&self, plaintext: &Plaintext<AP::PublicKey>) -> Option<SocketAddr> {
        self.protocol
            .is_connected_socket_and_public_key(
                &plaintext.dst,
                &plaintext
                    .encryption
                    .as_ref()
                    .expect("authenticated plaintext")
                    .identity,
            )
            .then_some(plaintext.dst)
    }
    fn routed(
        socket_id: UdpSocketId,
        mut plaintext: Plaintext<AP::PublicKey>,
        addr: SocketAddr,
    ) -> Box<UdpMsg<AP::PublicKey>> {
        debug_assert_eq!(socket_id, plaintext.socket_id);
        plaintext.dst = addr;
        plaintext
    }
}

impl<AP: AuthenticationProtocol> Backend<AP::PublicKey> for ProtocolBackend<AP> {
    fn receive(
        &mut self,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<Option<(Bytes, Option<AP::PublicKey>)>, ()> {
        match self.protocol.dispatch(packet, addr) {
            Ok(Some(message)) => Ok(Some(message)),
            Ok(None) => {
                self.pending_ready = true;
                Ok(None)
            }
            Err(error) => {
                debug!(?addr, ?error, "UDP authentication rejected packet");
                Err(())
            }
        }
    }
    fn connect(&mut self, key: AP::PublicKey, addr: SocketAddr, attempts: u64) {
        if let Err(error) = self.protocol.connect(&key, addr, attempts) {
            debug!(?addr, ?error, "UDP authentication connection failed");
        }
    }
    fn prepare(
        &mut self,
        socket_id: UdpSocketId,
        plaintext: Plaintext<AP::PublicKey>,
        output: &mut Vec<Box<UdpMsg<AP::PublicKey>>>,
    ) {
        if let Some(addr) = self.route(&plaintext) {
            output.push(Self::routed(socket_id, plaintext, addr));
            return;
        }
        if !self
            .protocol
            .has_initiator_session_by_socket_and_public_key(
                &plaintext.dst,
                &plaintext
                    .encryption
                    .as_ref()
                    .expect("authenticated plaintext")
                    .identity,
            )
        {
            self.connect(
                plaintext
                    .encryption
                    .as_ref()
                    .expect("authenticated plaintext")
                    .identity,
                plaintext.dst,
                2,
            );
        }
        if let Some(addr) = self.route(&plaintext) {
            output.push(Self::routed(socket_id, plaintext, addr));
            return;
        }
        if !self
            .protocol
            .has_initiator_session_by_socket_and_public_key(
                &plaintext.dst,
                &plaintext
                    .encryption
                    .as_ref()
                    .expect("authenticated plaintext")
                    .identity,
            )
        {
            return;
        }
        let bytes = plaintext.payload.len() + std::mem::size_of_val(&*plaintext);
        let used = self
            .pending_bytes
            .get(
                &plaintext
                    .encryption
                    .as_ref()
                    .expect("authenticated plaintext")
                    .identity,
            )
            .copied()
            .unwrap_or(0);
        // Handshake buffering stays plaintext outside WireAuth's own buffering,
        // which encrypts automatically when the handshake completes. Ready data
        // must first re-enter the pacing queue, retaining its traffic priority.
        if bytes > self.protocol.max_buffered_bytes().saturating_sub(used)
            || bytes > self.pending_limit.saturating_sub(self.total_pending)
        {
            return;
        }
        *self
            .pending_bytes
            .entry(
                plaintext
                    .encryption
                    .as_ref()
                    .expect("authenticated plaintext")
                    .identity,
            )
            .or_default() += bytes;
        self.total_pending += bytes;
        self.pending.push_back(plaintext);
    }
    fn writer(
        &mut self,
        encryption: Encryption<AP::PublicKey>,
        addr: SocketAddr,
        plaintext_len: usize,
    ) -> Option<monad_wireauth::Writer> {
        self.protocol
            .writer_for_peer(&encryption.identity, addr, plaintext_len)
    }
    fn deadline(&self) -> Option<Instant> {
        self.protocol.next_deadline()
    }
    fn tick(&mut self) {
        self.protocol.tick();
        self.pending_ready = true;
    }
    fn drain(&mut self, socket_id: UdpSocketId, output: &mut Vec<Box<UdpMsg<AP::PublicKey>>>) {
        while let Some((dst, payload)) = self.protocol.next_packet() {
            output.push(Box::new(UdpMsg {
                socket_id,
                dst,
                stride: payload.len().max(1).try_into().unwrap(),
                payload,
                priority: UdpPriority::High,
                encryption: None,
            }));
        }
        if !std::mem::take(&mut self.pending_ready) {
            return;
        }
        for _ in 0..self.pending.len() {
            let plaintext = self.pending.pop_front().unwrap();
            let route = self.route(&plaintext);
            let has_session = self
                .protocol
                .has_initiator_session_by_socket_and_public_key(
                    &plaintext.dst,
                    &plaintext
                        .encryption
                        .as_ref()
                        .expect("authenticated plaintext")
                        .identity,
                );
            if route.is_none() && has_session {
                self.pending.push_back(plaintext);
                continue;
            }
            let bytes = plaintext.payload.len() + std::mem::size_of_val(&*plaintext);
            let used = self
                .pending_bytes
                .get_mut(
                    &plaintext
                        .encryption
                        .as_ref()
                        .expect("authenticated plaintext")
                        .identity,
                )
                .unwrap();
            *used -= bytes;
            if *used == 0 {
                self.pending_bytes.remove(
                    &plaintext
                        .encryption
                        .as_ref()
                        .expect("authenticated plaintext")
                        .identity,
                );
            }
            self.total_pending -= bytes;
            if let Some(addr) = route {
                output.push(Self::routed(socket_id, plaintext, addr));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, sync::Mutex, time::Duration};

    use super::*;
    use crate::{DataplaneBuilder, UdpPacingConfig};

    #[derive(Clone)]
    struct Recorded(Arc<Mutex<Vec<(String, Instant)>>>);
    struct RecordingProtocol {
        recorded: Recorded,
        remote: Option<(u64, SocketAddr)>,
        handshake_pending: bool,
    }
    struct RecordingWriter(Recorded);
    impl monad_wireauth::PacketWriter for RecordingWriter {
        fn encrypt_into(
            &self,
            plaintext: &[u8],
            output: &mut [u8],
        ) -> Result<(), monad_wireauth::WriterError> {
            self.0 .0.lock().unwrap().push((
                std::thread::current().name().unwrap_or("").to_owned(),
                Instant::now(),
            ));
            let (header, body) = output.split_at_mut(8);
            header.fill(1);
            body.copy_from_slice(plaintext);
            Ok(())
        }
    }
    impl AuthenticationProtocol for RecordingProtocol {
        type PublicKey = u64;
        type Error = ();
        type Header = [u8; 8];
        const HEADER_SIZE: u16 = 8;
        fn into_initializer(self) -> Box<dyn FnOnce() -> Self + Send> {
            Box::new(move || {
                assert_eq!(std::thread::current().name(), Some("monad-dataplane"));
                self
            })
        }
        fn writer_for_peer(
            &mut self,
            key: &u64,
            addr: SocketAddr,
            _: usize,
        ) -> Option<monad_wireauth::Writer> {
            self.is_connected_socket_and_public_key(&addr, key)
                .then(|| Arc::new(RecordingWriter(self.recorded.clone())) as monad_wireauth::Writer)
        }
        fn connect(&mut self, key: &u64, addr: SocketAddr, _: u64) -> Result<(), ()> {
            self.remote = Some((*key, addr));
            Ok(())
        }
        fn dispatch(
            &mut self,
            packet: &mut [u8],
            _: SocketAddr,
        ) -> Result<Option<(Bytes, Option<u64>)>, ()> {
            if packet == b"handshake" {
                self.handshake_pending = false;
                return Ok(None);
            }
            if packet.len() < 8 || packet[..8] != [1; 8] {
                return Err(());
            }
            assert_eq!(std::thread::current().name(), Some("monad-dataplane"));
            Ok(Some((Bytes::copy_from_slice(&packet[8..]), Some(1))))
        }
        fn encrypt_by_public_key(&mut self, _: &u64, _: &mut [u8]) -> Result<Self::Header, ()> {
            self.recorded.0.lock().unwrap().push((
                std::thread::current().name().unwrap_or("").to_owned(),
                Instant::now(),
            ));
            Ok([1; 8])
        }
        fn encrypt_by_socket(
            &mut self,
            _: &SocketAddr,
            packet: &mut [u8],
        ) -> Result<Self::Header, ()> {
            self.encrypt_by_public_key(&1, packet)
        }

        fn is_connected_public_key(&self, key: &u64) -> bool {
            !self.handshake_pending && self.remote.is_some_and(|(remote, _)| remote == *key)
        }
        fn is_connected_socket_and_public_key(&self, addr: &SocketAddr, key: &u64) -> bool {
            !self.handshake_pending && self.remote == Some((*key, *addr))
        }
        fn get_socket_by_public_key(&self, key: &u64) -> Option<SocketAddr> {
            self.remote
                .filter(|(remote, _)| remote == key)
                .map(|(_, addr)| addr)
        }
        fn has_any_session_by_public_key(&self, key: &u64) -> bool {
            self.is_connected_public_key(key)
        }
        fn has_initiator_session_by_public_key(&self, key: &u64) -> bool {
            self.handshake_pending && self.remote.is_some_and(|(remote, _)| remote == *key)
        }
        fn has_initiator_session_by_socket_and_public_key(
            &self,
            addr: &SocketAddr,
            key: &u64,
        ) -> bool {
            self.handshake_pending && self.remote == Some((*key, *addr))
        }
        fn next_packet(&mut self) -> Option<(SocketAddr, Bytes)> {
            None
        }
        fn tick(&mut self) {}
        fn next_deadline(&self) -> Option<Instant> {
            None
        }
        fn metrics(&self) -> ExecutorMetricsChain<'_> {
            ExecutorMetricsChain::default()
        }
    }

    #[test]
    fn handshake_releases_plaintext_with_priority_before_encryption() {
        let recorded = Recorded(Arc::new(Mutex::new(Vec::new())));
        let mut backend = ProtocolBackend {
            protocol: RecordingProtocol {
                recorded: recorded.clone(),
                remote: None,
                handshake_pending: true,
            },
            pending: VecDeque::new(),
            pending_bytes: HashMap::new(),
            total_pending: 0,
            pending_ready: false,
            pending_limit: 1024 * 1024,
        };
        let destination = "127.0.0.1:12345".parse().unwrap();
        let mut output = Vec::new();
        backend.prepare(
            UdpSocketId::AuthenticatedRaptorcast,
            Box::new(UdpMsg {
                socket_id: UdpSocketId::AuthenticatedRaptorcast,
                dst: destination,
                payload: Bytes::from_static(b"plaintext"),
                stride: 9,
                priority: UdpPriority::Regular,
                encryption: Some(Encryption {
                    identity: 1,
                    header_size: 8,
                }),
            }),
            &mut output,
        );
        assert!(output.is_empty());
        assert_eq!(backend.pending.len(), 1);
        let mut handshake = *b"handshake";
        backend.receive(&mut handshake, destination).unwrap();
        backend.drain(UdpSocketId::AuthenticatedRaptorcast, &mut output);
        assert!(backend.pending.is_empty());
        assert_eq!(backend.total_pending, 0);
        assert!(backend.pending_bytes.is_empty());
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].payload.as_ref(), b"plaintext");
        assert_eq!(output[0].stride, 9);
        assert_eq!(output[0].priority, UdpPriority::Regular);
        assert!(output[0].encryption.is_some());
        assert!(recorded.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn encryption_runs_on_workers_after_peer_deadline() {
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let destination = sink.local_addr().unwrap();
        let mut dp = DataplaneBuilder::new(1_000)
            .with_udp_pacing_config(UdpPacingConfig {
                peer_bandwidth_mbps: 1,
                max_queued_bytes: 1024 * 1024,
            })
            .with_udp_sockets([(
                UdpSocketId::AuthenticatedRaptorcast,
                "127.0.0.1:0".parse().unwrap(),
            )])
            .build_with_identity::<u64>();
        let raw = dp
            .udp_sockets
            .take(UdpSocketId::AuthenticatedRaptorcast)
            .unwrap();
        let writer = raw.writer().clone();
        let recorded = Recorded(Arc::new(Mutex::new(Vec::new())));
        let socket = AuthenticatedUdpSocket::new(
            raw,
            RecordingProtocol {
                recorded: recorded.clone(),
                remote: None,
                handshake_pending: false,
            },
        );
        // A cloned raw writer must not bypass authentication once installed.
        writer.write(destination, Bytes::from_static(b"raw"), 3);
        socket.connect(1, destination, 1).unwrap();
        socket
            .write(
                1,
                destination,
                vec![2; 60_000].into(),
                60_000,
                UdpPriority::Regular,
            )
            .unwrap();
        socket
            .write(
                1,
                destination,
                Bytes::from_static(&[3]),
                1,
                UdpPriority::Regular,
            )
            .unwrap();
        let mut bytes = vec![0; 65_536];
        assert_eq!(sink.recv_from(&mut bytes).unwrap().0, 60_008);
        assert_eq!(sink.recv_from(&mut bytes).unwrap().0, 9);
        let events = recorded.0.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .all(|(name, _)| name.starts_with("monad-udp-tx-")));
        assert!(
            events[1].1.duration_since(events[0].1) >= Duration::from_millis(400),
            "the second packet must remain plaintext while peer pacing delays it"
        );
        let drops = dp
            .metrics()
            .metric_handles()
            .into_iter()
            .find(|(name, _, _)| *name == "monad.dataplane.udp.total_egress_messages_dropped");
        assert!(drops.unwrap().1.get() >= 1);
    }

    #[tokio::test]
    async fn typed_ingress_rejects_packets_before_authentication_installation() {
        use futures::poll;
        let mut dp = DataplaneBuilder::new(1_000)
            .with_udp_sockets([(
                UdpSocketId::AuthenticatedRaptorcast,
                "127.0.0.1:0".parse().unwrap(),
            )])
            .build_with_identity::<u64>();
        let mut raw = dp
            .udp_sockets
            .take(UdpSocketId::AuthenticatedRaptorcast)
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"unauthenticated", raw.local_addr())
            .unwrap();
        let received = dp
            .metrics()
            .metric_handles()
            .into_iter()
            .find(|(name, _, _)| *name == "monad.dataplane.udp.total_messages_received")
            .unwrap()
            .1;
        tokio::time::timeout(Duration::from_secs(1), async {
            while received.get() == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(poll!(std::pin::pin!(raw.recv())).is_pending());
        let mut socket = AuthenticatedUdpSocket::new(
            raw,
            RecordingProtocol {
                recorded: Recorded(Arc::new(Mutex::new(Vec::new()))),
                remote: None,
                handshake_pending: false,
            },
        );
        sender.send_to(&[1; 9], socket.local_addr()).unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(1), socket.recv())
            .await
            .unwrap();
        assert_eq!(msg.sender, Some(1));
        assert_eq!(msg.payload.as_ref(), &[1]);
    }
}
