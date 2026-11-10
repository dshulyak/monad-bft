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
//! wire bytes and encrypts selected plaintext immediately before worker dispatch.
//! Handshake buffering retains plaintext and priority outside WireAuth's own
//! encrypt-on-establishment buffer. Timers and handshake responses do not depend
//! on application receive polling. Session views expose shared metrics and a
//! bounded cache of connection metadata, without sharing the protocol engine.

use std::{convert::TryFrom, fmt::Debug, hash::Hash, net::SocketAddr, sync::Arc, time::Instant};

use bytes::Bytes;
use monad_executor::ExecutorMetricsChain;
use monad_wireauth::messages::{DataPacketHeader, Packet};
use zerocopy::{Immutable, IntoBytes};

/// An authenticated sender's grouping key. Transport scheduling does not depend
/// on a particular signature scheme or application node-ID representation.
pub trait Identity: Copy + Debug + Eq + Ord + Hash + Send + Sync + Unpin + 'static {}
impl<T: Copy + Debug + Eq + Ord + Hash + Send + Sync + Unpin + 'static> Identity for T {}

pub trait AuthenticationProtocol: Send + 'static {
    type PublicKey: Identity;
    type Error: std::fmt::Debug + Send + 'static;
    type Header: IntoBytes + Immutable;

    const HEADER_SIZE: u16;

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

pub struct WireAuthProtocol {
    buffer_limit: usize,
    api: monad_wireauth::API<
        monad_wireauth::StdContext<secp256k1::rand::rngs::StdRng>,
        Arc<monad_secp::KeyPair>,
    >,
}

impl WireAuthProtocol {
    pub fn new(
        metric_names: &'static monad_wireauth::MetricNames,
        config: monad_wireauth::Config,
        signing_key: Arc<monad_secp::KeyPair>,
    ) -> Self {
        use secp256k1::rand::SeedableRng;
        let context =
            monad_wireauth::StdContext::with_rng(secp256k1::rand::rngs::StdRng::from_os_rng());
        Self {
            buffer_limit: config.max_buffered_bytes_per_session,
            api: monad_wireauth::API::new(metric_names, config, signing_key, context),
        }
    }
}

impl AuthenticationProtocol for WireAuthProtocol {
    type PublicKey = monad_secp::PubKey;
    type Error = monad_wireauth::Error;
    type Header = monad_wireauth::messages::DataPacketHeader;

    const HEADER_SIZE: u16 = DataPacketHeader::SIZE as u16;

    fn max_buffered_bytes(&self) -> usize {
        self.buffer_limit
    }

    fn connect(
        &mut self,
        remote_public_key: &Self::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), Self::Error> {
        self.api
            .connect(*remote_public_key, remote_addr, retry_attempts)
    }

    fn dispatch(
        &mut self,
        packet: &mut [u8],
        remote_addr: SocketAddr,
    ) -> Result<Option<(Bytes, Option<Self::PublicKey>)>, Self::Error> {
        match Packet::try_from(packet).map_err(monad_wireauth::Error::from)? {
            Packet::Control(control_packet) => {
                self.api.dispatch_control(control_packet, remote_addr)?;
                Ok(None)
            }
            Packet::Data(data_packet) => {
                let (plaintext, public_key) = self.api.decrypt(data_packet, remote_addr)?;
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
        self.api.encrypt_by_public_key(public_key, plaintext)
    }

    fn encrypt_by_socket(
        &mut self,
        socket_addr: &SocketAddr,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        self.api.encrypt_by_socket(socket_addr, plaintext)
    }

    fn next_packet(&mut self) -> Option<(SocketAddr, Bytes)> {
        self.api.next_packet()
    }

    fn tick(&mut self) {
        self.api.tick();
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.api.next_deadline()
    }

    fn is_connected_public_key(&self, public_key: &Self::PublicKey) -> bool {
        self.api.is_connected_public_key(public_key)
    }

    fn is_connected_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &Self::PublicKey,
    ) -> bool {
        self.api
            .is_connected_socket_and_public_key(socket_addr, public_key)
    }

    fn get_socket_by_public_key(&self, public_key: &Self::PublicKey) -> Option<SocketAddr> {
        self.api.get_socket_by_public_key(public_key)
    }

    fn has_any_session_by_public_key(&self, public_key: &Self::PublicKey) -> bool {
        self.api.has_any_session_by_public_key(public_key)
    }

    fn has_initiator_session_by_public_key(&self, public_key: &Self::PublicKey) -> bool {
        self.api.has_initiator_session_by_public_key(public_key)
    }

    fn has_initiator_session_by_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &Self::PublicKey,
    ) -> bool {
        self.api
            .has_initiator_session_by_socket_and_public_key(socket_addr, public_key)
    }

    fn metrics(&self) -> ExecutorMetricsChain<'_> {
        self.api.metrics()
    }
}

use std::{
    collections::{HashMap, HashSet, VecDeque},
    marker::PhantomData,
    sync::RwLock,
};

use monad_executor::ExecutorMetrics;
use monad_types::UdpPriority;
use tracing::debug;

use crate::{RecvUdpMsg, UdpMsg, UdpSocketHandle, UdpSocketId};

#[derive(Clone, Copy)]
pub(crate) struct Encryption<I: Identity> {
    pub identity: I,
    pub by_address: bool,
    pub header_size: u16,
}

pub(crate) struct Plaintext<I: Identity> {
    pub identity: I,
    pub address: Option<SocketAddr>,
    pub payload: Bytes,
    pub stride: u16,
    pub priority: UdpPriority,
}

pub(crate) enum UdpCommand<I: Identity> {
    Send(UdpMsg<I>),
    Install(
        UdpSocketId,
        Box<dyn Backend<I>>,
        std::sync::mpsc::SyncSender<()>,
    ),
    Connect(UdpSocketId, I, SocketAddr, u64),
    Plaintext(UdpSocketId, Plaintext<I>),
}

#[derive(Clone, Default)]
struct Peer {
    address: Option<SocketAddr>,
    any: bool,
    initiator: bool,
    connected: bool,
    connected_addresses: HashSet<SocketAddr>,
}

type Peers<I> = Arc<RwLock<HashMap<I, Peer>>>;

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
/// this handle only queues plaintext/commands and reads published session views.
pub struct AuthenticatedUdpSocket<AP: AuthenticationProtocol> {
    socket: UdpSocketHandle<AP::PublicKey>,
    peers: Peers<AP::PublicKey>,
    metrics: Vec<ExecutorMetrics>,
    _protocol: PhantomData<fn() -> AP>,
}

impl<AP: AuthenticationProtocol> AuthenticatedUdpSocket<AP> {
    pub fn new(socket: UdpSocketHandle<AP::PublicKey>, protocol: AP) -> Self {
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let metrics = protocol.metrics().cloned_metrics();
        let backend = ProtocolBackend {
            protocol,
            peers: peers.clone(),
            known: lru::LruCache::new(std::num::NonZeroUsize::new(1000).unwrap()),
            pending: VecDeque::new(),
            pending_bytes: HashMap::new(),
            total_pending: 0,
            pending_ready: false,
            pending_limit: socket.writer.max_pending_bytes,
        };
        let (installed, ready) = std::sync::mpsc::sync_channel(1);
        assert!(
            socket.command(UdpCommand::Install(
                socket.writer.socket_id,
                Box::new(backend),
                installed
            )),
            "UDP authentication install queue is full"
        );
        ready
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("UDP authentication installation did not complete");
        Self {
            socket,
            peers,
            metrics,
            _protocol: PhantomData,
        }
    }

    pub fn write(
        &self,
        identity: AP::PublicKey,
        address: Option<SocketAddr>,
        payload: Bytes,
        stride: u16,
        priority: UdpPriority,
    ) -> Result<(), CommandQueueFull> {
        if payload.is_empty() {
            return Ok(());
        }
        assert!(stride > 0);
        self.socket
            .command(UdpCommand::Plaintext(
                self.socket.writer.socket_id,
                Plaintext {
                    identity,
                    address,
                    payload,
                    stride,
                    priority,
                },
            ))
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
            .command(UdpCommand::Connect(
                self.socket.writer.socket_id,
                identity,
                address,
                attempts,
            ))
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
    pub fn is_connected_public_key(&self, key: &AP::PublicKey) -> bool {
        self.peers
            .read()
            .unwrap()
            .get(key)
            .is_some_and(|peer| peer.connected)
    }
    pub fn is_connected_socket_and_public_key(
        &self,
        address: &SocketAddr,
        key: &AP::PublicKey,
    ) -> bool {
        self.peers
            .read()
            .unwrap()
            .get(key)
            .is_some_and(|peer| peer.connected_addresses.contains(address))
    }
    pub fn get_socket_by_public_key(&self, key: &AP::PublicKey) -> Option<SocketAddr> {
        self.peers
            .read()
            .unwrap()
            .get(key)
            .and_then(|peer| peer.address)
    }
    pub fn has_any_session_by_public_key(&self, key: &AP::PublicKey) -> bool {
        self.peers
            .read()
            .unwrap()
            .get(key)
            .is_some_and(|peer| peer.any)
    }
    pub fn has_initiator_session_by_public_key(&self, key: &AP::PublicKey) -> bool {
        self.peers
            .read()
            .unwrap()
            .get(key)
            .is_some_and(|peer| peer.initiator)
    }
    pub fn metrics(&self) -> ExecutorMetricsChain<'_> {
        self.metrics
            .iter()
            .fold(ExecutorMetricsChain::default(), |chain, metrics| {
                chain.push(metrics)
            })
    }
}

pub(crate) trait Backend<I: Identity>: Send {
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
        output: &mut Vec<UdpMsg<I>>,
    );
    fn encrypt(
        &mut self,
        encryption: Encryption<I>,
        addr: SocketAddr,
        plaintext: Bytes,
        stride: u16,
    ) -> Option<Bytes>;
    fn deadline(&self) -> Option<Instant>;
    fn tick(&mut self);
    fn drain(&mut self, socket_id: UdpSocketId, output: &mut Vec<UdpMsg<I>>);
}

struct ProtocolBackend<AP: AuthenticationProtocol> {
    protocol: AP,
    peers: Peers<AP::PublicKey>,
    known: lru::LruCache<AP::PublicKey, HashSet<SocketAddr>>,
    pending: VecDeque<Plaintext<AP::PublicKey>>,
    pending_bytes: HashMap<AP::PublicKey, usize>,
    total_pending: usize,
    pending_ready: bool,
    pending_limit: usize,
}

impl<AP: AuthenticationProtocol> ProtocolBackend<AP> {
    fn remember(&mut self, key: AP::PublicKey, address: Option<SocketAddr>) {
        if self.known.get(&key).is_none() {
            if self.known.len() == self.known.cap().get() {
                if let Some((evicted, _)) = self.known.pop_lru() {
                    self.peers.write().unwrap().remove(&evicted);
                }
            }
            self.known.put(key, HashSet::new());
        }
        let addresses = self.known.get_mut(&key).unwrap();
        if let Some(address) = address {
            if !addresses.contains(&address) && addresses.len() == 8 {
                addresses.clear();
            }
            addresses.insert(address);
        }
    }
    fn publish(&self) {
        let mut peers = self.peers.write().unwrap();
        for (key, addresses) in self.known.iter() {
            let peer = Peer {
                address: self.protocol.get_socket_by_public_key(key),
                any: self.protocol.has_any_session_by_public_key(key),
                initiator: self.protocol.has_initiator_session_by_public_key(key),
                connected: self.protocol.is_connected_public_key(key),
                connected_addresses: addresses
                    .iter()
                    .copied()
                    .filter(|addr| self.protocol.is_connected_socket_and_public_key(addr, key))
                    .collect(),
            };
            peers.insert(*key, peer);
        }
    }
    fn route(&self, plaintext: &Plaintext<AP::PublicKey>) -> Option<(SocketAddr, bool)> {
        match plaintext.address {
            Some(addr)
                if self
                    .protocol
                    .is_connected_socket_and_public_key(&addr, &plaintext.identity) =>
            {
                Some((addr, true))
            }
            Some(_) => None,
            None if self.protocol.is_connected_public_key(&plaintext.identity) => self
                .protocol
                .get_socket_by_public_key(&plaintext.identity)
                .map(|addr| (addr, false)),
            None => None,
        }
    }
    fn routed(
        socket_id: UdpSocketId,
        plaintext: Plaintext<AP::PublicKey>,
        addr: SocketAddr,
        by_address: bool,
    ) -> UdpMsg<AP::PublicKey> {
        UdpMsg {
            socket_id,
            dst: addr,
            payload: plaintext.payload,
            stride: plaintext.stride,
            priority: plaintext.priority,
            encryption: Some(Encryption {
                identity: plaintext.identity,
                by_address,
                header_size: AP::HEADER_SIZE,
            }),
        }
    }
}

impl<AP: AuthenticationProtocol> Backend<AP::PublicKey> for ProtocolBackend<AP> {
    fn receive(
        &mut self,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<Option<(Bytes, Option<AP::PublicKey>)>, ()> {
        match self.protocol.dispatch(packet, addr) {
            Ok(Some((bytes, identity))) => {
                if let Some(key) = identity {
                    if !self
                        .known
                        .get(&key)
                        .is_some_and(|addresses| addresses.contains(&addr))
                    {
                        self.remember(key, Some(addr));
                        self.publish();
                    }
                }
                Ok(Some((bytes, identity)))
            }
            Ok(None) => {
                self.pending_ready = true;
                self.publish();
                Ok(None)
            }
            Err(error) => {
                debug!(?addr, ?error, "UDP authentication rejected packet");
                Err(())
            }
        }
    }
    fn connect(&mut self, key: AP::PublicKey, addr: SocketAddr, attempts: u64) {
        self.remember(key, Some(addr));
        if let Err(error) = self.protocol.connect(&key, addr, attempts) {
            debug!(?addr, ?error, "UDP authentication connection failed");
        }
        self.publish();
    }
    fn prepare(
        &mut self,
        socket_id: UdpSocketId,
        plaintext: Plaintext<AP::PublicKey>,
        output: &mut Vec<UdpMsg<AP::PublicKey>>,
    ) {
        self.remember(plaintext.identity, plaintext.address);
        if let Some((addr, by_address)) = self.route(&plaintext) {
            output.push(Self::routed(socket_id, plaintext, addr, by_address));
            return;
        }
        if let Some(addr) = plaintext.address {
            if !self
                .protocol
                .has_initiator_session_by_socket_and_public_key(&addr, &plaintext.identity)
            {
                self.connect(plaintext.identity, addr, 2);
            }
        }
        if let Some((addr, by_address)) = self.route(&plaintext) {
            output.push(Self::routed(socket_id, plaintext, addr, by_address));
            return;
        }
        if !self
            .protocol
            .has_initiator_session_by_public_key(&plaintext.identity)
        {
            return;
        }
        let bytes = plaintext.payload.len() + std::mem::size_of_val(&plaintext);
        let used = self
            .pending_bytes
            .get(&plaintext.identity)
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
        *self.pending_bytes.entry(plaintext.identity).or_default() += bytes;
        self.total_pending += bytes;
        self.pending.push_back(plaintext);
    }
    fn encrypt(
        &mut self,
        encryption: Encryption<AP::PublicKey>,
        addr: SocketAddr,
        mut plaintext: Bytes,
        stride: u16,
    ) -> Option<Bytes> {
        // A route may change while plaintext waits in the pacing queue. Never
        // encrypt for a different peer/session and send to the stale address.
        if encryption.by_address {
            if !self
                .protocol
                .is_connected_socket_and_public_key(&addr, &encryption.identity)
            {
                return None;
            }
        } else if self.protocol.get_socket_by_public_key(&encryption.identity) != Some(addr) {
            return None;
        }
        let header_size = usize::from(AP::HEADER_SIZE);
        let mut encrypted = bytes::BytesMut::with_capacity(
            plaintext.len() + plaintext.len().div_ceil(usize::from(stride)) * header_size,
        );
        while !plaintext.is_empty() {
            let piece = plaintext.split_to(plaintext.len().min(usize::from(stride)));
            let start = encrypted.len();
            encrypted.resize(start + header_size, 0);
            encrypted.extend_from_slice(&piece);
            let result = if encryption.by_address {
                self.protocol
                    .encrypt_by_socket(&addr, &mut encrypted[start + header_size..])
            } else {
                self.protocol.encrypt_by_public_key(
                    &encryption.identity,
                    &mut encrypted[start + header_size..],
                )
            };
            let header = match result {
                Ok(header) => header,
                Err(error) => {
                    debug!(?addr, ?error, "paced UDP encryption failed");
                    return None;
                }
            };
            encrypted[start..start + header_size].copy_from_slice(header.as_bytes());
        }
        Some(encrypted.freeze())
    }
    fn deadline(&self) -> Option<Instant> {
        self.protocol.next_deadline()
    }
    fn tick(&mut self) {
        self.protocol.tick();
        self.pending_ready = true;
        self.publish();
    }
    fn drain(&mut self, socket_id: UdpSocketId, output: &mut Vec<UdpMsg<AP::PublicKey>>) {
        while let Some((dst, payload)) = self.protocol.next_packet() {
            output.push(UdpMsg {
                socket_id,
                dst,
                stride: payload.len().max(1).try_into().unwrap(),
                payload,
                priority: UdpPriority::High,
                encryption: None,
            });
        }
        if !std::mem::take(&mut self.pending_ready) {
            return;
        }
        for _ in 0..self.pending.len() {
            let plaintext = self.pending.pop_front().unwrap();
            let route = self.route(&plaintext);
            let has_session = match plaintext.address {
                Some(addr) => self
                    .protocol
                    .has_initiator_session_by_socket_and_public_key(&addr, &plaintext.identity),
                None => self
                    .protocol
                    .has_initiator_session_by_public_key(&plaintext.identity),
            };
            if route.is_none() && has_session {
                self.pending.push_back(plaintext);
                continue;
            }
            let bytes = plaintext.payload.len() + std::mem::size_of_val(&plaintext);
            let used = self.pending_bytes.get_mut(&plaintext.identity).unwrap();
            *used -= bytes;
            if *used == 0 {
                self.pending_bytes.remove(&plaintext.identity);
            }
            self.total_pending -= bytes;
            if let Some((addr, by_address)) = route {
                output.push(Self::routed(socket_id, plaintext, addr, by_address));
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
    }
    impl AuthenticationProtocol for RecordingProtocol {
        type PublicKey = u64;
        type Error = ();
        type Header = [u8; 8];
        const HEADER_SIZE: u16 = 8;
        fn connect(&mut self, key: &u64, addr: SocketAddr, _: u64) -> Result<(), ()> {
            self.remote = Some((*key, addr));
            Ok(())
        }
        fn dispatch(
            &mut self,
            packet: &mut [u8],
            _: SocketAddr,
        ) -> Result<Option<(Bytes, Option<u64>)>, ()> {
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
            self.remote.is_some_and(|(remote, _)| remote == *key)
        }
        fn is_connected_socket_and_public_key(&self, addr: &SocketAddr, key: &u64) -> bool {
            self.remote == Some((*key, *addr))
        }
        fn get_socket_by_public_key(&self, key: &u64) -> Option<SocketAddr> {
            self.remote
                .filter(|(remote, _)| remote == key)
                .map(|(_, addr)| addr)
        }
        fn has_any_session_by_public_key(&self, key: &u64) -> bool {
            self.is_connected_public_key(key)
        }
        fn has_initiator_session_by_public_key(&self, _: &u64) -> bool {
            false
        }
        fn has_initiator_session_by_socket_and_public_key(&self, _: &SocketAddr, _: &u64) -> bool {
            false
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

    #[tokio::test]
    async fn encryption_runs_on_dataplane_after_peer_pacing() {
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
            },
        );
        // A cloned raw writer must not bypass authentication once installed.
        writer.write(destination, Bytes::from_static(b"raw"), 3);
        socket.connect(1, destination, 1).unwrap();
        socket
            .write(
                1,
                Some(destination),
                vec![2; 60_000].into(),
                60_000,
                UdpPriority::Regular,
            )
            .unwrap();
        socket
            .write(
                1,
                Some(destination),
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
        assert!(events.iter().all(|(name, _)| name == "monad-dataplane"));
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
