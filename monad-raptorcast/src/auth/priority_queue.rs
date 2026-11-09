// Copyright (C) 2026 Category Labs, Inc.
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

//! Bounded receive buffering with strict priority and round-robin service.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    future::Future,
    net::IpAddr,
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    future::BoxFuture,
    stream::{BoxStream, FuturesUnordered},
    FutureExt, Stream, StreamExt,
};
use lru::LruCache;
use monad_crypto::certificate_signature::PubKey;
use monad_types::NodeId;
use tokio::sync::watch;

use super::AuthRecvMsg;

const BATCH_SIZE: usize = 64;
const LOOKUP_CAPACITY: usize = 1000;

/// Only authenticated public keys may appear here. Ports are deliberately
/// excluded so reconnects cannot multiply an IP's allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sender<P: PubKey> {
    pub ip: IpAddr,
    pub public_key: NodeId<P>,
}

impl<P: PubKey> Sender<P> {
    fn of(message: &AuthRecvMsg<P>) -> Option<Self> {
        Some(Self {
            ip: message.src_addr.ip(),
            public_key: message.sender?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueueIdentity<P: PubKey> {
    PublicKey(NodeId<P>),
    Ip(IpAddr),
}

/// Supplies pinning decisions independently of the receive queue.
///
/// Return the sender's authenticated public key or source IP to pin its group,
/// or None to use the ordinary per-IP queue. A lookup must own its state so it
/// can remain pending while other senders and updates make progress.
pub trait Pinned {
    type PublicKey: PubKey;

    fn lookup(
        &self,
        sender: Sender<Self::PublicKey>,
    ) -> impl Future<Output = Option<QueueIdentity<Self::PublicKey>>> + Send + 'static;

    /// Consume a change notification. Pending must register the caller's waker.
    /// After the update source closes, return Pending without waking the caller.
    fn poll_updated(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}

/// Pinning backed by a watch channel. Public-key pins take precedence over IP
/// pins. Updates are coalesced, and closing the channel preserves its last set.
pub struct WatchPinned<P: PubKey> {
    current: watch::Receiver<HashSet<QueueIdentity<P>>>,
    updates: BoxStream<'static, ()>,
}

impl<P: PubKey> WatchPinned<P> {
    pub fn new(current: watch::Receiver<HashSet<QueueIdentity<P>>>) -> Self {
        let updates = futures::stream::unfold(current.clone(), |mut receiver| async move {
            receiver.changed().await.ok()?;
            Some(((), receiver))
        })
        .boxed();
        Self { current, updates }
    }
}

impl<P: PubKey> Pinned for WatchPinned<P> {
    type PublicKey = P;

    fn lookup(
        &self,
        sender: Sender<P>,
    ) -> impl Future<Output = Option<QueueIdentity<P>>> + Send + 'static {
        let current = self.current.borrow();
        let identity = [
            QueueIdentity::PublicKey(sender.public_key),
            QueueIdentity::Ip(sender.ip),
        ]
        .into_iter()
        .find(|identity| current.contains(identity));
        std::future::ready(identity)
    }

    fn poll_updated(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            // watch::changed can yield when Tokio's cooperative budget runs
            // out, even if a new value exists. Observe the version directly
            // before allowing buffered messages to use cached priority.
            if self.current.borrow_and_update().has_changed() {
                return Poll::Ready(());
            }
            match self.updates.poll_next_unpin(cx) {
                // The notification may refer to a version consumed above.
                Poll::Ready(Some(())) => continue,
                Poll::Ready(None) | Poll::Pending => {
                    // Close the race between checking the version and
                    // registering the asynchronous notification's waker.
                    return if self.current.borrow_and_update().has_changed() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    };
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PriorityQueueConfig {
    pub pinned_bytes: usize,
    pub other_ip_bytes: usize,
    pub total_bytes: usize,
}

impl Default for PriorityQueueConfig {
    fn default() -> Self {
        Self {
            pinned_bytes: 5 * 1024 * 1024,
            other_ip_bytes: 2 * 1024 * 1024,
            total_bytes: 1024 * 1024 * 1024,
        }
    }
}

struct Message<P: PubKey> {
    sequence: u64,
    value: AuthRecvMsg<P>,
}

impl<P: PubKey> Message<P> {
    fn bytes(&self) -> usize {
        // Charge metadata as well, including for empty datagrams.
        self.value.payload.len() + std::mem::size_of::<Self>()
    }
}

#[derive(Default)]
struct Messages<P: PubKey> {
    // Async lookups can complete out of order. Sequence numbers preserve FIFO
    // when several authenticated senders share one ordinary IP queue.
    values: BTreeMap<u64, Message<P>>,
    bytes: usize,
}

impl<P: PubKey> Messages<P> {
    fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, message: Message<P>) {
        self.bytes += message.bytes();
        self.values.insert(message.sequence, message);
    }

    fn pop(&mut self) -> Option<Message<P>> {
        let (_, message) = self.values.pop_first()?;
        self.bytes -= message.bytes();
        Some(message)
    }
}

struct Groups<P: PubKey> {
    queues: HashMap<QueueIdentity<P>, Messages<P>>,
    ready: VecDeque<QueueIdentity<P>>,
}

impl<P: PubKey> Groups<P> {
    fn new() -> Self {
        Self {
            queues: HashMap::new(),
            ready: VecDeque::new(),
        }
    }

    fn bytes(&self, identity: QueueIdentity<P>) -> usize {
        self.queues.get(&identity).map_or(0, |queue| queue.bytes)
    }

    fn push(&mut self, identity: QueueIdentity<P>, message: Message<P>, limit: usize) -> usize {
        let queue = self.queues.entry(identity).or_insert_with(|| {
            self.ready.push_back(identity);
            Messages::new()
        });
        queue.push(message);
        let mut dropped_bytes = 0;
        while queue.bytes > limit {
            let (_, dropped) = queue.values.pop_last().unwrap();
            let bytes = dropped.bytes();
            queue.bytes -= bytes;
            dropped_bytes += bytes;
        }
        if queue.values.is_empty() {
            self.queues.remove(&identity);
            self.ready.retain(|key| *key != identity);
        }
        dropped_bytes
    }

    fn pop(&mut self, pending: &HashMap<Sender<P>, Messages<P>>) -> Option<Message<P>> {
        for _ in 0..self.ready.len() {
            let identity = self.ready.pop_front().unwrap();
            let queue = self.queues.get_mut(&identity).unwrap();
            let sequence = *queue.values.first_key_value().unwrap().0;
            // An unresolved earlier message could belong to this same group.
            // It must not be overtaken by a faster lookup or a cache hit.
            let blocked = pending.iter().any(|(sender, messages)| {
                let same_group = match identity {
                    QueueIdentity::PublicKey(key) => sender.public_key == key,
                    QueueIdentity::Ip(ip) => sender.ip == ip,
                };
                same_group && *messages.values.first_key_value().unwrap().0 < sequence
            });
            if blocked {
                self.ready.push_back(identity);
                continue;
            }
            let message = queue.pop().unwrap();
            if queue.values.is_empty() {
                self.queues.remove(&identity);
            } else {
                self.ready.push_back(identity);
            }
            return Some(message);
        }
        None
    }
}

type LookupResult<P> = (Sender<P>, Option<QueueIdentity<P>>);

/// Receives from one authenticated socket (or an equivalent Stream).
///
/// Each poll reads a bounded batch even with a backlog, then returns one item.
/// Pinned groups always precede ordinary groups, so pinned traffic may starve
/// ordinary traffic. Each class uses round robin across groups and FIFO within
/// a group. Ordinary authenticated identities on the same IP share one queue.
/// Input without an authenticated sender identity is dropped, including when
/// its source IP is pinned. An IP is a grouping key, never authentication.
///
/// Limits account for payload bytes plus per-message metadata. Pending lookups
/// count toward the total and initially share the ordinary IP limit. On a
/// pinning update, admitted data is retained until its new limit is known, then
/// excess newest messages are dropped. Global overflow drops the incoming item.
pub struct PriorityQueue<S: Stream, P: Pinned> {
    socket: S,
    pinned: P,
    config: PriorityQueueConfig,
    priority: Groups<P::PublicKey>,
    ordinary: Groups<P::PublicKey>,
    pending: HashMap<Sender<P::PublicKey>, Messages<P::PublicKey>>,
    pending_ip_bytes: HashMap<IpAddr, usize>,
    lookups: FuturesUnordered<BoxFuture<'static, LookupResult<P::PublicKey>>>,
    resolved: VecDeque<LookupResult<P::PublicKey>>,
    routes: LruCache<Sender<P::PublicKey>, Option<QueueIdentity<P::PublicKey>>>,
    reclassifying: VecDeque<Messages<P::PublicKey>>,
    sequence: u64,
    queued_bytes: usize,
    dropped_bytes: u64,
    socket_closed: bool,
    socket_error: Option<Box<S::Item>>,
}

impl<S: Stream, P: Pinned> PriorityQueue<S, P> {
    pub fn new(socket: S, pinned: P, config: PriorityQueueConfig) -> Self {
        assert!(config.pinned_bytes > 0);
        assert!(config.other_ip_bytes > 0);
        assert!(config.total_bytes > 0);
        Self {
            socket,
            pinned,
            config,
            priority: Groups::new(),
            ordinary: Groups::new(),
            pending: HashMap::new(),
            pending_ip_bytes: HashMap::new(),
            lookups: FuturesUnordered::new(),
            resolved: VecDeque::new(),
            routes: LruCache::new(NonZeroUsize::new(LOOKUP_CAPACITY).unwrap()),
            reclassifying: VecDeque::new(),
            sequence: 0,
            queued_bytes: 0,
            dropped_bytes: 0,
            socket_closed: false,
            socket_error: None,
        }
    }

    pub fn socket_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }

    fn drop_bytes(&mut self, bytes: usize) {
        self.queued_bytes -= bytes;
        self.dropped_bytes += bytes as u64;
    }

    fn push_ready(
        &mut self,
        message: Message<P::PublicKey>,
        route: Option<QueueIdentity<P::PublicKey>>,
    ) {
        let dropped = match route {
            Some(identity) => self
                .priority
                .push(identity, message, self.config.pinned_bytes),
            None => self.ordinary.push(
                QueueIdentity::Ip(message.value.src_addr.ip()),
                message,
                self.config.other_ip_bytes,
            ),
        };
        self.drop_bytes(dropped);
    }

    fn push_pending(&mut self, message: Message<P::PublicKey>) {
        let sender = Sender::of(&message.value).expect("queued senders must be authenticated");
        let queue = self.pending.entry(sender).or_insert_with(|| {
            let lookup = self.pinned.lookup(sender);
            self.lookups
                .push(async move { (sender, lookup.await) }.boxed());
            Messages::new()
        });
        *self.pending_ip_bytes.entry(sender.ip).or_default() += message.bytes();
        queue.push(message);
    }

    fn push(&mut self, value: AuthRecvMsg<P::PublicKey>) {
        let message = Message {
            sequence: self.sequence,
            value,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("receive sequence overflow");
        let bytes = message.bytes();
        let Some(sender) = Sender::of(&message.value) else {
            self.dropped_bytes += bytes as u64;
            return;
        };
        let route = self.routes.get(&sender).copied();
        let (used, limit) = match route {
            Some(Some(identity)) => (self.priority.bytes(identity), self.config.pinned_bytes),
            _ => (
                self.ordinary.bytes(QueueIdentity::Ip(sender.ip))
                    + self.pending_ip_bytes.get(&sender.ip).copied().unwrap_or(0),
                self.config.other_ip_bytes,
            ),
        };
        if bytes > self.config.total_bytes - self.queued_bytes
            || bytes > limit.saturating_sub(used)
            || (route.is_none()
                && !self.pending.contains_key(&sender)
                && self.pending.len() == LOOKUP_CAPACITY)
        {
            self.dropped_bytes += bytes as u64;
            return;
        }
        self.queued_bytes += bytes;
        match route {
            Some(route) => self.push_ready(message, route),
            None => self.push_pending(message),
        }
    }

    fn updated(&mut self) {
        self.routes.clear();
        self.lookups.clear();
        self.resolved.clear();
        self.pending_ip_bytes.clear();
        self.reclassifying
            .extend(self.pending.drain().map(|(_, queue)| queue));
        self.reclassifying
            .extend(self.priority.queues.drain().map(|(_, queue)| queue));
        self.reclassifying
            .extend(self.ordinary.queues.drain().map(|(_, queue)| queue));
        self.priority.ready.clear();
        self.ordinary.ready.clear();
    }

    fn poll_lookups(&mut self, cx: &mut Context<'_>, budget: &mut usize) {
        while *budget > 0 {
            if let Poll::Ready(Some((sender, route))) = self.lookups.poll_next_unpin(cx) {
                // A provider may pin only the authenticated key or IP it was given.
                let route = route.filter(|identity| match identity {
                    QueueIdentity::PublicKey(key) => sender.public_key == *key,
                    QueueIdentity::Ip(ip) => sender.ip == *ip,
                });
                self.routes.put(sender, route);
                self.resolved.push_back((sender, route));
            }
            let Some((sender, route)) = self.resolved.pop_front() else {
                break;
            };
            *budget -= 1;
            let messages = self.pending.get_mut(&sender).unwrap();
            let message = messages.pop().unwrap();
            let empty = messages.values.is_empty();
            let bytes = self.pending_ip_bytes.get_mut(&sender.ip).unwrap();
            *bytes -= message.bytes();
            if *bytes == 0 {
                self.pending_ip_bytes.remove(&sender.ip);
            }
            if empty {
                self.pending.remove(&sender);
            } else {
                self.resolved.push_back((sender, route));
            }
            self.push_ready(message, route);
        }
    }

    fn reclassify(&mut self, budget: &mut usize) {
        while *budget > 0 && self.pending.len() < LOOKUP_CAPACITY {
            let Some(messages) = self.reclassifying.front_mut() else {
                break;
            };
            let message = messages.pop().unwrap();
            if messages.values.is_empty() {
                self.reclassifying.pop_front();
            }
            *budget -= 1;
            let sender = Sender::of(&message.value).expect("queued senders must be authenticated");
            match self.routes.get(&sender).copied() {
                Some(route) => self.push_ready(message, route),
                None => self.push_pending(message),
            }
        }
    }
}

// Preserve the socket's send and metrics interfaces while replacing receives
// with the queue's recv/Stream implementations.
impl<S: Stream, P: Pinned> Deref for PriorityQueue<S, P> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<S: Stream, P: Pinned> DerefMut for PriorityQueue<S, P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl<S, P, E> Stream for PriorityQueue<S, P>
where
    P: Pinned + Unpin,
    S: Stream<Item = Result<AuthRecvMsg<P::PublicKey>, E>> + Unpin,
{
    type Item = Result<AuthRecvMsg<P::PublicKey>, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.pinned.poll_updated(cx).is_ready() {
            this.updated();
        }
        let mut work = BATCH_SIZE;
        this.reclassify(&mut work);
        this.poll_lookups(cx, &mut work);
        let mut received = 0;
        while received < BATCH_SIZE && !this.socket_closed {
            match Pin::new(&mut this.socket).poll_next(cx) {
                Poll::Ready(Some(Ok(message))) => {
                    received += 1;
                    this.push(message);
                    this.poll_lookups(cx, &mut work);
                }
                Poll::Ready(Some(Err(error))) => {
                    received += 1;
                    this.socket_error = Some(Box::new(Err(error)));
                }
                Poll::Ready(None) => this.socket_closed = true,
                Poll::Pending => break,
            }
        }
        // Finishing a bounded batch must not rely on another socket notification.
        if received == BATCH_SIZE
            || work == 0
            || (!this.reclassifying.is_empty() && this.pending.len() < LOOKUP_CAPACITY)
        {
            cx.waker().wake_by_ref();
        }
        if this.reclassifying.is_empty() {
            if let Some(message) = this
                .priority
                .pop(&this.pending)
                .or_else(|| this.ordinary.pop(&this.pending))
            {
                this.queued_bytes -= message.bytes();
                return Poll::Ready(Some(Ok(message.value)));
            }
        }
        if let Some(error) = this.socket_error.take() {
            return Poll::Ready(Some(*error));
        }
        if this.socket_closed && this.queued_bytes == 0 {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

impl<S, P, E> PriorityQueue<S, P>
where
    P: Pinned + Unpin,
    S: Stream<Item = Result<AuthRecvMsg<P::PublicKey>, E>> + Unpin,
{
    /// Cancellation safe: buffered messages and in-flight lookups belong to self.
    pub async fn recv(&mut self) -> Option<Result<AuthRecvMsg<P::PublicKey>, E>> {
        self.next().await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::Ready,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use bytes::Bytes;
    use monad_crypto::NopPubKey;

    use super::*;

    fn packet(ip: u8, key: u8, value: u8) -> AuthRecvMsg<NopPubKey> {
        AuthRecvMsg {
            src_addr: ([127, 0, 0, ip], 1000 + u16::from(value)).into(),
            payload: Bytes::copy_from_slice(&[value]),
            stride: 1,
            sender: Some(NodeId::new(NopPubKey::from_bytes(&[key; 32]).unwrap())),
        }
    }

    fn pin(key: u8) -> QueueIdentity<NopPubKey> {
        QueueIdentity::PublicKey(NodeId::new(NopPubKey::from_bytes(&[key; 32]).unwrap()))
    }

    fn unit_bytes() -> usize {
        Message {
            sequence: 0,
            value: packet(1, 1, 1),
        }
        .bytes()
    }

    #[tokio::test]
    async fn priority_and_round_robin_preserve_fifo() {
        let (_updates, pins) = watch::channel(HashSet::from([pin(1), pin(2)]));
        let source = futures::stream::iter(
            [
                packet(3, 3, 31),
                packet(1, 1, 11),
                packet(1, 1, 12),
                packet(4, 4, 41),
                packet(2, 2, 21),
                packet(2, 2, 22),
                packet(3, 3, 32),
                packet(4, 4, 42),
            ]
            .map(Ok::<_, Infallible>),
        );
        let mut queue = PriorityQueue::new(source, WatchPinned::new(pins), Default::default());
        let mut values = Vec::new();
        while let Some(message) = queue.recv().await {
            values.push(message.unwrap().payload[0]);
        }
        assert_eq!(values, [11, 21, 12, 22, 31, 41, 32, 42]);
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn receives_priority_traffic_while_ordinary_work_is_buffered() {
        let (_updates, pins) = watch::channel(HashSet::from([pin(2)]));
        let (incoming, source) = futures::channel::mpsc::unbounded();
        let mut queue = PriorityQueue::new(source, WatchPinned::new(pins), Default::default());
        incoming
            .unbounded_send(Ok::<_, Infallible>(packet(1, 1, 11)))
            .unwrap();
        incoming.unbounded_send(Ok(packet(1, 1, 12))).unwrap();
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 11);
        assert_eq!(queue.queued_bytes(), unit_bytes());
        incoming.unbounded_send(Ok(packet(2, 2, 21))).unwrap();
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 21);
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 12);
    }

    #[tokio::test]
    async fn enforces_pinned_and_total_byte_limits() {
        let (_updates, pins) = watch::channel(HashSet::from([pin(1)]));
        let source = futures::stream::iter(
            (1..=6)
                .map(|value| packet(1, 1, value))
                .chain((7..=9).map(|value| packet(2, 2, value)))
                .map(Ok::<_, Infallible>),
        );
        let unit = unit_bytes();
        let config = PriorityQueueConfig {
            pinned_bytes: 5 * unit,
            other_ip_bytes: 2 * unit,
            total_bytes: 6 * unit,
        };
        let mut queue = PriorityQueue::new(source, WatchPinned::new(pins), config);
        let mut values = Vec::new();
        while let Some(message) = queue.recv().await {
            values.push(message.unwrap().payload[0]);
            assert!(queue.queued_bytes() <= config.total_bytes);
        }
        assert_eq!(values, [1, 2, 3, 4, 5, 7]);
        assert_eq!(queue.dropped_bytes(), 3 * unit as u64);
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn ordinary_identities_and_ports_share_the_ip_limit() {
        let (_updates, pins) = watch::channel(HashSet::new());
        let source = futures::stream::iter(
            [packet(1, 1, 1), packet(1, 2, 2), packet(1, 3, 3)].map(Ok::<_, Infallible>),
        );
        let config = PriorityQueueConfig {
            other_ip_bytes: 2 * unit_bytes(),
            ..Default::default()
        };
        let mut queue = PriorityQueue::new(source, WatchPinned::new(pins), config);
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 1);
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 2);
        assert!(queue.recv().await.is_none());
        assert_eq!(queue.dropped_bytes(), unit_bytes() as u64);
    }

    #[tokio::test]
    async fn updates_reclassify_buffered_messages_and_trim_newest() {
        let (updates, pins) = watch::channel(HashSet::from([pin(1)]));
        let source = futures::stream::iter(
            [
                packet(1, 1, 11),
                packet(1, 1, 12),
                packet(1, 1, 13),
                packet(1, 1, 14),
                packet(2, 2, 21),
                packet(2, 2, 22),
            ]
            .map(Ok::<_, Infallible>),
        );
        let config = PriorityQueueConfig {
            other_ip_bytes: 2 * unit_bytes(),
            ..Default::default()
        };
        let mut queue = PriorityQueue::new(source, WatchPinned::new(pins), config);
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 11);
        updates.send_replace(HashSet::from([pin(2)]));
        let mut values = Vec::new();
        while let Some(message) = queue.recv().await {
            values.push(message.unwrap().payload[0]);
        }
        assert_eq!(values, [21, 22, 12, 13]);
        assert_eq!(queue.dropped_bytes(), unit_bytes() as u64);
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn unchanged_pins_retain_their_larger_buffer_after_an_update() {
        let (updates, pins) = watch::channel(HashSet::from([pin(1)]));
        let source = futures::stream::iter((1..=5).map(|v| Ok::<_, Infallible>(packet(1, 1, v))));
        let config = PriorityQueueConfig {
            other_ip_bytes: 2 * unit_bytes(),
            ..Default::default()
        };
        let mut queue = PriorityQueue::new(source, WatchPinned::new(pins), config);
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 1);
        updates.send_replace(HashSet::from([pin(1)]));
        let mut values = Vec::new();
        while let Some(message) = queue.recv().await {
            values.push(message.unwrap().payload[0]);
        }
        assert_eq!(values, [2, 3, 4, 5]);
        assert_eq!(queue.dropped_bytes(), 0);
    }

    #[tokio::test]
    async fn pin_updates_precede_dequeue_when_tokio_budget_is_exhausted() {
        let (updates, pins) = watch::channel(HashSet::from([pin(1)]));
        let source = futures::stream::iter(
            [packet(1, 1, 11), packet(1, 1, 12), packet(2, 2, 21)].map(Ok::<_, Infallible>),
        );
        let mut queue = PriorityQueue::new(source, WatchPinned::new(pins), Default::default());
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 11);

        while tokio::task::coop::has_budget_remaining() {
            let mut consume = std::pin::pin!(tokio::task::consume_budget());
            assert!(futures::poll!(&mut consume).is_ready());
        }
        updates.send_replace(HashSet::from([pin(2)]));
        let mut receive = std::pin::pin!(queue.recv());
        let Poll::Ready(Some(Ok(message))) = futures::poll!(&mut receive) else {
            panic!("ready pin update must not wait for Tokio's cooperative budget");
        };
        assert_eq!(message.payload[0], 21);
    }

    #[tokio::test]
    async fn authentication_errors_do_not_starve_queued_messages() {
        let (_updates, pins) = watch::channel(HashSet::from([pin(1)]));
        let source = futures::stream::iter([Ok(packet(1, 1, 1)), Err("invalid authentication")]);
        let mut queue = PriorityQueue::new(source, WatchPinned::new(pins), Default::default());
        assert_eq!(queue.recv().await.unwrap().unwrap().payload[0], 1);
        assert!(matches!(
            queue.recv().await,
            Some(Err("invalid authentication"))
        ));
        assert!(queue.recv().await.is_none());
    }

    struct PinEveryIp(Arc<AtomicUsize>);

    impl Pinned for PinEveryIp {
        type PublicKey = NopPubKey;

        fn lookup(&self, sender: Sender<NopPubKey>) -> Ready<Option<QueueIdentity<NopPubKey>>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Some(QueueIdentity::Ip(sender.ip)))
        }

        fn poll_updated(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
            // This provider has no updates.
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn pinned_ip_cannot_admit_unauthenticated_traffic() {
        let calls = Arc::new(AtomicUsize::new(0));
        let message = AuthRecvMsg::<NopPubKey> {
            src_addr: "127.0.0.1:1234".parse().unwrap(),
            payload: Bytes::from_static(b"unauthenticated"),
            stride: 15,
            sender: None,
        };
        let source = futures::stream::iter([Ok::<_, Infallible>(message)]);
        let mut queue = PriorityQueue::new(source, PinEveryIp(calls.clone()), Default::default());

        assert!(queue.recv().await.is_none());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(queue.queued_bytes(), 0);
        assert!(queue.dropped_bytes() > 0);
    }

    #[tokio::test]
    async fn authenticated_traffic_can_be_grouped_by_pinned_ip() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sender = NodeId::new(NopPubKey::from_bytes(&[1; 32]).unwrap());
        let message = AuthRecvMsg {
            src_addr: "127.0.0.1:1234".parse().unwrap(),
            payload: Bytes::from_static(b"authenticated"),
            stride: 13,
            sender: Some(sender),
        };
        let source = futures::stream::iter([Ok::<_, Infallible>(message)]);
        let mut queue = PriorityQueue::new(source, PinEveryIp(calls.clone()), Default::default());

        let received = queue.recv().await.unwrap().unwrap();
        assert_eq!(received.sender, Some(sender));
        assert_eq!(received.payload, Bytes::from_static(b"authenticated"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(queue.queued_bytes(), 0);
        assert_eq!(queue.dropped_bytes(), 0);
        assert!(queue.recv().await.is_none());
    }
}
