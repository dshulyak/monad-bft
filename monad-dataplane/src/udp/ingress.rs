// Copyright (C) 2026 Category Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    net::IpAddr,
    rc::Rc,
    task::{Poll, Waker},
};

use futures::future::poll_fn;
use tokio::sync::{mpsc, watch};

use super::wake::WakeBridge;
use crate::{auth::Identity, metrics::DataplaneMetrics, RecvUdpMsg};

pub(crate) const RECEIVE_BATCH: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct ReceiveConfig {
    pub prioritize: bool,
    pub pinned_bytes: usize,
    pub other_ip_bytes: usize,
    pub total_bytes: usize,
}
impl Default for ReceiveConfig {
    fn default() -> Self {
        Self {
            prioritize: true,
            pinned_bytes: 5 * 1024 * 1024,
            other_ip_bytes: 2 * 1024 * 1024,
            total_bytes: 1024 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum Group<I> {
    Pinned(I),
    Ordinary(IpAddr),
}
struct Packet<I: Identity> {
    sequence: u64,
    message: RecvUdpMsg<I>,
}
impl<I: Identity> Packet<I> {
    fn bytes(&self) -> usize {
        self.message.payload.len() + std::mem::size_of::<Self>()
    }
}
struct Flow<I: Identity> {
    messages: BTreeMap<u64, Packet<I>>,
    bytes: usize,
}
impl<I: Identity> Default for Flow<I> {
    fn default() -> Self {
        Self {
            messages: BTreeMap::new(),
            bytes: 0,
        }
    }
}

struct Queue<I: Identity> {
    config: ReceiveConfig,
    pins: HashSet<I>,
    flows: HashMap<Group<I>, Flow<I>>,
    priority: VecDeque<Group<I>>,
    ordinary: VecDeque<Group<I>>,
    reclassifying: VecDeque<Flow<I>>,
    bytes: usize,
    sequence: u64,
    waker: Option<Waker>,
    closed: bool,
    metrics: DataplaneMetrics,
}
impl<I: Identity> Queue<I> {
    fn new(config: ReceiveConfig, metrics: DataplaneMetrics) -> Self {
        assert!(config.pinned_bytes > 0 && config.other_ip_bytes > 0 && config.total_bytes > 0);
        Self {
            config,
            pins: HashSet::new(),
            flows: HashMap::new(),
            priority: VecDeque::new(),
            ordinary: VecDeque::new(),
            reclassifying: VecDeque::new(),
            bytes: 0,
            sequence: 0,
            waker: None,
            closed: false,
            metrics,
        }
    }
    fn group(&self, message: &RecvUdpMsg<I>) -> Group<I> {
        match message.sender {
            Some(key) if self.pins.contains(&key) => Group::Pinned(key),
            _ => Group::Ordinary(message.src_addr.ip()),
        }
    }
    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
    fn account_remove(&mut self, bytes: usize) {
        self.bytes -= bytes;
        self.metrics.udp_ingress_queued_bytes.sub(bytes as u64);
    }
    fn dropped(&mut self, bytes: usize) {
        self.metrics.udp_ingress_packets_dropped.inc();
        self.metrics.udp_ingress_bytes_dropped.add(bytes as u64);
    }
    fn insert(&mut self, packet: Packet<I>) {
        let group = self.group(&packet.message);
        let limit = match group {
            Group::Pinned(_) => self.config.pinned_bytes,
            _ => self.config.other_ip_bytes,
        };
        let flow = self.flows.entry(group).or_insert_with(|| {
            match group {
                Group::Pinned(_) => self.priority.push_back(group),
                _ => self.ordinary.push_back(group),
            }
            Flow::default()
        });
        flow.bytes += packet.bytes();
        flow.messages.insert(packet.sequence, packet);
        let mut dropped = Vec::new();
        while flow.bytes > limit {
            let (_, packet) = flow.messages.pop_last().unwrap();
            let bytes = packet.bytes();
            flow.bytes -= bytes;
            dropped.push(bytes);
        }
        if flow.messages.is_empty() {
            self.flows.remove(&group);
            self.priority.retain(|key| *key != group);
            self.ordinary.retain(|key| *key != group);
        }
        for bytes in dropped {
            self.account_remove(bytes);
            self.dropped(bytes);
        }
    }
    fn push(&mut self, message: RecvUdpMsg<I>) {
        if self.closed {
            return;
        }
        let packet = Packet {
            sequence: self.sequence,
            message,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("UDP receive sequence overflow");
        let bytes = packet.bytes();
        if bytes > self.config.total_bytes.saturating_sub(self.bytes) {
            self.dropped(bytes);
            return;
        }
        self.bytes += bytes;
        self.metrics.udp_ingress_queued_bytes.add(bytes as u64);
        self.insert(packet);
        self.wake();
    }
    fn update(&mut self, pins: HashSet<I>) {
        if self.pins == pins {
            return;
        }
        self.pins = pins;
        self.reclassifying
            .extend(self.flows.drain().map(|(_, flow)| flow));
        self.priority.clear();
        self.ordinary.clear();
        self.wake();
    }
    fn reclassify(&mut self) {
        for _ in 0..RECEIVE_BATCH {
            let Some(flow) = self.reclassifying.front_mut() else {
                break;
            };
            let (_, packet) = flow.messages.pop_first().unwrap();
            if flow.messages.is_empty() {
                self.reclassifying.pop_front();
            }
            self.insert(packet);
        }
    }
    fn pop_batch(&mut self) -> Vec<RecvUdpMsg<I>> {
        self.reclassify();
        let mut batch = Vec::with_capacity(RECEIVE_BATCH);
        if !self.reclassifying.is_empty() {
            return batch;
        }
        for _ in 0..RECEIVE_BATCH {
            let next = if self.config.prioritize {
                self.priority
                    .pop_front()
                    .or_else(|| self.ordinary.pop_front())
            } else {
                let next = self
                    .flows
                    .iter()
                    .min_by_key(|(_, flow)| *flow.messages.first_key_value().unwrap().0)
                    .map(|(group, _)| *group);
                if let Some(group) = next {
                    let ready = match group {
                        Group::Pinned(_) => &mut self.priority,
                        _ => &mut self.ordinary,
                    };
                    let index = ready.iter().position(|key| *key == group).unwrap();
                    ready.remove(index);
                }
                next
            };
            let Some(group) = next else {
                break;
            };
            let flow = self.flows.get_mut(&group).unwrap();
            let (_, packet) = flow.messages.pop_first().unwrap();
            let bytes = packet.bytes();
            flow.bytes -= bytes;
            if flow.messages.is_empty() {
                self.flows.remove(&group);
            } else {
                match group {
                    Group::Pinned(_) => self.priority.push_back(group),
                    _ => self.ordinary.push_back(group),
                }
            }
            self.account_remove(bytes);
            if self.config.prioritize && matches!(group, Group::Pinned(_)) {
                self.metrics.udp_ingress_priority_packets_delivered.inc();
            }
            batch.push(packet.message);
        }
        batch
    }
}

#[derive(Clone)]
pub(crate) struct Ingress<I: Identity>(Rc<RefCell<Queue<I>>>);
impl<I: Identity> Ingress<I> {
    pub(crate) fn push(&self, message: RecvUdpMsg<I>) {
        self.0.borrow_mut().push(message);
    }
}

struct Close<I: Identity>(Ingress<I>);
impl<I: Identity> Drop for Close<I> {
    fn drop(&mut self) {
        let mut queue = self.0 .0.borrow_mut();
        queue.closed = true;
        let bytes = queue.bytes;
        queue.account_remove(bytes);
        queue.flows.clear();
        queue.reclassifying.clear();
        queue.priority.clear();
        queue.ordinary.clear();
    }
}

pub(crate) fn start<I: Identity>(
    delivery: mpsc::Sender<Vec<RecvUdpMsg<I>>>,
    config: ReceiveConfig,
    metrics: DataplaneMetrics,
    mut updates: watch::Receiver<(HashSet<I>, bool)>,
) -> Ingress<I> {
    let ingress = Ingress(Rc::new(RefCell::new(Queue::new(config, metrics.clone()))));
    let controller = ingress.clone();
    let mut notifications = updates.clone();
    monoio::spawn(async move {
        let wake = WakeBridge::new();
        loop {
            let (pins, enabled) = notifications.borrow_and_update().clone();
            {
                let mut queue = controller.0.borrow_mut();
                if queue.closed {
                    break;
                }
                queue.update(pins);
                queue.config.prioritize = enabled;
            }
            if wake.wait(notifications.changed()).await.is_err() {
                break;
            }
        }
    });
    let dispatcher = ingress.clone();
    monoio::spawn(async move {
        let _close = Close(dispatcher.clone());
        let wake = WakeBridge::new();
        loop {
            let Ok(permit) = wake.wait(delivery.clone().reserve_owned()).await else {
                break;
            };
            let next = poll_fn(|cx| {
                let mut queue = dispatcher.0.borrow_mut();
                if updates.borrow_and_update().has_changed() {
                    let (pins, enabled) = updates.borrow().clone();
                    queue.update(pins);
                    queue.config.prioritize = enabled;
                }
                let batch = queue.pop_batch();
                if !batch.is_empty() {
                    return Poll::Ready(batch);
                }
                queue.waker = Some(cx.waker().clone());
                if !queue.reclassifying.is_empty() {
                    let waker = cx.waker().clone();
                    monoio::spawn(async move {
                        waker.wake();
                    });
                }
                Poll::Pending
            });
            let batch = monoio::select! { batch = next => batch, _ = wake.wait(delivery.closed()) => break };
            metrics.udp_ingress_batches_delivered.inc();
            metrics
                .udp_ingress_packets_delivered
                .add(batch.len() as u64);
            permit.send(batch);
            yield_receive().await;
        }
    });
    ingress
}

pub(crate) async fn yield_receive() {
    monoio::spawn(async {}).await;
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    fn packet(key: u64, ip: u8, value: u8) -> RecvUdpMsg<u64> {
        RecvUdpMsg {
            src_addr: (std::net::Ipv4Addr::new(127, 0, 0, ip), 1000 + value as u16).into(),
            payload: Bytes::copy_from_slice(&[value]),
            stride: 1,
            sender: Some(key),
        }
    }
    fn unit() -> usize {
        Packet {
            sequence: 0,
            message: packet(1, 1, 1),
        }
        .bytes()
    }
    fn values(queue: &mut Queue<u64>) -> Vec<u8> {
        queue
            .pop_batch()
            .into_iter()
            .map(|msg| msg.payload[0])
            .collect()
    }
    #[test]
    fn authenticated_identity_priority_and_ordinary_ip_round_robin() {
        let mut q = Queue::new(ReceiveConfig::default(), DataplaneMetrics::new());
        q.update(HashSet::from([1, 2]));
        for (key, ip, value) in [
            (3, 1, 31),
            (1, 1, 11),
            (4, 4, 41),
            (2, 2, 21),
            (1, 5, 12),
            (2, 2, 22),
            (3, 1, 32),
            (4, 4, 42),
        ] {
            q.push(packet(key, ip, value));
        }
        assert_eq!(values(&mut q), [11, 21, 12, 22, 31, 41, 32, 42]);
        assert_eq!(q.bytes, 0);
    }
    #[test]
    fn fifo_uses_identical_limits_and_preserves_global_arrival_order() {
        let mut q = Queue::new(
            ReceiveConfig {
                prioritize: false,
                other_ip_bytes: unit(),
                ..Default::default()
            },
            DataplaneMetrics::new(),
        );
        q.update(HashSet::from([2]));
        for (key, ip, value) in [(1, 1, 11), (3, 1, 12), (2, 2, 21), (4, 4, 41)] {
            q.push(packet(key, ip, value));
        }
        assert_eq!(values(&mut q), [11, 21, 41]);
        assert_eq!(q.metrics.udp_ingress_packets_dropped.get(), 1);
    }
    #[test]
    fn pin_updates_reclassify_buffered_data_and_trim_newest() {
        let mut q = Queue::new(
            ReceiveConfig {
                pinned_bytes: 5 * unit(),
                other_ip_bytes: 2 * unit(),
                ..Default::default()
            },
            DataplaneMetrics::new(),
        );
        q.update(HashSet::from([1]));
        for value in 11..=15 {
            q.push(packet(1, 1, value));
        }
        for value in 21..=22 {
            q.push(packet(2, 2, value));
        }
        q.update(HashSet::from([2]));
        assert_eq!(values(&mut q), [21, 22, 11, 12]);
        assert_eq!(q.bytes, 0);
        assert_eq!(q.metrics.udp_ingress_packets_dropped.get(), 3);
    }
    #[test]
    fn total_limit_and_reclassification_work_are_bounded() {
        let mut q = Queue::new(
            ReceiveConfig {
                total_bytes: 400 * unit(),
                ..Default::default()
            },
            DataplaneMetrics::new(),
        );
        for value in 0..500 {
            q.push(packet(1, 1, value as u8));
        }
        assert_eq!(q.bytes, 400 * unit());
        assert_eq!(q.metrics.udp_ingress_packets_dropped.get(), 100);
        q.update(HashSet::from([1]));
        assert!(q.pop_batch().is_empty());
        assert_eq!(q.reclassifying.front().unwrap().messages.len(), 400 - 128);
        let mut count = 0;
        while q.bytes > 0 {
            count += q.pop_batch().len();
        }
        assert_eq!(count, 400);
    }
}
