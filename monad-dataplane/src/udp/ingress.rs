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

use std::{
    cell::RefCell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    rc::Rc,
    task::{Poll, Waker},
};

use bytes::Bytes;
use futures::future::poll_fn;
use tokio::sync::{mpsc, watch};

use super::wake::WakeBridge;
use crate::{metrics::DataplaneMetrics, RecvUdpMsg, UdpReceiveConfig};

pub(crate) const RECEIVE_BATCH_SIZE: usize = 128;

struct Packet {
    sequence: u64,
    message: RecvUdpMsg,
}

impl Packet {
    fn bytes(&self) -> usize {
        self.message.payload.len() + std::mem::size_of::<Self>()
    }
}

#[derive(Default)]
struct Flow {
    packets: VecDeque<Packet>,
    bytes: usize,
}

struct Queue {
    config: UdpReceiveConfig,
    pins: HashSet<IpAddr>,
    flows: HashMap<IpAddr, Flow>,
    pinned: VecDeque<IpAddr>,
    ordinary: VecDeque<IpAddr>,
    fifo: BinaryHeap<Reverse<(u64, IpAddr)>>,
    trimming: VecDeque<IpAddr>,
    bytes: usize,
    sequence: u64,
    waker: Option<Waker>,
    closed: bool,
    metrics: DataplaneMetrics,
}

impl Queue {
    fn new(config: UdpReceiveConfig, metrics: DataplaneMetrics) -> Self {
        Self {
            config,
            pins: HashSet::new(),
            flows: HashMap::new(),
            pinned: VecDeque::new(),
            ordinary: VecDeque::new(),
            fifo: BinaryHeap::new(),
            trimming: VecDeque::new(),
            bytes: 0,
            sequence: 0,
            waker: None,
            closed: false,
            metrics,
        }
    }

    fn limit(&self, ip: &IpAddr) -> usize {
        if self.pins.contains(ip) {
            self.config.pinned_ip_bytes
        } else {
            self.config.other_ip_bytes
        }
    }

    fn drop_packet(&self, bytes: usize) {
        self.metrics.udp_ingress_packets_dropped.inc();
        self.metrics.udp_ingress_bytes_dropped.add(bytes as u64);
    }

    fn account_pop(&mut self, bytes: usize) {
        self.bytes -= bytes;
        self.metrics.udp_ingress_queued_bytes.sub(bytes as u64);
    }

    #[cfg(test)]
    fn push(&mut self, message: RecvUdpMsg) -> bool {
        self.push_with(
            message.src_addr,
            message.payload.len(),
            message.stride,
            || message.payload,
        )
    }

    fn push_with(
        &mut self,
        src_addr: SocketAddr,
        len: usize,
        stride: u16,
        payload: impl FnOnce() -> Bytes,
    ) -> bool {
        if self.closed {
            return false;
        }
        let ip = src_addr.ip();
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .expect("UDP ingress sequence overflow");
        let bytes = len + std::mem::size_of::<Packet>();
        let used = self.flows.get(&ip).map_or(0, |flow| flow.bytes);
        if bytes > self.config.total_bytes - self.bytes
            || bytes > self.limit(&ip).saturating_sub(used)
        {
            self.drop_packet(bytes);
            return true;
        }
        // Rejected datagrams never allocate or copy their payload out of the
        // receive ring; the admission budget is known from address and length.
        let packet = Packet {
            sequence,
            message: RecvUdpMsg {
                src_addr,
                payload: payload(),
                stride,
            },
        };
        let flow = self.flows.entry(ip).or_default();
        if flow.packets.is_empty() {
            if !self.config.prioritize {
                self.fifo.push(Reverse((packet.sequence, ip)));
            } else if self.pins.contains(&ip) {
                self.pinned.push_back(ip);
            } else {
                self.ordinary.push_back(ip);
            }
        }
        flow.bytes += bytes;
        flow.packets.push_back(packet);
        self.bytes += bytes;
        self.metrics.udp_ingress_queued_bytes.add(bytes as u64);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
        true
    }

    fn update(&mut self, pins: HashSet<IpAddr>) {
        if self.pins == pins {
            return;
        }
        self.pins = pins;
        self.trimming = self
            .flows
            .iter()
            .filter(|(ip, flow)| flow.bytes > self.limit(ip))
            .map(|(ip, _)| *ip)
            .collect();
        if self.config.prioritize {
            let ready = std::mem::take(&mut self.pinned)
                .into_iter()
                .chain(std::mem::take(&mut self.ordinary));
            for ip in ready {
                if self.pins.contains(&ip) {
                    self.pinned.push_back(ip);
                } else {
                    self.ordinary.push_back(ip);
                }
            }
        }
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    // Demotion keeps the oldest packets, with bounded cleanup work per poll.
    fn trim(&mut self) {
        for _ in 0..RECEIVE_BATCH_SIZE {
            let Some(ip) = self.trimming.pop_front() else {
                break;
            };
            let limit = self.limit(&ip);
            let Some(flow) = self.flows.get_mut(&ip) else {
                continue;
            };
            if flow.bytes <= limit {
                continue;
            }
            let packet = flow.packets.pop_back().unwrap();
            let bytes = packet.bytes();
            flow.bytes -= bytes;
            if flow.bytes > limit {
                self.trimming.push_back(ip);
            }
            if flow.packets.is_empty() {
                self.flows.remove(&ip);
                self.pinned.retain(|key| *key != ip);
                self.ordinary.retain(|key| *key != ip);
                self.fifo.retain(|Reverse((_, key))| *key != ip);
            }
            self.account_pop(bytes);
            self.drop_packet(bytes);
        }
    }

    fn next_ip(&mut self) -> Option<IpAddr> {
        if !self.config.prioritize {
            while let Some(Reverse((sequence, ip))) = self.fifo.peek().copied() {
                let flow = self.flows.get(&ip).unwrap();
                let Some(front) = flow.packets.front() else {
                    self.fifo.pop();
                    self.flows.remove(&ip);
                    continue;
                };
                debug_assert_eq!(sequence, front.sequence);
                if flow.bytes > self.limit(&ip) {
                    return None;
                }
                self.fifo.pop();
                return Some(ip);
            }
            return None;
        }
        for priority in [true, false] {
            let turns = if priority {
                self.pinned.len()
            } else {
                self.ordinary.len()
            };
            for _ in 0..turns {
                let ip = if priority {
                    self.pinned.pop_front().unwrap()
                } else {
                    self.ordinary.pop_front().unwrap()
                };
                let flow = self.flows.get(&ip).unwrap();
                if flow.packets.is_empty() {
                    self.flows.remove(&ip);
                    continue;
                }
                if flow.bytes > self.limit(&ip) {
                    if priority {
                        self.pinned.push_back(ip);
                    } else {
                        self.ordinary.push_back(ip);
                    }
                    continue;
                }
                return Some(ip);
            }
        }
        None
    }

    fn pop_batch(&mut self, limit: usize) -> Vec<RecvUdpMsg> {
        self.trim();
        let mut batch = Vec::with_capacity(RECEIVE_BATCH_SIZE);
        let mut priority_packets = 0;
        while batch.len() < limit {
            let Some(ip) = self.next_ip() else {
                break;
            };
            let flow = self.flows.get_mut(&ip).unwrap();
            let packet = flow.packets.pop_front().unwrap();
            let bytes = packet.bytes();
            flow.bytes -= bytes;
            if let Some(front) = flow.packets.front() {
                if !self.config.prioritize {
                    self.fifo.push(Reverse((front.sequence, ip)));
                } else if self.pins.contains(&ip) {
                    self.pinned.push_back(ip);
                } else {
                    self.ordinary.push_back(ip);
                }
            } else {
                self.flows.remove(&ip);
            }
            self.account_pop(bytes);
            priority_packets += u64::from(self.config.prioritize && self.pins.contains(&ip));
            batch.push(packet.message);
        }
        self.metrics
            .udp_ingress_priority_packets_delivered
            .add(priority_packets);
        batch
    }
}

#[derive(Clone)]
pub(crate) struct Ingress {
    queue: Rc<RefCell<Queue>>,
    delivery: mpsc::Sender<Vec<RecvUdpMsg>>,
}

impl Ingress {
    #[cfg(test)]
    fn push(&self, message: RecvUdpMsg) -> bool {
        self.push_with(
            message.src_addr,
            message.payload.len(),
            message.stride,
            || message.payload,
        )
    }

    pub(crate) fn push_with(
        &self,
        src_addr: SocketAddr,
        len: usize,
        stride: u16,
        payload: impl FnOnce() -> Bytes,
    ) -> bool {
        if self.delivery.is_closed() {
            return false;
        }
        self.queue
            .borrow_mut()
            .push_with(src_addr, len, stride, payload)
    }
}

struct CloseQueue(Rc<RefCell<Queue>>);
impl Drop for CloseQueue {
    fn drop(&mut self) {
        let mut queue = self.0.borrow_mut();
        queue.closed = true;
        let bytes = queue.bytes;
        queue.account_pop(bytes);
        queue.flows.clear();
        queue.fifo.clear();
        queue.pinned.clear();
        queue.ordinary.clear();
        queue.trimming.clear();
    }
}

pub(crate) fn start(
    delivery: mpsc::Sender<Vec<RecvUdpMsg>>,
    mut updates: watch::Receiver<HashSet<IpAddr>>,
    config: UdpReceiveConfig,
    metrics: DataplaneMetrics,
) -> Ingress {
    let mut state = Queue::new(config, metrics.clone());
    state.update(updates.borrow_and_update().clone());
    let queue = Rc::new(RefCell::new(state));
    let sender = Ingress {
        queue: queue.clone(),
        delivery: delivery.clone(),
    };
    let update_queue = queue.clone();
    let mut notifications = updates.clone();
    monoio::spawn(async move {
        let wake = WakeBridge::new();
        while wake.wait(notifications.changed()).await.is_ok() {
            {
                let mut queue = update_queue.borrow_mut();
                if queue.closed {
                    break;
                }
                queue.update(notifications.borrow_and_update().clone());
            }
            loop {
                {
                    let mut queue = update_queue.borrow_mut();
                    if queue.closed || queue.trimming.is_empty() {
                        break;
                    }
                    if notifications.borrow_and_update().has_changed() {
                        queue.update(notifications.borrow().clone());
                    }
                    queue.trim();
                }
                yield_receive().await;
            }
        }
    });
    // The dispatcher owns the queue and the update receiver. Check updates
    // immediately before selection, even if the channel permit was pending.
    monoio::spawn(async move {
        let _close = CloseQueue(queue.clone());
        let wake = WakeBridge::new();
        loop {
            let Ok(permit) = wake.wait(delivery.clone().reserve_owned()).await else {
                break;
            };
            let next_batch = poll_fn(|cx| {
                let mut queue = queue.borrow_mut();
                if updates.borrow_and_update().has_changed() {
                    queue.update(updates.borrow().clone());
                }
                let batch = queue.pop_batch(RECEIVE_BATCH_SIZE);
                if !batch.is_empty() {
                    return Poll::Ready(batch);
                }
                queue.waker = Some(cx.waker().clone());
                if !queue.trimming.is_empty() {
                    let waker = cx.waker().clone();
                    monoio::spawn(async move {
                        waker.wake();
                    });
                }
                Poll::Pending
            });
            let batch = monoio::select! {
                batch = next_batch => batch,
                _ = wake.wait(delivery.closed()) => break,
            };
            metrics.udp_ingress_batches_delivered.inc();
            metrics
                .udp_ingress_packets_delivered
                .add(batch.len() as u64);
            permit.send(batch);
            yield_receive().await;
        }
    });
    sender
}

/// Yield on the dataplane's Monoio runtime after each bounded socket intake.
pub(crate) async fn yield_receive() {
    // Monoio puts self-woken tasks at the front of its queue. Awaiting a new
    // task instead lets already-ready dispatch and control tasks run first.
    monoio::spawn(async {}).await;
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::{Duration, Instant},
    };

    use bytes::Bytes;

    use super::*;

    fn ip(value: u8) -> IpAddr {
        Ipv4Addr::new(127, 0, 0, value).into()
    }
    fn packet(address: u8, value: u64) -> RecvUdpMsg {
        RecvUdpMsg {
            src_addr: SocketAddr::new(ip(address), 1000 + value as u16),
            payload: Bytes::copy_from_slice(&value.to_le_bytes()),
            stride: 8,
        }
    }
    fn value(message: &RecvUdpMsg) -> u64 {
        u64::from_le_bytes(message.payload[..8].try_into().unwrap())
    }
    fn unit() -> usize {
        Packet {
            sequence: 0,
            message: packet(1, 1),
        }
        .bytes()
    }
    fn queue(prioritize: bool) -> Queue {
        Queue::new(
            UdpReceiveConfig {
                prioritize,
                ..Default::default()
            },
            DataplaneMetrics::default(),
        )
    }

    #[test]
    fn priority_and_round_robin_preserve_per_ip_fifo() {
        let mut queue = queue(true);
        queue.update(HashSet::from([ip(1), ip(2)]));
        for (address, value) in [
            (3, 31),
            (1, 11),
            (1, 12),
            (4, 41),
            (2, 21),
            (2, 22),
            (3, 32),
            (4, 42),
        ] {
            assert!(queue.push(packet(address, value)));
        }
        let batch = queue.pop_batch(128);
        assert_eq!(
            batch.iter().map(value).collect::<Vec<_>>(),
            [11, 21, 12, 22, 31, 41, 32, 42]
        );
        assert_eq!(queue.bytes, 0);
        assert!(queue.flows.is_empty());
        assert_eq!(
            queue.metrics.udp_ingress_priority_packets_delivered.get(),
            4
        );
    }

    #[test]
    fn fifo_baseline_uses_global_arrival_order_with_identical_limits() {
        let mut queue = queue(false);
        queue.update(HashSet::from([ip(2)]));
        for (address, number) in [(1, 11), (2, 21), (1, 12), (3, 31), (2, 22)] {
            queue.push(packet(address, number));
        }
        assert_eq!(
            queue.pop_batch(128).iter().map(value).collect::<Vec<_>>(),
            [11, 21, 12, 31, 22]
        );
        assert_eq!(
            queue.metrics.udp_ingress_priority_packets_delivered.get(),
            0
        );
        assert_eq!(queue.bytes, 0);
    }

    #[test]
    fn ports_share_ip_limits_and_total_accounting_in_both_modes() {
        for prioritize in [false, true] {
            let mut queue = Queue::new(
                UdpReceiveConfig {
                    prioritize,
                    pinned_ip_bytes: 5 * unit(),
                    other_ip_bytes: 2 * unit(),
                    total_bytes: 6 * unit(),
                },
                DataplaneMetrics::default(),
            );
            queue.update(HashSet::from([ip(1)]));
            for number in 1..=6 {
                queue.push(packet(1, number));
            }
            for number in 7..=9 {
                queue.push(packet(2, number));
            }
            assert_eq!(queue.bytes, 6 * unit());
            assert_eq!(queue.metrics.udp_ingress_packets_dropped.get(), 3);
            assert_eq!(
                queue.metrics.udp_ingress_bytes_dropped.get(),
                3 * unit() as u64
            );
            let batch = queue.pop_batch(128);
            assert_eq!(
                batch
                    .iter()
                    .filter(|m| m.src_addr.ip() == ip(1))
                    .map(value)
                    .collect::<Vec<_>>(),
                [1, 2, 3, 4, 5]
            );
            assert_eq!(queue.bytes, 0);
            assert_eq!(queue.metrics.udp_ingress_queued_bytes.get(), 0);
        }
    }

    #[test]
    fn rejected_payloads_are_not_copied_for_ip_or_global_overflow() {
        for prioritize in [false, true] {
            let mut queue = Queue::new(
                UdpReceiveConfig {
                    prioritize,
                    other_ip_bytes: unit(),
                    total_bytes: 2 * unit(),
                    ..Default::default()
                },
                DataplaneMetrics::default(),
            );
            queue.push(packet(1, 1));
            queue.push_with(packet(1, 2).src_addr, 8, 8, || {
                panic!("per-IP overflow copied its payload")
            });
            queue.push(packet(2, 3));
            queue.push_with(packet(3, 4).src_addr, 8, 8, || {
                panic!("global overflow copied its payload")
            });
            assert_eq!(queue.bytes, 2 * unit());
            assert_eq!(queue.metrics.udp_ingress_packets_dropped.get(), 2);
            assert_eq!(
                queue.pop_batch(128).iter().map(value).collect::<Vec<_>>(),
                [1, 3]
            );
        }
    }

    #[test]
    fn pin_updates_reclassify_queued_ips_and_trim_newest_on_demotion() {
        for prioritize in [false, true] {
            let mut queue = Queue::new(
                UdpReceiveConfig {
                    prioritize,
                    other_ip_bytes: 2 * unit(),
                    ..Default::default()
                },
                DataplaneMetrics::default(),
            );
            queue.update(HashSet::from([ip(1)]));
            for (address, number) in [(1, 11), (1, 12), (1, 13), (1, 14), (2, 21), (2, 22)] {
                queue.push(packet(address, number));
            }
            assert_eq!(value(&queue.pop_batch(1)[0]), 11);
            queue.update(HashSet::from([ip(2)]));
            let actual = queue.pop_batch(128).iter().map(value).collect::<Vec<_>>();
            assert_eq!(
                actual,
                if prioritize {
                    vec![21, 22, 12, 13]
                } else {
                    vec![12, 13, 21, 22]
                }
            );
            assert_eq!(queue.metrics.udp_ingress_packets_dropped.get(), 1);
            assert_eq!(queue.bytes, 0);
        }
    }

    #[test]
    fn demotion_cleanup_is_bounded_and_empty_flow_can_be_reused() {
        for prioritize in [false, true] {
            let mut queue = Queue::new(
                UdpReceiveConfig {
                    prioritize,
                    pinned_ip_bytes: 500 * unit(),
                    other_ip_bytes: 1,
                    total_bytes: 1000 * unit(),
                },
                DataplaneMetrics::default(),
            );
            queue.update(HashSet::from([ip(1)]));
            for number in 0..400 {
                queue.push(packet(1, number));
            }
            queue.update(HashSet::new());
            queue.trim();
            assert_eq!(queue.metrics.udp_ingress_packets_dropped.get(), 128);
            assert_eq!(queue.bytes, 272 * unit());
            while !queue.trimming.is_empty() {
                queue.trim();
            }
            queue.update(HashSet::from([ip(1)]));
            queue.push(packet(1, 999));
            assert_eq!(
                queue.pop_batch(128).iter().map(value).collect::<Vec<_>>(),
                [999]
            );
            assert!(queue.flows.is_empty());
            assert_eq!(queue.bytes, 0);
        }
    }

    async fn wait_for(mut condition: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(2);
        while !condition() {
            assert!(Instant::now() < until, "dataplane task did not progress");
            yield_receive().await;
        }
    }

    #[test]
    fn single_slot_prefetch_keeps_intake_and_updates_live_and_selects_on_permit() {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(async {
                let (tx, mut rx) = mpsc::channel(1);
                let (pins, updates) = watch::channel(HashSet::new());
                let metrics = DataplaneMetrics::default();
                let ingress = start(tx, updates, UdpReceiveConfig::default(), metrics.clone());
                ingress.push(packet(1, 0));
                wait_for(|| metrics.udp_ingress_batches_delivered.get() == 1).await;
                for number in 1..=300 {
                    assert!(ingress.push(packet(1, number)));
                }
                ingress.push(packet(2, 999));
                assert_eq!(ingress.queue.borrow().bytes, 301 * unit());
                assert_eq!(metrics.udp_ingress_batches_delivered.get(), 1);
                pins.send_replace(HashSet::from([ip(2)]));
                wait_for(|| ingress.queue.borrow().pins.contains(&ip(2))).await;
                // The single prepared batch stays selected; subsequent selection
                // happens only after its channel slot becomes available.
                assert_eq!(
                    rx.recv()
                        .await
                        .unwrap()
                        .iter()
                        .map(value)
                        .collect::<Vec<_>>(),
                    [0]
                );
                let next = rx.recv().await.unwrap();
                assert_eq!(next.len(), 128);
                assert_eq!(value(&next[0]), 999);
                assert_eq!(
                    next[1..].iter().map(value).collect::<Vec<_>>(),
                    (1..=127).collect::<Vec<_>>()
                );
                drop(rx);
                wait_for(|| ingress.queue.borrow().closed).await;
                assert_eq!(metrics.udp_ingress_queued_bytes.get(), 0);
                assert!(!ingress.push(packet(1, 1000)));
            });
    }

    #[test]
    fn dropping_idle_receiver_closes_dispatcher_waiting_with_a_permit() {
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(async {
                let (tx, rx) = mpsc::channel(1);
                let (_pins, updates) = watch::channel(HashSet::new());
                let ingress = start(
                    tx,
                    updates,
                    UdpReceiveConfig::default(),
                    DataplaneMetrics::default(),
                );
                yield_receive().await;
                drop(rx);
                wait_for(|| ingress.queue.borrow().closed).await;
            });
    }

    #[test]
    fn foreign_receiver_and_pin_updates_progress_while_local_tasks_stay_ready() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(async {
                let (tx, mut rx) = mpsc::channel(1);
                let (pins, updates) = watch::channel(HashSet::new());
                let metrics = DataplaneMetrics::default();
                let ingress = start(tx, updates, Default::default(), metrics.clone());
                ingress.push(packet(1, 0));
                wait_for(|| metrics.udp_ingress_batches_delivered.get() == 1).await;
                ingress.push(packet(1, 1));
                ingress.push(packet(2, 999));
                let release = Arc::new(AtomicBool::new(false));
                let released = release.clone();
                let thread = std::thread::spawn(move || {
                    pins.send_replace(HashSet::from([ip(2)]));
                    while !released.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    assert_eq!(
                        rx.blocking_recv()
                            .unwrap()
                            .iter()
                            .map(value)
                            .collect::<Vec<_>>(),
                        [0]
                    );
                    rx.blocking_recv().unwrap()
                });
                // wait_for deliberately keeps a local task runnable, exercising
                // Monoio's submission path rather than relying on parking for wakes.
                wait_for(|| ingress.queue.borrow().pins.contains(&ip(2))).await;
                release.store(true, Ordering::Release);
                wait_for(|| metrics.udp_ingress_batches_delivered.get() == 2).await;
                assert_eq!(
                    thread.join().unwrap().iter().map(value).collect::<Vec<_>>(),
                    [999, 1]
                );
            });
    }
}
