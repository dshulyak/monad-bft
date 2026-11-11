// Copyright (C) 2026 Category Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    cell::RefCell,
    collections::VecDeque,
    net::SocketAddr,
    rc::Rc,
    time::{Duration, Instant},
};

use bytes::Bytes;

use super::ingress::Ingress;
use crate::{
    auth::{Backend, Encryption, Identity, UdpCommand},
    metrics::DataplaneMetrics,
    RecvUdpMsg, UdpMsg, UdpSocketId,
};

struct Socket<I: Identity> {
    id: UdpSocketId,
    backend: Option<Box<dyn Backend<I>>>,
    ingress: Ingress<I>,
}
pub(super) struct Runtime<I: Identity> {
    sockets: [Option<Socket<I>>; 3],
    ready: [VecDeque<Box<UdpMsg<I>>>; 2],
    ready_bytes: [usize; 2],
    pub(super) ready_limit: usize,
    ready_notify: async_channel::Sender<()>,
    timer_notify: async_channel::Sender<()>,
    metrics: DataplaneMetrics,
    pub(super) require_auth: bool,
}
impl<I: Identity> Runtime<I> {
    pub(super) fn new(
        metrics: DataplaneMetrics,
    ) -> (
        Rc<RefCell<Self>>,
        async_channel::Receiver<()>,
        async_channel::Receiver<()>,
    ) {
        let (ready_notify, ready_rx) = async_channel::bounded(1);
        let (timer_notify, timer_rx) = async_channel::bounded(1);
        (
            Rc::new(RefCell::new(Self {
                sockets: std::array::from_fn(|_| None),
                ready: std::array::from_fn(|_| VecDeque::new()),
                ready_bytes: [0; 2],
                ready_limit: crate::DEFAULT_UDP_MAX_QUEUED_BYTES,
                ready_notify,
                timer_notify,
                metrics,
                require_auth: false,
            })),
            ready_rx,
            timer_rx,
        )
    }
    pub(super) fn add_socket(&mut self, id: UdpSocketId, ingress: Ingress<I>) {
        self.sockets[id as usize] = Some(Socket {
            id,
            backend: None,
            ingress,
        });
    }
    fn enqueue(&mut self, output: impl IntoIterator<Item = Box<UdpMsg<I>>>) {
        for msg in output {
            let bytes = msg.payload.len() + std::mem::size_of::<UdpMsg<I>>();
            let priority = msg.priority as usize;
            if bytes > self.ready_limit.saturating_sub(self.ready_bytes[priority]) {
                self.metrics.udp_egress_messages_dropped.inc();
                continue;
            }
            self.ready_bytes[priority] += bytes;
            self.ready[priority].push_back(msg);
        }
        if self.ready.iter().any(|queue| !queue.is_empty()) {
            let _ = self.ready_notify.try_send(());
        }
    }
    pub(super) fn take_ready(&mut self, limit: usize) -> Vec<Box<UdpMsg<I>>> {
        let mut result = Vec::with_capacity(limit);
        for _ in 0..limit {
            let Some(msg) = self.ready.iter_mut().find_map(|queue| queue.pop_front()) else {
                break;
            };
            self.ready_bytes[msg.priority as usize] -=
                msg.payload.len() + std::mem::size_of::<UdpMsg<I>>();
            result.push(msg);
        }
        if self.ready.iter().any(|queue| !queue.is_empty()) {
            let _ = self.ready_notify.try_send(());
        }
        result
    }
    pub(super) fn ready_payload_bytes(&self) -> [usize; 2] {
        std::array::from_fn(|priority| {
            self.ready_bytes[priority]
                - self.ready[priority].len() * std::mem::size_of::<UdpMsg<I>>()
        })
    }
    pub(super) fn has_ready_fitting(&self, capacity: [usize; 2]) -> bool {
        self.ready.iter().enumerate().any(|(priority, queue)| {
            queue
                .front()
                .is_some_and(|msg| msg.payload.len() <= capacity[priority])
        })
    }
    /// Keep FIFO within each priority and leave messages without pacing space buffered.
    pub(super) fn take_ready_fitting(
        &mut self,
        limit: usize,
        mut capacity: [usize; 2],
    ) -> Vec<Box<UdpMsg<I>>> {
        let mut result = Vec::with_capacity(limit);
        for (priority, queue) in self.ready.iter_mut().enumerate() {
            while result.len() < limit {
                let Some(msg) = queue.front() else { break };
                if msg.payload.len() > capacity[priority] {
                    break;
                }
                let msg = queue.pop_front().unwrap();
                capacity[priority] -= msg.payload.len();
                self.ready_bytes[priority] -= msg.payload.len() + std::mem::size_of::<UdpMsg<I>>();
                result.push(msg);
            }
        }
        if self.has_ready_fitting(capacity) {
            let _ = self.ready_notify.try_send(());
        }
        result
    }
    pub(super) fn command(&mut self, command: UdpCommand<I>) {
        let mut output = Vec::new();
        match command {
            UdpCommand::Send(msg) => {
                if self.require_auth
                    || self.sockets[msg.socket_id as usize]
                        .as_ref()
                        .is_some_and(|socket| socket.backend.is_some())
                {
                    self.metrics.udp_egress_messages_dropped.inc();
                    return;
                }
                self.enqueue([msg]);
                return;
            }
            UdpCommand::Install(installation) => {
                let (id, backend, installed) = *installation;
                let (backend, metrics) = backend();
                self.sockets[id as usize].as_mut().unwrap().backend = Some(backend);
                let _ = installed.send(metrics);
            }
            UdpCommand::Connect(connection) => {
                let (id, key, addr, attempts) = *connection;
                if let Some(backend) = self.sockets[id as usize].as_mut().unwrap().backend.as_mut()
                {
                    backend.connect(key, addr, attempts);
                    backend.drain(id, &mut output);
                }
            }
            UdpCommand::Plaintext(plaintext) => {
                let id = plaintext.socket_id;
                if let Some(backend) = self.sockets[id as usize].as_mut().unwrap().backend.as_mut()
                {
                    backend.prepare(id, plaintext, &mut output);
                }
            }
        }
        self.enqueue(output);
        let _ = self.timer_notify.try_send(());
    }
    pub(super) fn receive(&mut self, id: UdpSocketId, src_addr: SocketAddr, packet: &mut [u8]) {
        let socket = self.sockets[id as usize].as_mut().unwrap();
        let mut output = Vec::new();
        if let Some(backend) = socket.backend.as_mut() {
            let result = backend.receive(packet, src_addr);
            match result {
                Ok(Some((payload, sender))) => {
                    let stride = payload.len().max(1).try_into().unwrap();
                    socket.ingress.push(RecvUdpMsg {
                        src_addr,
                        payload,
                        sender,
                        stride,
                    });
                }
                Ok(None) => {
                    backend.drain(id, &mut output);
                    let _ = self.timer_notify.try_send(());
                }
                Err(()) => {
                    self.metrics.udp_auth_packets_rejected.inc();
                }
            }
        } else if !self.require_auth {
            socket.ingress.push(RecvUdpMsg {
                src_addr,
                payload: Bytes::copy_from_slice(packet),
                stride: packet.len().max(1).try_into().unwrap(),
                sender: None,
            });
        } else {
            self.metrics.udp_auth_packets_rejected.inc();
        }
        self.enqueue(output);
    }
    pub(super) fn writer(
        &mut self,
        id: UdpSocketId,
        encryption: Encryption<I>,
        addr: SocketAddr,
        plaintext_len: usize,
    ) -> Option<monad_wireauth::Writer> {
        let backend = self.sockets[id as usize].as_mut()?.backend.as_mut()?;
        let writer = backend.writer(encryption, addr, plaintext_len);
        let _ = self.timer_notify.try_send(());
        writer
    }
    fn next_deadline(&self) -> Option<Instant> {
        self.sockets
            .iter()
            .flatten()
            .filter_map(|socket| {
                socket
                    .backend
                    .as_ref()
                    .and_then(|backend| backend.deadline())
            })
            .min()
    }
    fn tick(&mut self) {
        let mut output = Vec::new();
        let now = Instant::now();
        for socket in self.sockets.iter_mut().flatten() {
            if let Some(backend) = socket.backend.as_mut() {
                if backend.deadline().is_some_and(|deadline| deadline <= now) {
                    backend.tick();
                    backend.drain(socket.id, &mut output);
                }
            }
        }
        self.enqueue(output);
    }
}

pub(super) async fn timers<I: Identity>(
    runtime: Rc<RefCell<Runtime<I>>>,
    notifications: async_channel::Receiver<()>,
) {
    loop {
        let delay = runtime
            .borrow()
            .next_deadline()
            .map_or(Duration::from_secs(3600), |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
        monoio::select! { _ = monoio::time::sleep(delay) => {}, _ = notifications.recv() => {} }
        runtime.borrow_mut().tick();
        super::ingress::yield_receive().await;
    }
}
