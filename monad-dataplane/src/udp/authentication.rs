// Copyright (C) 2026 Category Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
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
    backend: Option<Box<dyn Backend<I>>>,
    ingress: Ingress<I>,
}
pub(super) struct Runtime<I: Identity> {
    sockets: HashMap<UdpSocketId, Socket<I>>,
    ready: [VecDeque<UdpMsg<I>>; 2],
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
                sockets: HashMap::new(),
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
        self.sockets.insert(
            id,
            Socket {
                backend: None,
                ingress,
            },
        );
    }
    fn enqueue(&mut self, output: impl IntoIterator<Item = UdpMsg<I>>) {
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
    pub(super) fn take_ready(&mut self, limit: usize) -> Vec<UdpMsg<I>> {
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
    pub(super) fn command(&mut self, command: UdpCommand<I>) {
        let mut output = Vec::new();
        let id = match command {
            UdpCommand::Send(msg) => {
                if self.require_auth
                    || self
                        .sockets
                        .get(&msg.socket_id)
                        .is_some_and(|socket| socket.backend.is_some())
                {
                    self.metrics.udp_egress_messages_dropped.inc();
                    return;
                }
                self.enqueue([msg]);
                return;
            }
            UdpCommand::Install(id, backend, installed) => {
                self.sockets.get_mut(&id).unwrap().backend = Some(backend);
                let _ = installed.send(());
                id
            }
            UdpCommand::Connect(id, key, addr, attempts) => {
                if let Some(backend) = self.sockets.get_mut(&id).unwrap().backend.as_mut() {
                    backend.connect(key, addr, attempts);
                }
                id
            }
            UdpCommand::Plaintext(id, plaintext) => {
                if let Some(backend) = self.sockets.get_mut(&id).unwrap().backend.as_mut() {
                    backend.prepare(id, plaintext, &mut output);
                }
                id
            }
        };
        if let Some(backend) = self.sockets.get_mut(&id).unwrap().backend.as_mut() {
            backend.drain(id, &mut output);
        }
        self.enqueue(output);
        let _ = self.timer_notify.try_send(());
    }
    pub(super) fn receive(&mut self, id: UdpSocketId, src_addr: SocketAddr, packet: &mut [u8]) {
        let socket = self.sockets.get_mut(&id).unwrap();
        let mut output = Vec::new();
        if let Some(backend) = socket.backend.as_mut() {
            let result = backend.receive(packet, src_addr);
            backend.drain(id, &mut output);
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
    pub(super) fn encrypt(
        &mut self,
        id: UdpSocketId,
        encryption: Encryption<I>,
        addr: SocketAddr,
        bytes: Bytes,
        stride: u16,
    ) -> Option<Bytes> {
        let backend = self.sockets.get_mut(&id)?.backend.as_mut()?;
        let result = backend.encrypt(encryption, addr, bytes, stride);
        let mut output = Vec::new();
        backend.drain(id, &mut output);
        self.enqueue(output);
        let _ = self.timer_notify.try_send(());
        result
    }
    fn next_deadline(&self) -> Option<Instant> {
        self.sockets
            .values()
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
        for (id, socket) in &mut self.sockets {
            if let Some(backend) = socket.backend.as_mut() {
                if backend.deadline().is_some_and(|deadline| deadline <= now) {
                    backend.tick();
                    backend.drain(*id, &mut output);
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
