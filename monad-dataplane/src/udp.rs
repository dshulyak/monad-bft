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

use std::{
    cell::RefCell,
    future::Future,
    io::{Error, ErrorKind},
    net::SocketAddr,
    num::NonZeroU64,
    os::fd::{AsRawFd, FromRawFd},
    rc::Rc,
    sync::mpsc as std_mpsc,
    thread,
    time::Instant,
};

use async_channel::{Receiver, Sender};
use bytes::{Bytes, BytesMut};
use futures::future::join_all;
use monoio::{
    buf::{Ipv4RecvMsgParser, UserRecvMsgRingBuf},
    net::udp::UdpSocket,
    select, spawn,
    time::sleep,
    IoUringDriver, RuntimeBuilder,
};
use tokio::sync::mpsc::{self, error::TryRecvError};
use tracing::{debug, error, trace, warn};

use super::{RecvUdpMsg, UdpMsg, UdpPacingConfig, UdpSocketId, IPV4_HDR_SIZE, UDP_HDR_SIZE};
use crate::{
    buffer_ext::SocketBufferExt,
    metrics::DataplaneMetrics,
    pacing::{PacingItem, PacingQueue, Scheduled},
};

mod authentication;
mod ingress;
mod wake;
use authentication::Runtime;
pub use ingress::ReceiveConfig;

use crate::auth::{Identity, UdpCommand};

const DEFAULT_RINGBUF_COUNT: u32 = 2048;
const DEFAULT_RINGBUF_SIZE: u32 = ETHERNET_SEGMENT_SIZE as u32;

pub const DEFAULT_MTU: u16 = monad_types::DEFAULT_MTU;

const MAX_AGGREGATED_WRITE_SIZE: u16 = u16::MAX - IPV4_HDR_SIZE - UDP_HDR_SIZE;
const MAX_AGGREGATED_SEGMENTS: u16 = 128;
const MAX_CHANNEL_DRAIN: usize = 64;
const UDP_TX_QUEUE_SIZE_PER_WORKER: usize = 8;

struct UdpSend {
    socket_id: UdpSocketId,
    dst: SocketAddr,
    payload: Bytes,
    writer: Option<monad_wireauth::Writer>,
    header_size: u16,
}

impl<I: Identity> PacingItem for UdpMsg<I> {
    fn queued_bytes(&self) -> usize {
        self.payload.len()
    }

    fn next_payload_bytes(&self) -> usize {
        let header = self
            .encryption
            .map_or(0, |encryption| usize::from(encryption.header_size));
        self.payload
            .len()
            .min(self.stride.max(1) as usize)
            .min(usize::from(u16::MAX - IPV4_HDR_SIZE - UDP_HDR_SIZE))
            .min(max_write_size_for_segment_size(DEFAULT_SEGMENT_SIZE) as usize - header)
            + header
    }
}

impl<I: Identity> Scheduled<Box<UdpMsg<I>>> {
    pub(crate) fn take_chunk(&mut self) -> Bytes {
        self.item.payload.split_to(
            self.batch_bytes
                - self
                    .item
                    .encryption
                    .map_or(0, |encryption| usize::from(encryption.header_size)),
        )
    }
}

pub const fn segment_size_for_mtu(mtu: u16) -> u16 {
    mtu - IPV4_HDR_SIZE - UDP_HDR_SIZE
}

pub const DEFAULT_SEGMENT_SIZE: u16 = segment_size_for_mtu(DEFAULT_MTU);
pub const ETHERNET_SEGMENT_SIZE: u16 = segment_size_for_mtu(monad_types::ETHERNET_MTU);

pub(crate) struct UdpTaskConfig {
    pub up_bandwidth_mbps: u64,
    pub pacing: UdpPacingConfig,
    pub buffer_size: Option<usize>,
    pub use_multishot: bool,
    pub workers: usize,
    pub require_auth: bool,
    pub receive: ReceiveConfig,
}

fn configure_socket(socket: &UdpSocket, buffer_size: Option<usize>) {
    if let Some(size) = buffer_size {
        set_socket_buffer_sizes(socket, size);
    }
    set_mtu_discovery(socket);
}

fn set_socket_buffer_sizes(socket: &UdpSocket, requested_size: usize) {
    set_recv_buffer_size(socket, requested_size);
    set_send_buffer_size(socket, requested_size);
}

fn set_recv_buffer_size(socket: &UdpSocket, requested_size: usize) {
    if let Err(e) = socket.set_recv_buffer_size(requested_size) {
        panic!("set_recv_buffer_size to {requested_size} failed with: {e}");
    }
    let actual_size = socket.recv_buffer_size().expect("get recv buffer size");
    if actual_size < requested_size {
        panic!("unable to set udp receive buffer size to {requested_size}. Got {actual_size} instead. Set net.core.rmem_max to at least {requested_size}");
    }
}

fn set_send_buffer_size(socket: &UdpSocket, requested_size: usize) {
    if let Err(e) = socket.set_send_buffer_size(requested_size) {
        panic!("set_send_buffer_size to {requested_size} failed with: {e}");
    }
    let actual_size = socket.send_buffer_size().expect("get send buffer size");
    if actual_size < requested_size {
        panic!("unable to set udp send buffer size to {requested_size}. got {actual_size} instead. set net.core.wmem_max to at least {requested_size}");
    }
}

fn set_mtu_discovery(socket: &UdpSocket) {
    const MTU_DISCOVER: libc::c_int = libc::IP_PMTUDISC_OMIT;
    let raw_fd = socket.as_raw_fd();

    if unsafe {
        libc::setsockopt(
            raw_fd,
            libc::SOL_IP,
            libc::IP_MTU_DISCOVER,
            &MTU_DISCOVER as *const _ as _,
            std::mem::size_of_val(&MTU_DISCOVER) as _,
        )
    } != 0
    {
        panic!(
            "set IP_MTU_DISCOVER failed with: {}",
            Error::last_os_error()
        );
    }
}

pub(crate) fn spawn_tasks<I: Identity>(
    socket_configs: Vec<(
        UdpSocketId,
        SocketAddr,
        mpsc::Sender<Vec<RecvUdpMsg<I>>>,
        tokio::sync::watch::Receiver<(std::collections::HashSet<I>, bool)>,
    )>,
    udp_egress_rx: mpsc::Receiver<UdpCommand<I>>,
    config: UdpTaskConfig,
    bound_addrs_tx: std_mpsc::SyncSender<Vec<(UdpSocketId, SocketAddr)>>,
    metrics: DataplaneMetrics,
) {
    let UdpTaskConfig {
        up_bandwidth_mbps,
        pacing,
        buffer_size,
        use_multishot,
        workers: worker_count,
        require_auth,
        receive,
    } = config;
    assert!(worker_count != 0, "at least one UDP TX worker is required");
    let mut worker_sockets: Vec<Vec<_>> = (0..worker_count).map(|_| Vec::new()).collect();
    let mut bound_addrs = Vec::with_capacity(socket_configs.len());

    let (runtime, ready_rx, timer_rx) = Runtime::new(metrics.clone());
    runtime.borrow_mut().require_auth = require_auth;
    runtime.borrow_mut().ready_limit = pacing.max_queued_bytes;
    for (socket_id, socket_addr, ingress_tx, priority_rx) in socket_configs {
        runtime.borrow_mut().add_socket(
            socket_id,
            ingress::start(ingress_tx, receive, metrics.clone(), priority_rx),
        );
        let socket = std::net::UdpSocket::bind(socket_addr).unwrap();
        for sockets in &mut worker_sockets {
            sockets.push((
                socket_id,
                socket.try_clone().expect("failed to clone UDP TX socket"),
            ));
        }
        let rx = UdpSocket::from_std(socket).unwrap();
        configure_socket(&rx, buffer_size);
        let actual_addr = rx.local_addr().unwrap();
        bound_addrs.push((socket_id, actual_addr));

        let group_id = socket_id as u16;
        if use_multishot {
            spawn(rx_multishot_socket(
                rx,
                socket_id,
                runtime.clone(),
                group_id,
                metrics.clone(),
            ));
            trace!(
                ?socket_id,
                ?socket_addr,
                ?actual_addr,
                "created multishot socket"
            );
        } else {
            spawn(rx_single_socket(
                rx,
                socket_id,
                runtime.clone(),
                metrics.clone(),
            ));
            trace!(?socket_id, ?socket_addr, ?actual_addr, "created socket");
        }
    }

    let (dispatch_tx, dispatch_rx) =
        async_channel::bounded(UDP_TX_QUEUE_SIZE_PER_WORKER * worker_count);
    let (startup_tx, startup_rx) = std_mpsc::channel();
    for (worker, sockets) in worker_sockets.into_iter().enumerate() {
        let metrics = metrics.clone();
        let startup_tx = startup_tx.clone();
        let dispatch_rx = dispatch_rx.clone();
        thread::Builder::new()
            .name(format!("monad-udp-tx-{worker}"))
            .spawn(move || {
                RuntimeBuilder::<IoUringDriver>::new()
                    .enable_timer()
                    .build()
                    .expect("failed building UDP TX runtime")
                    .block_on(tx_worker(sockets, dispatch_rx, metrics, startup_tx));
            })
            .expect("failed to spawn UDP TX thread");
    }
    drop(startup_tx);

    for _ in 0..worker_count {
        startup_rx
            .recv()
            .expect("UDP TX worker exited during startup");
    }
    bound_addrs_tx.send(bound_addrs).unwrap();
    spawn(authentication::timers(runtime.clone(), timer_rx));
    spawn(tx_pacing(
        dispatch_tx,
        udp_egress_rx,
        up_bandwidth_mbps,
        pacing,
        metrics,
        runtime,
        ready_rx,
    ));
}

async fn rx_single_socket<I: Identity>(
    socket: UdpSocket,
    socket_id: UdpSocketId,
    runtime: Rc<RefCell<Runtime<I>>>,
    metrics: DataplaneMetrics,
) {
    let mut intake = 0;
    loop {
        let buf = BytesMut::with_capacity(ETHERNET_SEGMENT_SIZE.into());

        match socket.recv_from(buf).await {
            (Ok((len, src_addr)), mut buf) => {
                metrics.udp_messages_received.inc();
                metrics.udp_bytes_received.add(len as u64);

                runtime
                    .borrow_mut()
                    .receive(socket_id, src_addr, &mut buf[..len]);
            }
            (Err(err), _buf) => {
                metrics.udp_receive_errors.inc();
                warn!("socket.recv_from() error {}", err);
            }
        }
        intake += 1;
        if intake == ingress::RECEIVE_BATCH {
            intake = 0;
            ingress::yield_receive().await;
        }
    }
}

enum MultishotResult<R> {
    ReuseRing(R),
    RecreateRing,
}

async fn run_multishot_stream<I: Identity>(
    socket: &UdpSocket,
    socket_id: UdpSocketId,
    runtime: &Rc<RefCell<Runtime<I>>>,
    ring: UserRecvMsgRingBuf<Ipv4RecvMsgParser>,
    metrics: &DataplaneMetrics,
) -> MultishotResult<UserRecvMsgRingBuf<Ipv4RecvMsgParser>> {
    let mut multishot = socket
        .recvmsg_multishot(ring)
        .expect("failed to create multishot stream");
    let mut stream = multishot.stream();

    let mut intake = 0;
    while let Some(result) = stream.next().await {
        match result {
            Ok((src_addr, mut buf)) => {
                let len = buf.len();
                metrics.udp_messages_received.inc();
                metrics.udp_bytes_received.add(len as u64);
                runtime
                    .borrow_mut()
                    .receive(socket_id, src_addr.into(), &mut buf);
                drop(buf);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                metrics.udp_receive_errors.inc();
                debug!("ringbuf exhausted, recreating stream");
            }
            Err(e) => {
                metrics.udp_receive_errors.inc();
                warn!("multishot recv error: {:?}", e);
            }
        }
        intake += 1;
        if intake == ingress::RECEIVE_BATCH {
            intake = 0;
            ingress::yield_receive().await;
        }
    }

    debug!("multishot stream needs to be recreated");
    match multishot.try_into_ring() {
        Ok(ring) => MultishotResult::ReuseRing(ring),
        Err(_) => {
            error!("multishot stream not terminated after poll returned None, recreating ring");
            MultishotResult::RecreateRing
        }
    }
}

async fn rx_multishot_socket<I: Identity>(
    socket: UdpSocket,
    socket_id: UdpSocketId,
    runtime: Rc<RefCell<Runtime<I>>>,
    group_id: u16,
    metrics: DataplaneMetrics,
) {
    let create_ring = || {
        UserRecvMsgRingBuf::<Ipv4RecvMsgParser>::new(
            DEFAULT_RINGBUF_COUNT as u16,
            DEFAULT_RINGBUF_SIZE as usize,
            group_id,
        )
    };

    let mut ring = match create_ring() {
        Ok(ring) => ring,
        Err(err) => {
            warn!(
                ?err,
                "failed to create multishot buffer ring, falling back to single-shot UDP receiver"
            );
            return rx_single_socket(socket, socket_id, runtime, metrics).await;
        }
    };

    loop {
        match run_multishot_stream(&socket, socket_id, &runtime, ring, &metrics).await {
            MultishotResult::ReuseRing(r) => ring = r,
            MultishotResult::RecreateRing => {
                ring = create_ring().expect("failed to recreate multishot buffer ring")
            }
        }
    }
}

fn enqueue_udp_msg<I: Identity>(
    queue: &mut PacingQueue<Box<UdpMsg<I>>>,
    metrics: &DataplaneMetrics,
    msg: Box<UdpMsg<I>>,
) {
    let SocketAddr::V4(destination) = msg.dst else {
        metrics.udp_egress_messages_dropped.inc();
        debug!(destination = ?msg.dst, "IPv6 UDP message is not supported");
        return;
    };
    let priority = msg.priority;
    let _ = queue.enqueue(destination, priority, msg);
}

fn can_receive_egress<I: Identity>(
    queue: &PacingQueue<Box<UdpMsg<I>>>,
    runtime: &Runtime<I>,
) -> bool {
    let pending = runtime.ready_payload_bytes();
    queue
        .remaining_capacity()
        .iter()
        .zip(pending)
        .all(|(&available, pending)| available > pending)
}

struct EgressIntake<'a, I: Identity> {
    receiver: &'a mut mpsc::Receiver<UdpCommand<I>>,
    runtime: &'a Rc<RefCell<Runtime<I>>>,
    ready_rx: &'a Receiver<()>,
}

impl<I: Identity> EgressIntake<'_, I> {
    async fn wait<F: Future>(
        &mut self,
        future: F,
        queue: &mut PacingQueue<Box<UdpMsg<I>>>,
        metrics: &DataplaneMetrics,
        wake: &wake::WakeBridge,
    ) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut closed = false;
        loop {
            let can_receive = can_receive_egress(queue, &self.runtime.borrow());
            let can_drain = queue.remaining_capacity().iter().any(|&bytes| bytes > 0);
            // Both channels share one bridge, so either can wake a busy Monoio loop.
            let result = wake
                .wait(async {
                    select! {
                        biased;
                        result = future.as_mut() => Some(result),
                        command = self.receiver.recv(), if !closed && can_receive => {
                            let mut received = 0;
                            if let Some(command) = command {
                                self.runtime.borrow_mut().command(command);
                                received += 1;
                                for _ in 1..MAX_CHANNEL_DRAIN {
                                    if !can_receive_egress(queue, &self.runtime.borrow()) {
                                        break;
                                    }
                                    match self.receiver.try_recv() {
                                        Ok(command) => {
                                            self.runtime.borrow_mut().command(command);
                                            received += 1;
                                        }
                                        Err(TryRecvError::Empty) => break,
                                        Err(TryRecvError::Disconnected) => {
                                            closed = true;
                                            break;
                                        }
                                    }
                                }
                            } else {
                                closed = true;
                            }
                            metrics.udp_tx_commands_during_dispatch_wait.add(received);
                            None
                        }
                        Ok(()) = self.ready_rx.recv(), if can_drain => None,
                    }
                })
                .await;
            if let Some(result) = result {
                return result;
            }
            for msg in self
                .runtime
                .borrow_mut()
                .take_ready_fitting(MAX_CHANNEL_DRAIN, queue.remaining_capacity())
            {
                enqueue_udp_msg(queue, metrics, msg);
            }
            // Recheck worker readiness after at most 64 commands, and let RX/auth run.
            ingress::yield_receive().await;
        }
    }
}

async fn tx_pacing<I: Identity>(
    dispatch_tx: Sender<Vec<UdpSend>>,
    mut udp_egress_rx: mpsc::Receiver<UdpCommand<I>>,
    up_bandwidth_mbps: u64,
    pacing_config: UdpPacingConfig,
    metrics: DataplaneMetrics,
    runtime: Rc<RefCell<Runtime<I>>>,
    ready_rx: async_channel::Receiver<()>,
) {
    let global_bytes_per_second = NonZeroU64::new(
        u64::try_from(u128::from(up_bandwidth_mbps) * 1_000_000 / 8)
            .expect("UDP bandwidth overflows bytes per second"),
    )
    .expect("UDP bandwidth must be non-zero");
    let peer_bytes_per_second = NonZeroU64::new(
        u64::try_from(u128::from(pacing_config.peer_bandwidth_mbps) * 1_000_000 / 8)
            .expect("UDP peer bandwidth overflows bytes per second"),
    )
    .expect("UDP peer bandwidth must be non-zero");
    let mut queue = PacingQueue::new(
        global_bytes_per_second,
        peer_bytes_per_second,
        pacing_config.max_queued_bytes,
        metrics.clone(),
    );
    let max_batch_bytes = max_write_size_for_segment_size(DEFAULT_SEGMENT_SIZE) as usize;
    let max_batch_items = MAX_AGGREGATED_SEGMENTS as usize;
    let wake = wake::WakeBridge::new();

    loop {
        ingress::yield_receive().await;
        for _ in 0..MAX_CHANNEL_DRAIN {
            match udp_egress_rx.try_recv() {
                Ok(command) => runtime.borrow_mut().command(command),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        for msg in runtime.borrow_mut().take_ready(MAX_CHANNEL_DRAIN) {
            enqueue_udp_msg(&mut queue, &metrics, msg);
        }
        if queue.is_empty() {
            select! {
                command = wake.wait(udp_egress_rx.recv()) => {
                    let Some(command) = command else { return; };
                    runtime.borrow_mut().command(command);
                }
                _ = ready_rx.recv() => {}
            }
            continue;
        }

        let now = queue.elapsed();
        let Some(at) = queue.next_wakeup(now) else {
            continue;
        };
        let delay = at.saturating_sub(now);
        if !delay.is_zero() {
            select! {
                command = wake.wait(udp_egress_rx.recv()) => {
                    let Some(command) = command else { return };
                    runtime.borrow_mut().command(command);
                    continue;
                }
                _ = ready_rx.recv() => { continue; }
                _ = sleep(delay) => {}
            }
        }

        let now = queue.elapsed();
        if queue.next_wakeup(now).is_none_or(|at| at > now) {
            continue;
        }

        let queue_len = queue.len();
        let mut batch = Vec::with_capacity(max_batch_items);
        let mut total_bytes = 0;
        while batch.len() < max_batch_items && total_bytes < max_batch_bytes {
            let Some(mut scheduled) = queue.dequeue(now, max_batch_bytes - total_bytes) else {
                break;
            };
            let chunk = scheduled.take_chunk();
            let wire_bytes = scheduled.batch_bytes;
            let msg = &scheduled.item;
            let socket_id = msg.socket_id;
            let dst = msg.dst;
            let encryption = msg.encryption;

            if !msg.payload.is_empty() {
                let SocketAddr::V4(destination) = dst else {
                    unreachable!("only IPv4 messages enter the pacing queue")
                };
                assert!(
                    queue.requeue(destination, scheduled).is_ok(),
                    "requeueing admitted UDP bytes cannot exceed memory"
                );
            }

            total_bytes += wire_bytes;
            let writer = if let Some(encryption) = encryption {
                let Some(writer) =
                    runtime
                        .borrow_mut()
                        .writer(socket_id, encryption, dst, chunk.len())
                else {
                    metrics.udp_egress_messages_dropped.inc();
                    continue;
                };
                Some(writer)
            } else {
                None
            };
            let header_size = encryption.map_or(0, |encryption| encryption.header_size);
            debug_assert_eq!(chunk.len() + usize::from(header_size), wire_bytes);
            batch.push(UdpSend {
                socket_id,
                dst,
                payload: chunk,
                writer,
                header_size,
            });
        }

        if batch.is_empty() {
            continue;
        }
        let batch_count = batch.len();
        if batch_count > 1 {
            trace!(
                batch_size = batch_count,
                total_bytes,
                queue_size = queue_len,
                "sending udp batch"
            );
        }

        let started = Instant::now();
        let result = EgressIntake {
            receiver: &mut udp_egress_rx,
            runtime: &runtime,
            ready_rx: &ready_rx,
        }
        .wait(dispatch_tx.send(batch), &mut queue, &metrics, &wake)
        .await;
        metrics
            .udp_tx_queue_wait_micros
            .add(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
        ingress::yield_receive().await;
        if let Err(error) = result {
            metrics
                .udp_egress_messages_dropped
                .add(u64::try_from(error.0.len()).unwrap_or(u64::MAX));
            return;
        }
    }
}

enum WorkerPayload {
    Original(Bytes),
    Encrypted(std::ops::Range<usize>),
}

async fn tx_worker(
    tx_sockets: Vec<(UdpSocketId, std::net::UdpSocket)>,
    dispatch_rx: Receiver<Vec<UdpSend>>,
    metrics: DataplaneMetrics,
    startup_tx: std_mpsc::Sender<()>,
) {
    let mut sockets: [Option<UdpSocket>; 3] = std::array::from_fn(|_| None);
    for (id, socket) in tx_sockets {
        sockets[id as usize] = Some(UdpSocket::from_std(socket).unwrap());
    }
    // One output allocation for this worker. Immutable slices keep it alive
    // across concurrent monoio operations; completion restores unique ownership.
    let mut buffer = BytesMut::zeroed(usize::from(max_write_size_for_segment_size(
        DEFAULT_SEGMENT_SIZE,
    )));
    metrics.udp_tx_buffer_allocations.inc();
    let mut prepared = Vec::with_capacity(MAX_AGGREGATED_SEGMENTS as usize);
    if startup_tx.send(()).is_err() {
        return;
    }
    drop(startup_tx);

    while let Ok(dispatch) = dispatch_rx.recv().await {
        let mut offset = 0;
        for message in dispatch {
            let payload = if let Some(writer) = message.writer {
                let end = offset + message.payload.len() + usize::from(message.header_size);
                match writer.encrypt_into(&message.payload, &mut buffer[offset..end]) {
                    Ok(()) => {
                        metrics.udp_tx_encrypted_packets.inc();
                        let range = offset..end;
                        offset = end;
                        WorkerPayload::Encrypted(range)
                    }
                    Err(_) => {
                        metrics.udp_tx_encryption_errors.inc();
                        metrics.udp_egress_messages_dropped.inc();
                        continue;
                    }
                }
            } else {
                WorkerPayload::Original(message.payload)
            };
            prepared.push((message.socket_id, message.dst, payload));
        }
        let frozen = buffer.freeze();
        let sends = prepared.drain(..).map(|(socket_id, dst, payload)| {
            let socket = sockets[socket_id as usize]
                .as_ref()
                .expect("valid socket_id");
            let bytes = match payload {
                WorkerPayload::Original(bytes) => bytes,
                WorkerPayload::Encrypted(range) => frozen.slice(range),
            };
            socket.send_to(bytes, dst)
        });
        for (ret, chunk) in join_all(sends).await {
            match ret {
                Ok(payload_bytes_sent) => {
                    metrics.udp_messages_sent.inc();
                    metrics.udp_bytes_sent.add(payload_bytes_sent as u64);
                }
                Err(err) => record_send_error(&metrics, err, chunk.len()),
            }
            drop(chunk);
        }
        buffer = frozen
            .try_into_mut()
            .expect("all transmit slices completed");
    }
}

fn record_send_error(metrics: &DataplaneMetrics, err: Error, len: usize) {
    metrics.udp_send_errors.inc();
    match err.kind() {
        ErrorKind::NetworkUnreachable => {
            debug!("send address family mismatch. message is dropped")
        }
        ErrorKind::InvalidInput => warn!(len, "got EINVAL on send. message is dropped"),
        _ if is_eafnosupport(&err) => {
            debug!("send address family mismatch. message is dropped")
        }
        _ => error!(len, ?err, "unexpected send error. message is dropped"),
    }
}

fn max_write_size_for_segment_size(segment_size: u16) -> u16 {
    (MAX_AGGREGATED_WRITE_SIZE / segment_size).min(MAX_AGGREGATED_SEGMENTS) * segment_size
}

fn is_eafnosupport(err: &Error) -> bool {
    const EAFNOSUPPORT: &str = "Address family not supported by protocol";

    let err = format!("{}", err);

    err.len() >= EAFNOSUPPORT.len() && &err[0..EAFNOSUPPORT.len()] == EAFNOSUPPORT
}

pub trait UdpSocketExt: AsRawFd {
    fn dup(&self) -> std::io::Result<UdpSocket> {
        let fd = self.as_raw_fd();
        let new_fd = unsafe { libc::dup(fd) };
        if new_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(new_fd) };
        UdpSocket::from_std(std_socket)
    }
}

impl UdpSocketExt for UdpSocket {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use monoio::time;

    use super::*;

    fn queued_message(value: u8, bytes: usize) -> Box<UdpMsg<()>> {
        Box::new(UdpMsg {
            socket_id: UdpSocketId::Raptorcast,
            dst: "127.0.0.1:1".parse().unwrap(),
            payload: vec![value; bytes].into(),
            stride: bytes.try_into().unwrap(),
            priority: monad_types::UdpPriority::Regular,
            encryption: None,
        })
    }

    fn paced_message() -> UdpSend {
        UdpSend {
            socket_id: UdpSocketId::Raptorcast,
            dst: "127.0.0.1:1".parse().unwrap(),
            payload: Bytes::from_static(b"already paced"),
            writer: None,
            header_size: 0,
        }
    }

    #[test]
    fn limited_ready_drain_preserves_priority_fifo_and_payload_accounting() {
        let metrics = DataplaneMetrics::new();
        let (runtime, _ready_rx, _timer_rx) = Runtime::<()>::new(metrics.clone());
        for (value, bytes, priority) in [
            (1, 48, monad_types::UdpPriority::High),
            (2, 8, monad_types::UdpPriority::High),
            (3, 16, monad_types::UdpPriority::Regular),
            (4, 8, monad_types::UdpPriority::Regular),
        ] {
            let mut msg = queued_message(value, bytes);
            msg.priority = priority;
            runtime.borrow_mut().command(UdpCommand::Send(msg));
        }
        let mut runtime = runtime.borrow_mut();
        assert_eq!(runtime.ready_payload_bytes(), [56, 24]);
        let batch = runtime.take_ready_fitting(4, [32, 16]);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload[0], 3);
        assert_eq!(runtime.ready_payload_bytes(), [56, 8]);
        assert!(!runtime.has_ready_fitting([32, 0]));
        let batch = runtime.take_ready_fitting(1, [64, 16]);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload[0], 1);
        assert_eq!(runtime.ready_payload_bytes(), [8, 8]);
        let batch = runtime.take_ready_fitting(4, [8, 8]);
        assert_eq!(
            batch.iter().map(|msg| msg.payload[0]).collect::<Vec<_>>(),
            [2, 4]
        );
        assert_eq!(runtime.ready_payload_bytes(), [0, 0]);
        assert_eq!(metrics.udp_egress_messages_dropped.get(), 0);
    }

    #[monoio::test(timer_enabled = true)]
    async fn worker_wait_drains_intake_and_stops_at_pacing_capacity() {
        let metrics = DataplaneMetrics::new();
        let (runtime, ready_rx, _timer_rx) = Runtime::<()>::new(metrics.clone());
        let (sender, mut receiver) = mpsc::channel(4);
        for value in 0..4 {
            sender
                .try_send(UdpCommand::Send(queued_message(value, 48)))
                .unwrap_or_else(|_| panic!("input queue has four slots"));
        }
        let (dispatch_tx, dispatch_rx) = async_channel::bounded(1);
        dispatch_tx.try_send(Vec::new()).unwrap();
        let mut queue = PacingQueue::new(
            NonZeroU64::new(1_000_000).unwrap(),
            NonZeroU64::new(1_000_000).unwrap(),
            128,
            metrics.clone(),
        );
        let (done, finished) = async_channel::bounded(1);
        let wait_runtime = runtime.clone();
        let wait_metrics = metrics.clone();
        spawn(async move {
            let wake = wake::WakeBridge::new();
            EgressIntake {
                receiver: &mut receiver,
                runtime: &wait_runtime,
                ready_rx: &ready_rx,
            }
            .wait(
                dispatch_tx.send(vec![paced_message()]),
                &mut queue,
                &wait_metrics,
                &wake,
            )
            .await
            .unwrap();
            assert_eq!(queue.len(), 2);
            assert_eq!(queue.remaining_capacity(), [128, 32]);
            done.send(()).await.unwrap();
        });
        time::timeout(Duration::from_secs(1), async {
            while metrics.udp_pacing_queued_bytes.get() != 96 {
                ingress::yield_receive().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(metrics.udp_tx_commands_during_dispatch_wait.get(), 3);
        assert_eq!(runtime.borrow().ready_payload_bytes(), [0, 48]);
        assert_eq!(sender.capacity(), 3);
        for value in 4..7 {
            sender
                .try_send(UdpCommand::Send(queued_message(value, 48)))
                .unwrap_or_else(|_| panic!("intake freed three channel slots"));
        }
        time::sleep(Duration::from_millis(5)).await;
        assert_eq!(sender.capacity(), 0, "full pacer must stop draining input");
        assert_eq!(metrics.udp_tx_commands_during_dispatch_wait.get(), 3);
        assert_eq!(metrics.udp_egress_messages_dropped.get(), 0);
        assert!(finished.try_recv().is_err());
        dispatch_rx.try_recv().unwrap();
        let batch = time::timeout(Duration::from_secs(1), dispatch_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload.as_ref(), b"already paced");
        time::timeout(Duration::from_secs(1), finished.recv())
            .await
            .unwrap()
            .unwrap();
    }

    #[monoio::test(timer_enabled = true)]
    async fn ready_worker_wins_over_queued_input() {
        let metrics = DataplaneMetrics::new();
        let (runtime, ready_rx, _timer_rx) = Runtime::<()>::new(metrics.clone());
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .try_send(UdpCommand::Send(queued_message(1, 48)))
            .unwrap_or_else(|_| panic!("input queue is empty"));
        let (dispatch_tx, dispatch_rx) = async_channel::bounded(1);
        let mut queue = PacingQueue::new(
            NonZeroU64::new(1_000_000).unwrap(),
            NonZeroU64::new(1_000_000).unwrap(),
            128,
            metrics.clone(),
        );
        EgressIntake {
            receiver: &mut receiver,
            runtime: &runtime,
            ready_rx: &ready_rx,
        }
        .wait(
            dispatch_tx.send(vec![paced_message()]),
            &mut queue,
            &metrics,
            &wake::WakeBridge::new(),
        )
        .await
        .unwrap();
        assert_eq!(dispatch_rx.try_recv().unwrap().len(), 1);
        assert_eq!(sender.capacity(), 0);
        assert_eq!(metrics.udp_tx_commands_during_dispatch_wait.get(), 0);
        assert!(queue.is_empty());
    }

    #[monoio::test(timer_enabled = true)]
    async fn closed_input_preserves_pending_worker_dispatch() {
        let metrics = DataplaneMetrics::new();
        let (runtime, ready_rx, _timer_rx) = Runtime::<()>::new(metrics.clone());
        let (sender, mut receiver) = mpsc::channel(1);
        drop(sender);
        let (dispatch_tx, dispatch_rx) = async_channel::bounded(1);
        dispatch_tx.try_send(Vec::new()).unwrap();
        let mut queue = PacingQueue::new(
            NonZeroU64::new(1_000_000).unwrap(),
            NonZeroU64::new(1_000_000).unwrap(),
            128,
            metrics.clone(),
        );
        let consumer = spawn(async move {
            time::sleep(Duration::from_millis(5)).await;
            dispatch_rx.try_recv().unwrap();
            dispatch_rx.recv().await.unwrap()
        });
        time::timeout(
            Duration::from_secs(1),
            EgressIntake {
                receiver: &mut receiver,
                runtime: &runtime,
                ready_rx: &ready_rx,
            }
            .wait(
                dispatch_tx.send(vec![paced_message()]),
                &mut queue,
                &metrics,
                &wake::WakeBridge::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let batch = consumer.await;
        assert_eq!(batch[0].payload.as_ref(), b"already paced");
        assert_eq!(metrics.udp_tx_commands_during_dispatch_wait.get(), 0);
    }

    #[monoio::test(timer_enabled = true)]
    async fn pacing_waits_for_worker_queue_space_and_counts_closed_queue_drops() {
        let metrics = DataplaneMetrics::new();
        let (runtime, ready_rx, _timer_rx) = Runtime::<()>::new(metrics.clone());
        let (sender, receiver) = mpsc::channel(4);
        let (dispatch_tx, dispatch_rx) = async_channel::bounded(1);
        dispatch_tx.try_send(Vec::new()).unwrap();
        let message = || {
            UdpCommand::Send(Box::new(UdpMsg {
                socket_id: UdpSocketId::Raptorcast,
                dst: "127.0.0.1:1".parse().unwrap(),
                payload: Bytes::from_static(&[1]),
                stride: 1,
                priority: monad_types::UdpPriority::High,
                encryption: None,
            }))
        };
        assert!(sender.try_send(message()).is_ok());
        let (done, finished) = async_channel::bounded(1);
        let pacing_metrics = metrics.clone();
        spawn(async move {
            tx_pacing(
                dispatch_tx,
                receiver,
                1_000,
                UdpPacingConfig::for_global_bandwidth(1_000),
                pacing_metrics,
                runtime,
                ready_rx,
            )
            .await;
            done.send(()).await.unwrap();
        });
        time::sleep(Duration::from_millis(5)).await;
        assert_eq!(metrics.udp_egress_messages_dropped.get(), 0);
        assert!(finished.try_recv().is_err());
        dispatch_rx.try_recv().unwrap(); // release the deliberately full worker queue
        let batch = time::timeout(Duration::from_secs(1), dispatch_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].payload.as_ref(), &[1]);
        assert!(metrics.udp_tx_queue_wait_micros.get() > 0);
        dispatch_rx.close();
        assert!(sender.try_send(message()).is_ok());
        time::timeout(Duration::from_secs(1), finished.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(metrics.udp_egress_messages_dropped.get(), 1);
    }

    #[monoio::test(timer_enabled = true)]
    async fn new_peer_wakes_transmit_while_another_peer_is_cooling() {
        let regular = UdpSocket::bind("127.0.0.1:0").unwrap();
        let high = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (dispatch_tx, dispatch_rx) = async_channel::bounded(UDP_TX_QUEUE_SIZE_PER_WORKER);
        let (startup_tx, _startup_rx) = std_mpsc::channel();
        spawn(tx_worker(
            vec![(UdpSocketId::Raptorcast, socket)],
            dispatch_rx,
            DataplaneMetrics::new(),
            startup_tx,
        ));
        let (sender, receiver) = mpsc::channel(4);
        for _ in 0..2 {
            assert!(sender
                .try_send(UdpCommand::Send(Box::new(UdpMsg {
                    socket_id: UdpSocketId::Raptorcast,
                    dst: regular.local_addr().unwrap(),
                    payload: vec![1; 60_000].into(),
                    stride: 60_000,
                    priority: monad_types::UdpPriority::Regular,
                    encryption: None,
                })))
                .is_ok());
        }
        let (runtime, ready_rx, _timer_rx) = Runtime::<()>::new(DataplaneMetrics::new());
        spawn(tx_pacing(
            dispatch_tx,
            receiver,
            1_000,
            UdpPacingConfig {
                peer_bandwidth_mbps: 1,
                max_queued_bytes: 1024 * 1024,
            },
            DataplaneMetrics::new(),
            runtime,
            ready_rx,
        ));
        let (result, _) = time::timeout(Duration::from_secs(1), regular.recv_from(vec![0; 60_000]))
            .await
            .unwrap();
        assert_eq!(result.unwrap().0, 60_000);
        // Regular traffic is cooling for about 480 ms; the new peer need not wait.
        assert!(sender
            .try_send(UdpCommand::Send(Box::new(UdpMsg {
                socket_id: UdpSocketId::Raptorcast,
                dst: high.local_addr().unwrap(),
                payload: Bytes::from_static(&[2]),
                stride: 1,
                priority: monad_types::UdpPriority::High,
                encryption: None,
            })))
            .is_ok());
        let (result, payload) =
            time::timeout(Duration::from_millis(100), high.recv_from(vec![0; 1]))
                .await
                .unwrap();
        assert_eq!(result.unwrap().0, 1);
        assert_eq!(payload, [2]);
    }

    #[monoio::test]
    async fn test_dup_independent() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let main_socket = monoio::net::udp::UdpSocket::bind(addr).unwrap();
        let actual_addr = main_socket.local_addr().unwrap();

        let dup1 = main_socket.dup().unwrap();
        let dup2 = main_socket.dup().unwrap();

        drop(dup1);

        let result = dup2.send_to(b"test", actual_addr).await.0.map(|_| ());
        assert!(result.is_ok(), "dup2 should still work after dup1 dropped");

        let result = main_socket
            .send_to(b"test", actual_addr)
            .await
            .0
            .map(|_| ());
        assert!(
            result.is_ok(),
            "main socket should still work after dup1 dropped"
        );
    }

    #[monoio::test(timer_enabled = true)]
    async fn worker_buffer_is_reused_after_concurrent_successful_and_failed_sends() {
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buffer = BytesMut::zeroed(usize::from(DEFAULT_SEGMENT_SIZE));
        let allocation = buffer.as_ptr();
        for _ in 0..3 {
            buffer[..13].copy_from_slice(b"worker packet");
            let frozen = buffer.freeze();
            let destinations = [sink.local_addr().unwrap(), "127.0.0.1:0".parse().unwrap()];
            let sends = destinations
                .iter()
                .map(|dst| socket.send_to(frozen.slice(..13), *dst));
            for ((result, owned), dst) in join_all(sends).await.into_iter().zip(destinations) {
                if dst.port() == 0 {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap(), 13);
                    let mut received = [0; 32];
                    let count = sink.recv(&mut received).unwrap();
                    assert_eq!(&received[..count], b"worker packet");
                }
                drop(owned);
            }
            buffer = frozen
                .try_into_mut()
                .expect("all slices must return on completion");
            assert_eq!(buffer.as_ptr(), allocation);
        }
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_multishot_falls_back_when_ring_creation_fails() {
        const GROUP_ID: u16 = 42;

        let existing_ring = match UserRecvMsgRingBuf::<Ipv4RecvMsgParser>::new(
            DEFAULT_RINGBUF_COUNT as u16,
            DEFAULT_RINGBUF_SIZE as usize,
            GROUP_ID,
        ) {
            Ok(ring) => Some(ring),
            Err(err) if err.raw_os_error() == Some(libc::EINVAL) => None,
            Err(err) => panic!("unexpected buffer ring creation error: {err}"),
        };

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let rx_socket = UdpSocket::bind(addr).unwrap();
        let rx_addr = rx_socket.local_addr().unwrap();
        let tx_socket = UdpSocket::bind(addr).unwrap();
        let (ingress_tx, mut ingress_rx) = mpsc::channel(1);

        let metrics = DataplaneMetrics::new();
        let (runtime, _ready_rx, _timer_rx) = Runtime::<()>::new(metrics.clone());
        let (_pins, priority_rx) =
            tokio::sync::watch::channel((std::collections::HashSet::new(), true));
        runtime.borrow_mut().add_socket(
            UdpSocketId::Raptorcast,
            ingress::start(
                ingress_tx,
                ReceiveConfig::default(),
                metrics.clone(),
                priority_rx,
            ),
        );
        spawn(rx_multishot_socket(
            rx_socket,
            UdpSocketId::Raptorcast,
            runtime,
            GROUP_ID,
            metrics,
        ));

        let payload = b"fallback";
        let bytes_sent = tx_socket.send_to(payload, rx_addr).await.0.unwrap();
        assert_eq!(bytes_sent, payload.len());

        let msg = time::timeout(Duration::from_secs(1), ingress_rx.recv())
            .await
            .expect("timed out waiting for UDP message")
            .expect("UDP ingress channel closed");
        assert_eq!(msg[0].payload.as_ref(), payload);

        drop(existing_ring);
    }
}
