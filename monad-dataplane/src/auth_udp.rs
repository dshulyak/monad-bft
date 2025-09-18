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
    collections::VecDeque,
    io::{Error, ErrorKind},
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd},
    rc::Rc,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use futures::future::join_all;
use monoio::{net::udp::UdpSocket, spawn, time};
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

use super::{InitSessionsMessage, RecvUdpMsg, UdpEgressMessage};
use crate::{
    buffer_ext::SocketBufferExt,
    manager::{
        MonoioAuthProtocol, MonoioAuthProtocolBackground, MonoioAuthProtocolReceiver,
        MonoioAuthProtocolSender,
    },
    udp::{UdpMessageType, DEFAULT_SEGMENT_SIZE},
};

const ETHERNET_MTU: u16 = 1500;
const IPV4_HDR_SIZE: u16 = 20;
const UDP_HDR_SIZE: u16 = 8;
const ETHERNET_SEGMENT_SIZE: u16 = ETHERNET_MTU - IPV4_HDR_SIZE - UDP_HDR_SIZE;

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

pub(crate) fn spawn_tasks(
    local_addr: SocketAddr,
    direct_socket_port: Option<u16>,
    udp_ingress_tx: mpsc::Sender<RecvUdpMsg>,
    udp_direct_ingress_tx: mpsc::Sender<RecvUdpMsg>,
    udp_egress_rx: mpsc::Receiver<UdpEgressMessage>,
    init_sessions_rx: mpsc::UnboundedReceiver<InitSessionsMessage>,
    up_bandwidth_mbps: u64,
    buffer_size: Option<usize>,
    auth: Option<Vec<u8>>,
) {
    let auth_bytes = auth.expect("auth required for auth_udp");
    // For now, expect auth to be concatenated private key (32 bytes) + public key (33 bytes) = 65 bytes
    if auth_bytes.len() != 65 {
        panic!(
            "Expected 65 bytes for auth (32 byte private key + 33 byte public key), got {}",
            auth_bytes.len()
        );
    }
    let (private_key, public_key) = auth_bytes.split_at(32);
    let auth_protocol = MonoioAuthProtocol::new_from_bytes(private_key, public_key)
        .expect("Failed to create auth protocol");
    let (sender, receiver, background) = auth_protocol.split();

    let sender = Rc::new(sender);
    let receiver = Rc::new(receiver);


    let (udp_socket_rx, udp_socket_tx) = create_socket_pair(local_addr, buffer_size);
    let (direct_socket_rx, direct_socket_tx) = direct_socket_port
        .map(|port| {
            let mut direct_addr = local_addr;
            direct_addr.set_port(port);
            let (rx, tx) = create_socket_pair(direct_addr, buffer_size);
            (Some(rx), Some(tx))
        })
        .unwrap_or((None, None));

    spawn(rx(
        udp_socket_rx,
        direct_socket_rx,
        udp_ingress_tx,
        udp_direct_ingress_tx,
        receiver.clone(),
    ));
    spawn(tx(
        udp_socket_tx,
        direct_socket_tx,
        udp_egress_rx,
        init_sessions_rx,
        up_bandwidth_mbps,
        sender.clone(),
        background,
    ));
}

fn create_socket_pair(addr: SocketAddr, buffer_size: Option<usize>) -> (UdpSocket, UdpSocket) {
    let rx = UdpSocket::bind(addr).unwrap();
    configure_socket(&rx, buffer_size);
    let tx =
        UdpSocket::from_std(unsafe { std::net::UdpSocket::from_raw_fd(rx.as_raw_fd()) }).unwrap();
    (rx, tx)
}

async fn rx(
    udp_socket_rx: UdpSocket,
    direct_socket_rx: Option<UdpSocket>,
    udp_ingress_tx: mpsc::Sender<RecvUdpMsg>,
    udp_direct_ingress_tx: mpsc::Sender<RecvUdpMsg>,
    receiver: Rc<MonoioAuthProtocolReceiver>,
) {
    match direct_socket_rx {
        Some(direct_socket) => {
            spawn(rx_single_socket(
                udp_socket_rx,
                udp_ingress_tx,
                receiver.clone(),
            ));
            spawn(rx_single_socket(
                direct_socket,
                udp_direct_ingress_tx,
                receiver,
            ));
        }
        None => {
            rx_single_socket(udp_socket_rx, udp_ingress_tx, receiver).await;
        }
    }
}

async fn rx_single_socket(
    socket: UdpSocket,
    udp_ingress_tx: mpsc::Sender<RecvUdpMsg>,
    receiver: Rc<MonoioAuthProtocolReceiver>,
) {
    let local_addr = socket.local_addr().unwrap();
    debug!(?local_addr, "AUTH UDP rx_single_socket started listening");
    
    loop {
        let buf = BytesMut::with_capacity(ETHERNET_SEGMENT_SIZE.into());
        debug!("awaiting read");
        match socket.recv_from(buf).await {
            (Ok((len, src_addr)), mut buf) => {
                trace!(?local_addr, ?src_addr, len, "received packet on socket");
                
                debug!(
                    ?src_addr,
                    packet_len = len,
                    first_32_bytes = ?buf.get(0..32.min(len)).map(hex::encode),
                    "before decryption: raw packet received"
                );
                
                match receiver.on_packet(buf.clone(), src_addr) {
                    Ok(Some(decrypted)) => {
                        debug!(
                            ?src_addr, 
                            original_packet_len = len,
                            decrypted_len = decrypted.len(),
                            decrypted_preview = ?String::from_utf8_lossy(&decrypted[..decrypted.len().min(50)]),
                            "after decryption: packet decrypted successfully"
                        );
                        
                        buf = BytesMut::from(decrypted.as_ref());
                        let payload = buf.freeze();
                        
                        debug!(
                            ?src_addr,
                            payload_len = payload.len(),
                            payload_is_empty = payload.is_empty(),
                            "creating RecvUdpMsg with payload"
                        );

                        let msg = RecvUdpMsg {
                            src_addr,
                            payload,
                            stride: len.max(1).try_into().unwrap(),
                        };

                        if let Err(err) = udp_ingress_tx.send(msg).await {
                            warn!(?src_addr, ?err, "error queueing up decrypted UDP message");
                            break;
                        }
                    }
                    Ok(None) => {
                        debug!(?src_addr, len, "handshake/control packet processed (no data to forward)");
                    }
                    Err(err) => {
                        warn!(?src_addr, ?err, "decryption failed, dropping packet");
                    }
                }
            },
            (Err(err), _buf) => {
                warn!("socket.recv_from() error {}", err);
            }
        }
    }
}

const PACING_SLEEP_OVERSHOOT_DETECTION_WINDOW: Duration = Duration::from_millis(100);

async fn tx(
    socket_tx: UdpSocket,
    direct_socket_tx: Option<UdpSocket>,
    mut udp_egress_rx: mpsc::Receiver<UdpEgressMessage>,
    mut init_sessions_rx: mpsc::UnboundedReceiver<InitSessionsMessage>,
    up_bandwidth_mbps: u64,
    sender: Rc<MonoioAuthProtocolSender>,
    mut background: MonoioAuthProtocolBackground,
) {
    let mut next_transmit = Instant::now();
    let mut messages_to_send: VecDeque<(SocketAddr, Bytes, u16, UdpMessageType)> = VecDeque::new();
    let max_batch_bytes = max_write_size_for_segment_size(DEFAULT_SEGMENT_SIZE) as usize;
    let mut send_futures = Vec::with_capacity(MAX_AGGREGATED_SEGMENTS as usize);
    
    let mut buffer_pool: VecDeque<BytesMut> = VecDeque::with_capacity(MAX_AGGREGATED_SEGMENTS as usize);
    for _ in 0..MAX_AGGREGATED_SEGMENTS {
        buffer_pool.push_back(BytesMut::with_capacity(1500));
    }

    loop {
        let now = Instant::now();
        if next_transmit > now {
            time::sleep(next_transmit - now).await;
        } else {
            let late = now - next_transmit;
            if late > PACING_SLEEP_OVERSHOOT_DETECTION_WINDOW {
                next_transmit = now;
            }
        }

        while messages_to_send.is_empty() || !udp_egress_rx.is_empty() {
            use futures::{future::FutureExt, select};
            
            select! {
                msg = udp_egress_rx.recv().fuse() => {
                    let Some(msg) = msg else {
                        return;
                    };

                    match msg {
                        UdpEgressMessage::Unicast(unicast_msg) => {
                            for (addr, udp_msg) in unicast_msg.into_iter() {
                                debug!(
                                    ?addr,
                                    payload_len = udp_msg.payload.len(),
                                    payload_preview = ?String::from_utf8_lossy(&udp_msg.payload[..udp_msg.payload.len().min(50)]),
                                    "received unicast message to send"
                                );
                                messages_to_send.push_back((
                                    addr,
                                    udp_msg.payload,
                                    udp_msg.stride,
                                    UdpMessageType::Common,
                                ));
                            }
                        }
                        UdpEgressMessage::Broadcast(broadcast_msg) => {
                            for (addr, udp_msg) in broadcast_msg.into_iter() {
                                debug!(
                                    ?addr,
                                    payload_len = udp_msg.payload.len(),
                                    payload_preview = ?String::from_utf8_lossy(&udp_msg.payload[..udp_msg.payload.len().min(50)]),
                                    "received broadcast message to send"
                                );
                                messages_to_send.push_back((
                                    addr,
                                    udp_msg.payload,
                                    udp_msg.stride,
                                    UdpMessageType::Common,
                                ));
                            }
                        }
                        UdpEgressMessage::Direct {
                            dst,
                            payload,
                            stride,
                        } => {
                            messages_to_send.push_back((dst, payload, stride, UdpMessageType::Direct));
                        }
                    }
                }
                init_msg = init_sessions_rx.recv().fuse() => {
                    if let Some(msg) = init_msg {
                        if let Err(err) = background.init_sessions(msg.sessions) {
                            warn!(?err, "failed to initialize sessions");
                        }
                    }
                }
                packet = (&mut background).fuse() => {
                    let (dst, data) = packet;
                    let data_len = data.len() as u16;
                    trace!(?dst, len = data_len, "auth protocol generated packet");
                    messages_to_send.push_back((dst, data, data_len, UdpMessageType::Auth));
                }
            }
        }

        let queue_len = messages_to_send.len();
        let mut total_bytes = 0usize;
        let mut batch_count = 0usize;
        send_futures.clear();

        while !messages_to_send.is_empty()
            && total_bytes < max_batch_bytes
            && batch_count < MAX_AGGREGATED_SEGMENTS as usize
        {
            let (addr, mut payload, stride, msg_type) = messages_to_send.pop_front().unwrap();

            let chunk_size = payload.len().min(stride as usize);

            if chunk_size + total_bytes + 32 > max_batch_bytes {
                messages_to_send.push_front((addr, payload, stride, msg_type));
                break;
            }

            let chunk = payload.split_to(chunk_size);

            if matches!(msg_type, UdpMessageType::Auth) {
                let mut buffer = buffer_pool.pop_front().unwrap_or_else(|| BytesMut::with_capacity(1500));
                buffer.clear();
                buffer.extend_from_slice(chunk.as_ref());
                
                total_bytes += buffer.len();

                let socket = &socket_tx;

                if !payload.is_empty() {
                    messages_to_send.push_front((addr, payload, stride, msg_type.clone()));
                }

                trace!(
                    dst_addr = ?addr,
                    auth_len = buffer.len(),
                    local_addr = ?socket.local_addr().ok(),
                    "sending auth control packet"
                );

                send_futures.push(socket.send_to(buffer, addr));
            } else {
                let mut buffer = buffer_pool.pop_front().unwrap_or_else(|| BytesMut::with_capacity(1500));
                buffer.clear();
                buffer.resize(32 + chunk.len(), 0);
                buffer[32..].copy_from_slice(chunk.as_ref());
                
                debug!(
                    dst_addr = ?addr,
                    original_payload_len = chunk.len(),
                    payload_preview = ?String::from_utf8_lossy(&chunk[..chunk.len().min(50)]),
                    "before encryption: preparing payload"
                );
                
                match sender.encrypt_by_socket(&addr, &mut buffer[32..]) {
                    Ok(header) => {
                        debug!(
                            dst_addr = ?addr,
                            encrypted_payload_len = buffer[32..].len(),
                            "after encryption: payload encrypted"
                        );
                        
                        let header_bytes = unsafe {
                            std::slice::from_raw_parts(&header as *const _ as *const u8, 32)
                        };
                        buffer[..32].copy_from_slice(header_bytes);

                        total_bytes += buffer.len();

                        let socket = match (&msg_type, &direct_socket_tx) {
                            (UdpMessageType::Direct, Some(direct_socket)) => direct_socket,
                            _ => &socket_tx,
                        };

                        if !payload.is_empty() {
                            messages_to_send.push_front((addr, payload, stride, msg_type.clone()));
                        }

                        trace!(
                            dst_addr = ?addr,
                            encrypted_len = buffer.len(),
                            msg_type = ?msg_type,
                            total_packet_len = buffer.len(),
                            header_len = 32,
                            "preparing encrypted udp send"
                        );

                        send_futures.push(socket.send_to(buffer, addr));
                    }
                    Err(err) => {
                        warn!(?err, ?addr, "encryption failed, dropping packet");
                        buffer_pool.push_back(buffer);
                    }
                }
            }
            batch_count += 1;
        }

        if batch_count > 1 {
            trace!(
                batch_size = batch_count,
                total_bytes = total_bytes,
                queue_size = queue_len,
                "sending udp batch"
            );
        }

        let results = join_all(send_futures.drain(..)).await;

        
        for (ret, chunk) in results {
            if let Ok(bytes_sent) = &ret {
                trace!(bytes_sent, "UDP packet sent successfully");
            }
            if let Err(err) = &ret {
                match err.kind() {
                    ErrorKind::NetworkUnreachable => {
                        debug!("send address family mismatch. message is dropped")
                    }
                    ErrorKind::InvalidInput => {
                        warn!(len = chunk.len(), "got EINVAL on send. message is dropped")
                    }
                    _ => {
                        if is_eafnosupport(err) {
                            debug!("send address family mismatch. message is dropped");
                        } else {
                            error!(
                                len = chunk.len(),
                                ?err,
                                "unexpected send error. message is dropped"
                            );
                        }
                    }
                }
            }
            buffer_pool.push_back(chunk);
        }

        if total_bytes > 0 {
            next_transmit +=
                Duration::from_nanos((total_bytes as u64) * 8 * 1000 / up_bandwidth_mbps);
        }
    }
}

const MAX_AGGREGATED_WRITE_SIZE: u16 = 65535 - IPV4_HDR_SIZE - UDP_HDR_SIZE;
const MAX_AGGREGATED_SEGMENTS: u16 = 128;

fn max_write_size_for_segment_size(segment_size: u16) -> u16 {
    (MAX_AGGREGATED_WRITE_SIZE / segment_size).min(MAX_AGGREGATED_SEGMENTS) * segment_size
}


fn is_eafnosupport(err: &Error) -> bool {
    const EAFNOSUPPORT: &str = "Address family not supported by protocol";
    let err = format!("{}", err);
    err.len() >= EAFNOSUPPORT.len() && &err[0..EAFNOSUPPORT.len()] == EAFNOSUPPORT
}
