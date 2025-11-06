use std::{net::SocketAddr, pin::Pin, time::Instant};

use bytes::{Bytes, BytesMut};
use monad_dataplane::{RecvUdpMsg, UdpSocketHandle, UnicastMsg};
use monad_types::UdpPriority;
use tokio::time::Sleep;
use tracing::{trace, warn};
use zerocopy::IntoBytes;

use crate::authentication::AuthenticationProtocol;

pub struct DualSocketHandle<AP>
where
    AP: AuthenticationProtocol,
{
    authenticated: AuthenticatedSocketHandle<AP>,
    non_authenticated: UdpSocketHandle,
}

impl<AP> DualSocketHandle<AP>
where
    AP: AuthenticationProtocol,
{
    pub fn new(
        authenticated: AuthenticatedSocketHandle<AP>,
        non_authenticated: UdpSocketHandle,
    ) -> Self {
        Self {
            authenticated,
            non_authenticated,
        }
    }

    pub fn write_unicast_with_priority(&mut self, msg: UnicastMsg, priority: UdpPriority) {
        let mut auth_msgs = Vec::new();
        let mut non_auth_msgs = Vec::new();

        for (addr, payload) in msg.msgs {
            if self.authenticated.auth_protocol.is_connected_socket(&addr) {
                auth_msgs.push((addr, payload));
            } else {
                non_auth_msgs.push((addr, payload));
            }
        }

        if !auth_msgs.is_empty() {
            self.authenticated.write_unicast_with_priority(
                UnicastMsg {
                    msgs: auth_msgs,
                    stride: msg.stride + AP::HEADER_SIZE,
                },
                priority,
            );
        }

        if !non_auth_msgs.is_empty() {
            self.non_authenticated.write_unicast_with_priority(
                UnicastMsg {
                    msgs: non_auth_msgs,
                    stride: msg.stride,
                },
                priority,
            );
        }
    }

    pub fn connect(
        &mut self,
        remote_public_key: &AP::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), AP::Error> {
        self.authenticated
            .connect(remote_public_key, remote_addr, retry_attempts)
    }

    pub fn disconnect(&mut self, remote_public_key: &AP::PublicKey) {
        self.authenticated.disconnect(remote_public_key);
    }

    pub fn flush(&mut self) {
        self.authenticated.flush();
    }

    pub fn poll_timer(&mut self) {
        self.authenticated.poll_timer();
    }

    pub async fn recv(&mut self) -> Result<RecvUdpMsg, AP::Error> {
        tokio::select! {
            result = self.authenticated.recv() => result,
            msg = self.non_authenticated.recv() => Ok(msg),
        }
    }

    pub fn is_connected_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &AP::PublicKey,
    ) -> bool {
        self.authenticated
            .auth_protocol
            .is_connected_socket_and_public_key(socket_addr, public_key)
    }

    pub fn get_socket_by_public_key(&self, public_key: &AP::PublicKey) -> Option<SocketAddr> {
        self.authenticated
            .auth_protocol
            .get_socket_by_public_key(public_key)
    }

    pub fn metrics(&self) -> monad_executor::ExecutorMetricsChain {
        self.authenticated.auth_protocol.metrics()
    }
}

pub struct AuthenticatedSocketHandle<AP>
where
    AP: AuthenticationProtocol,
{
    socket: UdpSocketHandle,
    pub(crate) auth_protocol: AP,
    auth_timer: Option<(Pin<Box<Sleep>>, Instant)>,
}

impl<AP> AuthenticatedSocketHandle<AP>
where
    AP: AuthenticationProtocol,
    AP::PublicKey: Clone,
{
    pub fn new(socket: UdpSocketHandle, auth_protocol: AP) -> Self {
        Self {
            socket,
            auth_protocol,
            auth_timer: None,
        }
    }

    pub async fn recv(&mut self) -> Result<RecvUdpMsg, AP::Error> {
        loop {
            let message = self.socket.recv().await;

            let mut packet_buf = message.payload.to_vec();
            match self
                .auth_protocol
                .dispatch(&mut packet_buf, message.src_addr)
            {
                Ok(Some((plaintext, _public_key))) => {
                    return Ok(RecvUdpMsg {
                        src_addr: message.src_addr,
                        payload: plaintext.into(),
                        stride: message.stride,
                    })
                }
                Ok(None) => {
                    self.flush();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn write_unicast_with_priority(&mut self, msg: UnicastMsg, priority: UdpPriority) {
        let total_msgs = msg.msgs.len();
        let encrypted_msgs: Vec<(SocketAddr, Bytes)> = msg
            .msgs
            .into_iter()
            .filter_map(|(addr, chunk)| self.encrypt_packet(addr, chunk))
            .collect();

        if encrypted_msgs.len() < total_msgs {
            warn!(
                total = total_msgs,
                encrypted = encrypted_msgs.len(),
                failed = total_msgs - encrypted_msgs.len(),
                "some messages failed to encrypt"
            );
        }

        if !encrypted_msgs.is_empty() {
            self.socket.write_unicast_with_priority(
                UnicastMsg {
                    msgs: encrypted_msgs,
                    stride: msg.stride,
                },
                priority,
            );
        }
    }

    pub fn connect(
        &mut self,
        remote_public_key: &AP::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), AP::Error> {
        self.auth_protocol
            .connect(remote_public_key, remote_addr, retry_attempts)
    }

    pub fn disconnect(&mut self, remote_public_key: &AP::PublicKey) {
        self.auth_protocol.disconnect(remote_public_key);
    }

    pub fn poll_timer(&mut self) {
        let next_deadline = self.auth_protocol.next_deadline();

        let deadline_shortened = match (next_deadline, &self.auth_timer) {
            (Some(new_deadline), Some((_, stored_deadline))) => new_deadline < *stored_deadline,
            _ => false,
        };

        let timer_expired = self
            .auth_timer
            .as_ref()
            .map_or(false, |(_, deadline)| *deadline <= Instant::now());

        if !timer_expired && !deadline_shortened {
            return;
        }

        self.auth_timer = None;

        loop {
            trace!("polling auth");

            let Some(deadline) = self.auth_protocol.next_deadline() else {
                return;
            };

            if deadline <= Instant::now() {
                self.auth_protocol.tick();
                self.flush();
                continue;
            }

            self.auth_timer = Some((
                Box::pin(tokio::time::sleep_until(deadline.into())),
                deadline,
            ));
            break;
        }
    }

    pub fn flush(&mut self) {
        while let Some((addr, packet)) = self.auth_protocol.next_packet() {
            self.write_auth_packet(addr, packet);
        }
    }

    fn encrypt_packet(
        &mut self,
        addr: SocketAddr,
        plaintext: Bytes,
    ) -> Option<(SocketAddr, Bytes)> {
        let header_size = AP::HEADER_SIZE as usize;
        let mut packet = BytesMut::with_capacity(header_size + plaintext.len());
        packet.resize(header_size, 0);
        packet.extend_from_slice(&plaintext);

        match self
            .auth_protocol
            .encrypt_by_socket(&addr, &mut packet[header_size..])
        {
            Ok(header) => {
                let header_bytes = header.as_bytes();
                packet[..header_size].copy_from_slice(header_bytes);
                Some((addr, packet.freeze()))
            }
            Err(e) => {
                warn!(addr=?addr, error=?e, "failed to encrypt message");
                None
            }
        }
    }

    fn write_auth_packet(&self, addr: SocketAddr, packet: Bytes) {
        let stride = packet.len() as u16;
        self.socket.write_unicast(UnicastMsg {
            msgs: vec![(addr, packet)],
            stride,
        });
    }
}
