use std::{
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::Context,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::FutureExt;
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_dataplane::{RecvUdpMsg, UdpSocketHandle, UnicastMsg};
use tokio::time::Sleep;
use zerocopy::IntoBytes;

use crate::authentication::AuthenticationProtocol;

pub struct AuthenticatedSocketHandle<ST, AP>
where
    ST: CertificateSignatureRecoverable,
    AP: AuthenticationProtocol<ST>,
{
    socket: UdpSocketHandle,
    auth_protocol: AP,
    auth_timer: Option<Pin<Box<Sleep>>>,
    auth_timer_deadline: Option<Instant>,
    _phantom: PhantomData<ST>,
}

impl<ST, AP> AuthenticatedSocketHandle<ST, AP>
where
    ST: CertificateSignatureRecoverable,
    AP: AuthenticationProtocol<ST>,
{
    pub fn new(socket: UdpSocketHandle, auth_protocol: AP) -> Self {
        Self {
            socket,
            auth_protocol,
            auth_timer: None,
            auth_timer_deadline: None,
            _phantom: PhantomData,
        }
    }

    pub async fn recv(&mut self) -> Result<RecvUdpMsg, AP::Error> {
        loop {
            let message = self.socket.recv().await;

            let mut packet_buf = message.payload.to_vec();
            match self.auth_protocol.dispatch(&mut packet_buf, message.src_addr) {
                Ok(Some(plaintext)) => {
                    return Ok(RecvUdpMsg {
                        src_addr: message.src_addr,
                        payload: plaintext,
                        stride: message.stride,
                    })
                }
                Ok(None) => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn write_unicast(&mut self, msg: UnicastMsg) {
        let encrypted_msgs: Vec<(SocketAddr, Bytes)> = msg
            .msgs
            .into_iter()
            .filter_map(|(addr, chunk)| self.encrypt_packet(addr, chunk))
            .collect();

        self.socket.write_unicast(UnicastMsg {
            msgs: encrypted_msgs,
            stride: msg.stride,
        });
    }

    pub fn connect(
        &mut self,
        remote_public_key: &CertificateSignaturePubKey<ST>,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), AP::Error> {
        self.auth_protocol
            .connect(remote_public_key, remote_addr, retry_attempts)
    }

    pub fn disconnect(&mut self, remote_public_key: &CertificateSignaturePubKey<ST>) {
        self.auth_protocol.disconnect(remote_public_key);
    }

    pub fn poll_auth_timer(&mut self, cx: &mut Context<'_>) {
        loop {
            if let Some(duration) = self.auth_protocol.next_timer() {
                let new_deadline = Instant::now() + duration;

                let should_update = match self.auth_timer_deadline {
                    Some(old_deadline) => {
                        if new_deadline < old_deadline {
                            let diff = old_deadline - new_deadline;
                            diff > Duration::from_micros(100)
                        } else {
                            false
                        }
                    }
                    None => true,
                };

                if should_update {
                    self.auth_timer = Some(Box::pin(tokio::time::sleep(duration)));
                    self.auth_timer_deadline = Some(new_deadline);
                }
            } else {
                self.auth_timer = None;
                self.auth_timer_deadline = None;
                break;
            }

            if let Some(timer) = self.auth_timer.as_mut() {
                if timer.poll_unpin(cx).is_pending() {
                    break;
                }
                self.auth_protocol.tick();
                self.flush_auth_packets();
                self.auth_timer = None;
                self.auth_timer_deadline = None;
            } else {
                break;
            }
        }
    }

    pub fn flush_auth_packets(&mut self) {
        while let Some((addr, packet)) = self.auth_protocol.next_packet() {
            self.write_auth_packet(addr, packet);
        }
    }

    fn encrypt_packet(&mut self, addr: SocketAddr, chunk: Bytes) -> Option<(SocketAddr, Bytes)> {
        let mut plaintext = chunk.to_vec();
        match self.auth_protocol.encrypt_by_socket(&addr, &mut plaintext) {
            Ok(header) => {
                let header_bytes = header.as_bytes();
                let mut packet = Vec::with_capacity(header_bytes.len() + plaintext.len());
                packet.extend_from_slice(header_bytes);
                packet.extend_from_slice(&plaintext);
                Some((addr, Bytes::from(packet)))
            }
            Err(e) => {
                tracing::warn!(
                    addr = ?addr,
                    error = ?e,
                    "failed to encrypt message"
                );
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
