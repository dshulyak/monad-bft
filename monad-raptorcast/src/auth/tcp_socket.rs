use std::net::SocketAddr;

use monad_dataplane::{RecvTcpMsg, TcpMsg, TcpSocketReader, TcpSocketWriter};
use monad_executor::{ExecutorMetrics, ExecutorMetricsChain};
use tracing::warn;

use super::{
    metrics::{
        GAUGE_RAPTORCAST_AUTH_SIGNATURE_TCP_BYTES_READ,
        GAUGE_RAPTORCAST_AUTH_SIGNATURE_TCP_BYTES_WRITTEN,
        GAUGE_RAPTORCAST_AUTH_WIREAUTH_TCP_BYTES_READ,
        GAUGE_RAPTORCAST_AUTH_WIREAUTH_TCP_BYTES_WRITTEN,
    },
    tcp_protocol::TcpAuthenticationProtocol,
};

pub struct DualTcpSocketHandle<AP1, AP2>
where
    AP1: TcpAuthenticationProtocol,
    AP2: TcpAuthenticationProtocol<PublicKey = AP1::PublicKey>,
{
    signature_auth: AuthenticatedTcpSocketHandle<AP1>,
    wireauth: Option<AuthenticatedTcpSocketHandle<AP2>>,
    metrics: ExecutorMetrics,
}

impl<AP1, AP2> DualTcpSocketHandle<AP1, AP2>
where
    AP1: TcpAuthenticationProtocol,
    AP2: TcpAuthenticationProtocol<PublicKey = AP1::PublicKey>,
{
    pub fn new(
        signature_auth: AuthenticatedTcpSocketHandle<AP1>,
        wireauth: Option<AuthenticatedTcpSocketHandle<AP2>>,
    ) -> Self {
        Self {
            signature_auth,
            wireauth,
            metrics: ExecutorMetrics::default(),
        }
    }

    pub fn write(&mut self, addr: SocketAddr, msg: TcpMsg) {
        let msg_len = msg.msg.len() as u64;

        if let Some(wireauth) = &mut self.wireauth {
            if wireauth.is_connected(addr) {
                self.metrics[GAUGE_RAPTORCAST_AUTH_WIREAUTH_TCP_BYTES_WRITTEN] += msg_len;
                wireauth.write(addr, msg);
                return;
            }
        }

        self.metrics[GAUGE_RAPTORCAST_AUTH_SIGNATURE_TCP_BYTES_WRITTEN] += msg_len;
        self.signature_auth.write(addr, msg);
    }

    pub async fn recv(
        &mut self,
    ) -> Result<(RecvTcpMsg, AP1::PublicKey), TcpDualAuthError<AP1::Error, AP2::Error>> {
        if let Some(wireauth) = &mut self.wireauth {
            tokio::select! {
                result = wireauth.recv() => {
                    if let Ok(ref msg) = result {
                        self.metrics[GAUGE_RAPTORCAST_AUTH_WIREAUTH_TCP_BYTES_READ] += msg.0.payload.len() as u64;
                    }
                    result.map_err(TcpDualAuthError::WireauthError)
                },
                result = self.signature_auth.recv() => {
                    if let Ok(ref msg) = result {
                        self.metrics[GAUGE_RAPTORCAST_AUTH_SIGNATURE_TCP_BYTES_READ] += msg.0.payload.len() as u64;
                    }
                    result.map_err(TcpDualAuthError::SignatureError)
                },
            }
        } else {
            let result = self.signature_auth.recv().await;
            if let Ok(ref msg) = result {
                self.metrics[GAUGE_RAPTORCAST_AUTH_SIGNATURE_TCP_BYTES_READ] +=
                    msg.0.payload.len() as u64;
            }
            result.map_err(TcpDualAuthError::SignatureError)
        }
    }

    pub fn metrics(&self) -> ExecutorMetricsChain {
        let mut chain = ExecutorMetricsChain::default()
            .push(self.metrics.as_ref())
            .push(self.signature_auth.metrics.as_ref());
        if let Some(wireauth) = &self.wireauth {
            chain = chain.push(wireauth.metrics.as_ref());
        }
        chain
    }

    pub fn connect(
        &mut self,
        remote_public_key: &AP1::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), TcpDualAuthError<AP1::Error, AP2::Error>> {
        if let Some(wireauth) = &mut self.wireauth {
            wireauth
                .connect(remote_public_key, remote_addr, retry_attempts)
                .map_err(TcpDualAuthError::WireauthError)?;
        }
        Ok(())
    }

    pub fn disconnect(&mut self, remote_public_key: &AP1::PublicKey) {
        if let Some(wireauth) = &mut self.wireauth {
            wireauth.disconnect(remote_public_key);
        }
    }

    pub fn is_connected(&self, addr: SocketAddr, public_key: &AP1::PublicKey) -> bool {
        if let Some(wireauth) = &self.wireauth {
            if wireauth.is_connected_socket_and_public_key(addr, public_key) {
                return true;
            }
        }
        false
    }
}

pub struct AuthenticatedTcpSocketHandle<AP>
where
    AP: TcpAuthenticationProtocol,
{
    reader: TcpSocketReader,
    writer: TcpSocketWriter,
    auth_protocol: AP,
    metrics: ExecutorMetrics,
}

impl<AP> AuthenticatedTcpSocketHandle<AP>
where
    AP: TcpAuthenticationProtocol,
{
    pub fn new(reader: TcpSocketReader, writer: TcpSocketWriter, auth_protocol: AP) -> Self {
        Self {
            reader,
            writer,
            auth_protocol,
            metrics: ExecutorMetrics::default(),
        }
    }

    pub async fn recv(&mut self) -> Result<(RecvTcpMsg, AP::PublicKey), TcpAuthError<AP::Error>> {
        let message = self.reader.recv().await;
        let (plaintext, public_key) = self
            .auth_protocol
            .verify_and_extract(&message)
            .map_err(TcpAuthError::AuthError)?;

        Ok((
            RecvTcpMsg {
                src_addr: message.src_addr,
                payload: plaintext,
            },
            public_key,
        ))
    }

    pub fn write(&mut self, addr: SocketAddr, msg: TcpMsg) {
        let TcpMsg {
            msg: plaintext,
            completion,
        } = msg;

        match self.auth_protocol.sign_message(&plaintext) {
            Ok(signed_message) => {
                self.writer.write(
                    addr,
                    TcpMsg {
                        msg: signed_message,
                        completion,
                    },
                );
            }
            Err(e) => {
                warn!(addr=?addr, error=?e, "failed to sign tcp message");
            }
        }
    }

    pub fn connect(
        &mut self,
        remote_public_key: &AP::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), TcpAuthError<AP::Error>> {
        self.auth_protocol
            .connect(remote_public_key, remote_addr, retry_attempts)
            .map_err(TcpAuthError::AuthError)
    }

    pub fn disconnect(&mut self, remote_public_key: &AP::PublicKey) {
        self.auth_protocol.disconnect(remote_public_key);
    }

    pub fn is_connected(&self, addr: SocketAddr) -> bool {
        self.auth_protocol.is_connected_socket(&addr)
    }

    pub fn is_connected_socket_and_public_key(
        &self,
        addr: SocketAddr,
        public_key: &AP::PublicKey,
    ) -> bool {
        self.auth_protocol
            .is_connected_socket_and_public_key(&addr, public_key)
    }
}

#[derive(Debug)]
pub enum TcpAuthError<E> {
    AuthError(E),
}

#[derive(Debug)]
pub enum TcpDualAuthError<E1, E2> {
    SignatureError(TcpAuthError<E1>),
    WireauthError(TcpAuthError<E2>),
}
