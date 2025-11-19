use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use monad_dataplane::RecvTcpMsg;
use monad_wireauth::messages::DataPacketHeader;

use super::{protocol::WireAuthProtocol, tcp_protocol::TcpAuthenticationProtocol};

pub struct WireAuthTcpProtocol {
    wireauth: WireAuthProtocol,
}

impl WireAuthTcpProtocol {
    pub fn new(config: monad_wireauth::Config, signing_key: &Arc<monad_secp::KeyPair>) -> Self {
        Self {
            wireauth: WireAuthProtocol::new(config, signing_key),
        }
    }
}

impl TcpAuthenticationProtocol for WireAuthTcpProtocol {
    type PublicKey = monad_secp::PubKey;
    type Error = WireAuthTcpError;

    const HEADER_SIZE: usize = DataPacketHeader::SIZE;

    fn sign_message(&self, _plaintext: &[u8]) -> Result<Bytes, Self::Error> {
        Err(WireAuthTcpError::Unimplemented)
    }

    fn verify_and_extract(
        &self,
        _message: &RecvTcpMsg,
    ) -> Result<(Bytes, Self::PublicKey), Self::Error> {
        Err(WireAuthTcpError::Unimplemented)
    }

    fn connect(
        &mut self,
        remote_public_key: &Self::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), Self::Error> {
        self.wireauth
            .api
            .connect(*remote_public_key, remote_addr, retry_attempts)
            .map_err(WireAuthTcpError::from)
    }

    fn disconnect(&mut self, remote_public_key: &Self::PublicKey) {
        self.wireauth.api.disconnect(remote_public_key);
    }

    fn is_connected_socket(&self, socket_addr: &SocketAddr) -> bool {
        self.wireauth.api.is_connected_socket(socket_addr)
    }

    fn is_connected_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &Self::PublicKey,
    ) -> bool {
        self.wireauth
            .api
            .is_connected_socket_and_public_key(socket_addr, public_key)
    }
}

#[derive(Debug)]
pub enum WireAuthTcpError {
    Unimplemented,
    WireAuthError(monad_wireauth::Error),
    MessageTooShort,
    InvalidHeader,
}

impl From<monad_wireauth::Error> for WireAuthTcpError {
    fn from(e: monad_wireauth::Error) -> Self {
        WireAuthTcpError::WireAuthError(e)
    }
}
