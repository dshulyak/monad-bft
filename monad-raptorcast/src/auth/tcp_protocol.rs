use std::net::SocketAddr;

use bytes::Bytes;
use monad_crypto::certificate_signature::PubKey;
use monad_dataplane::RecvTcpMsg;

pub trait TcpAuthenticationProtocol {
    type PublicKey: PubKey;
    type Error: std::fmt::Debug;

    const HEADER_SIZE: usize;

    fn sign_message(&self, plaintext: &[u8]) -> Result<Bytes, Self::Error>;

    fn verify_and_extract(
        &self,
        message: &RecvTcpMsg,
    ) -> Result<(Bytes, Self::PublicKey), Self::Error>;

    fn connect(
        &mut self,
        remote_public_key: &Self::PublicKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), Self::Error>;

    fn disconnect(&mut self, remote_public_key: &Self::PublicKey);

    fn is_connected_socket(&self, socket_addr: &SocketAddr) -> bool;

    fn is_connected_socket_and_public_key(
        &self,
        socket_addr: &SocketAddr,
        public_key: &Self::PublicKey,
    ) -> bool;
}
