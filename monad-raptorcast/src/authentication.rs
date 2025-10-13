use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub trait AuthenticationProtocol<ST: CertificateSignatureRecoverable> {
    type Error: std::fmt::Debug;
    type Header: AsBytes;

    const HEADER_SIZE: u16;

    fn connect(
        &mut self,
        remote_public_key: &CertificateSignaturePubKey<ST>,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), Self::Error>;

    fn disconnect(&mut self, remote_public_key: &CertificateSignaturePubKey<ST>);

    fn dispatch(
        &mut self,
        packet: &mut [u8],
        remote_addr: SocketAddr,
    ) -> Result<Option<Bytes>, Self::Error>;

    fn encrypt_by_public_key(
        &mut self,
        public_key: &CertificateSignaturePubKey<ST>,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error>;

    fn encrypt_by_socket(
        &mut self,
        socket_addr: &SocketAddr,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error>;

    fn next_packet(&mut self) -> Option<(SocketAddr, Bytes)>;

    fn tick(&mut self);

    fn next_timer(&self) -> Option<Duration>;
}

pub struct WireAuthProtocol {
    api: monad_wireauth_api::API<monad_wireauth_api::StdContext>,
}

impl WireAuthProtocol {
    pub fn new(config: monad_wireauth_api::Config, signing_key: &Arc<monad_secp::KeyPair>) -> Self {
        let secret_key = signing_key.to_inner();
        let secret_bytes = secret_key.secret_bytes();
        let private_key = monad_wireauth_protocol::common::PrivateKey::from_bytes(&secret_bytes)
            .expect("valid secp256k1 secret key");
        let public_key = signing_key.pubkey().to_inner().into();
        let context = monad_wireauth_api::StdContext::new();

        Self {
            api: monad_wireauth_api::API::new(config, private_key, public_key, context),
        }
    }
}

impl AuthenticationProtocol<monad_secp::SecpSignature> for WireAuthProtocol {
    type Error = monad_wireauth_api::Error;
    type Header = monad_wireauth_protocol::messages::DataPacketHeader;

    const HEADER_SIZE: u16 = 32;

    fn connect(
        &mut self,
        remote_public_key: &monad_secp::PubKey,
        remote_addr: SocketAddr,
        retry_attempts: u64,
    ) -> Result<(), Self::Error> {
        let wireauth_pubkey = remote_public_key.to_inner().into();
        self.api
            .connect(wireauth_pubkey, remote_addr, retry_attempts)
    }

    fn disconnect(&mut self, remote_public_key: &monad_secp::PubKey) {
        let wireauth_pubkey = remote_public_key.to_inner().into();
        self.api.disconnect(&wireauth_pubkey)
    }

    fn dispatch(
        &mut self,
        packet: &mut [u8],
        remote_addr: SocketAddr,
    ) -> Result<Option<Bytes>, Self::Error> {
        self.api.dispatch(packet, remote_addr)
    }

    fn encrypt_by_public_key(
        &mut self,
        public_key: &monad_secp::PubKey,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        let wireauth_pubkey = public_key.to_inner().into();
        self.api.encrypt_by_public_key(&wireauth_pubkey, plaintext)
    }

    fn encrypt_by_socket(
        &mut self,
        socket_addr: &SocketAddr,
        plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        self.api.encrypt_by_socket(socket_addr, plaintext)
    }

    fn next_packet(&mut self) -> Option<(SocketAddr, Bytes)> {
        self.api.next_packet()
    }

    fn tick(&mut self) {
        self.api.tick()
    }

    fn next_timer(&self) -> Option<Duration> {
        self.api.next_timer()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct NoopHeader;

pub struct NoopAuthProtocol<ST: CertificateSignatureRecoverable> {
    _phantom: std::marker::PhantomData<ST>,
}

impl<ST: CertificateSignatureRecoverable> NoopAuthProtocol<ST> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<ST: CertificateSignatureRecoverable> Default for NoopAuthProtocol<ST> {
    fn default() -> Self {
        Self::new()
    }
}

impl<ST: CertificateSignatureRecoverable> AuthenticationProtocol<ST> for NoopAuthProtocol<ST> {
    type Error = std::convert::Infallible;
    type Header = NoopHeader;

    const HEADER_SIZE: u16 = 0;

    fn connect(
        &mut self,
        _remote_public_key: &CertificateSignaturePubKey<ST>,
        _remote_addr: SocketAddr,
        _retry_attempts: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn disconnect(&mut self, _remote_public_key: &CertificateSignaturePubKey<ST>) {}

    fn dispatch(
        &mut self,
        _packet: &mut [u8],
        _remote_addr: SocketAddr,
    ) -> Result<Option<Bytes>, Self::Error> {
        Ok(None)
    }

    fn encrypt_by_public_key(
        &mut self,
        _public_key: &CertificateSignaturePubKey<ST>,
        _plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        Ok(NoopHeader)
    }

    fn encrypt_by_socket(
        &mut self,
        _socket_addr: &SocketAddr,
        _plaintext: &mut [u8],
    ) -> Result<Self::Header, Self::Error> {
        Ok(NoopHeader)
    }

    fn next_packet(&mut self) -> Option<(SocketAddr, Bytes)> {
        None
    }

    fn tick(&mut self) {}

    fn next_timer(&self) -> Option<Duration> {
        None
    }
}
