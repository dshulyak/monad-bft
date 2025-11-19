use std::{net::SocketAddr, sync::Arc};

use bytes::{Bytes, BytesMut};
use monad_crypto::{
    certificate_signature::{
        CertificateSignature, CertificateSignaturePubKey, CertificateSignatureRecoverable,
    },
    signing_domain,
};
use monad_dataplane::RecvTcpMsg;
use tracing::warn;

use super::tcp_protocol::TcpAuthenticationProtocol;

const SIGNATURE_SIZE: usize = 65;

pub struct SignatureBasedTcpAuth<ST: CertificateSignatureRecoverable> {
    signing_key: Arc<ST::KeyPairType>,
}

impl<ST: CertificateSignatureRecoverable> SignatureBasedTcpAuth<ST> {
    pub fn new(signing_key: Arc<ST::KeyPairType>) -> Self {
        Self { signing_key }
    }
}

impl<ST: CertificateSignatureRecoverable> TcpAuthenticationProtocol for SignatureBasedTcpAuth<ST> {
    type PublicKey = CertificateSignaturePubKey<ST>;
    type Error = SignatureAuthError;

    const HEADER_SIZE: usize = SIGNATURE_SIZE;

    fn sign_message(&self, plaintext: &[u8]) -> Result<Bytes, Self::Error> {
        let mut signed_message = BytesMut::zeroed(SIGNATURE_SIZE + plaintext.len());
        let signature =
            <ST as CertificateSignature>::serialize(&ST::sign::<
                signing_domain::RaptorcastAppMessage,
            >(plaintext, &self.signing_key));

        if signature.len() != SIGNATURE_SIZE {
            return Err(SignatureAuthError::InvalidSignatureSize);
        }

        signed_message[..SIGNATURE_SIZE].copy_from_slice(&signature);
        signed_message[SIGNATURE_SIZE..].copy_from_slice(plaintext);
        Ok(signed_message.freeze())
    }

    fn verify_and_extract(
        &self,
        message: &RecvTcpMsg,
    ) -> Result<(Bytes, Self::PublicKey), Self::Error> {
        let RecvTcpMsg { payload, src_addr } = message;

        if payload.len() < SIGNATURE_SIZE {
            warn!(
                ?src_addr,
                "invalid message, message length less than signature size"
            );
            return Err(SignatureAuthError::MessageTooShort);
        }

        let signature_bytes = &payload[..SIGNATURE_SIZE];
        let signature = <ST as CertificateSignature>::deserialize(signature_bytes)
            .map_err(|_| SignatureAuthError::InvalidSignature)?;

        let app_message_bytes = payload.slice(SIGNATURE_SIZE..);
        let from = signature
            .recover_pubkey::<signing_domain::RaptorcastAppMessage>(app_message_bytes.as_ref())
            .map_err(|_| SignatureAuthError::RecoveryFailed)?;

        Ok((app_message_bytes, from))
    }

    fn connect(
        &mut self,
        _remote_public_key: &Self::PublicKey,
        _remote_addr: SocketAddr,
        _retry_attempts: u64,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn disconnect(&mut self, _remote_public_key: &Self::PublicKey) {}

    fn is_connected_socket(&self, _socket_addr: &SocketAddr) -> bool {
        false
    }

    fn is_connected_socket_and_public_key(
        &self,
        _socket_addr: &SocketAddr,
        _public_key: &Self::PublicKey,
    ) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum SignatureAuthError {
    MessageTooShort,
    InvalidSignature,
    RecoveryFailed,
    InvalidSignatureSize,
}
