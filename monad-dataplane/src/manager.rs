use std::{
    cell::RefCell,
    convert::TryFrom,
    net::SocketAddr,
    pin::Pin,
    rc::Rc,
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant, SystemTime},
};

use bytes::{Bytes, BytesMut};
use futures::Future;
use monoio::time;
use rand::rngs::OsRng;
use thiserror::Error;
use session::{Config, Context, SessionManager};
use wireauth_protocol::{common::PublicKey as WirePublicKey, messages::DataPacketHeader};

#[derive(Error, Debug)]
pub enum AdapterError {
    #[error("Session error: {0}")]
    Session(#[from] session::SessionError),
    #[error("Key conversion error: {0}")]
    KeyConversion(String),
    #[error("Invalid packet")]
    InvalidPacket,
}

struct AdapterContext {
    rng: OsRng,
    start_time: Instant,
}

impl Context for AdapterContext {
    type Rng = OsRng;

    fn system_time(&self) -> SystemTime {
        SystemTime::now()
    }

    fn duration_since_start(&self) -> Duration {
        self.start_time.elapsed()
    }

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }
}

struct MonoioAuthProtocolInner {
    manager: SessionManager<AdapterContext>,
    waker: Option<std::task::Waker>,
}

pub struct MonoioAuthProtocolSender {
    inner: Rc<RefCell<MonoioAuthProtocolInner>>,
}

pub struct MonoioAuthProtocolReceiver {
    inner: Rc<RefCell<MonoioAuthProtocolInner>>,
}

pub struct MonoioAuthProtocolBackground {
    inner: Rc<RefCell<MonoioAuthProtocolInner>>,
}

impl MonoioAuthProtocolSender {
    pub fn encrypt_by_socket(
        &self,
        socket: &SocketAddr,
        plaintext: &mut [u8],
    ) -> Result<DataPacketHeader, AdapterError> {
        let mut inner = self.inner.borrow_mut();
        let header = inner.manager.encrypt_by_socket(socket, plaintext)?;
        Ok(header)
    }
}

impl MonoioAuthProtocolReceiver {
    pub fn on_packet(
        &self,
        mut data: BytesMut,
        sender: SocketAddr,
    ) -> Result<Option<Bytes>, AdapterError> {
        let mut inner = self.inner.borrow_mut();
        let result = inner.manager.dispatch(data.as_mut(), sender)?;
        
        if let Some(ref waker) = inner.waker.take() {
            waker.wake_by_ref();
        }
        
        Ok(result)
    }
}

impl MonoioAuthProtocolBackground {
    pub fn init_sessions(
        &mut self,
        sessions: Vec<(SocketAddr, Vec<u8>)>,
    ) -> Result<(), AdapterError> {
        let mut inner = self.inner.borrow_mut();
        for (remote_addr, pubkey_bytes) in sessions {
            if pubkey_bytes.len() != 33 {
                return Err(AdapterError::KeyConversion(format!(
                    "Invalid public key length: expected 33, got {}",
                    pubkey_bytes.len()
                )));
            }
            let mut key_array = [0u8; 33];
            key_array.copy_from_slice(&pubkey_bytes);
            let wire_public = WirePublicKey::try_from(key_array)
                .map_err(|e| AdapterError::KeyConversion(format!("Failed to parse public key: {:?}", e)))?;
            inner
                .manager
                .init_session(wire_public, remote_addr, true)?;
        }
        Ok(())
    }
}

impl Future for MonoioAuthProtocolBackground {
    type Output = (SocketAddr, Bytes);

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let mut inner = self.inner.borrow_mut();

        inner.waker = Some(cx.waker().clone());

        if let Some(packet) = inner.manager.next_packet() {
            return Poll::Ready(packet);
        }

        loop {
            match inner.manager.next_timer() {
                Some(duration) if duration.is_zero() => {
                    inner.manager.tick();
                }
                Some(duration) => {
                    let mut sleep = std::pin::pin!(time::sleep(duration));
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(_) => {
                            inner.manager.tick();
                        }
                        Poll::Pending => {
                            return Poll::Pending;
                        }
                    }
                }
                None => {
                    break;
                }
            }
        }
        if let Some(packet) = inner.manager.next_packet() {
            return Poll::Ready(packet);
        }
        Poll::Pending
    }
}

pub struct MonoioAuthProtocol {
    sender: MonoioAuthProtocolSender,
    receiver: MonoioAuthProtocolReceiver,
    background: MonoioAuthProtocolBackground,
}

impl MonoioAuthProtocol {
    pub fn new_from_bytes(private_key_bytes: &[u8], public_key_bytes: &[u8]) -> Result<Self, AdapterError> {
        if private_key_bytes.len() != 32 {
            return Err(AdapterError::KeyConversion(format!(
                "Invalid private key length: expected 32, got {}",
                private_key_bytes.len()
            )));
        }
        
        if public_key_bytes.len() != 33 {
            return Err(AdapterError::KeyConversion(format!(
                "Invalid public key length: expected 33, got {}",
                public_key_bytes.len()
            )));
        }

        let config = Config {
            init_response_timeout: Duration::from_secs(10),
            init_retry_interval: Duration::from_secs(1),
            keepalive_interval: Duration::from_secs(25),
            keepalive_timeout: Duration::from_secs(10),
            rekey_interval: Duration::from_secs(120),
            handshake_rate_limit: 50,
            cookie_refresh_duration: Duration::from_secs(120),
        };

        let context = AdapterContext {
            rng: OsRng,
            start_time: Instant::now(),
        };

        let wire_private = wireauth_protocol::common::PrivateKey::from_bytes(private_key_bytes)
            .map_err(|e| {
                AdapterError::KeyConversion(format!("Failed to convert private key: {:?}", e))
            })?;
        
        let mut pubkey_array = [0u8; 33];
        pubkey_array.copy_from_slice(public_key_bytes);
        let wire_public = WirePublicKey::try_from(pubkey_array)
            .map_err(|e| AdapterError::KeyConversion(format!("Failed to convert public key: {:?}", e)))?;

        let manager = SessionManager::new(config, wire_private, wire_public, context);

        let inner = Rc::new(RefCell::new(MonoioAuthProtocolInner { 
            manager,
            waker: None,
        }));

        Ok(Self {
            sender: MonoioAuthProtocolSender {
                inner: inner.clone(),
            },
            receiver: MonoioAuthProtocolReceiver {
                inner: inner.clone(),
            },
            background: MonoioAuthProtocolBackground { inner },
        })
    }

    pub fn split(
        self,
    ) -> (
        MonoioAuthProtocolSender,
        MonoioAuthProtocolReceiver,
        MonoioAuthProtocolBackground,
    ) {
        (self.sender, self.receiver, self.background)
    }
}
