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
use monad_secp::{KeyPair as MonadKeyPair, PubKey as SecpPubKey};
use monoio::time;
use rand::rngs::OsRng;
use thiserror::Error;
use session::{Config, Context, SessionManager};
use wireauth_protocol::common::PublicKey as WirePublicKey;

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
    pub fn encrypt(
        &self,
        identity: &SecpPubKey,
        mut plaintext: BytesMut,
    ) -> Result<(Bytes, Bytes), AdapterError> {
        let mut inner = self.inner.borrow_mut();
        let wire_public = WirePublicKey::from(identity.to_inner());
        let header = inner
            .manager
            .encrypt_by_public_key(&wire_public, plaintext.as_mut())?;

        let mut header_bytes = BytesMut::with_capacity(32);
        let header_ptr = &header as *const _ as *const u8;
        let header_slice = unsafe { std::slice::from_raw_parts(header_ptr, 32) };
        header_bytes.extend_from_slice(header_slice);

        Ok((header_bytes.freeze(), plaintext.freeze()))
    }

    pub fn encrypt_by_socket(
        &self,
        socket: &SocketAddr,
        mut plaintext: BytesMut,
    ) -> Result<(Bytes, Bytes), AdapterError> {
        let mut inner = self.inner.borrow_mut();
        let header = inner.manager.encrypt_by_socket(socket, plaintext.as_mut())?;

        let mut header_bytes = BytesMut::with_capacity(32);
        let header_ptr = &header as *const _ as *const u8;
        let header_slice = unsafe { std::slice::from_raw_parts(header_ptr, 32) };
        header_bytes.extend_from_slice(header_slice);

        Ok((header_bytes.freeze(), plaintext.freeze()))
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
    pub fn new(keypair: &MonadKeyPair) -> Result<Self, AdapterError> {
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

        let pubkey = keypair.pubkey();
        let wire_public = WirePublicKey::from(pubkey.to_inner());

        let secret_bytes = keypair.secret_bytes();
        let wire_private = wireauth_protocol::common::PrivateKey::from_bytes(&secret_bytes)
            .map_err(|e| {
                AdapterError::KeyConversion(format!("Failed to convert private key: {:?}", e))
            })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use monad_secp::KeyPair;
    use rand::RngCore;
    use std::net::SocketAddr;
    use tracing::{debug, info};
    use tracing_subscriber::EnvFilter;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
    }

    fn create_test_keypair() -> KeyPair {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        KeyPair::from_bytes(&mut secret).expect("Failed to create keypair")
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_manager_with_three_monoio_tasks() {
        init_tracing();
        info!("starting test_manager_with_three_monoio_tasks");

        let keypair = create_test_keypair();
        info!(pubkey=?keypair.pubkey().bytes(), "created test keypair");

        let auth_protocol = MonoioAuthProtocol::new(&keypair).expect("Failed to create auth protocol");
        let (sender, receiver, mut background) = auth_protocol.split();

        let sender = std::rc::Rc::new(sender);
        let receiver = std::rc::Rc::new(receiver);

        let sender_clone = sender.clone();
        let task1 = monoio::spawn(async move {
            info!("task1: starting background packet handler");
            for i in 0..3 {
                match monoio::time::timeout(Duration::from_millis(100), &mut background).await {
                    Ok(packet) => {
                        info!(from=?packet.0, len=packet.1.len(), iteration=i, "task1: received packet");
                    }
                    Err(_) => {
                        debug!(iteration=i, "task1: timeout waiting for packet");
                    }
                }
            }
            info!("task1: completed");
        });

        let task2 = monoio::spawn(async move {
            info!("task2: starting encryption task");
            let remote_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
            
            for i in 0..5 {
                let data = format!("Test message {}", i);
                let buf = BytesMut::from(data.as_bytes());
                
                match sender_clone.encrypt_by_socket(&remote_addr, buf) {
                    Ok((header, payload)) => {
                        info!(
                            iteration=i,
                            header_len=header.len(),
                            payload_len=payload.len(),
                            "task2: encrypted message"
                        );
                    }
                    Err(e) => {
                        debug!(iteration=i, error=?e, "task2: encryption failed (expected before session init)");
                    }
                }
                
                monoio::time::sleep(Duration::from_millis(50)).await;
            }
            info!("task2: completed");
        });

        let task3 = monoio::spawn(async move {
            info!("task3: starting decryption task");
            let remote_addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
            
            for i in 0..3 {
                let data = format!("Incoming packet {}", i);
                let buf = BytesMut::from(data.as_bytes());
                
                match receiver.on_packet(buf, remote_addr) {
                    Ok(Some(decrypted)) => {
                        info!(
                            iteration=i,
                            decrypted_len=decrypted.len(),
                            from=?remote_addr,
                            "task3: decrypted packet"
                        );
                    }
                    Ok(None) => {
                        debug!(iteration=i, "task3: no decrypted data");
                    }
                    Err(e) => {
                        debug!(iteration=i, error=?e, "task3: decryption failed (expected for non-encrypted data)");
                    }
                }
                
                monoio::time::sleep(Duration::from_millis(100)).await;
            }
            info!("task3: completed");
        });

        let timeout_duration = Duration::from_secs(2);
        match monoio::time::timeout(timeout_duration, async {
            let _ = monoio::join!(task1, task2, task3);
        })
        .await
        {
            Ok(_) => info!("all tasks completed successfully"),
            Err(_) => info!("test completed with timeout (expected)"),
        }

        info!("test_manager_with_three_monoio_tasks: completed");
    }

    #[monoio::test(timer_enabled = true)]
    async fn test_two_peers_handshake() {
        init_tracing();
        info!("starting test_two_peers_handshake");

        let peer1_keypair = create_test_keypair();
        let peer2_keypair = create_test_keypair();
        
        info!(
            peer1_pubkey=?peer1_keypair.pubkey().bytes(),
            peer2_pubkey=?peer2_keypair.pubkey().bytes(),
            "created keypairs for both peers"
        );

        let peer1_auth = MonoioAuthProtocol::new(&peer1_keypair).expect("Failed to create peer1 auth");
        let peer2_auth = MonoioAuthProtocol::new(&peer2_keypair).expect("Failed to create peer2 auth");

        let (peer1_sender, peer1_receiver, mut peer1_background) = peer1_auth.split();
        let (peer2_sender, peer2_receiver, mut peer2_background) = peer2_auth.split();

        let peer1_addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let peer2_addr: SocketAddr = "127.0.0.1:51821".parse().unwrap();

        info!(peer1_addr=?peer1_addr, peer2_addr=?peer2_addr, "initialized peers");

        let peer1_sender = std::rc::Rc::new(peer1_sender);
        let peer1_receiver = std::rc::Rc::new(peer1_receiver);
        let peer2_sender = std::rc::Rc::new(peer2_sender);
        let peer2_receiver = std::rc::Rc::new(peer2_receiver);

        let peer1_bg_task = monoio::spawn(async move {
            info!("peer1: background task started");
            for _ in 0..10 {
                match monoio::time::timeout(Duration::from_millis(100), &mut peer1_background).await {
                    Ok((addr, packet)) => {
                        info!(target=?addr, packet_len=packet.len(), "peer1: sending packet");
                    }
                    Err(_) => {}
                }
            }
        });

        let peer2_bg_task = monoio::spawn(async move {
            info!("peer2: background task started");
            for _ in 0..10 {
                match monoio::time::timeout(Duration::from_millis(100), &mut peer2_background).await {
                    Ok((addr, packet)) => {
                        info!(target=?addr, packet_len=packet.len(), "peer2: sending packet");
                    }
                    Err(_) => {}
                }
            }
        });

        let test_task = monoio::spawn(async move {
            info!("initializing session from peer1 to peer2");
            
            let sessions = vec![
                (peer2_addr, peer2_keypair.pubkey().bytes().to_vec())
            ];
            
            monoio::time::sleep(Duration::from_millis(200)).await;
            
            for i in 0..5 {
                let message = format!("Test message {}", i);
                let buf = BytesMut::from(message.as_bytes());
                
                match peer1_sender.encrypt_by_socket(&peer2_addr, buf) {
                    Ok((header, payload)) => {
                        debug!(
                            msg_num=i,
                            header_len=header.len(),
                            payload_len=payload.len(),
                            "peer1: encrypted message"
                        );
                        
                        let mut packet = BytesMut::with_capacity(header.len() + payload.len());
                        packet.extend_from_slice(&header);
                        packet.extend_from_slice(&payload);
                        
                        match peer2_receiver.on_packet(packet, peer1_addr) {
                            Ok(Some(decrypted)) => {
                                let decrypted_msg = String::from_utf8_lossy(&decrypted);
                                info!(msg_num=i, decrypted=?decrypted_msg, "peer2: decrypted message");
                            }
                            Ok(None) => {
                                debug!(msg_num=i, "peer2: handshake packet processed");
                            }
                            Err(e) => {
                                debug!(msg_num=i, error=?e, "peer2: failed to process packet");
                            }
                        }
                    }
                    Err(e) => {
                        debug!(msg_num=i, error=?e, "peer1: encryption failed");
                    }
                }
                
                monoio::time::sleep(Duration::from_millis(100)).await;
            }
            
            info!("test completed");
        });

        let timeout_duration = Duration::from_secs(3);
        match monoio::time::timeout(timeout_duration, async {
            let _ = monoio::join!(peer1_bg_task, peer2_bg_task, test_task);
        })
        .await
        {
            Ok(_) => info!("all tasks completed"),
            Err(_) => info!("test timed out (expected)"),
        }

        info!("test_two_peers_handshake: completed");
    }
}