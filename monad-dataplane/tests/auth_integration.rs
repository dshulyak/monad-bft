use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use futures::executor;
use monad_dataplane::{BroadcastMsg, DataplaneBuilder, RecvUdpMsg};
use ntest::timeout;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

const UP_BANDWIDTH_MBPS: u64 = 1_000;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();
}

fn generate_test_keypair_with_seed(seed: u8) -> (Vec<u8>, Vec<u8>) {
    use rand::{rngs::StdRng, SeedableRng};
    
    // Use a deterministic RNG with the seed
    let seed_array = [seed; 32];
    let mut rng = StdRng::from_seed(seed_array);
    
    // Generate a proper keypair using wireauth's crypto
    let (public_key, private_key) = wireauth_protocol::crypto::generate_keypair(&mut rng).unwrap();
    
    // Convert public key to bytes
    let public_key_bytes: [u8; 33] = (&public_key).into();
    
    // The problem is we can't extract private key bytes from wireauth's PrivateKey
    // So we need to use a known private key that we can control
    // Let's generate a valid secp256k1 private key deterministically
    let mut private_key_bytes = [0u8; 32];
    private_key_bytes[0] = 0x01;
    for i in 1..32 {
        private_key_bytes[i] = seed.wrapping_add(i as u8);
    }
    
    // Make sure this is a valid private key
    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&private_key_bytes).unwrap();
    // Get the ACTUAL public key that corresponds to THIS private key
    let real_public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let real_public_key_bytes = real_public_key.serialize().to_vec();
    
    (private_key_bytes.to_vec(), real_public_key_bytes)
}

#[test]
#[timeout(5000)]
fn test_two_nodes_auth() {
    init_tracing();
    info!("starting test_two_nodes_auth");
    
    let (node1_private, node1_public) = generate_test_keypair_with_seed(1);
    let (node2_private, node2_public) = generate_test_keypair_with_seed(2);
    
    info!("node1 public key: {:?}", hex::encode(&node1_public));
    info!("node2 public key: {:?}", hex::encode(&node2_public));
    
    let mut node1_auth = node1_private.clone();
    node1_auth.extend_from_slice(&node1_public);
    
    let mut node2_auth = node2_private.clone();
    node2_auth.extend_from_slice(&node2_public);
    
    let node1_addr: SocketAddr = "127.0.0.1:19000".parse().unwrap();
    let node2_addr: SocketAddr = "127.0.0.1:19001".parse().unwrap();
    
    info!(node1_addr = %node1_addr, node2_addr = %node2_addr, "initializing nodes");
    
    let mut node1 = DataplaneBuilder::new(&node1_addr, UP_BANDWIDTH_MBPS)
        .with_authentication(node1_auth)
        .build();
    
    let mut node2 = DataplaneBuilder::new(&node2_addr, UP_BANDWIDTH_MBPS)
        .with_authentication(node2_auth)
        .build();
    
    assert!(node1.block_until_ready(Duration::from_secs(1)));
    assert!(node2.block_until_ready(Duration::from_secs(1)));
    
    // Give the runtime threads time to fully start
    std::thread::sleep(Duration::from_millis(100));
    
    info!("nodes initialized, setting up sessions");
    
    // Try initiating from just one side first
    node1.init_sessions(vec![(node2_addr, node2_public.clone())]);
    
    info!("waiting for handshake completion");
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(100));
        std::thread::yield_now();
    }
    
    info!("sending encrypted messages between nodes");
    
    for i in 0..10 {
        let message = format!("Message {} from node1 to node2", i);
        let payload = Bytes::from(message.clone());
        
        node1.udp_write_broadcast(BroadcastMsg {
            targets: vec![node2_addr],
            payload: payload.clone(),
            stride: payload.len() as u16,
        });
        
        let received: RecvUdpMsg = executor::block_on(node2.udp_read());
        assert_eq!(received.src_addr, node1_addr);
        
        let received_message = String::from_utf8_lossy(&received.payload);
        assert_eq!(received_message, message);
        debug!(message_num = i, "node2 received message from node1");
        
        let message = format!("Message {} from node2 to node1", i);
        let payload = Bytes::from(message.clone());
        
        node2.udp_write_broadcast(BroadcastMsg {
            targets: vec![node1_addr],
            payload: payload.clone(),
            stride: payload.len() as u16,
        });
        
        let received: RecvUdpMsg = executor::block_on(node1.udp_read());
        assert_eq!(received.src_addr, node2_addr);
        
        let received_message = String::from_utf8_lossy(&received.payload);
        assert_eq!(received_message, message);
        debug!(message_num = i, "node1 received message from node2");
    }
    
    info!("successfully exchanged 10 encrypted messages in each direction");
}