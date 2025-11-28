use std::net::SocketAddrV4;

use serde::{Deserialize, Serialize};

mod socket_addr_v4_serde {
    use std::net::SocketAddrV4;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(addr: &SocketAddrV4, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        addr.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SocketAddrV4, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub public_key: String,
    pub private_key: String,
    #[serde(with = "socket_addr_v4_serde")]
    pub tcp_addr: SocketAddrV4,
    #[serde(with = "socket_addr_v4_serde")]
    pub udp_addr: SocketAddrV4,
    #[serde(with = "socket_addr_v4_serde")]
    pub authenticated_udp_addr: SocketAddrV4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootnodeConfig {
    pub public_key: String,
    pub private_key: String,
    #[serde(with = "socket_addr_v4_serde")]
    pub tcp_addr: SocketAddrV4,
    #[serde(with = "socket_addr_v4_serde")]
    pub udp_addr: SocketAddrV4,
    #[serde(with = "socket_addr_v4_serde")]
    pub authenticated_udp_addr: SocketAddrV4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullnodeConfig {
    pub public_key: String,
    pub private_key: String,
    #[serde(with = "socket_addr_v4_serde")]
    pub tcp_addr: SocketAddrV4,
    #[serde(with = "socket_addr_v4_serde")]
    pub udp_addr: SocketAddrV4,
    #[serde(with = "socket_addr_v4_serde")]
    pub authenticated_udp_addr: SocketAddrV4,
    #[serde(default)]
    pub dedicated: bool,
    #[serde(default)]
    pub prioritized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadConfig {
    #[serde(default = "default_validator_broadcast_window_ms")]
    pub validator_broadcast_window_ms: u64,
    #[serde(default = "default_validator_message_size_min")]
    pub validator_message_size_min: usize,
    #[serde(default = "default_validator_message_size_max")]
    pub validator_message_size_max: usize,
    #[serde(default = "default_fullnode_p2p_window_ms")]
    pub fullnode_p2p_window_ms: u64,
    #[serde(default = "default_fullnode_p2p_targets_min")]
    pub fullnode_p2p_targets_min: usize,
    #[serde(default = "default_fullnode_p2p_targets_max")]
    pub fullnode_p2p_targets_max: usize,
    #[serde(default = "default_fullnode_message_size_min")]
    pub fullnode_message_size_min: usize,
    #[serde(default = "default_fullnode_message_size_max")]
    pub fullnode_message_size_max: usize,
}

fn default_validator_broadcast_window_ms() -> u64 {
    1000
}
fn default_validator_message_size_min() -> usize {
    131072
}
fn default_validator_message_size_max() -> usize {
    1048576
}
fn default_fullnode_p2p_window_ms() -> u64 {
    10000
}
fn default_fullnode_p2p_targets_min() -> usize {
    1
}
fn default_fullnode_p2p_targets_max() -> usize {
    5
}
fn default_fullnode_message_size_min() -> usize {
    16384
}
fn default_fullnode_message_size_max() -> usize {
    131072
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        Self {
            validator_broadcast_window_ms: default_validator_broadcast_window_ms(),
            validator_message_size_min: default_validator_message_size_min(),
            validator_message_size_max: default_validator_message_size_max(),
            fullnode_p2p_window_ms: default_fullnode_p2p_window_ms(),
            fullnode_p2p_targets_min: default_fullnode_p2p_targets_min(),
            fullnode_p2p_targets_max: default_fullnode_p2p_targets_max(),
            fullnode_message_size_min: default_fullnode_message_size_min(),
            fullnode_message_size_max: default_fullnode_message_size_max(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterInfo {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    #[serde(default)]
    pub cluster: ClusterInfo,
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    #[serde(default)]
    pub bootnodes: Vec<BootnodeConfig>,
    #[serde(default)]
    pub fullnodes: Vec<FullnodeConfig>,
    #[serde(default)]
    pub workload: WorkloadConfig,
}
