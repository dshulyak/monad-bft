// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::BTreeMap;

use alloy_primitives::Address;
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_eth_types::{serde::deserialize_eth_address_from_str, EthExecutionProtocol};
use monad_peer_score::ema;
use serde::Deserialize;

pub use self::{
    bootstrap::{NodeBootstrapConfig, NodeBootstrapPeerConfig},
    fullnode::{FullNodeConfig, FullNodeIdentityConfig},
    network::NodeNetworkConfig,
    peers::PeerDiscoveryConfig,
    sync_peers::{BlockSyncPeersConfig, StateSyncPeersConfig, SyncPeerIdentityConfig},
};

mod bootstrap;
mod fullnode;
mod network;
mod peers;

pub mod fullnode_raptorcast;
pub use fullnode_raptorcast::FullNodeRaptorCastConfig;

pub mod raptorcast;
pub use raptorcast::DeterministicProtocolRolloutStage;

mod sync_peers;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DkgConfig {
    pub enabled: bool,
    #[serde(deserialize_with = "deserialize_eth_address_from_str")]
    pub contract_address: Address,
    pub tx_gas_limit: u64,
    pub tx_max_priority_fee_per_gas: u128,
}

impl Default for DkgConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            contract_address: Address::ZERO,
            tx_gas_limit: 5_000_000,
            tx_max_priority_fee_per_gas: 1,
        }
    }
}

impl DkgConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.contract_address.is_zero() {
            return Err("dkg.contract_address must be nonzero when DKG is enabled".to_owned());
        }
        if self.tx_gas_limit == 0 {
            return Err("dkg.tx_gas_limit must be nonzero".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
#[serde(bound = "")]
pub struct NodeConfig<ST: CertificateSignatureRecoverable> {
    /////////////////////////////////
    // NODE-SPECIFIC CONFIGURATION //
    /////////////////////////////////
    pub node_name: String,
    pub network_name: String,

    #[serde(default)]
    pub prometheus: Option<PrometheusConfig>,

    #[serde(default)]
    pub dkg: DkgConfig,

    #[serde(deserialize_with = "deserialize_eth_address_from_str")]
    pub beneficiary: Address,

    pub ipc_tx_batch_size: u32,
    pub ipc_max_queued_batches: u8,
    // must be <= ipc_max_queued_batches
    pub ipc_queued_batches_watermark: u8,

    pub statesync_threshold: u16,
    pub statesync_max_concurrent_requests: u8,

    pub bootstrap: NodeBootstrapConfig<ST>,
    pub fullnode_dedicated: FullNodeConfig<CertificateSignaturePubKey<ST>>,
    pub blocksync_override: BlockSyncPeersConfig<CertificateSignaturePubKey<ST>>,
    pub statesync: StateSyncPeersConfig<CertificateSignaturePubKey<ST>>,
    pub network: NodeNetworkConfig,

    #[serde(deserialize_with = "peers::deserialize_peer_discovery_config")]
    pub peer_discovery: PeerDiscoveryConfig<ST>,
    #[serde(default)]
    pub txpool_peer_score: ema::ScoreConfig,

    pub fullnode_raptorcast: FullNodeRaptorCastConfig<CertificateSignaturePubKey<ST>>,

    #[serde(default)]
    pub deterministic_raptorcast_rollout: DeterministicProtocolRolloutStage,

    // TODO split network-wide configuration into separate file
    ////////////////////////////////
    // NETWORK-WIDE CONFIGURATION //
    ////////////////////////////////
    pub chain_id: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PrometheusConfig {
    pub bind_addr: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[cfg(feature = "crypto")]
pub type SignatureType = monad_secp::SecpSignature;
#[cfg(feature = "crypto")]
pub type SignatureCollectionType =
    monad_bls::BlsSignatureCollection<CertificateSignaturePubKey<SignatureType>>;
pub type ExecutionProtocolType = EthExecutionProtocol;
#[cfg(feature = "crypto")]
pub type ForkpointConfig = monad_consensus_types::checkpoint::Checkpoint<
    SignatureType,
    SignatureCollectionType,
    ExecutionProtocolType,
>;
#[cfg(feature = "crypto")]
pub type ValidatorsConfigType =
    monad_consensus_types::validator_data::ValidatorsConfig<SignatureCollectionType>;
#[cfg(feature = "crypto")]
pub type MonadNodeConfig = NodeConfig<SignatureType>;

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct DkgOnly {
        #[serde(default)]
        dkg: DkgConfig,
    }

    #[test]
    fn dkg_config_defaults_to_disabled() {
        let parsed: DkgOnly = toml::from_str("").unwrap();
        assert_eq!(parsed.dkg, DkgConfig::default());
    }

    #[test]
    fn dkg_config_parses_and_validates() {
        let parsed: DkgOnly = toml::from_str(
            r#"
                [dkg]
                enabled = true
                contract_address = "0x0000000000000000000000000000000000001000"
                tx_gas_limit = 4000000
                tx_max_priority_fee_per_gas = 2
            "#,
        )
        .unwrap();
        assert!(parsed.dkg.validate().is_ok());
    }
}
