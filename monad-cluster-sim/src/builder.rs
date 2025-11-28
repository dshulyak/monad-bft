use std::{
    collections::{BTreeMap, BTreeSet},
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use eyre::Result;
use monad_dataplane::DataplaneBuilder;
use monad_executor::Executor;
use monad_executor_glue::RouterCommand;
use monad_node_config::{
    fullnode_raptorcast::FullNodeRaptorCastConfig, FullNodeConfig, FullNodeIdentityConfig,
};
use monad_peer_discovery::{discovery::PeerDiscoveryBuilder, MonadNameRecord, NameRecord};
use monad_raptorcast::{
    config::{RaptorCastConfig, RaptorCastConfigPrimary},
    AUTHENTICATED_RAPTORCAST_SOCKET, RAPTORCAST_SOCKET,
};
use monad_router_multi::MultiRouter;
use monad_secp::KeyPair;
use monad_types::{Epoch, NodeId, Round, Stake};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::{
    config::{BootnodeConfig, ClusterConfig, FullnodeConfig, ValidatorConfig, WorkloadConfig},
    roles::{MultiRouterType, NodeType, PubKeyType, SignatureType},
};

const UDP_BW: u64 = 1_000;

fn parse_keypair(private_key: &str) -> Result<(NodeId<PubKeyType>, Arc<KeyPair>)> {
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&hex::decode(private_key)?);
    let keypair = KeyPair::from_bytes(&mut pk)?;
    let node_id = NodeId::new(keypair.pubkey());
    Ok((node_id, Arc::new(keypair)))
}

fn create_name_record(
    keypair: &KeyPair,
    tcp_addr: SocketAddrV4,
    udp_addr: SocketAddrV4,
    authenticated_udp_addr: SocketAddrV4,
) -> MonadNameRecord<SignatureType> {
    let name_record = NameRecord::new_with_authentication(
        *tcp_addr.ip(),
        tcp_addr.port(),
        udp_addr.port(),
        authenticated_udp_addr.port(),
        0,
    );
    MonadNameRecord::<SignatureType>::new(name_record, keypair)
}

pub struct NodeRunConfig {
    pub node_id: NodeId<PubKeyType>,
    pub node_type: NodeType,
    pub keypair: Arc<KeyPair>,
    pub tcp_addr: SocketAddrV4,
    pub udp_addr: SocketAddrV4,
    pub authenticated_udp_addr: SocketAddrV4,
    pub self_record: MonadNameRecord<SignatureType>,
    pub bootstrap_peers: BTreeMap<NodeId<PubKeyType>, MonadNameRecord<SignatureType>>,
    pub epoch_validators: BTreeMap<NodeId<PubKeyType>, Stake>,
    pub dedicated_fullnodes: Vec<NodeId<PubKeyType>>,
    pub prioritized_fullnodes: Vec<NodeId<PubKeyType>>,
    pub known_peers: Vec<NodeId<PubKeyType>>,
}

impl NodeRunConfig {
    pub fn build_router(&self) -> MultiRouterType {
        let bind_ip = std::net::Ipv4Addr::new(0, 0, 0, 0);
        let tcp_bind_addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, self.tcp_addr.port()));
        let authenticated_udp_bind = SocketAddr::V4(SocketAddrV4::new(
            bind_ip,
            self.authenticated_udp_addr.port(),
        ));
        let non_authenticated_bind =
            SocketAddr::V4(SocketAddrV4::new(bind_ip, self.udp_addr.port()));

        let dataplane_builder =
            DataplaneBuilder::new(&tcp_bind_addr, UDP_BW).extend_udp_sockets(vec![
                monad_dataplane::UdpSocketConfig {
                    socket_addr: authenticated_udp_bind,
                    label: AUTHENTICATED_RAPTORCAST_SOCKET.to_string(),
                },
                monad_dataplane::UdpSocketConfig {
                    socket_addr: non_authenticated_bind,
                    label: RAPTORCAST_SOCKET.to_string(),
                },
            ]);

        let epoch_validators_set: BTreeSet<_> = self.epoch_validators.keys().cloned().collect();
        let pinned_full_nodes: BTreeSet<_> = self
            .dedicated_fullnodes
            .iter()
            .chain(self.prioritized_fullnodes.iter())
            .chain(self.bootstrap_peers.keys())
            .cloned()
            .collect();
        let prioritized_full_nodes_set: BTreeSet<_> =
            self.prioritized_fullnodes.iter().cloned().collect();

        let (enable_publisher, enable_client) = match self.node_type {
            NodeType::Validator => (true, false),
            NodeType::Bootnode => (false, false),
            NodeType::Fullnode { .. } => (false, true),
        };

        let epoch_validators_for_pd: BTreeMap<Epoch, BTreeSet<_>> =
            std::iter::once((Epoch(0), epoch_validators_set)).collect();

        let peer_discovery_builder = PeerDiscoveryBuilder {
            self_id: self.node_id,
            self_record: self.self_record.clone(),
            current_round: Round(0),
            current_epoch: Epoch(0),
            epoch_validators: epoch_validators_for_pd.clone(),
            pinned_full_nodes,
            prioritized_full_nodes: prioritized_full_nodes_set,
            bootstrap_peers: self.bootstrap_peers.clone(),
            refresh_period: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            unresponsive_prune_threshold: 5,
            last_participation_prune_threshold: Round(5000),
            min_num_peers: 0,
            max_num_peers: 200,
            max_group_size: 50,
            enable_publisher,
            enable_client,
            rng: ChaCha8Rng::from_entropy(),
        };

        let wireauth_config = monad_wireauth::Config::default();
        let auth_protocol =
            monad_raptorcast::auth::WireAuthProtocol::new(wireauth_config, self.keypair.clone());

        let raptorcast_config = RaptorCastConfig {
            shared_key: self.keypair.clone(),
            mtu: monad_dataplane::udp::DEFAULT_MTU,
            udp_message_max_age_ms: 5000,
            primary_instance: RaptorCastConfigPrimary {
                fullnode_dedicated: self.dedicated_fullnodes.clone(),
                ..Default::default()
            },
            secondary_instance: FullNodeRaptorCastConfig {
                enable_publisher,
                enable_client,
                full_nodes_prioritized: FullNodeConfig {
                    identities: self
                        .prioritized_fullnodes
                        .iter()
                        .map(|id| FullNodeIdentityConfig {
                            secp256k1_pubkey: id.pubkey(),
                        })
                        .collect(),
                },
                raptor10_fullnode_redundancy_factor: 2.0,
                round_span: Round(1200),
                invite_lookahead: Round(1200),
                max_invite_wait: Round(100),
                deadline_round_dist: Round(100),
                init_empty_round_span: Round(201),
                max_group_size: 50,
                max_num_group: 5,
                invite_future_dist_min: Round(1),
                invite_future_dist_max: Round(1200),
                invite_accept_heartbeat_ms: 100,
            },
        };

        let mut router = MultiRouter::new(
            self.node_id,
            raptorcast_config,
            dataplane_builder,
            peer_discovery_builder,
            Epoch(0),
            epoch_validators_for_pd,
            auth_protocol,
        );

        router.exec(vec![RouterCommand::AddEpochValidatorSet {
            epoch: Epoch(0),
            validator_set: self
                .epoch_validators
                .iter()
                .map(|(id, stake)| (*id, *stake))
                .collect(),
        }]);

        router
    }
}

pub struct BootnodesInitialized {
    pub configs: Vec<NodeRunConfig>,
    pub records: BTreeMap<NodeId<PubKeyType>, MonadNameRecord<SignatureType>>,
}

pub struct ValidatorsInitialized {
    pub configs: Vec<NodeRunConfig>,
    pub records: BTreeMap<NodeId<PubKeyType>, MonadNameRecord<SignatureType>>,
    pub stakes: BTreeMap<NodeId<PubKeyType>, Stake>,
}

pub struct DedicatedFullnodesInitialized {
    pub configs: Vec<NodeRunConfig>,
    pub records: BTreeMap<NodeId<PubKeyType>, MonadNameRecord<SignatureType>>,
}

pub struct PrioritizedFullnodesInitialized {
    pub configs: Vec<NodeRunConfig>,
    pub records: BTreeMap<NodeId<PubKeyType>, MonadNameRecord<SignatureType>>,
}

pub struct StandardFullnodesInitialized {
    pub configs: Vec<NodeRunConfig>,
    pub records: BTreeMap<NodeId<PubKeyType>, MonadNameRecord<SignatureType>>,
}

pub struct ClusterBuilder {
    bootnodes: Option<BootnodesInitialized>,
    validators: Option<ValidatorsInitialized>,
    dedicated_fullnodes: Option<DedicatedFullnodesInitialized>,
    prioritized_fullnodes: Option<PrioritizedFullnodesInitialized>,
    fullnodes: Option<StandardFullnodesInitialized>,
    workload: WorkloadConfig,
}

impl ClusterBuilder {
    pub fn new() -> Self {
        Self {
            bootnodes: None,
            validators: None,
            dedicated_fullnodes: None,
            prioritized_fullnodes: None,
            fullnodes: None,
            workload: WorkloadConfig::default(),
        }
    }

    pub fn with_workload(mut self, workload: WorkloadConfig) -> Self {
        self.workload = workload;
        self
    }

    pub fn with_bootnodes(mut self, configs: &[BootnodeConfig]) -> Result<Self> {
        let mut node_configs = Vec::with_capacity(configs.len());
        let mut records = BTreeMap::new();

        for config in configs {
            let (node_id, keypair) = parse_keypair(&config.private_key)?;
            let self_record = create_name_record(
                &keypair,
                config.tcp_addr,
                config.udp_addr,
                config.authenticated_udp_addr,
            );

            records.insert(node_id, self_record.clone());

            node_configs.push(NodeRunConfig {
                node_id,
                node_type: NodeType::Bootnode,
                keypair,
                tcp_addr: config.tcp_addr,
                udp_addr: config.udp_addr,
                authenticated_udp_addr: config.authenticated_udp_addr,
                self_record,
                bootstrap_peers: BTreeMap::new(),
                epoch_validators: BTreeMap::new(),
                dedicated_fullnodes: Vec::new(),
                prioritized_fullnodes: Vec::new(),
                known_peers: Vec::new(),
            });
        }

        for cfg in &mut node_configs {
            cfg.bootstrap_peers = records
                .iter()
                .filter(|(id, _)| **id != cfg.node_id)
                .map(|(id, r)| (*id, r.clone()))
                .collect();
            cfg.known_peers = records
                .keys()
                .filter(|id| **id != cfg.node_id)
                .copied()
                .collect();
        }

        tracing::info!(bootnode_count = node_configs.len(), "initialized bootnodes");

        self.bootnodes = Some(BootnodesInitialized {
            configs: node_configs,
            records,
        });
        Ok(self)
    }

    pub fn with_validators(mut self, configs: &[ValidatorConfig]) -> Result<Self> {
        let bootnodes = self
            .bootnodes
            .as_mut()
            .ok_or_else(|| eyre::eyre!("bootnodes must be initialized before validators"))?;

        let bootnode_records = bootnodes.records.clone();
        let mut node_configs = Vec::with_capacity(configs.len());
        let mut records = BTreeMap::new();
        let mut stakes = BTreeMap::new();

        for config in configs {
            let (node_id, keypair) = parse_keypair(&config.private_key)?;
            let self_record = create_name_record(
                &keypair,
                config.tcp_addr,
                config.udp_addr,
                config.authenticated_udp_addr,
            );

            records.insert(node_id, self_record.clone());
            stakes.insert(node_id, Stake::ONE);

            node_configs.push(NodeRunConfig {
                node_id,
                node_type: NodeType::Validator,
                keypair,
                tcp_addr: config.tcp_addr,
                udp_addr: config.udp_addr,
                authenticated_udp_addr: config.authenticated_udp_addr,
                self_record,
                bootstrap_peers: bootnode_records.clone(),
                epoch_validators: BTreeMap::new(),
                dedicated_fullnodes: Vec::new(),
                prioritized_fullnodes: Vec::new(),
                known_peers: Vec::new(),
            });
        }

        for cfg in &mut node_configs {
            cfg.epoch_validators = stakes.clone();
            cfg.known_peers = bootnode_records
                .keys()
                .chain(records.keys())
                .filter(|id| **id != cfg.node_id)
                .copied()
                .collect();
        }

        for bootnode_cfg in &mut bootnodes.configs {
            bootnode_cfg.epoch_validators = stakes.clone();
            bootnode_cfg.bootstrap_peers.extend(records.clone());
            bootnode_cfg.known_peers.extend(records.keys().copied());
        }

        tracing::info!(
            validator_count = node_configs.len(),
            bootstrap_peers = bootnode_records.len(),
            "initialized validators with bootnode records"
        );

        self.validators = Some(ValidatorsInitialized {
            configs: node_configs,
            records,
            stakes,
        });
        Ok(self)
    }

    pub fn with_dedicated_fullnodes(mut self, configs: &[FullnodeConfig]) -> Result<Self> {
        let bootnodes = self.bootnodes.as_mut().ok_or_else(|| {
            eyre::eyre!("bootnodes must be initialized before dedicated fullnodes")
        })?;
        let validators = self.validators.as_mut().ok_or_else(|| {
            eyre::eyre!("validators must be initialized before dedicated fullnodes")
        })?;

        let dedicated_configs: Vec<_> = configs.iter().filter(|c| c.dedicated).collect();

        if dedicated_configs.is_empty() || validators.configs.is_empty() {
            self.dedicated_fullnodes = Some(DedicatedFullnodesInitialized {
                configs: Vec::new(),
                records: BTreeMap::new(),
            });
            return Ok(self);
        }

        let bootnode_records = bootnodes.records.clone();
        let validator_count = validators.configs.len();

        let mut node_configs = Vec::with_capacity(dedicated_configs.len());
        let mut records = BTreeMap::new();

        for (i, config) in dedicated_configs.into_iter().enumerate() {
            let (node_id, keypair) = parse_keypair(&config.private_key)?;
            let self_record = create_name_record(
                &keypair,
                config.tcp_addr,
                config.udp_addr,
                config.authenticated_udp_addr,
            );

            records.insert(node_id, self_record.clone());

            let assigned_validator_idx = i % validator_count;
            validators.configs[assigned_validator_idx]
                .dedicated_fullnodes
                .push(node_id);

            tracing::debug!(
                fullnode = ?node_id,
                validator_idx = assigned_validator_idx,
                "assigned dedicated fullnode to validator"
            );

            node_configs.push(NodeRunConfig {
                node_id,
                node_type: NodeType::Fullnode {
                    dedicated: true,
                    prioritized: false,
                },
                keypair,
                tcp_addr: config.tcp_addr,
                udp_addr: config.udp_addr,
                authenticated_udp_addr: config.authenticated_udp_addr,
                self_record,
                bootstrap_peers: bootnode_records.clone(),
                epoch_validators: validators.stakes.clone(),
                dedicated_fullnodes: Vec::new(),
                prioritized_fullnodes: Vec::new(),
                known_peers: bootnode_records
                    .keys()
                    .chain(validators.records.keys())
                    .copied()
                    .collect(),
            });
        }

        for bootnode_cfg in &mut bootnodes.configs {
            bootnode_cfg.bootstrap_peers.extend(records.clone());
            bootnode_cfg.known_peers.extend(records.keys().copied());
        }

        for validator_cfg in &mut validators.configs {
            validator_cfg.known_peers.extend(records.keys().copied());
        }

        tracing::info!(
            dedicated_fullnode_count = node_configs.len(),
            validator_count,
            "initialized dedicated fullnodes with round-robin validator assignment"
        );

        self.dedicated_fullnodes = Some(DedicatedFullnodesInitialized {
            configs: node_configs,
            records,
        });
        Ok(self)
    }

    pub fn with_prioritized_fullnodes(mut self, configs: &[FullnodeConfig]) -> Result<Self> {
        let bootnodes = self.bootnodes.as_mut().ok_or_else(|| {
            eyre::eyre!("bootnodes must be initialized before prioritized fullnodes")
        })?;
        let validators = self.validators.as_mut().ok_or_else(|| {
            eyre::eyre!("validators must be initialized before prioritized fullnodes")
        })?;
        let dedicated = self.dedicated_fullnodes.as_mut().ok_or_else(|| {
            eyre::eyre!("dedicated fullnodes must be initialized before prioritized fullnodes")
        })?;

        let prioritized_configs: Vec<_> = configs.iter().filter(|c| c.prioritized).collect();

        if prioritized_configs.is_empty() || validators.configs.is_empty() {
            self.prioritized_fullnodes = Some(PrioritizedFullnodesInitialized {
                configs: Vec::new(),
                records: BTreeMap::new(),
            });
            return Ok(self);
        }

        let bootnode_records = bootnodes.records.clone();
        let validator_count = validators.configs.len();

        let mut node_configs = Vec::with_capacity(prioritized_configs.len());
        let mut records = BTreeMap::new();

        for (i, config) in prioritized_configs.into_iter().enumerate() {
            let (node_id, keypair) = parse_keypair(&config.private_key)?;
            let self_record = create_name_record(
                &keypair,
                config.tcp_addr,
                config.udp_addr,
                config.authenticated_udp_addr,
            );

            records.insert(node_id, self_record.clone());

            let assigned_validator_idx = i % validator_count;
            validators.configs[assigned_validator_idx]
                .prioritized_fullnodes
                .push(node_id);

            tracing::debug!(
                fullnode = ?node_id,
                validator_idx = assigned_validator_idx,
                "assigned prioritized fullnode to validator"
            );

            node_configs.push(NodeRunConfig {
                node_id,
                node_type: NodeType::Fullnode {
                    dedicated: false,
                    prioritized: true,
                },
                keypair,
                tcp_addr: config.tcp_addr,
                udp_addr: config.udp_addr,
                authenticated_udp_addr: config.authenticated_udp_addr,
                self_record,
                bootstrap_peers: bootnode_records.clone(),
                epoch_validators: validators.stakes.clone(),
                dedicated_fullnodes: Vec::new(),
                prioritized_fullnodes: Vec::new(),
                known_peers: bootnode_records
                    .keys()
                    .chain(validators.records.keys())
                    .copied()
                    .collect(),
            });
        }

        for bootnode_cfg in &mut bootnodes.configs {
            bootnode_cfg.bootstrap_peers.extend(records.clone());
            bootnode_cfg.known_peers.extend(records.keys().copied());
        }

        for validator_cfg in &mut validators.configs {
            validator_cfg.known_peers.extend(records.keys().copied());
        }

        for dedicated_cfg in &mut dedicated.configs {
            dedicated_cfg.known_peers.extend(records.keys().copied());
        }

        tracing::info!(
            prioritized_fullnode_count = node_configs.len(),
            validator_count,
            "initialized prioritized fullnodes with round-robin validator assignment"
        );

        self.prioritized_fullnodes = Some(PrioritizedFullnodesInitialized {
            configs: node_configs,
            records,
        });
        Ok(self)
    }

    pub fn with_fullnodes(mut self, configs: &[FullnodeConfig]) -> Result<Self> {
        let bootnodes = self.bootnodes.as_mut().ok_or_else(|| {
            eyre::eyre!("bootnodes must be initialized before standard fullnodes")
        })?;
        let validators = self.validators.as_ref().ok_or_else(|| {
            eyre::eyre!("validators must be initialized before standard fullnodes")
        })?;
        let dedicated = self.dedicated_fullnodes.as_mut().ok_or_else(|| {
            eyre::eyre!("dedicated fullnodes must be initialized before standard fullnodes")
        })?;
        let prioritized = self.prioritized_fullnodes.as_mut().ok_or_else(|| {
            eyre::eyre!("prioritized fullnodes must be initialized before standard fullnodes")
        })?;

        let standard_configs: Vec<_> = configs
            .iter()
            .filter(|c| !c.dedicated && !c.prioritized)
            .collect();

        if standard_configs.is_empty() {
            self.fullnodes = Some(StandardFullnodesInitialized {
                configs: Vec::new(),
                records: BTreeMap::new(),
            });
            return Ok(self);
        }

        let bootnode_records = bootnodes.records.clone();

        let mut node_configs = Vec::with_capacity(standard_configs.len());
        let mut records = BTreeMap::new();

        for config in standard_configs {
            let (node_id, keypair) = parse_keypair(&config.private_key)?;
            let self_record = create_name_record(
                &keypair,
                config.tcp_addr,
                config.udp_addr,
                config.authenticated_udp_addr,
            );

            records.insert(node_id, self_record.clone());

            node_configs.push(NodeRunConfig {
                node_id,
                node_type: NodeType::Fullnode {
                    dedicated: false,
                    prioritized: false,
                },
                keypair,
                tcp_addr: config.tcp_addr,
                udp_addr: config.udp_addr,
                authenticated_udp_addr: config.authenticated_udp_addr,
                self_record,
                bootstrap_peers: bootnode_records.clone(),
                epoch_validators: validators.stakes.clone(),
                dedicated_fullnodes: Vec::new(),
                prioritized_fullnodes: Vec::new(),
                known_peers: bootnode_records.keys().copied().collect(),
            });
        }

        for bootnode_cfg in &mut bootnodes.configs {
            bootnode_cfg.bootstrap_peers.extend(records.clone());
            bootnode_cfg.known_peers.extend(records.keys().copied());
        }

        for dedicated_cfg in &mut dedicated.configs {
            dedicated_cfg.known_peers.extend(records.keys().copied());
        }

        for prioritized_cfg in &mut prioritized.configs {
            prioritized_cfg.known_peers.extend(records.keys().copied());
        }

        tracing::info!(
            standard_fullnode_count = node_configs.len(),
            bootstrap_peers = bootnode_records.len(),
            "initialized standard fullnodes with bootnode records only"
        );

        self.fullnodes = Some(StandardFullnodesInitialized {
            configs: node_configs,
            records,
        });
        Ok(self)
    }

    pub fn get_node_config(&self, index: usize) -> Option<&NodeRunConfig> {
        let bootnodes_count = self
            .bootnodes
            .as_ref()
            .map(|b| b.configs.len())
            .unwrap_or(0);
        let validators_count = self
            .validators
            .as_ref()
            .map(|v| v.configs.len())
            .unwrap_or(0);
        let dedicated_count = self
            .dedicated_fullnodes
            .as_ref()
            .map(|d| d.configs.len())
            .unwrap_or(0);
        let prioritized_count = self
            .prioritized_fullnodes
            .as_ref()
            .map(|p| p.configs.len())
            .unwrap_or(0);
        let fullnodes_count = self
            .fullnodes
            .as_ref()
            .map(|f| f.configs.len())
            .unwrap_or(0);

        if index < bootnodes_count {
            self.bootnodes.as_ref().map(|b| &b.configs[index])
        } else if index < bootnodes_count + validators_count {
            let local_idx = index - bootnodes_count;
            self.validators.as_ref().map(|v| &v.configs[local_idx])
        } else if index < bootnodes_count + validators_count + dedicated_count {
            let local_idx = index - bootnodes_count - validators_count;
            self.dedicated_fullnodes
                .as_ref()
                .map(|d| &d.configs[local_idx])
        } else if index < bootnodes_count + validators_count + dedicated_count + prioritized_count {
            let local_idx = index - bootnodes_count - validators_count - dedicated_count;
            self.prioritized_fullnodes
                .as_ref()
                .map(|p| &p.configs[local_idx])
        } else if index
            < bootnodes_count
                + validators_count
                + dedicated_count
                + prioritized_count
                + fullnodes_count
        {
            let local_idx =
                index - bootnodes_count - validators_count - dedicated_count - prioritized_count;
            self.fullnodes.as_ref().map(|f| &f.configs[local_idx])
        } else {
            None
        }
    }

    pub fn workload(&self) -> &WorkloadConfig {
        &self.workload
    }

    pub fn total_nodes(&self) -> usize {
        self.bootnodes
            .as_ref()
            .map(|b| b.configs.len())
            .unwrap_or(0)
            + self
                .validators
                .as_ref()
                .map(|v| v.configs.len())
                .unwrap_or(0)
            + self
                .dedicated_fullnodes
                .as_ref()
                .map(|d| d.configs.len())
                .unwrap_or(0)
            + self
                .prioritized_fullnodes
                .as_ref()
                .map(|p| p.configs.len())
                .unwrap_or(0)
            + self
                .fullnodes
                .as_ref()
                .map(|f| f.configs.len())
                .unwrap_or(0)
    }
}

impl Default for ClusterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn build_cluster_from_config(config: &ClusterConfig) -> Result<ClusterBuilder> {
    ClusterBuilder::new()
        .with_workload(config.workload.clone())
        .with_bootnodes(&config.bootnodes)?
        .with_validators(&config.validators)?
        .with_dedicated_fullnodes(&config.fullnodes)?
        .with_prioritized_fullnodes(&config.fullnodes)?
        .with_fullnodes(&config.fullnodes)
}
