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

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:16,prof_leak:true\0";

mod builder;
mod config;
mod roles;

use std::{
    collections::HashMap,
    env,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

use builder::build_cluster_from_config;
use clap::{Parser, Subcommand};
use config::{
    BootnodeConfig, ClusterConfig, ClusterInfo, FullnodeConfig, ValidatorConfig, WorkloadConfig,
};
use eyre::Result;
use monad_secp::KeyPair;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use roles::{LatencyMetrics, NodeType};
use tracing_subscriber::EnvFilter;

fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| e.to_string())
}

pub trait AddressAllocator {
    fn ip(&self) -> Ipv4Addr;
    fn tcp_port(&self) -> u16;
    fn udp_port(&self) -> u16;
    fn auth_udp_port(&self) -> u16;
    fn advance(&mut self);
    fn mode_name(&self) -> &'static str;
}

pub struct PortAllocator {
    ip: Ipv4Addr,
    base_port: u16,
    tcp_offset: u16,
    udp_offset: u16,
    auth_udp_offset: u16,
}

impl PortAllocator {
    pub fn new(ip: Ipv4Addr, base_port: u16) -> Self {
        Self {
            ip,
            base_port,
            tcp_offset: 0,
            udp_offset: 0,
            auth_udp_offset: 1,
        }
    }
}

impl AddressAllocator for PortAllocator {
    fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    fn tcp_port(&self) -> u16 {
        self.base_port + self.tcp_offset
    }

    fn udp_port(&self) -> u16 {
        self.base_port + self.udp_offset
    }

    fn auth_udp_port(&self) -> u16 {
        self.base_port + self.auth_udp_offset
    }

    fn advance(&mut self) {
        self.tcp_offset += 2;
        self.udp_offset += 2;
        self.auth_udp_offset += 2;
    }

    fn mode_name(&self) -> &'static str {
        "port-allocation"
    }
}

pub struct IpAllocator {
    base_ip: [u8; 4],
    ip_offset: u32,
    tcp_port: u16,
    udp_port: u16,
    auth_udp_port: u16,
}

impl IpAllocator {
    pub fn new(base_ip: Ipv4Addr, tcp_port: u16, udp_port: u16, auth_udp_port: u16) -> Self {
        Self {
            base_ip: base_ip.octets(),
            ip_offset: 0,
            tcp_port,
            udp_port,
            auth_udp_port,
        }
    }
}

impl AddressAllocator for IpAllocator {
    fn ip(&self) -> Ipv4Addr {
        let base_u32 = u32::from_be_bytes(self.base_ip);
        let current_u32 = base_u32 + self.ip_offset;
        Ipv4Addr::from(current_u32)
    }

    fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    fn udp_port(&self) -> u16 {
        self.udp_port
    }

    fn auth_udp_port(&self) -> u16 {
        self.auth_udp_port
    }

    fn advance(&mut self) {
        self.ip_offset += 1;
    }

    fn mode_name(&self) -> &'static str {
        "ip-allocation"
    }
}

fn create_allocator(base_ip: Ipv4Addr, base_port: u16) -> Box<dyn AddressAllocator> {
    if base_ip.is_loopback() {
        Box::new(PortAllocator::new(base_ip, base_port))
    } else {
        Box::new(IpAllocator::new(
            base_ip,
            base_port,
            base_port,
            base_port + 1,
        ))
    }
}

#[derive(Parser)]
#[command(name = "cluster")]
#[command(about = "Cluster workload simulator for RaptorCast protocol testing")]
#[command(long_about = r#"
Cluster workload simulator for RaptorCast protocol testing.

This tool simulates a network of nodes (validators, bootnodes, fullnodes) to test
the RaptorCast broadcast protocol. Each node type has different behavior:

NODE TYPES:
  Validator          - Broadcasts messages via RaptorCast, publishes to fullnodes
  Bootnode           - Peer discovery bootstrap node, no message broadcasting
  Dedicated Fullnode - Receives broadcasts directly from assigned validator (primary instance)
  Prioritized Fullnode - Receives broadcasts via secondary RaptorCast with guaranteed slot
  Standard Fullnode  - Receives broadcasts via secondary RaptorCast with dynamic slot

MESSAGE FLOW:
  - Validators broadcast to other validators via primary RaptorCast
  - Dedicated fullnodes receive via direct TCP/UDP path (low latency)
  - Prioritized/Standard fullnodes join groups via secondary RaptorCast (~20-30s group formation)
  - Standard fullnodes only know bootnodes initially, discover validators via peer discovery
"#)]
#[command(after_long_help = r#"
EXAMPLES:

  1. Generate a cluster config with 2 validators and 1 bootnode:
     $ cluster generate --output cluster.toml --validators 2 --bootnodes 1

  2. Generate config with dedicated fullnode:
     $ cluster g --output cluster.toml --validators 2 --bootnodes 1 --dedicated-fullnodes 1

  3. Generate config with all fullnode types:
     $ cluster generate --output cluster.toml \
         --validators 2 --bootnodes 1 \
         --dedicated-fullnodes 1 --prioritized-fullnodes 1 --fullnodes 1

  4. Run nodes in separate terminals (each node needs its own process):
     Terminal 1: $ RUST_LOG=debug cluster run --cluster cluster.toml --index 0
     Terminal 2: $ RUST_LOG=debug cluster r --cluster cluster.toml --index 1
     Terminal 3: $ RUST_LOG=debug cluster r --cluster cluster.toml --index 2

  5. Run nodes with output to log files:
     $ mkdir -p logs
     $ RUST_LOG=debug cluster r --cluster cluster.toml --index 0 > logs/node0.log 2>&1 &
     $ RUST_LOG=debug cluster r --cluster cluster.toml --index 1 > logs/node1.log 2>&1 &
     $ RUST_LOG=debug cluster r --cluster cluster.toml --index 2 > logs/node2.log 2>&1 &

  6. Full test script example (2 validators + 1 bootnode + 1 dedicated fullnode):
     $ cluster g --output /tmp/cluster.toml \
         --validators 2 --bootnodes 1 --dedicated-fullnodes 1
     $ mkdir -p /tmp/logs
     $ for i in 0 1 2 3; do
         RUST_LOG=debug cluster r --cluster /tmp/cluster.toml --index $i \
           > /tmp/logs/node_$i.log 2>&1 &
       done
     $ sleep 30  # Wait for group formation and message exchange
     $ pkill -f "cluster run"
     $ grep "message received" /tmp/logs/*.log

NODE INDEX MAPPING:
  The node index corresponds to the order in the config file:
  - Index 0 to (bootnodes-1): Bootnode nodes
  - Index bootnodes to (bootnodes+validators-1): Validator nodes
  - Remaining indices: Fullnode nodes (dedicated, then prioritized, then standard)
"#)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(visible_alias = "g", about = "Generate cluster configuration file")]
    #[command(long_about = r#"
Generate a TOML configuration file for the cluster.

The generated config includes keypairs, network addresses, and workload parameters
for all nodes. Node order in the config determines the index used with 'run' command.

FULLNODE TYPES:
  --fullnodes           Standard fullnodes that join groups dynamically
  --dedicated-fullnodes Fullnodes with direct delivery path from validators
  --prioritized-fullnodes Fullnodes with guaranteed slots in broadcast groups

Dedicated and prioritized fullnodes are assigned to validators in round-robin fashion.
"#)]
    Generate {
        #[arg(long, help = "Output config file path")]
        output: String,
        #[arg(long, default_value = "5", help = "Number of validator nodes")]
        validators: usize,
        #[arg(long, default_value = "2", help = "Number of bootnode nodes")]
        bootnodes: usize,
        #[arg(long, default_value = "0", help = "Number of standard full nodes")]
        fullnodes: usize,
        #[arg(long, default_value = "0", help = "Number of dedicated full nodes")]
        dedicated_fullnodes: usize,
        #[arg(long, default_value = "0", help = "Number of prioritized full nodes")]
        prioritized_fullnodes: usize,
        #[arg(long, default_value = "127.0.0.1", help = "Starting IP address")]
        base_ip: String,
        #[arg(long, default_value = "30000", help = "Starting port")]
        base_port: u16,
    },
    #[command(visible_alias = "r", about = "Run a node from the cluster config")]
    #[command(long_about = r#"
Run a single node from the cluster configuration.

Each node must be run in a separate process. The node index determines which
node configuration to use from the config file. Use NODE_INDEX environment
variable or --index flag to specify the node.
"#)]
    Run {
        #[arg(long, help = "Path to cluster config file")]
        cluster: String,
        #[arg(long, help = "Node index (0-based), can also use NODE_INDEX env var")]
        index: Option<usize>,
        #[arg(
            long,
            help = "OpenTelemetry collector endpoint (e.g., http://localhost:4317)"
        )]
        otel_endpoint: Option<String>,
        #[arg(
            long,
            value_parser = parse_duration,
            default_value = "10s",
            help = "Metrics reporting interval when using OpenTelemetry"
        )]
        metrics_interval: Duration,
    },
}

fn setup_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt::fmt()
        .with_env_filter(env_filter)
        .init();
}

fn build_otel_meter_provider(
    otel_endpoint: &str,
    service_name: String,
    interval: Duration,
) -> Result<opentelemetry_sdk::metrics::SdkMeterProvider> {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_timeout(interval * 2)
        .with_endpoint(otel_endpoint)
        .build()?;

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(interval / 2)
        .build();

    let attrs = vec![opentelemetry::KeyValue::new(
        opentelemetry_semantic_conventions::resource::SERVICE_NAME,
        service_name,
    )];

    let provider_builder = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(
            opentelemetry_sdk::Resource::builder_empty()
                .with_attributes(attrs)
                .build(),
        );

    Ok(provider_builder.build())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    async_main().await
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    setup_tracing();

    match cli.command {
        Commands::Generate {
            output,
            validators,
            bootnodes,
            fullnodes,
            dedicated_fullnodes,
            prioritized_fullnodes,
            base_ip,
            base_port,
        } => generate_config(
            output,
            validators,
            bootnodes,
            fullnodes,
            dedicated_fullnodes,
            prioritized_fullnodes,
            base_ip,
            base_port,
        ),
        Commands::Run {
            cluster,
            index,
            otel_endpoint,
            metrics_interval,
        } => run_node(cluster, index, otel_endpoint, metrics_interval).await,
    }
}

fn get_node_index(index_arg: Option<usize>) -> Result<usize> {
    let node_index = if let Ok(env_index) = env::var("NODE_INDEX") {
        let parsed = env_index
            .parse::<usize>()
            .map_err(|_| eyre::eyre!("NODE_INDEX must be a valid number"))?;
        tracing::info!(
            node_index = parsed,
            source = "NODE_INDEX env variable",
            "using node index from environment"
        );
        parsed
    } else if let Some(index) = index_arg {
        tracing::info!(
            node_index = index,
            source = "--index argument",
            "using node index from command line"
        );
        index
    } else {
        eyre::bail!(
            "node index must be provided via --index argument or NODE_INDEX environment variable"
        );
    };

    Ok(node_index)
}

fn compute_service_name(
    cluster_config: &ClusterConfig,
    node_index: usize,
    node_type: &NodeType,
) -> String {
    let bootnode_count = cluster_config.bootnodes.len();
    let validator_count = cluster_config.validators.len();

    match node_type {
        NodeType::Bootnode => {
            format!("bootnode-{}", node_index)
        }
        NodeType::Validator => {
            let validator_idx = node_index - bootnode_count;
            format!("validator-{}", validator_idx)
        }
        NodeType::Fullnode {
            dedicated,
            prioritized,
        } => {
            let fullnode_idx = node_index - bootnode_count - validator_count;

            let mut dedicated_count = 0;
            let mut prioritized_count = 0;
            let mut regular_count = 0;

            for (idx, fullnode_config) in cluster_config.fullnodes.iter().enumerate() {
                if idx == fullnode_idx {
                    break;
                }
                if fullnode_config.dedicated {
                    dedicated_count += 1;
                } else if fullnode_config.prioritized {
                    prioritized_count += 1;
                } else {
                    regular_count += 1;
                }
            }

            if *dedicated {
                format!("fullnode-dedicated-{}", dedicated_count)
            } else if *prioritized {
                format!("fullnode-prioritized-{}", prioritized_count)
            } else {
                format!("fullnode-{}", regular_count)
            }
        }
    }
}

async fn run_node(
    cluster_path: String,
    index_arg: Option<usize>,
    otel_endpoint: Option<String>,
    metrics_interval: Duration,
) -> Result<()> {
    let node_index = get_node_index(index_arg)?;

    let config_str = std::fs::read_to_string(&cluster_path)?;
    let cluster_config: ClusterConfig = toml::from_str(&config_str)?;

    let cluster = build_cluster_from_config(&cluster_config)?;

    let node_config = cluster
        .get_node_config(node_index)
        .ok_or_else(|| eyre::eyre!("node index {} out of range", node_index))?;

    let workload = cluster.workload();

    let mut router = node_config.build_router();

    let service_name = compute_service_name(&cluster_config, node_index, &node_config.node_type);

    tracing::info!(
        node_id = ?node_config.node_id,
        node_type = %node_config.node_type,
        tcp_addr = ?node_config.tcp_addr,
        otel_endpoint = ?otel_endpoint,
        known_peers = node_config.known_peers.len(),
        dedicated_fullnodes = node_config.dedicated_fullnodes.len(),
        prioritized_fullnodes = node_config.prioritized_fullnodes.len(),
        "started node"
    );

    let (maybe_otel_meter_provider, mut maybe_metrics_ticker) = otel_endpoint
        .map(|endpoint| {
            let provider =
                build_otel_meter_provider(&endpoint, service_name.clone(), metrics_interval)
                    .expect("failed to build otel provider");

            let mut timer = tokio::time::interval(metrics_interval);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            (provider, timer)
        })
        .unzip();

    let maybe_otel_meter = maybe_otel_meter_provider
        .as_ref()
        .map(|provider| provider.meter("raptorcast_latency"));

    let mut gauge_cache = HashMap::new();
    let process_start = Instant::now();
    let mut metrics = LatencyMetrics::new();

    match node_config.node_type {
        NodeType::Validator => {
            roles::validator::run_workload(
                &mut router,
                workload,
                &mut metrics,
                &maybe_otel_meter,
                &mut gauge_cache,
                &mut maybe_metrics_ticker,
                &process_start,
            )
            .await
        }
        NodeType::Bootnode => {
            roles::bootnode::run_workload(
                &mut router,
                &mut metrics,
                &maybe_otel_meter,
                &mut gauge_cache,
                &mut maybe_metrics_ticker,
                &process_start,
            )
            .await
        }
        NodeType::Fullnode { .. } => {
            roles::fullnode::run_workload(
                &mut router,
                workload,
                &node_config.known_peers,
                &mut metrics,
                &maybe_otel_meter,
                &mut gauge_cache,
                &mut maybe_metrics_ticker,
                &process_start,
            )
            .await
        }
    }
}

fn generate_config(
    output_path: String,
    validators: usize,
    bootnodes: usize,
    fullnodes: usize,
    dedicated_fullnodes: usize,
    prioritized_fullnodes: usize,
    base_ip: String,
    base_port: u16,
) -> Result<()> {
    let base_ip_addr: Ipv4Addr = base_ip
        .parse()
        .map_err(|_| eyre::eyre!("invalid ip address: {}", base_ip))?;

    let mut allocator = create_allocator(base_ip_addr, base_port);
    println!("Address allocation mode: {}", allocator.mode_name());

    let mut bootnodes_cfg = Vec::with_capacity(bootnodes);
    for i in 0..bootnodes {
        let ikm = (i as u32).to_le_bytes();
        let keypair = KeyPair::from_ikm(&ikm)?;
        let pubkey = keypair.pubkey();
        let pubkey_bytes = pubkey.bytes();
        let privkey = keypair.privkey_view().to_string();

        bootnodes_cfg.push(BootnodeConfig {
            public_key: hex::encode(pubkey_bytes),
            private_key: privkey,
            tcp_addr: SocketAddrV4::new(allocator.ip(), allocator.tcp_port()),
            udp_addr: SocketAddrV4::new(allocator.ip(), allocator.udp_port()),
            authenticated_udp_addr: SocketAddrV4::new(allocator.ip(), allocator.auth_udp_port()),
        });
        allocator.advance();
    }

    let mut validators_cfg = Vec::with_capacity(validators);
    for i in 0..validators {
        let ikm = ((bootnodes + i) as u32).to_le_bytes();
        let keypair = KeyPair::from_ikm(&ikm)?;
        let pubkey = keypair.pubkey();
        let pubkey_bytes = pubkey.bytes();
        let privkey = keypair.privkey_view().to_string();

        validators_cfg.push(ValidatorConfig {
            public_key: hex::encode(pubkey_bytes),
            private_key: privkey,
            tcp_addr: SocketAddrV4::new(allocator.ip(), allocator.tcp_port()),
            udp_addr: SocketAddrV4::new(allocator.ip(), allocator.udp_port()),
            authenticated_udp_addr: SocketAddrV4::new(allocator.ip(), allocator.auth_udp_port()),
        });
        allocator.advance();
    }

    let total_fullnodes = fullnodes + dedicated_fullnodes + prioritized_fullnodes;
    let mut fullnodes_cfg = Vec::with_capacity(total_fullnodes);

    for i in 0..dedicated_fullnodes {
        let ikm = ((bootnodes + validators + i) as u32).to_le_bytes();
        let keypair = KeyPair::from_ikm(&ikm)?;
        let pubkey = keypair.pubkey();
        let pubkey_bytes = pubkey.bytes();
        let privkey = keypair.privkey_view().to_string();

        fullnodes_cfg.push(FullnodeConfig {
            public_key: hex::encode(pubkey_bytes),
            private_key: privkey,
            tcp_addr: SocketAddrV4::new(allocator.ip(), allocator.tcp_port()),
            udp_addr: SocketAddrV4::new(allocator.ip(), allocator.udp_port()),
            authenticated_udp_addr: SocketAddrV4::new(allocator.ip(), allocator.auth_udp_port()),
            dedicated: true,
            prioritized: false,
        });
        allocator.advance();
    }

    for i in 0..prioritized_fullnodes {
        let ikm = ((bootnodes + validators + dedicated_fullnodes + i) as u32).to_le_bytes();
        let keypair = KeyPair::from_ikm(&ikm)?;
        let pubkey = keypair.pubkey();
        let pubkey_bytes = pubkey.bytes();
        let privkey = keypair.privkey_view().to_string();

        fullnodes_cfg.push(FullnodeConfig {
            public_key: hex::encode(pubkey_bytes),
            private_key: privkey,
            tcp_addr: SocketAddrV4::new(allocator.ip(), allocator.tcp_port()),
            udp_addr: SocketAddrV4::new(allocator.ip(), allocator.udp_port()),
            authenticated_udp_addr: SocketAddrV4::new(allocator.ip(), allocator.auth_udp_port()),
            dedicated: false,
            prioritized: true,
        });
        allocator.advance();
    }

    for i in 0..fullnodes {
        let ikm = ((bootnodes + validators + dedicated_fullnodes + prioritized_fullnodes + i)
            as u32)
            .to_le_bytes();
        let keypair = KeyPair::from_ikm(&ikm)?;
        let pubkey = keypair.pubkey();
        let pubkey_bytes = pubkey.bytes();
        let privkey = keypair.privkey_view().to_string();

        fullnodes_cfg.push(FullnodeConfig {
            public_key: hex::encode(pubkey_bytes),
            private_key: privkey,
            tcp_addr: SocketAddrV4::new(allocator.ip(), allocator.tcp_port()),
            udp_addr: SocketAddrV4::new(allocator.ip(), allocator.udp_port()),
            authenticated_udp_addr: SocketAddrV4::new(allocator.ip(), allocator.auth_udp_port()),
            dedicated: false,
            prioritized: false,
        });
        allocator.advance();
    }

    let cluster_config = ClusterConfig {
        cluster: ClusterInfo {
            name: "test-cluster".to_string(),
        },
        validators: validators_cfg,
        bootnodes: bootnodes_cfg,
        fullnodes: fullnodes_cfg,
        workload: WorkloadConfig::default(),
    };

    let toml_str = toml::to_string_pretty(&cluster_config)?;
    std::fs::write(&output_path, toml_str)?;

    let total_nodes = validators + bootnodes + total_fullnodes;
    println!(
        "Generated cluster configuration with {} nodes at {}",
        total_nodes, output_path
    );
    println!("  Bootnodes: {}", bootnodes);
    println!("  Validators: {}", validators);
    println!("  Dedicated Fullnodes: {}", dedicated_fullnodes);
    println!("  Prioritized Fullnodes: {}", prioritized_fullnodes);
    println!("  Standard Fullnodes: {}", fullnodes);

    Ok(())
}
