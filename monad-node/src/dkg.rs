use std::path::Path;

use alloy_consensus::TxEnvelope;
use monad_chain_config::ChainConfig;
use monad_crypto::certificate_signature::CertificateSignaturePubKey;
use monad_dkg_runner::{new_triedb_runner, DkgChainConfig, DkgError, DkgRunner};
use monad_ethcall::ffi::PoolConfig;
use monad_execution_state_read::ExecutionStateReadThreadClient;
use monad_execution_state_read_cache::ExecutionStateReadCache;
use monad_node_config::{SignatureCollectionType, SignatureType};
use monad_triedb_utils::TriedbReader;
use monad_types::{NodeId, SeqNum};

use crate::state::NodeState;

const DKG_ETH_CALL_QUEUE_LIMIT: u32 = 8;
const DKG_ETH_CALL_TIMEOUT_SECS: u32 = 30;
const DKG_ETH_CALL_NODE_CACHE_BYTES: u64 = 50 << 20;

pub fn build_state_reader(
    node: &NodeState,
    execution_delay: SeqNum,
) -> ExecutionStateReadThreadClient<SignatureType, SignatureCollectionType> {
    let triedb_path = node.triedb_path.clone();
    let dkg_enabled = node.node_config.dkg.enabled;
    ExecutionStateReadThreadClient::new(move || {
        let triedb = if dkg_enabled {
            let pool = PoolConfig {
                num_threads: 1,
                num_fibers: 1,
                timeout_sec: DKG_ETH_CALL_TIMEOUT_SECS,
                queue_limit: DKG_ETH_CALL_QUEUE_LIMIT,
            };
            TriedbReader::try_new_with_eth_call(
                &triedb_path,
                pool,
                pool,
                pool,
                1,
                DKG_ETH_CALL_NODE_CACHE_BYTES,
            )
        } else {
            TriedbReader::try_new(&triedb_path)
        }
        .expect("triedb should exist in path");
        ExecutionStateReadCache::new(triedb, execution_delay)
    })
}

pub fn build_runner(
    node: &NodeState,
    self_id: NodeId<CertificateSignaturePubKey<SignatureType>>,
    storage_root: &Path,
    state_read: ExecutionStateReadThreadClient<SignatureType, SignatureCollectionType>,
    execution_delay: SeqNum,
) -> Result<Option<(DkgRunner<SignatureType>, flume::Receiver<TxEnvelope>)>, DkgError> {
    if !node.node_config.dkg.enabled {
        return Ok(None);
    }

    let config = &node.node_config.dkg;
    let mut chain_config = DkgChainConfig::new(
        node.secp256k1_identity.privkey_view().to_bytes(),
        config.contract_address,
        node.chain_config.chain_id(),
    );
    chain_config.gas_limit = config.tx_gas_limit;
    chain_config.max_priority_fee_per_gas = config.tx_max_priority_fee_per_gas;

    new_triedb_runner(
        self_id,
        storage_root.to_path_buf(),
        chain_config,
        state_read,
        execution_delay,
    )
    .map(Some)
}
