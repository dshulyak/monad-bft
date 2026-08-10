use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use dkg_core::{Record, RecordId};
use dkg_protocol::{chain::adapter, ChainCall, ChainEvent, DkgEnginePhase};
use monad_crypto::{
    certificate_signature::{CertificateKeyPair, CertificateSignaturePubKey},
    NopKeyPair, NopSignature,
};
use monad_types::{Epoch, NodeId};
use proptest::prelude::*;

use super::*;
use crate::{test_registered_key_material, DeliveryOutbound};

const NODE_COUNT: usize = 4;
const TEST_EPOCH: Epoch = Epoch(12);
const DEFAULT_RECOVERY_SCHEDULES: u32 = 16;
const PROPERTY_OUTPUT_COUNT: usize = 2;
const QUIET_RECOVERY_STEPS: usize = 1_000;
const MODEL_STEP: Duration = Duration::from_secs(31);

#[derive(Clone, Debug)]
enum ModelStep {
    Exchange,
    Stop { node_mask: u8, missed_steps: u8 },
}

struct NetworkMessage {
    source: usize,
    outbound: DeliveryOutbound<NopSignature>,
}

struct ChainMessage {
    target: usize,
    input: ChainInput,
}

enum ChainInput {
    Event(Box<ChainEvent>),
    RecoveryComplete,
}

struct NodeRuntime {
    session: DkgSession<NopSignature>,
}

struct ModelNode {
    id: NodeId<CertificateSignaturePubKey<NopSignature>>,
    storage_root: PathBuf,
    runtime: Option<NodeRuntime>,
    stopped_steps: u8,
}

struct ContractModel {
    events: Vec<ChainEvent>,
    records: BTreeSet<(Vec<u8>, Vec<u8>)>,
    result_epochs: BTreeSet<u64>,
    party_count: usize,
}

impl ContractModel {
    fn post(&mut self, call: ChainCall) -> Option<ChainEvent> {
        if let ChainCall::PostDkgResult { qc } = &call {
            if !self.result_epochs.insert(qc.epoch.0) {
                return None;
            }
        }
        if matches!(call, ChainCall::PostRegistration { .. }) {
            return None;
        }
        let (key, bytes) = adapter::encode_call(&call);
        if !self.records.insert((key.0.clone(), bytes.clone())) {
            return None;
        }
        let record = Record {
            id: RecordId(self.events.len() as u64),
            key,
            bytes,
        };
        let event = adapter::decode_record(&record, self.party_count)
            .expect("session emitted a decodable contract record");
        self.events.push(event.clone());
        Some(event)
    }

    fn has_result(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, ChainEvent::DkgResultRecorded { .. }))
    }
}

struct RecoveryModel {
    validators: Vec<NodeId<CertificateSignaturePubKey<NopSignature>>>,
    voting_weights: Vec<NativeVotingWeight>,
    nodes: Vec<ModelNode>,
    network: VecDeque<NetworkMessage>,
    chain_messages: VecDeque<ChainMessage>,
    chain: ContractModel,
    output_count: usize,
    now: Instant,
    steps: usize,
}

struct RecoveryModelBuilder<'a> {
    root: &'a Path,
    voting_weights: Vec<u64>,
    output_count: usize,
}

impl<'a> RecoveryModelBuilder<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            voting_weights: vec![1; NODE_COUNT],
            output_count: DKG_OUTPUT_COUNT.get(),
        }
    }

    fn node_count(mut self, node_count: usize) -> Self {
        self.voting_weights = vec![1; node_count];
        self
    }

    fn voting_weights(mut self, voting_weights: Vec<u64>) -> Self {
        self.voting_weights = voting_weights;
        self
    }

    fn output_count(mut self, output_count: usize) -> Self {
        self.output_count = output_count;
        self
    }

    fn build(self) -> RecoveryModel {
        let Self {
            root,
            voting_weights,
            output_count,
        } = self;
        let voting_weights = voting_weights
            .into_iter()
            .map(NativeVotingWeight::new)
            .collect::<Vec<_>>();
        let node_count = voting_weights.len();
        let mut validators = test_validators(node_count as u8);
        validators.sort();
        let mut nodes = validators
            .iter()
            .enumerate()
            .map(|(index, id)| ModelNode {
                id: *id,
                storage_root: root.join(format!("node-{index}")),
                runtime: None,
                stopped_steps: 0,
            })
            .collect::<Vec<_>>();
        for node in &mut nodes {
            node.runtime = Some(start_runtime(
                node.id,
                &validators,
                &voting_weights,
                &node.storage_root,
                output_count,
            ));
        }
        let chain_messages = (0..nodes.len())
            .map(|target| ChainMessage {
                target,
                input: ChainInput::RecoveryComplete,
            })
            .collect();
        RecoveryModel {
            validators,
            voting_weights,
            nodes,
            network: VecDeque::new(),
            chain_messages,
            chain: ContractModel {
                events: Vec::new(),
                records: BTreeSet::new(),
                result_epochs: BTreeSet::new(),
                party_count: node_count,
            },
            output_count,
            now: Instant::now(),
            steps: 0,
        }
    }
}

impl RecoveryModel {
    fn new(root: &Path) -> Self {
        RecoveryModelBuilder::new(root).build()
    }

    fn apply(&mut self, step: &ModelStep) {
        if let ModelStep::Stop {
            node_mask,
            missed_steps,
        } = *step
        {
            self.stop(node_mask, missed_steps);
        }
        self.exchange_step();
    }

    fn stop(&mut self, node_mask: u8, missed_steps: u8) {
        let missed_steps = missed_steps.max(1);
        for index in 0..self.nodes.len() {
            if node_mask & (1 << index) == 0 {
                continue;
            }
            let node = &mut self.nodes[index];
            node.runtime = None;
            node.stopped_steps = node.stopped_steps.max(missed_steps);
        }
    }

    fn exchange_step(&mut self) {
        self.collect_outputs();
        self.collect_retries();
        self.drain_network_queue();
        self.drain_chain_queue();
        self.steps += 1;
        self.now += MODEL_STEP;
        self.advance_stopped_nodes();
    }

    fn collect_outputs(&mut self) {
        let node_count = self.nodes.len();
        for source in 0..self.nodes.len() {
            let Some(runtime) = &mut self.nodes[source].runtime else {
                continue;
            };
            for effect in runtime.session.take_effects() {
                match effect {
                    SessionEffect::Network(outbound) | SessionEffect::Acknowledgement(outbound) => {
                        self.network.push_back(NetworkMessage { source, outbound });
                    }
                    SessionEffect::Chain(call) => {
                        let Some(event) = self.chain.post(*call) else {
                            continue;
                        };
                        self.chain_messages
                            .extend((0..node_count).map(|target| ChainMessage {
                                target,
                                input: ChainInput::Event(Box::new(event.clone())),
                            }));
                    }
                }
            }
        }
    }

    fn collect_retries(&mut self) {
        for node in &mut self.nodes {
            let Some(runtime) = &mut node.runtime else {
                continue;
            };
            runtime.session.handle_timer(self.now).unwrap();
        }
    }

    fn drain_network_queue(&mut self) {
        while let Some(message) = self.network.pop_front() {
            let target = self.node_index(message.outbound.to);
            let Some(runtime) = &mut self.nodes[target].runtime else {
                continue;
            };
            let envelope: DeliveryEnvelope = message.outbound.payload.as_ref().try_into().unwrap();
            runtime
                .session
                .handle_network_message(self.validators[message.source], envelope.message)
                .unwrap();
        }
    }

    fn drain_chain_queue(&mut self) {
        while let Some(message) = self.chain_messages.pop_front() {
            let Some(runtime) = &mut self.nodes[message.target].runtime else {
                continue;
            };
            match message.input {
                ChainInput::Event(event) => runtime.session.handle_chain_event(*event).unwrap(),
                ChainInput::RecoveryComplete => runtime.session.finish_chain_recovery().unwrap(),
            }
        }
    }

    fn advance_stopped_nodes(&mut self) {
        for target in 0..self.nodes.len() {
            let node = &mut self.nodes[target];
            if node.stopped_steps == 0 {
                continue;
            }
            node.stopped_steps -= 1;
            if node.stopped_steps == 0 {
                self.restart(target);
            }
        }
    }

    fn restart(&mut self, target: usize) {
        let node = &mut self.nodes[target];
        node.runtime = Some(start_runtime(
            node.id,
            &self.validators,
            &self.voting_weights,
            &node.storage_root,
            self.output_count,
        ));
        self.chain_messages
            .extend(self.chain.events.iter().cloned().map(|event| ChainMessage {
                target,
                input: ChainInput::Event(Box::new(event)),
            }));
        self.chain_messages.push_back(ChainMessage {
            target,
            input: ChainInput::RecoveryComplete,
        });
    }

    fn run_to_completion(&mut self) {
        if self.completed() {
            return;
        }
        for _ in 0..QUIET_RECOVERY_STEPS {
            self.exchange_step();
            if self.completed() {
                return;
            }
        }
        let phases = self
            .nodes
            .iter()
            .map(|node| {
                node.runtime
                    .as_ref()
                    .map(|runtime| runtime.session.engine.phase())
            })
            .collect::<Vec<_>>();
        panic!(
            "DKG did not recover: steps={} phases={phases:?} stopped={:?} chain_events={:?} network_queue={} chain_queue={}",
            self.steps,
            self.nodes
                .iter()
                .map(|node| node.stopped_steps)
                .collect::<Vec<_>>(),
            self.chain
                .events
                .iter()
                .map(|event| match event {
                    ChainEvent::PCQc { qc, .. } => format!("pc:{}", qc.dealer.0),
                    ChainEvent::BveQcFinalized { qc, .. } => format!("bve:{}", qc.dealer.0),
                    ChainEvent::DkgResultRecorded { .. } => "result".to_owned(),
                })
                .collect::<Vec<_>>(),
            self.network.len(),
            self.chain_messages.len()
        );
    }

    fn completed(&self) -> bool {
        self.chain.has_result()
            && self.nodes.iter().all(|node| {
                node.runtime.as_ref().is_some_and(|runtime| {
                    runtime.session.engine.phase() == DkgEnginePhase::Complete
                })
            })
    }

    fn node_index(&self, id: NodeId<CertificateSignaturePubKey<NopSignature>>) -> usize {
        self.validators
            .iter()
            .position(|candidate| *candidate == id)
            .expect("DKG command targets a validator")
    }
}

#[test]
fn one_to_three_nodes_complete_without_byzantine_tolerance() {
    for node_count in 1..=3 {
        let directory = tempfile::tempdir().unwrap();
        RecoveryModelBuilder::new(directory.path())
            .node_count(node_count)
            .build()
            .run_to_completion();
    }
}

#[test]
fn asymmetric_voting_weight_uses_independent_quantized_domains() {
    let directory = tempfile::tempdir().unwrap();
    RecoveryModelBuilder::new(directory.path())
        .voting_weights(vec![4, 3, 2, 1])
        .build()
        .run_to_completion();
}

#[test]
fn seven_equal_stake_nodes_complete_with_quantized_dealers() {
    let directory = tempfile::tempdir().unwrap();
    RecoveryModelBuilder::new(directory.path())
        .node_count(7)
        .build()
        .run_to_completion();
}

fn recovery_step() -> impl Strategy<Value = ModelStep> {
    prop_oneof![
        15 => Just(ModelStep::Exchange),
        1 => (1_u8..16, 1_u8..6).prop_map(|(node_mask, missed_steps)| ModelStep::Stop {
            node_mask,
            missed_steps,
        }),
    ]
}

fn recovery_schedule() -> impl Strategy<Value = Vec<ModelStep>> {
    prop::collection::vec(recovery_step(), 32..128).prop_filter(
        "schedule must contain a memory-loss event",
        |steps| {
            steps
                .iter()
                .any(|step| matches!(step, ModelStep::Stop { .. }))
        },
    )
}

fn recovery_proptest_config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = DEFAULT_RECOVERY_SCHEDULES;
    }
    config
}

proptest! {
    #![proptest_config(recovery_proptest_config())]

    #[test]
    fn four_nodes_finish_after_random_memory_loss(schedule in recovery_schedule()) {
        let directory = tempfile::tempdir().unwrap();
        let mut model = RecoveryModelBuilder::new(directory.path())
            .output_count(PROPERTY_OUTPUT_COUNT)
            .build();
        for step in &schedule {
            model.apply(step);
        }
        model.run_to_completion();
    }
}

#[test]
fn four_nodes_recover_when_one_starts_late() {
    let directory = tempfile::tempdir().unwrap();
    let mut model = RecoveryModel::new(directory.path());
    model.nodes[0].runtime = None;
    fs::remove_dir_all(&model.nodes[0].storage_root).unwrap();
    model.nodes[0].stopped_steps = 5;
    model.run_to_completion();
}

#[test]
fn fourth_node_recovers_after_other_nodes_finish() {
    let directory = tempfile::tempdir().unwrap();
    let mut model = RecoveryModel::new(directory.path());
    model.nodes[0].runtime = None;
    fs::remove_dir_all(&model.nodes[0].storage_root).unwrap();

    for _ in 0..QUIET_RECOVERY_STEPS {
        model.exchange_step();
        if model.chain.has_result()
            && model.nodes[1..].iter().all(|node| {
                node.runtime.as_ref().is_some_and(|runtime| {
                    runtime.session.engine.phase() == DkgEnginePhase::Complete
                })
            })
        {
            break;
        }
    }
    assert!(
        model.chain.has_result(),
        "three live nodes did not finalize DKG"
    );

    model.restart(0);
    model.run_to_completion();
}

#[test]
fn four_nodes_recover_after_late_memory_loss() {
    let directory = tempfile::tempdir().unwrap();
    let mut model = RecoveryModel::new(directory.path());
    for _ in 0..27 {
        model.exchange_step();
    }
    model.stop(0b0011, 1);
    model.run_to_completion();
}

fn start_runtime(
    self_id: NodeId<CertificateSignaturePubKey<NopSignature>>,
    validators: &[NodeId<CertificateSignaturePubKey<NopSignature>>],
    voting_weights: &[NativeVotingWeight],
    storage_root: &Path,
    output_count: usize,
) -> NodeRuntime {
    let mapping = DkgPeerMap::<NopSignature>::new_ordered(validators.to_vec()).unwrap();
    let self_party = mapping.party_id(&self_id).unwrap();
    let (mut recovery_wal, mut recovery_state) = RecoveryWal::open(
        storage_root,
        TEST_EPOCH,
        RecoveryWalConfig {
            preallocate_bytes: 0,
            max_epochs: 2,
        },
    )
    .unwrap();
    let engine_seed = recovery_state
        .load_or_create_engine_seed(&mut recovery_wal)
        .unwrap();
    let (local_keys, parties) = test_registered_key_material(
        self_party,
        validators.len(),
        TEST_EPOCH,
        voting_weights.iter().copied(),
    );
    let session = DkgSession::new(SessionInit {
        epoch: TEST_EPOCH,
        self_party,
        mapping,
        parties,
        output_count: DkgOutputCount::new(output_count),
        engine_seed,
        local_keys,
        recovery_wal,
        recovery_state,
    })
    .unwrap();
    NodeRuntime { session }
}

fn test_validators(count: u8) -> Vec<NodeId<CertificateSignaturePubKey<NopSignature>>> {
    (0..count)
        .map(|seed| {
            let mut bytes = [seed.saturating_add(1); 32];
            NodeId::new(NopKeyPair::from_bytes(&mut bytes).unwrap().pubkey())
        })
        .collect()
}
