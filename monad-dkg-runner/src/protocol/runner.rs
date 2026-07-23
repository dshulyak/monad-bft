use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    mem,
    time::Instant,
};

use bytes::Bytes;
use dkg_core::{CoreInput, PartyId, RecordId, RuntimeCommand};
use dkg_protocol::{
    ChainCall, ChainEvent, DkgEngineError, DkgEnginePhase, DkgInput, DkgMessage, DkgMessageId,
    DkgMessageIdentity, DkgMessageKey, DkgMessageKind,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::engine::{build_engine, EngineBuildError, ResearchEngine, DKG_OUTPUT_COUNT};
use crate::{
    chain::chain_event_kind,
    session::{DkgRegisteredKeyMaterial, DkgSessionConfig},
    storage::{
        DkgMessageStore, EngineSeed, IncomingMessageRecord, IncomingStatus, MessageStoreError,
        OutgoingMessageRecord, RecoveryState, RecoveryWal, RecoveryWalConfig, RecoveryWalError,
    },
    transport::{
        delivery_abort_group_for_peer_payload, DeliveryAbortGroup, DeliveryEngine, DeliveryInbound,
        DeliveryOutbound, DkgManagerCommand, DkgSend,
    },
    DkgError,
};

struct DkgPeerMap<ST: CertificateSignatureRecoverable> {
    by_member: BTreeMap<NodeId<CertificateSignaturePubKey<ST>>, PartyId>,
    members: Vec<NodeId<CertificateSignaturePubKey<ST>>>,
}

impl<ST: CertificateSignatureRecoverable> DkgPeerMap<ST> {
    fn new_ordered(
        members: Vec<NodeId<CertificateSignaturePubKey<ST>>>,
    ) -> Result<Self, NodeId<CertificateSignaturePubKey<ST>>> {
        let mut by_member = BTreeMap::new();
        for (index, member) in members.iter().copied().enumerate() {
            let party = PartyId(u32::try_from(index).expect("validator count fits in u32"));
            if by_member.insert(member, party).is_some() {
                return Err(member);
            }
        }
        Ok(Self { by_member, members })
    }

    fn party_id(&self, member: &NodeId<CertificateSignaturePubKey<ST>>) -> Option<PartyId> {
        self.by_member.get(member).copied()
    }

    fn member_id(&self, party: PartyId) -> Option<NodeId<CertificateSignaturePubKey<ST>>> {
        self.members.get(party.0 as usize).copied()
    }

    fn parties(&self) -> Vec<PartyId> {
        (0..self.members.len())
            .map(|party| PartyId(party as u32))
            .collect()
    }

    fn len(&self) -> usize {
        self.members.len()
    }
}

#[derive(Debug, Error)]
pub(crate) enum RunnerError {
    #[error(transparent)]
    EngineBuild(#[from] EngineBuildError),
    #[error(transparent)]
    RecoveryWal(#[from] RecoveryWalError),
    #[error(transparent)]
    MessageStore(#[from] MessageStoreError),
    #[error("research DKG engine {action} failed: {error:?}")]
    Engine {
        action: &'static str,
        error: DkgEngineError,
    },
    #[error("cannot {action} DKG delivery for unknown party {party}")]
    UnknownParty { action: &'static str, party: u32 },
    #[error("accepted DKG input conflicts with durable ingress")]
    DurableIngressConflict,
    #[error("self-generated DKG message conflicts with recovery WAL")]
    SelfGeneratedMessageConflict,
    #[error("conflicting finalized DKG chain record for ID {record_id}")]
    ConflictingChainRecord { record_id: u64 },
    #[error("send DKG chain submission failed: {0}")]
    ChainSubmissionChannel(#[source] Box<flume::SendError<DkgManagerCommand>>),
    #[error("transport-acknowledged DKG message has {actual} semantic keys, expected 1")]
    TransportAckKeyCount { actual: usize },
}

pub(crate) fn start<ST>(
    config: DkgSessionConfig<ST>,
    commands: flume::Sender<DkgManagerCommand>,
    wait_for_chain_recovery: bool,
) -> Result<Option<Runner<ST>>, DkgError>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    let DkgSessionConfig {
        epoch,
        self_id,
        validators,
        storage_root,
        key_material,
    } = config;
    let mapping =
        DkgPeerMap::<ST>::new_ordered(validators).map_err(|_| DkgError::DuplicateValidator)?;
    let Some(self_party) = mapping.party_id(&self_id) else {
        info!(?self_id, "not starting DKG runner for non-validator node");
        return Ok(None);
    };

    if mapping.len() < 4 {
        return Err(DkgError::InsufficientValidators {
            actual: mapping.len(),
            minimum: 4,
        });
    }
    let (mut recovery_wal, mut recovery_state) =
        RecoveryWal::open(&storage_root, epoch, RecoveryWalConfig::default())
            .map_err(|err| DkgError::operation("open DKG recovery WAL", err))?;
    let engine_seed = recovery_state
        .load_or_create_engine_seed(&mut recovery_wal)
        .map_err(|err| DkgError::operation("persist DKG engine seed", err))?;
    let mut runner = Runner::new(RunnerInit {
        epoch,
        self_party,
        mapping,
        engine_seed,
        key_material,
        recovery_wal,
        recovery_state,
        commands,
        wait_for_chain_recovery,
    })
    .map_err(|err| DkgError::operation("initialize DKG runner", err))?;
    runner
        .initialize()
        .map_err(|err| DkgError::operation("start DKG runner", err))?;
    Ok(Some(runner))
}

struct RunnerInit<ST>
where
    ST: CertificateSignatureRecoverable,
{
    epoch: Epoch,
    self_party: PartyId,
    mapping: DkgPeerMap<ST>,
    engine_seed: EngineSeed,
    key_material: DkgRegisteredKeyMaterial,
    recovery_wal: RecoveryWal,
    recovery_state: RecoveryState,
    commands: flume::Sender<DkgManagerCommand>,
    wait_for_chain_recovery: bool,
}

pub(crate) struct Runner<ST>
where
    ST: CertificateSignatureRecoverable,
{
    engine: ResearchEngine,
    epoch: Epoch,
    self_party: PartyId,
    mapping: DkgPeerMap<ST>,
    delivery: DeliveryEngine<ST>,
    delivery_outbound: Vec<DeliveryOutbound<ST>>,
    commands: flume::Sender<DkgManagerCommand>,
    pending_inputs: VecDeque<PendingEngineInput>,
    deferred_outgoing: Vec<OutgoingMessageRecord>,
    message_store: DkgMessageStore,
    chain_events: BTreeMap<RecordId, ChainEvent>,
    last_phase: DkgEnginePhase,
    awaiting_chain_recovery: bool,
    engine_started: bool,
}

enum PendingEngineInput {
    Peer(PendingPeerInput),
    Chain(ChainEvent),
}

struct PendingPeerInput {
    input: CoreInput<DkgMessage>,
    identity: DkgMessageIdentity,
    record: Option<IncomingMessageRecord>,
    acknowledge: bool,
}

impl<ST> Runner<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    pub(crate) fn next_timer(&self) -> Option<Instant> {
        self.delivery.next_timer()
    }

    pub(crate) fn take_delivery_outbound(&mut self) -> Vec<DeliveryOutbound<ST>> {
        mem::take(&mut self.delivery_outbound)
    }

    fn new(init: RunnerInit<ST>) -> Result<Self, RunnerError> {
        let parties = init.mapping.parties();
        let party_count = parties.len();
        let delivery =
            DeliveryEngine::with_inbound_validators(init.epoch, init.mapping.members.clone());
        let engine = build_engine(
            init.epoch,
            init.self_party,
            parties,
            init.key_material,
            init.engine_seed,
        )?;
        let max_ladder_level = DKG_OUTPUT_COUNT.trailing_zeros().into();
        let initial_phase = engine.phase();
        let message_store = DkgMessageStore::load(
            init.self_party,
            party_count,
            max_ladder_level,
            init.recovery_wal,
            init.recovery_state,
        );
        info!(
            epoch = init.epoch.0,
            party = init.self_party.0,
            party_count = init.mapping.len(),
            output_count = DKG_OUTPUT_COUNT,
            phase = ?initial_phase,
            "initialized DKG runner"
        );

        Ok(Self {
            engine,
            epoch: init.epoch,
            self_party: init.self_party,
            mapping: init.mapping,
            delivery,
            delivery_outbound: Vec::new(),
            commands: init.commands,
            pending_inputs: VecDeque::new(),
            deferred_outgoing: Vec::new(),
            message_store,
            chain_events: BTreeMap::new(),
            last_phase: initial_phase,
            awaiting_chain_recovery: init.wait_for_chain_recovery,
            engine_started: false,
        })
    }

    fn initialize(&mut self) -> Result<(), RunnerError> {
        let startup_incoming_messages = self.message_store.incoming_records();
        let startup_outgoing_messages = self.message_store.outgoing_records();
        self.replay_persisted_incoming_messages(startup_incoming_messages);
        if self.awaiting_chain_recovery {
            self.deferred_outgoing = startup_outgoing_messages;
            info!(
                pending_inputs = self.pending_inputs.len(),
                deferred_outgoing = self.deferred_outgoing.len(),
                "waiting for DKG chain recovery before starting engine"
            );
            return Ok(());
        }

        self.start_engine()?;
        self.drain_engine_inputs()?;
        self.replay_persisted_outgoing_messages(startup_outgoing_messages);
        self.log_phase_change();
        Ok(())
    }

    fn start_engine(&mut self) -> Result<(), RunnerError> {
        if self.engine_started {
            return Ok(());
        }
        let effects = self.engine.start().map_err(|error| RunnerError::Engine {
            action: "start",
            error,
        })?;
        self.engine_started = true;
        self.dispatch_effects(effects)
    }

    pub(crate) fn handle_network_message(
        &mut self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        message: Bytes,
    ) -> Result<(), RunnerError> {
        let Some(inbound) = self.delivery.handle_network_message(sender, message) else {
            return Ok(());
        };
        self.accept_delivery(inbound)?;
        self.settle()?;
        Ok(())
    }

    pub(crate) fn handle_timer(&mut self, now: Instant) -> Result<(), RunnerError> {
        self.delivery_outbound
            .extend(self.delivery.handle_timer(now));
        self.settle()
    }

    pub(crate) fn handle_chain_event(&mut self, event: ChainEvent) -> Result<(), RunnerError> {
        self.accept_chain_event(event)?;
        self.settle()
    }

    pub(crate) fn finish_chain_recovery(&mut self) -> Result<(), RunnerError> {
        self.complete_chain_recovery()?;
        self.settle()
    }

    fn settle(&mut self) -> Result<(), RunnerError> {
        if self.awaiting_chain_recovery {
            return Ok(());
        }
        self.drain_engine_inputs()
    }

    fn accept_delivery(&mut self, inbound: DeliveryInbound<ST>) -> Result<(), RunnerError> {
        match inbound {
            DeliveryInbound::Delivered { sender, payload } => {
                let from = self
                    .mapping
                    .party_id(&sender)
                    .expect("delivery engine validated DKG sender");
                self.handle_data_payload(from, payload)
            }
            DeliveryInbound::TransportAck { sender, key } => {
                let from = self
                    .mapping
                    .party_id(&sender)
                    .expect("delivery engine validated DKG acknowledgement");
                let Some(message_id) = self.message_store.complete_key(key, from)? else {
                    return Ok(());
                };
                self.complete_delivery(from, &message_id)
            }
        }
    }

    fn complete_chain_recovery(&mut self) -> Result<(), RunnerError> {
        if !self.awaiting_chain_recovery {
            return Ok(());
        }

        let (chain, peer) = mem::take(&mut self.pending_inputs)
            .into_iter()
            .partition(|input| matches!(input, PendingEngineInput::Chain(_)));
        self.pending_inputs = chain;
        self.drain_engine_inputs()?;
        self.start_engine()?;
        self.pending_inputs.extend(peer);
        self.drain_engine_inputs()?;
        self.awaiting_chain_recovery = false;
        let deferred_outgoing = mem::take(&mut self.deferred_outgoing);
        self.replay_persisted_outgoing_messages(deferred_outgoing);
        info!(
            phase = ?self.engine.phase(),
            "started DKG runner from synchronized chain state"
        );
        Ok(())
    }

    fn finish_inbound_delivery(
        &mut self,
        source: PartyId,
        transport_ack: Option<DkgMessageKey>,
    ) -> Result<(), RunnerError> {
        let Some(to) = self.mapping.member_id(source) else {
            return Err(RunnerError::UnknownParty {
                action: "finish inbound",
                party: source.0,
            });
        };
        self.delivery_outbound
            .extend(self.delivery.finish_inbound(to, transport_ack));
        Ok(())
    }

    fn complete_delivery(
        &mut self,
        target: PartyId,
        message_id: &DkgMessageId,
    ) -> Result<(), RunnerError> {
        let Some(peer) = self.mapping.member_id(target) else {
            return Err(RunnerError::UnknownParty {
                action: "complete outbound",
                party: target.0,
            });
        };
        self.delivery.complete(message_id, peer);
        Ok(())
    }

    fn complete_from_application(
        &mut self,
        identity: &DkgMessageIdentity,
    ) -> Result<(), RunnerError> {
        for (outgoing, target) in identity.completed_outgoing() {
            let Some(message_id) = self.message_store.complete_key(outgoing, target)? else {
                continue;
            };
            self.complete_delivery(target, &message_id)?;
        }
        Ok(())
    }

    fn handle_data_payload(&mut self, from: PartyId, payload: Bytes) -> Result<(), RunnerError> {
        let message = match DkgMessage::decode(payload.clone()) {
            Ok(message) => message,
            Err(err) => {
                warn!(
                    ?err,
                    from_party = from.0,
                    "rejected malformed typed DKG message"
                );
                return Ok(());
            }
        };
        let identity = match self.message_store.identity(from, self.self_party, &message) {
            Ok(identity) => identity,
            Err(err) => {
                warn!(
                    ?err,
                    from_party = from.0,
                    "rejected invalid typed DKG message identity"
                );
                return Ok(());
            }
        };
        let message_id = identity.message_id();
        let transport_ack = transport_ack_key(&identity)?;
        let record = IncomingMessageRecord {
            source: from,
            message_id: message_id.clone(),
            payload: payload.clone(),
        };
        match self.message_store.incoming_status(&record, &identity) {
            IncomingStatus::Duplicate => {
                self.finish_inbound_delivery(from, transport_ack)?;
                self.complete_from_application(&identity)?;
                debug!(
                    from_party = from.0,
                    message_id = ?message_id,
                    "finished previously accepted duplicate DKG inbound message"
                );
                return Ok(());
            }
            IncomingStatus::Conflict => {
                warn!(
                    from_party = from.0,
                    message_id = ?message_id,
                    "rejected conflicting DKG inbound message"
                );
                return Ok(());
            }
            IncomingStatus::New => {}
        }
        self.pending_inputs
            .push_back(PendingEngineInput::Peer(PendingPeerInput {
                input: CoreInput::new(from, message),
                identity,
                record: Some(record),
                acknowledge: true,
            }));
        Ok(())
    }

    fn drain_engine_inputs(&mut self) -> Result<(), RunnerError> {
        while let Some(input) = self.pending_inputs.pop_front() {
            let processed = match input {
                PendingEngineInput::Peer(peer) => self.process_peer_input(peer)?,
                PendingEngineInput::Chain(event) => {
                    let effects =
                        self.engine
                            .handle_event(DkgInput::Chain(event))
                            .map_err(|error| RunnerError::Engine {
                                action: "handle chain input",
                                error,
                            })?;
                    self.dispatch_effects(effects)?;
                    true
                }
            };
            if processed {
                self.log_phase_change();
            }
        }
        Ok(())
    }

    fn process_peer_input(&mut self, peer: PendingPeerInput) -> Result<bool, RunnerError> {
        let source = peer.input.source;
        let record = peer.record;
        let effects = match self.engine.handle_peer_event(peer.input) {
            Ok(effects) => effects,
            Err(DkgEngineError::PeerInput(reason)) => {
                if peer.acknowledge {
                    self.finish_inbound_delivery(source, None)?;
                }
                debug!(
                    ?reason,
                    source = source.0,
                    "DKG protocol rejected peer input"
                );
                return Ok(false);
            }
            Err(error) => {
                return Err(RunnerError::Engine {
                    action: "handle peer input",
                    error,
                })
            }
        };
        if let Some(record) = record {
            if self.message_store.accept_incoming(record, &peer.identity)?
                == IncomingStatus::Conflict
            {
                return Err(RunnerError::DurableIngressConflict);
            }
        }
        self.dispatch_effects(effects)?;
        if peer.acknowledge {
            self.finish_inbound_delivery(source, transport_ack_key(&peer.identity)?)?;
        }
        self.complete_from_application(&peer.identity)?;
        Ok(true)
    }

    fn dispatch_effects(
        &mut self,
        effects: Vec<dkg_protocol::DkgEffect>,
    ) -> Result<(), RunnerError> {
        for effect in effects {
            match effect {
                RuntimeCommand::Unicast { to, payload } => {
                    let abort_group =
                        delivery_abort_group_for_peer_payload(payload.kind(), self.self_party, to);
                    self.send_data_to_recipients([to], payload, abort_group)?;
                }
                RuntimeCommand::Multicast { payload } => {
                    let abort_group = delivery_abort_group_for_peer_payload(
                        payload.kind(),
                        self.self_party,
                        self.self_party,
                    );
                    if matches!(
                        payload.kind(),
                        DkgMessageKind::LowerConversion | DkgMessageKind::OpenPower
                    ) {
                        let identity = self.message_store.identity(
                            self.self_party,
                            self.self_party,
                            &payload,
                        )?;
                        let record = IncomingMessageRecord {
                            source: self.self_party,
                            message_id: identity.message_id(),
                            payload: payload.clone().into_bytes(),
                        };
                        match self.message_store.incoming_status(&record, &identity) {
                            IncomingStatus::New => {
                                self.pending_inputs.push_back(PendingEngineInput::Peer(
                                    PendingPeerInput {
                                        input: CoreInput::new(self.self_party, payload.clone()),
                                        identity,
                                        record: Some(record),
                                        acknowledge: false,
                                    },
                                ));
                            }
                            IncomingStatus::Duplicate => {}
                            IncomingStatus::Conflict => {
                                return Err(RunnerError::SelfGeneratedMessageConflict);
                            }
                        }
                    }
                    let self_party = self.self_party;
                    let recipients = self
                        .mapping
                        .parties()
                        .into_iter()
                        .filter(|party| *party != self_party);
                    self.send_data_to_recipients(recipients, payload, abort_group)?;
                }
                RuntimeCommand::PostToChain { call } => {
                    self.handle_chain_call(call)?;
                }
            }
        }
        Ok(())
    }

    fn replay_persisted_incoming_messages(&mut self, records: Vec<IncomingMessageRecord>) {
        for record in records {
            if self.mapping.member_id(record.source).is_none() {
                warn!(
                    source_party = record.source.0,
                    message_id = ?record.message_id,
                    "skipping persisted incoming DKG message from unknown party"
                );
                continue;
            }
            let message = match DkgMessage::decode(record.payload.clone()) {
                Ok(message) => message,
                Err(err) => {
                    warn!(?err, "skipping malformed persisted DKG message");
                    continue;
                }
            };
            let Ok(identity) =
                self.message_store
                    .identity(record.source, self.self_party, &message)
            else {
                continue;
            };
            self.pending_inputs
                .push_back(PendingEngineInput::Peer(PendingPeerInput {
                    input: CoreInput::new(record.source, message),
                    identity,
                    record: None,
                    acknowledge: record.source != self.self_party,
                }));
        }
    }

    fn accept_chain_event(&mut self, event: ChainEvent) -> Result<(), RunnerError> {
        let event_kind = chain_event_kind(&event);
        let record_id = event.record_id();
        if let Some(existing) = self.chain_events.get(&record_id) {
            if existing != &event {
                return Err(RunnerError::ConflictingChainRecord {
                    record_id: record_id.0,
                });
            }
            return Ok(());
        }
        self.chain_events.insert(record_id, event.clone());
        self.delivery
            .abort_group(delivery_abort_group_for_chain_event(&event));
        self.enqueue_chain_event(event);
        info!(
            epoch = self.epoch.0,
            event_kind,
            record_id = record_id.0,
            "accepted finalized DKG chain event"
        );
        Ok(())
    }

    fn replay_persisted_outgoing_messages(&mut self, records: Vec<OutgoingMessageRecord>) {
        for record in records {
            let message = match DkgMessage::decode(record.payload.clone()) {
                Ok(message) => message,
                Err(err) => {
                    warn!(?err, "skipping malformed persisted outgoing DKG message");
                    continue;
                }
            };
            for to in record.recipients {
                if self.message_store.is_complete(&record.message_id, to) {
                    debug!(
                        message_id = ?record.message_id,
                        target_party = to.0,
                        "skipping completed persisted outgoing DKG message"
                    );
                    continue;
                }
                self.queue_delivery_send(
                    record.message_id.clone(),
                    to,
                    record.payload.clone(),
                    delivery_abort_group_for_peer_payload(message.kind(), self.self_party, to),
                );
            }
        }
    }

    fn handle_chain_call(&mut self, call: ChainCall) -> Result<(), RunnerError> {
        if let Some(group) = delivery_abort_group_for_chain_call(&call) {
            self.delivery.abort_group(group);
        }
        self.commands
            .send(DkgManagerCommand {
                epoch: self.epoch,
                call,
            })
            .map_err(|err| RunnerError::ChainSubmissionChannel(Box::new(err)))?;
        Ok(())
    }

    fn enqueue_chain_event(&mut self, event: ChainEvent) {
        self.pending_inputs
            .push_back(PendingEngineInput::Chain(event));
    }

    fn send_data_to_recipients(
        &mut self,
        recipients: impl IntoIterator<Item = PartyId>,
        message: DkgMessage,
        abort_group: Option<DeliveryAbortGroup>,
    ) -> Result<(), RunnerError> {
        let recipients = recipients.into_iter().collect::<BTreeSet<_>>();
        if recipients.is_empty() {
            return Ok(());
        }
        if let Some(recipient) = recipients
            .iter()
            .find(|recipient| self.mapping.member_id(**recipient).is_none())
        {
            return Err(RunnerError::UnknownParty {
                action: "send to",
                party: recipient.0,
            });
        }
        let Some((message_id, payload)) = self
            .message_store
            .accept_outgoing(recipients.clone(), message)?
        else {
            return Ok(());
        };
        for recipient in recipients {
            self.queue_delivery_send(message_id.clone(), recipient, payload.clone(), abort_group);
        }
        Ok(())
    }

    fn queue_delivery_send(
        &mut self,
        message_id: DkgMessageId,
        to: PartyId,
        payload: Bytes,
        abort_group: Option<DeliveryAbortGroup>,
    ) {
        let Some(to_monad) = self.mapping.member_id(to) else {
            warn!(?to, "dropping DKG message to unknown party");
            return;
        };
        self.delivery_outbound.extend(self.delivery.send(
            DkgSend {
                message_id,
                to: to_monad,
                payload,
                abort_group,
            },
            Instant::now(),
        ));
    }

    fn log_phase_change(&mut self) {
        let phase = self.engine.phase();
        if phase == self.last_phase {
            return;
        }
        if phase == DkgEnginePhase::Complete {
            info!(
                epoch = self.epoch.0,
                party = self.self_party.0,
                "DKG runner completed"
            );
        }
        if self.last_phase == DkgEnginePhase::Vss && phase != DkgEnginePhase::Vss {
            self.delivery.abort_group(DeliveryAbortGroup::Vss);
        }
        if self.last_phase == DkgEnginePhase::Extraction && phase != DkgEnginePhase::Extraction {
            self.delivery.abort_group(DeliveryAbortGroup::Extraction);
            self.message_store.clear_ephemeral();
        }
        info!(
            from_phase = ?self.last_phase,
            to_phase = ?phase,
            "DKG phase changed"
        );
        self.last_phase = phase;
    }
}

fn transport_ack_key(identity: &DkgMessageIdentity) -> Result<Option<DkgMessageKey>, RunnerError> {
    if !identity.requires_transport_ack() {
        return Ok(None);
    }
    match identity.keys.as_slice() {
        [key] => Ok(Some(*key)),
        keys => Err(RunnerError::TransportAckKeyCount { actual: keys.len() }),
    }
}

fn delivery_abort_group_for_chain_call(call: &ChainCall) -> Option<DeliveryAbortGroup> {
    match call {
        ChainCall::PostPCQc { qc } => Some(DeliveryAbortGroup::CommitmentQc(qc.dealer)),
        ChainCall::PostBveQc { qc } => Some(DeliveryAbortGroup::BveQc(qc.dealer)),
        ChainCall::PostDkgResult { .. } => Some(DeliveryAbortGroup::DoneQc),
        ChainCall::PostRegistration { .. } => None,
    }
}

fn delivery_abort_group_for_chain_event(event: &ChainEvent) -> DeliveryAbortGroup {
    match event {
        ChainEvent::PCQc { qc, .. } => DeliveryAbortGroup::CommitmentQc(qc.dealer),
        ChainEvent::BveQcFinalized { qc, .. } => DeliveryAbortGroup::BveQc(qc.dealer),
        ChainEvent::DkgResultRecorded { .. } => DeliveryAbortGroup::DoneQc,
    }
}

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod recovery_tests;
