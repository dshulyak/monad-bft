//! Per-epoch DKG protocol runtime.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    mem,
    time::{Duration, Instant},
};

use alloy_primitives::U256;
use bytes::Bytes;
use dkg_core::{CoreInput, PartyId, RuntimeCommand, SessionId};
use dkg_crypto::{BlstBackend, K256SecpBackend};
use dkg_protocol::{
    ChainCall, ChainEvent, DkgDeliveryPolicy, DkgEngine, DkgEngineError, DkgEngineParams,
    DkgEnginePhase, DkgInput, DkgMessage, DkgMessageError, DkgMessageId, DkgMessageKey,
    DkgMessageKind, DkgRegisteredSetupError, DkgSetupContext, Epsilon, NativeVotingWeight,
    PartyRegistration, SecretKeys,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId, Stake};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::{
    chain::chain_event_kind,
    record::{
        DurableDkgMessage, DurableMessageError, EngineSeed, IncomingRecord, OutgoingRecord,
        RecoveryRecord,
    },
    recovery::{RecoveryState, RecoveryWal, RecoveryWalConfig, RecoveryWalError},
    registration::RegisteredSession,
    reliable::{EnqueueError, ObsolescencePolicy, RetryConfig, RetryScheduler},
    runner::{DeliveryEnvelope, DeliveryMessage, DeliveryOutbound},
    DkgError,
};

pub(crate) const WEI_PER_MON: u64 = 1_000_000_000_000_000_000;
const DKG_OUTPUT_COUNT: DkgOutputCount = DkgOutputCount::new(256);

#[derive(Clone, Copy)]
struct DkgOutputCount(usize);

impl DkgOutputCount {
    const fn new(count: usize) -> Self {
        assert!(count >= 2 && count.is_power_of_two());
        Self(count)
    }

    const fn get(self) -> usize {
        self.0
    }

    const fn max_ladder_level(self) -> u64 {
        self.0.trailing_zeros() as u64
    }
}

const DKG_RETRY: RetryConfig = RetryConfig::new(
    Duration::from_secs(2),
    Duration::from_secs(2),
    Duration::from_secs(30),
    Duration::from_millis(500),
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum DeliveryAbortGroup {
    Vss,
    Extraction,
    CommitmentQc(PartyId),
    BveQc(PartyId),
    DoneQc,
}

impl DeliveryAbortGroup {
    fn is_aborted_by(self, group: Self) -> bool {
        self == group
            || matches!(group, Self::Vss) && matches!(self, Self::CommitmentQc(_) | Self::BveQc(_))
    }
}

struct DkgObsolescence;

impl ObsolescencePolicy for DkgObsolescence {
    type Scope = DeliveryAbortGroup;
    type Evidence = DeliveryAbortGroup;

    fn obsolete(scope: &Self::Scope, evidence: &Self::Evidence) -> bool {
        scope.is_aborted_by(*evidence)
    }
}

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
pub(crate) enum SessionError {
    #[error("DKG validator stake does not round to a positive u64 MON weight")]
    InvalidVotingWeights,
    #[error("assemble registered DKG setup failed: {0}")]
    RegisteredSetup(#[from] DkgRegisteredSetupError),
    #[error("initialize research DKG engine failed: {0:?}")]
    EngineInitialization(DkgEngineError),
    #[error(transparent)]
    RecoveryWal(#[from] RecoveryWalError),
    #[error("classify DKG message failed: {0}")]
    Message(#[from] DkgMessageError),
    #[error("classify durable DKG message failed: {0}")]
    DurableMessage(#[from] DurableMessageError),
    #[error("research DKG engine {action} failed: {error:?}")]
    Engine {
        action: &'static str,
        error: DkgEngineError,
    },
    #[error("cannot {action} DKG delivery for unknown party {party}")]
    UnknownParty { action: &'static str, party: u32 },
    #[error("DKG sync messages must be unicast")]
    SyncMustBeUnicast,
    #[error("conflicting DKG reliable delivery")]
    ReliableDelivery(#[from] EnqueueError),
}

pub(crate) fn start<ST>(
    epoch: Epoch,
    self_id: NodeId<CertificateSignaturePubKey<ST>>,
    storage_root: &std::path::Path,
    registered: RegisteredSession<ST>,
) -> Result<Option<DkgSession<ST>>, DkgError>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    let mapping = DkgPeerMap::<ST>::new_ordered(
        registered
            .parties
            .iter()
            .map(|party| party.node_id)
            .collect(),
    )
    .map_err(|_| DkgError::DuplicateValidator)?;
    let Some(self_party) = mapping.party_id(&self_id) else {
        info!(?self_id, "not starting DKG session for non-validator node");
        return Ok(None);
    };

    let voting_weights = decode_voting_weights(
        &registered
            .parties
            .iter()
            .map(|party| party.stake)
            .collect::<Vec<_>>(),
    )
    .map_err(|err| DkgError::operation("decode DKG validator stakes", err))?;
    let (mut recovery_wal, mut recovery_state) =
        RecoveryWal::open(storage_root, epoch, RecoveryWalConfig::default())
            .map_err(|err| DkgError::operation("open DKG recovery WAL", err))?;
    let engine_seed = recovery_state
        .load_or_create_engine_seed(&mut recovery_wal)
        .map_err(|err| DkgError::operation("persist DKG engine seed", err))?;
    failpoint::failpoint!(
        name = "dkg.session.seed_persisted",
        description = "after the DKG engine seed is durable and before session construction",
    );
    let session = DkgSession::new(SessionInit {
        epoch,
        self_party,
        mapping,
        parties: registered
            .parties
            .into_iter()
            .zip(voting_weights)
            .map(|(party, voting_weight)| {
                RegisteredEngineParty::new(voting_weight, party.registration)
            })
            .collect(),
        output_count: DKG_OUTPUT_COUNT,
        engine_seed,
        local_keys: registered.local_keys,
        recovery_wal,
        recovery_state,
    })
    .map_err(|err| DkgError::operation("initialize DKG session", err))?;
    Ok(Some(session))
}

struct SessionInit<ST>
where
    ST: CertificateSignatureRecoverable,
{
    epoch: Epoch,
    self_party: PartyId,
    mapping: DkgPeerMap<ST>,
    parties: Vec<RegisteredEngineParty>,
    output_count: DkgOutputCount,
    engine_seed: EngineSeed,
    local_keys: SecretKeys<K256SecpBackend>,
    recovery_wal: RecoveryWal,
    recovery_state: RecoveryState,
}

pub(crate) struct RegisteredEngineParty {
    voting_weight: NativeVotingWeight,
    registration: PartyRegistration<K256SecpBackend>,
}

impl RegisteredEngineParty {
    pub(crate) fn new(
        voting_weight: NativeVotingWeight,
        registration: PartyRegistration<K256SecpBackend>,
    ) -> Self {
        Self {
            voting_weight,
            registration,
        }
    }
}

pub(crate) struct DkgSession<ST>
where
    ST: CertificateSignatureRecoverable,
{
    engine: DkgEngine<BlstBackend, K256SecpBackend>,
    epoch: Epoch,
    self_party: PartyId,
    party_count: usize,
    max_ladder_level: u64,
    mapping: DkgPeerMap<ST>,
    retries: RetryScheduler<
        NodeId<CertificateSignaturePubKey<ST>>,
        DkgMessageId,
        Bytes,
        DkgObsolescence,
    >,
    effects: Vec<SessionEffect<ST>>,
    pending_inputs: VecDeque<PendingEngineInput>,
    recovery_wal: RecoveryWal,
    recovery: SessionRecovery,
    last_phase: DkgEnginePhase,
}

enum SessionRecovery {
    AwaitingChain { outgoing: Vec<OutgoingRecord> },
    Complete,
}

pub(crate) enum SessionEffect<ST>
where
    ST: CertificateSignatureRecoverable,
{
    Network(DeliveryOutbound<ST>),
    Acknowledgement(DeliveryOutbound<ST>),
    Chain(Box<ChainCall>),
}

enum PendingEngineInput {
    Peer(PendingPeerInput),
    Chain(ChainEvent),
}

enum PendingPeerInput {
    WithoutWalWrite {
        input: CoreInput<DkgMessage>,
        acknowledgement: Option<DkgMessageId>,
    },
    PersistAfterApply {
        input: CoreInput<DkgMessage>,
        record: IncomingRecord,
        acknowledgement: Option<DkgMessageId>,
    },
}

impl<ST> DkgSession<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    pub(crate) fn next_timer(&self) -> Option<Instant> {
        self.retries.next_timer()
    }

    pub(crate) fn take_effects(&mut self) -> Vec<SessionEffect<ST>> {
        mem::take(&mut self.effects)
    }

    fn new(init: SessionInit<ST>) -> Result<Self, SessionError> {
        let party_count = init.mapping.len();
        let params = DkgEngineParams {
            output_count: init.output_count.get(),
            ..DkgEngineParams::default()
        };
        let output_count = init.output_count;
        let engine = build_engine(
            init.epoch,
            init.self_party,
            init.local_keys,
            init.parties,
            params,
            init.engine_seed.to_bytes(),
        )?;
        let max_ladder_level = output_count.max_ladder_level();
        let initial_phase = engine.phase();
        let RecoveryState {
            outgoing: recovered_outgoing,
            incoming: recovered_incoming,
            ..
        } = init.recovery_state;
        let recovered_outgoing_count = recovered_outgoing.len();
        info!(
            epoch = init.epoch.0,
            party = init.self_party.0,
            party_count = init.mapping.len(),
            output_count = output_count.get(),
            phase = ?initial_phase,
            "initialized DKG session"
        );

        let mut session = Self {
            engine,
            epoch: init.epoch,
            self_party: init.self_party,
            party_count,
            max_ladder_level,
            mapping: init.mapping,
            retries: RetryScheduler::new(DKG_RETRY),
            effects: Vec::new(),
            pending_inputs: VecDeque::new(),
            recovery_wal: init.recovery_wal,
            recovery: SessionRecovery::AwaitingChain {
                outgoing: recovered_outgoing,
            },
            last_phase: initial_phase,
        };
        session.replay_persisted_incoming_messages(recovered_incoming);
        info!(
            pending_inputs = session.pending_inputs.len(),
            recovered_outgoing = recovered_outgoing_count,
            "waiting for DKG chain recovery before starting engine"
        );
        Ok(session)
    }

    pub(crate) fn handle_network_message(
        &mut self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        message: DeliveryMessage,
    ) -> Result<(), SessionError> {
        let Some(from) = self.mapping.party_id(&sender) else {
            warn!(
                epoch = self.epoch.0,
                ?sender,
                "dropping DKG delivery from non-validator"
            );
            return Ok(());
        };
        match message {
            DeliveryMessage::Data {
                message_id,
                payload,
            } => self.handle_data_payload(from, payload, Some(message_id))?,
            DeliveryMessage::Unacknowledged(payload) => {
                self.handle_data_payload(from, payload, None)?
            }
            DeliveryMessage::Ack(message_id) => {
                self.retries.acknowledge(&message_id, sender);
            }
        }
        self.settle()?;
        Ok(())
    }

    pub(crate) fn handle_timer(&mut self, now: Instant) -> Result<usize, SessionError> {
        let retries = self.retries.retry_due(now);
        let count = retries.len();
        self.effects.extend(
            retries
                .into_iter()
                .map(|send| SessionEffect::Network(send.into())),
        );
        self.settle()?;
        Ok(count)
    }

    pub(crate) fn pending_retry_count(&self) -> usize {
        self.retries.pending_count()
    }

    pub(crate) fn handle_chain_event(&mut self, event: ChainEvent) -> Result<(), SessionError> {
        self.accept_chain_event(event)?;
        self.settle()
    }

    pub(crate) fn finish_chain_recovery(&mut self) -> Result<(), SessionError> {
        self.complete_chain_recovery()?;
        self.settle()
    }

    fn settle(&mut self) -> Result<(), SessionError> {
        if matches!(self.recovery, SessionRecovery::AwaitingChain { .. }) {
            return Ok(());
        }
        self.drain_engine_inputs()
    }

    fn complete_chain_recovery(&mut self) -> Result<(), SessionError> {
        if matches!(self.recovery, SessionRecovery::Complete) {
            return Ok(());
        }

        let (chain, peer) = mem::take(&mut self.pending_inputs)
            .into_iter()
            .partition(|input| matches!(input, PendingEngineInput::Chain(_)));
        self.pending_inputs = chain;
        self.drain_engine_inputs()?;
        // Chain evidence is applied before recovery so the scheduler discards
        // obsolete WAL entries as they are restored.
        let SessionRecovery::AwaitingChain { outgoing } = &mut self.recovery else {
            unreachable!("checked recovery state above")
        };
        let recovered_outgoing = mem::take(outgoing);
        self.restore_persisted_outgoing_messages(recovered_outgoing)?;
        let effects = self.engine.start().map_err(|error| SessionError::Engine {
            action: "start",
            error,
        })?;
        // Once start succeeds, recovery must not start the same engine twice if
        // dispatching one of its initial effects fails.
        self.recovery = SessionRecovery::Complete;
        // Recovered inputs must precede start effects that loop back locally.
        // Otherwise every restart would persist the regenerated local message
        // once more before the replay taught the engine that it is a duplicate.
        self.pending_inputs.extend(peer);
        self.dispatch_effects(effects)?;
        self.drain_engine_inputs()?;
        info!(
            phase = ?self.engine.phase(),
            "started DKG session from synchronized chain state"
        );
        Ok(())
    }

    fn handle_data_payload(
        &mut self,
        from: PartyId,
        payload: Bytes,
        acknowledgement: Option<DkgMessageId>,
    ) -> Result<(), SessionError> {
        let message = match DkgMessage::decode(payload) {
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
        let identity = match message.identity(
            from,
            self.self_party,
            self.party_count,
            self.max_ladder_level,
        ) {
            Ok(identity) => identity,
            Err(err) => {
                warn!(
                    ?err,
                    from_party = from.0,
                    "rejected invalid DKG message identity"
                );
                return Ok(());
            }
        };
        // Sync requests are completed by their application response, not their
        // transport ACK: otherwise a lost one-shot response would strand them.
        let requires_ack = requires_transport_ack(message.delivery_policy());
        if requires_ack != acknowledgement.is_some() {
            warn!(
                from_party = from.0,
                kind = ?message.kind(),
                "rejected DKG message with inconsistent delivery policy"
            );
            return Ok(());
        }
        if acknowledgement.as_ref().is_some_and(|message_id| {
            !identity
                .keys
                .iter()
                .all(|key| message_id.keys().contains(key))
        }) {
            warn!(
                from_party = from.0,
                kind = ?message.kind(),
                "rejected DKG message with inconsistent delivery ID"
            );
            return Ok(());
        }
        if message.kind().is_sync() {
            self.pending_inputs.push_back(PendingEngineInput::Peer(
                PendingPeerInput::WithoutWalWrite {
                    input: CoreInput::new(from, message),
                    acknowledgement,
                },
            ));
            return Ok(());
        }
        let record = IncomingRecord {
            source: from,
            message: DurableDkgMessage::try_from(message.clone())?,
        };
        self.pending_inputs.push_back(PendingEngineInput::Peer(
            PendingPeerInput::PersistAfterApply {
                input: CoreInput::new(from, message),
                record,
                acknowledgement,
            },
        ));
        Ok(())
    }

    fn drain_engine_inputs(&mut self) -> Result<(), SessionError> {
        while let Some(input) = self.pending_inputs.pop_front() {
            let processed = match input {
                PendingEngineInput::Peer(peer) => self.process_peer_input(peer)?,
                PendingEngineInput::Chain(event) => {
                    let effects =
                        self.engine
                            .handle_event(DkgInput::Chain(event))
                            .map_err(|error| SessionError::Engine {
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

    fn process_peer_input(&mut self, peer: PendingPeerInput) -> Result<bool, SessionError> {
        let (input, record, acknowledgement) = match peer {
            PendingPeerInput::WithoutWalWrite {
                input,
                acknowledgement,
            } => (input, None, acknowledgement),
            PendingPeerInput::PersistAfterApply {
                input,
                record,
                acknowledgement,
            } => (input, Some(record), acknowledgement),
        };
        let source = input.source;
        let completed_request =
            request_completed_by_response(&input.message, self.self_party, source);
        let effects = match self.engine.handle_peer_event(input) {
            Ok(effects) => effects,
            Err(DkgEngineError::Duplicate) => {
                if let Some(message_id) = acknowledgement {
                    self.send_ack(source, message_id)?;
                }
                debug!(source = source.0, "ignored duplicate DKG peer input");
                return Ok(false);
            }
            Err(DkgEngineError::PeerInput(reason)) => {
                debug!(
                    ?reason,
                    source = source.0,
                    "DKG protocol rejected peer input"
                );
                return Ok(false);
            }
            Err(error) => {
                return Err(SessionError::Engine {
                    action: "handle peer input",
                    error,
                });
            }
        };
        if let Some(message_id) = completed_request {
            // One accepted chunk makes this responder's request obsolete; other
            // signers keep retrying until they contribute or extraction ends.
            self.retries.complete(&message_id);
        }
        if let Some(record) = record {
            failpoint::failpoint!(
                name = "dkg.peer.engine_applied",
                description = "after the engine applies a peer input and before durable ingress",
            );
            self.recovery_wal
                .append(&RecoveryRecord::Incoming(record))?;
            failpoint::failpoint!(
                name = "dkg.peer.input_persisted",
                description = "after an accepted DKG peer input is durable and before effects",
            );
        }
        self.dispatch_effects(effects)?;
        if let Some(message_id) = acknowledgement {
            self.send_ack(source, message_id)?;
        }
        Ok(true)
    }

    fn send_ack(&mut self, target: PartyId, message_id: DkgMessageId) -> Result<(), SessionError> {
        let to = self
            .mapping
            .member_id(target)
            .ok_or(SessionError::UnknownParty {
                action: "acknowledge message to",
                party: target.0,
            })?;
        self.effects
            .push(SessionEffect::Acknowledgement(DeliveryOutbound {
                to,
                payload: DeliveryEnvelope::ack(self.epoch, message_id).into(),
            }));
        Ok(())
    }

    fn dispatch_effects(
        &mut self,
        effects: Vec<dkg_protocol::DkgEffect>,
    ) -> Result<(), SessionError> {
        for effect in effects {
            match effect {
                RuntimeCommand::Unicast { to, payload } => {
                    self.send_data_to_recipients([to], payload)?;
                }
                RuntimeCommand::Multicast { payload } => {
                    if matches!(
                        payload.kind(),
                        DkgMessageKind::LowerConversion | DkgMessageKind::OpenPower
                    ) {
                        let record = IncomingRecord {
                            source: self.self_party,
                            message: DurableDkgMessage::try_from(payload.clone())?,
                        };
                        self.pending_inputs.push_back(PendingEngineInput::Peer(
                            PendingPeerInput::PersistAfterApply {
                                input: CoreInput::new(self.self_party, payload.clone()),
                                record,
                                acknowledgement: None,
                            },
                        ));
                    }
                    let self_party = self.self_party;
                    let recipients = self
                        .mapping
                        .parties()
                        .into_iter()
                        .filter(|party| *party != self_party);
                    self.send_data_to_recipients(recipients, payload)?;
                }
                RuntimeCommand::PostToChain { call } => {
                    self.handle_chain_call(call)?;
                }
            }
        }
        Ok(())
    }

    fn replay_persisted_incoming_messages(&mut self, records: Vec<IncomingRecord>) {
        for record in records {
            if self.mapping.member_id(record.source).is_none() {
                warn!(
                    source_party = record.source.0,
                    "skipping persisted incoming DKG message from unknown party"
                );
                continue;
            }
            self.pending_inputs.push_back(PendingEngineInput::Peer(
                PendingPeerInput::WithoutWalWrite {
                    input: CoreInput::new(record.source, record.message.into_message()),
                    acknowledgement: None,
                },
            ));
        }
    }

    fn accept_chain_event(&mut self, event: ChainEvent) -> Result<(), SessionError> {
        let event_kind = chain_event_kind(&event);
        let record_id = event.record_id();
        self.retries
            .observe(delivery_abort_group_for_chain_event(&event));
        self.pending_inputs
            .push_back(PendingEngineInput::Chain(event));
        failpoint::failpoint!(
            name = "dkg.chain.event_buffered",
            description = "after a finalized chain event is buffered and before engine application",
        );
        info!(
            epoch = self.epoch.0,
            event_kind,
            record_id = record_id.0,
            "accepted finalized DKG chain event"
        );
        Ok(())
    }

    fn restore_persisted_outgoing_messages(
        &mut self,
        records: Vec<OutgoingRecord>,
    ) -> Result<(), SessionError> {
        for record in records {
            let OutgoingRecord {
                recipients,
                message,
            } = record;
            let Some(first_recipient) = recipients.first().copied() else {
                warn!("skipping persisted DKG message without recipients");
                continue;
            };
            let message_id = self.message_id_for_recipients(&recipients, message.as_message())?;
            let delivery_recipients = recipients
                .iter()
                .map(|party| {
                    self.mapping
                        .member_id(*party)
                        .ok_or(SessionError::UnknownParty {
                            action: "restore delivery to",
                            party: party.0,
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let abort_group = delivery_abort_group_for_peer_payload(
                message.as_message().kind(),
                self.self_party,
                first_recipient,
            );
            let payload = DeliveryEnvelope::data(
                self.epoch,
                message_id.clone(),
                message.into_message().into_bytes(),
            )
            .into();
            self.effects.extend(
                self.retries
                    .enqueue(
                        message_id,
                        delivery_recipients,
                        payload,
                        abort_group,
                        Instant::now(),
                    )?
                    .into_iter()
                    .map(|send| SessionEffect::Network(send.into())),
            );
        }
        Ok(())
    }

    fn handle_chain_call(&mut self, call: ChainCall) -> Result<(), SessionError> {
        if let Some(group) = delivery_abort_group_for_chain_call(&call) {
            self.retries.observe(group);
        }
        self.effects.push(SessionEffect::Chain(Box::new(call)));
        Ok(())
    }

    fn send_data_to_recipients(
        &mut self,
        recipients: impl IntoIterator<Item = PartyId>,
        message: DkgMessage,
    ) -> Result<(), SessionError> {
        let policy = message.delivery_policy();
        let recipients = recipients.into_iter().collect::<BTreeSet<_>>();
        if recipients.is_empty() {
            return Ok(());
        }
        if policy != DkgDeliveryPolicy::Durable && recipients.len() != 1 {
            return Err(SessionError::SyncMustBeUnicast);
        }
        let message_id = self.message_id_for_recipients(&recipients, &message)?;
        let delivery_recipients = recipients
            .iter()
            .map(|party| {
                self.mapping
                    .member_id(*party)
                    .ok_or(SessionError::UnknownParty {
                        action: "send to",
                        party: party.0,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        match policy {
            DkgDeliveryPolicy::Once => {
                self.effects.push(SessionEffect::Network(DeliveryOutbound {
                    to: delivery_recipients[0],
                    payload: DeliveryEnvelope::unacknowledged(self.epoch, message.into_bytes())
                        .into(),
                }));
            }
            DkgDeliveryPolicy::Retry => {
                let delivery_payload =
                    DeliveryEnvelope::unacknowledged(self.epoch, message.into_bytes()).into();
                self.effects.extend(
                    self.retries
                        .enqueue(
                            message_id,
                            delivery_recipients,
                            delivery_payload,
                            Some(DeliveryAbortGroup::Extraction),
                            Instant::now(),
                        )?
                        .into_iter()
                        .map(|send| SessionEffect::Network(send.into())),
                );
            }
            DkgDeliveryPolicy::Durable => {
                let delivery_payload = DeliveryEnvelope::data(
                    self.epoch,
                    message_id.clone(),
                    message.as_bytes().clone(),
                )
                .into();
                let abort_group = delivery_abort_group_for_peer_payload(
                    message.kind(),
                    self.self_party,
                    *recipients.first().expect("checked recipients above"),
                );
                let sends = self.retries.enqueue(
                    message_id,
                    delivery_recipients,
                    delivery_payload,
                    abort_group,
                    Instant::now(),
                )?;
                if sends.is_empty() {
                    return Ok(());
                }
                // The scheduler is mutated first, but its sends remain private until
                // the WAL succeeds. A WAL failure terminates the session without
                // exposing an output that recovery could not reconstruct.
                self.recovery_wal
                    .append(&RecoveryRecord::Outgoing(OutgoingRecord {
                        recipients,
                        message: DurableDkgMessage::try_from(message)?,
                    }))?;
                failpoint::failpoint!(
                    name = "dkg.network.outgoing_persisted",
                    description = "after durable DKG output and before network delivery is exposed",
                );
                self.effects.extend(
                    sends
                        .into_iter()
                        .map(|send| SessionEffect::Network(send.into())),
                );
            }
        }
        Ok(())
    }

    fn message_id_for_recipients(
        &self,
        recipients: &BTreeSet<PartyId>,
        message: &DkgMessage,
    ) -> Result<DkgMessageId, DkgMessageError> {
        let mut keys = BTreeSet::new();
        for recipient in recipients {
            keys.extend(
                message
                    .identity(
                        self.self_party,
                        *recipient,
                        self.party_count,
                        self.max_ladder_level,
                    )?
                    .keys,
            );
        }
        DkgMessageId::new(keys)
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
                "DKG session completed"
            );
        }
        if self.last_phase == DkgEnginePhase::Vss && phase != DkgEnginePhase::Vss {
            self.retries.observe(DeliveryAbortGroup::Vss);
        }
        if self.last_phase == DkgEnginePhase::Extraction && phase != DkgEnginePhase::Extraction {
            self.retries.observe(DeliveryAbortGroup::Extraction);
        }
        info!(
            from_phase = ?self.last_phase,
            to_phase = ?phase,
            "DKG phase changed"
        );
        self.last_phase = phase;
    }
}

fn request_completed_by_response(
    message: &DkgMessage,
    requester: PartyId,
    responder: PartyId,
) -> Option<DkgMessageId> {
    let key = match message {
        DkgMessage::BveRetrievalResponse { dealer, .. } => DkgMessageKey::BveRetrievalRequest {
            dealer: *dealer,
            requester,
            responder,
        },
        DkgMessage::PcRetrievalResponse { dealer, .. } => DkgMessageKey::PcRetrievalRequest {
            dealer: *dealer,
            requester,
            responder,
        },
        _ => return None,
    };
    Some(DkgMessageId::single(key))
}

fn decode_voting_weights(stakes: &[Stake]) -> Result<Vec<NativeVotingWeight>, SessionError> {
    let unit = U256::from(WEI_PER_MON);
    let half_unit = U256::from(WEI_PER_MON / 2);
    stakes
        .iter()
        .map(|stake| {
            let whole = stake.0 / unit;
            let rounded = if stake.0 % unit >= half_unit {
                whole + U256::from(1)
            } else {
                whole
            };
            u64::try_from(rounded)
                .ok()
                .filter(|weight| *weight != 0)
                .map(NativeVotingWeight::new)
                .ok_or(SessionError::InvalidVotingWeights)
        })
        .collect()
}

fn build_engine(
    epoch: Epoch,
    self_party: PartyId,
    local_keys: SecretKeys<K256SecpBackend>,
    parties: Vec<RegisteredEngineParty>,
    params: DkgEngineParams,
    seed: [u8; 32],
) -> Result<DkgEngine<BlstBackend, K256SecpBackend>, SessionError> {
    // The research API accepts parallel vectors. Split the paired runner type
    // only at this boundary so registration and weight cannot drift internally.
    let (voting_weights, registrations) = parties
        .into_iter()
        .map(|party| (party.voting_weight, party.registration))
        .unzip::<_, _, Vec<_>, Vec<_>>();
    let setup = DkgSetupContext::from_registrations(
        self_party,
        SessionId(epoch.0),
        voting_weights,
        &registrations,
        params.output_count,
        Epsilon::default(),
    )?;
    DkgEngine::from_setup(setup, params, local_keys, seed)
        .map_err(SessionError::EngineInitialization)
}

fn delivery_abort_group_for_chain_call(call: &ChainCall) -> Option<DeliveryAbortGroup> {
    match call {
        ChainCall::PostPCQc { qc } => Some(DeliveryAbortGroup::CommitmentQc(qc.dealer)),
        ChainCall::PostBveQc { qc } => Some(DeliveryAbortGroup::BveQc(qc.dealer)),
        ChainCall::PostDkgResult { .. } => Some(DeliveryAbortGroup::DoneQc),
        ChainCall::PostRegistration { .. } => None,
    }
}

fn requires_transport_ack(policy: DkgDeliveryPolicy) -> bool {
    policy == DkgDeliveryPolicy::Durable
}

fn delivery_abort_group_for_chain_event(event: &ChainEvent) -> DeliveryAbortGroup {
    match event {
        ChainEvent::PCQc { qc, .. } => DeliveryAbortGroup::CommitmentQc(qc.dealer),
        ChainEvent::BveQcFinalized { qc, .. } => DeliveryAbortGroup::BveQc(qc.dealer),
        ChainEvent::DkgResultRecorded { .. } => DeliveryAbortGroup::DoneQc,
    }
}

fn delivery_abort_group_for_peer_payload(
    kind: DkgMessageKind,
    source: PartyId,
    target: PartyId,
) -> Option<DeliveryAbortGroup> {
    match kind {
        DkgMessageKind::PcProposal => Some(DeliveryAbortGroup::CommitmentQc(source)),
        DkgMessageKind::PcAck => Some(DeliveryAbortGroup::CommitmentQc(target)),
        DkgMessageKind::BveProposal => Some(DeliveryAbortGroup::BveQc(source)),
        // One approval batch can cover several dealers, so only the enclosing
        // phase can safely abort the whole delivery.
        DkgMessageKind::BveApprovalBatch => Some(DeliveryAbortGroup::Vss),
        DkgMessageKind::BveRetrievalRequest | DkgMessageKind::PcRetrievalRequest => {
            Some(DeliveryAbortGroup::Extraction)
        }
        DkgMessageKind::BveRetrievalResponse
        | DkgMessageKind::PcRetrievalResponse
        | DkgMessageKind::Ladder
        | DkgMessageKind::LowerConversion
        | DkgMessageKind::OpenPower => None,
        DkgMessageKind::Done => Some(DeliveryAbortGroup::DoneQc),
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "session_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "session_delivery_tests.rs"]
mod delivery_tests;
