//! Per-epoch DKG protocol runtime.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    mem,
    time::{Duration, Instant},
};

use alloy_primitives::U256;
use bytes::Bytes;
use dkg_core::{CoreInput, PartyId, PartySet, PartySetError, RuntimeCommand, SessionId};
use dkg_crypto::{BlstBackend, K256SecpBackend, Matrix, MatrixShapeError};
use dkg_protocol::{
    quantize, ChainCall, ChainEvent, DkgEngine, DkgEngineError, DkgEngineParams, DkgEnginePhase,
    DkgInput, DkgMessage, DkgMessageError, DkgMessageId, DkgMessageKey, DkgMessageKind,
    DkgSetupContext, DkgSetupError, DkgThresholdError, DkgThresholds, Epsilon, NativeVotingWeight,
    QuantizationError, VirtualTopology, VirtualTopologyError,
};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId, Stake};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::{
    chain::chain_event_kind,
    record::{EngineSeed, IncomingRecord, OutgoingRecord, RecoveryRecord},
    recovery::{RecoveryState, RecoveryWal, RecoveryWalConfig, RecoveryWalError},
    reliable::{EnqueueError, ObsolescencePolicy, RetryConfig, RetryScheduler},
    runner::{DeliveryEnvelope, DeliveryOutbound},
    DkgError, DkgRegisteredKeyMaterial, DkgValidator,
};

pub(crate) const WEI_PER_MON: u64 = 1_000_000_000_000_000_000;

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
    #[error("derive DKG thresholds failed: {0}")]
    Threshold(#[source] DkgThresholdError),
    #[error("build DKG party set failed: {0}")]
    PartySet(#[source] PartySetError),
    #[error("build DKG topology failed: {0}")]
    Topology(#[source] VirtualTopologyError),
    #[error("quantize DKG stake failed: {0}")]
    Quantization(#[source] QuantizationError),
    #[error("DKG validator stake does not round to a positive u64 MON weight")]
    InvalidVotingWeights,
    #[error("assemble DKG setup failed: {0}")]
    Setup(#[source] DkgSetupError),
    #[error("initialize research DKG engine failed: {0:?}")]
    EngineInitialization(DkgEngineError),
    #[error("shape DKG receiver public matrix failed: {0}")]
    ReceiverMatrix(#[source] MatrixShapeError),
    #[error(transparent)]
    RecoveryWal(#[from] RecoveryWalError),
    #[error("classify DKG message failed: {0}")]
    Message(#[from] DkgMessageError),
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
    validators: Vec<DkgValidator<ST>>,
    storage_root: &std::path::Path,
    key_material: DkgRegisteredKeyMaterial,
) -> Result<Option<DkgSession<ST>>, DkgError>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    let mapping = DkgPeerMap::<ST>::new_ordered(
        validators
            .iter()
            .map(|validator| validator.node_id)
            .collect(),
    )
    .map_err(|_| DkgError::DuplicateValidator)?;
    let Some(self_party) = mapping.party_id(&self_id) else {
        info!(?self_id, "not starting DKG session for non-validator node");
        return Ok(None);
    };

    let voting_weights = decode_voting_weights(
        &validators
            .iter()
            .map(|validator| validator.stake)
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
        voting_weights,
        engine_seed,
        key_material,
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
    voting_weights: Vec<NativeVotingWeight>,
    engine_seed: EngineSeed,
    key_material: DkgRegisteredKeyMaterial,
    recovery_wal: RecoveryWal,
    recovery_state: RecoveryState,
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
    delivery_outbound: Vec<DeliveryOutbound<ST>>,
    chain_calls: Vec<ChainCall>,
    pending_inputs: VecDeque<PendingEngineInput>,
    recovery_wal: RecoveryWal,
    recovered_outgoing: Vec<OutgoingRecord>,
    last_phase: DkgEnginePhase,
    awaiting_chain_recovery: bool,
}

enum PendingEngineInput {
    Peer(PendingPeerInput),
    Chain(ChainEvent),
}

struct PendingPeerInput {
    input: CoreInput<DkgMessage>,
    durable: Option<IncomingRecord>,
}

impl<ST> DkgSession<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    pub(crate) fn next_timer(&self) -> Option<Instant> {
        self.retries.next_timer()
    }

    pub(crate) fn take_delivery_outbound(&mut self) -> Vec<DeliveryOutbound<ST>> {
        mem::take(&mut self.delivery_outbound)
    }

    pub(crate) fn take_chain_calls(&mut self) -> Vec<ChainCall> {
        mem::take(&mut self.chain_calls)
    }

    fn new(init: SessionInit<ST>) -> Result<Self, SessionError> {
        let party_count = init.mapping.len();
        let params = DkgEngineParams::default();
        let output_count = params.output_count;
        let engine = build_engine(
            init.epoch,
            init.self_party,
            init.key_material,
            init.voting_weights,
            params,
            init.engine_seed,
        )?;
        let max_ladder_level = output_count.trailing_zeros().into();
        let initial_phase = engine.phase();
        let RecoveryState {
            outgoing: recovered_outgoing,
            incoming: recovered_incoming,
            ..
        } = init.recovery_state;
        info!(
            epoch = init.epoch.0,
            party = init.self_party.0,
            party_count = init.mapping.len(),
            output_count,
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
            delivery_outbound: Vec::new(),
            chain_calls: Vec::new(),
            pending_inputs: VecDeque::new(),
            recovery_wal: init.recovery_wal,
            recovered_outgoing,
            last_phase: initial_phase,
            awaiting_chain_recovery: true,
        };
        session.replay_persisted_incoming_messages(recovered_incoming);
        info!(
            pending_inputs = session.pending_inputs.len(),
            recovered_outgoing = session.recovered_outgoing.len(),
            "waiting for DKG chain recovery before starting engine"
        );
        Ok(session)
    }

    pub(crate) fn handle_network_message(
        &mut self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        payload: Bytes,
    ) -> Result<(), SessionError> {
        let Some(from) = self.mapping.party_id(&sender) else {
            warn!(
                epoch = self.epoch.0,
                ?sender,
                "dropping DKG delivery from non-validator"
            );
            return Ok(());
        };
        self.handle_data_payload(from, payload)?;
        self.settle()?;
        Ok(())
    }

    pub(crate) fn handle_timer(&mut self, now: Instant) -> Result<(), SessionError> {
        self.delivery_outbound
            .extend(self.retries.retry_due(now).into_iter().map(Into::into));
        self.settle()
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
        if self.awaiting_chain_recovery {
            return Ok(());
        }
        self.drain_engine_inputs()
    }

    fn complete_chain_recovery(&mut self) -> Result<(), SessionError> {
        if !self.awaiting_chain_recovery {
            return Ok(());
        }

        let (chain, peer) = mem::take(&mut self.pending_inputs)
            .into_iter()
            .partition(|input| matches!(input, PendingEngineInput::Chain(_)));
        self.pending_inputs = chain;
        self.drain_engine_inputs()?;
        // Chain evidence is applied before recovery so the scheduler discards
        // obsolete WAL entries as they are restored.
        let recovered_outgoing = mem::take(&mut self.recovered_outgoing);
        self.restore_persisted_outgoing_messages(recovered_outgoing)?;
        let effects = self.engine.start().map_err(|error| SessionError::Engine {
            action: "start",
            error,
        })?;
        // Once start succeeds, recovery must not start the same engine twice if
        // dispatching one of its initial effects fails.
        self.awaiting_chain_recovery = false;
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

    fn handle_data_payload(&mut self, from: PartyId, payload: Bytes) -> Result<(), SessionError> {
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
        if message.kind().is_sync() {
            if let Err(err) = message.identity(
                from,
                self.self_party,
                self.party_count,
                self.max_ladder_level,
            ) {
                warn!(
                    ?err,
                    from_party = from.0,
                    "rejected invalid DKG sync message identity"
                );
                return Ok(());
            }
            self.pending_inputs
                .push_back(PendingEngineInput::Peer(PendingPeerInput {
                    input: CoreInput::new(from, message),
                    durable: None,
                }));
            return Ok(());
        }
        let record = IncomingRecord {
            source: from,
            payload: payload.clone(),
        };
        self.pending_inputs
            .push_back(PendingEngineInput::Peer(PendingPeerInput {
                input: CoreInput::new(from, message),
                durable: Some(record),
            }));
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
        let source = peer.input.source;
        let completed_request =
            request_completed_by_response(&peer.input.message, self.self_party, source);
        let durable = peer.durable;
        let effects = match self.engine.handle_peer_event(peer.input) {
            Ok(effects) => effects,
            Err(DkgEngineError::Duplicate) => {
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
        if let Some(record) = durable {
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
        Ok(true)
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
                            payload: payload.clone().into_bytes(),
                        };
                        self.pending_inputs
                            .push_back(PendingEngineInput::Peer(PendingPeerInput {
                                input: CoreInput::new(self.self_party, payload.clone()),
                                durable: Some(record),
                            }));
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
            let message = match DkgMessage::decode(record.payload.clone()) {
                Ok(message) => message,
                Err(err) => {
                    warn!(?err, "skipping malformed persisted DKG message");
                    continue;
                }
            };
            self.pending_inputs
                .push_back(PendingEngineInput::Peer(PendingPeerInput {
                    input: CoreInput::new(record.source, message),
                    durable: None,
                }));
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
            let message = match DkgMessage::decode(record.payload.clone()) {
                Ok(message) => message,
                Err(err) => {
                    warn!(?err, "skipping malformed persisted outgoing DKG message");
                    continue;
                }
            };
            let Some(first_recipient) = record.recipients.first().copied() else {
                warn!("skipping persisted DKG message without recipients");
                continue;
            };
            let message_id = self.message_id_for_recipients(&record.recipients, &message)?;
            let recipients = record
                .recipients
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
            let payload = DeliveryEnvelope {
                epoch: self.epoch.0,
                payload: record.payload,
            }
            .into();
            self.delivery_outbound.extend(
                self.retries
                    .enqueue(
                        message_id,
                        recipients,
                        payload,
                        delivery_abort_group_for_peer_payload(
                            message.kind(),
                            self.self_party,
                            first_recipient,
                        ),
                        Instant::now(),
                    )?
                    .into_iter()
                    .map(Into::into),
            );
        }
        Ok(())
    }

    fn handle_chain_call(&mut self, call: ChainCall) -> Result<(), SessionError> {
        if let Some(group) = delivery_abort_group_for_chain_call(&call) {
            self.retries.observe(group);
        }
        self.chain_calls.push(call);
        Ok(())
    }

    fn send_data_to_recipients(
        &mut self,
        recipients: impl IntoIterator<Item = PartyId>,
        message: DkgMessage,
    ) -> Result<(), SessionError> {
        let kind = message.kind();
        let recipients = recipients.into_iter().collect::<BTreeSet<_>>();
        if recipients.is_empty() {
            return Ok(());
        }
        if let Some(recipient) = recipients
            .iter()
            .find(|recipient| self.mapping.member_id(**recipient).is_none())
        {
            return Err(SessionError::UnknownParty {
                action: "send to",
                party: recipient.0,
            });
        }
        if kind.is_sync() {
            if recipients.len() != 1 {
                return Err(SessionError::SyncMustBeUnicast);
            }
            let recipient = *recipients.first().expect("checked one sync recipient");
            let identity = message.identity(
                self.self_party,
                recipient,
                self.party_count,
                self.max_ladder_level,
            )?;
            let to = self
                .mapping
                .member_id(recipient)
                .expect("recipient validated above");
            if kind.is_sync_request() {
                let payload = DeliveryEnvelope {
                    epoch: self.epoch.0,
                    payload: message.into_bytes(),
                }
                .into();
                self.delivery_outbound.extend(
                    self.retries
                        .enqueue(
                            identity.message_id(),
                            [to],
                            payload,
                            Some(DeliveryAbortGroup::Extraction),
                            Instant::now(),
                        )?
                        .into_iter()
                        .map(Into::into),
                );
                return Ok(());
            }
            // A lost response is recreated by the requester's next retry, so it
            // must not acquire its own retry timer or sender-side dedup entry.
            self.delivery_outbound.push(DeliveryOutbound {
                to,
                payload: DeliveryEnvelope {
                    epoch: self.epoch.0,
                    payload: message.into_bytes(),
                }
                .into(),
            });
            return Ok(());
        }
        let message_id = self.message_id_for_recipients(&recipients, &message)?;
        let payload = message.into_bytes();
        let abort_group = delivery_abort_group_for_peer_payload(
            kind,
            self.self_party,
            *recipients.first().expect("checked recipients above"),
        );
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
        let delivery_payload = DeliveryEnvelope {
            epoch: self.epoch.0,
            payload: payload.clone(),
        }
        .into();
        let sends = self.retries.enqueue(
            message_id.clone(),
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
                payload,
            }))?;
        failpoint::failpoint!(
            name = "dkg.network.outgoing_persisted",
            description = "after durable DKG output and before network delivery is exposed",
        );
        self.delivery_outbound
            .extend(sends.into_iter().map(Into::into));
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
    key_material: DkgRegisteredKeyMaterial,
    voting_weights: Vec<NativeVotingWeight>,
    params: DkgEngineParams,
    seed: [u8; 32],
) -> Result<DkgEngine<BlstBackend, K256SecpBackend>, SessionError> {
    let DkgRegisteredKeyMaterial {
        local_keys,
        registrations,
    } = key_material;
    let party_count = registrations.len();
    let receiver_publics = Matrix::from_vec(
        party_count,
        1,
        registrations
            .iter()
            .map(|registration| registration.receiver.public_key)
            .collect(),
    )
    .map_err(SessionError::ReceiverMatrix)?;
    let epsilon = Epsilon::default();
    let quantized = quantize(&voting_weights, epsilon, params.output_count)
        .map_err(SessionError::Quantization)?;
    let party_set = PartySet::new(
        (0..party_count)
            .map(|party| PartyId(u32::try_from(party).expect("party count fits u32")))
            .collect(),
    )
    .map_err(SessionError::PartySet)?;
    let topology = VirtualTopology::from_weights(
        party_set,
        voting_weights,
        quantized.dealer_tickets,
        quantized.receiver_tickets,
    )
    .map_err(SessionError::Topology)?;
    let thresholds = DkgThresholds::derive_quantized(
        &topology,
        params.output_count,
        quantized.dealer_batch_size,
        epsilon,
    )
    .map_err(SessionError::Threshold)?;
    let setup = DkgSetupContext::assemble(
        self_party,
        SessionId(epoch.0),
        topology,
        thresholds,
        registrations
            .iter()
            .map(|registration| registration.qc_verifier)
            .collect(),
        receiver_publics,
        registrations
            .iter()
            .map(|registration| registration.address)
            .collect(),
    )
    .map_err(SessionError::Setup)?;
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
