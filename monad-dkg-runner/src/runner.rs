use std::{mem, path::PathBuf, sync::Arc, time::Instant};

use alloy_rlp::{RlpDecodable, RlpEncodable};
use bytes::Bytes;
use dkg_protocol::{ChainEvent, RegistrationCall};
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_executor::ExecutorMetrics;
use monad_types::{Epoch, NodeId, SeqNum};
use tracing::{debug, error, info, warn};

use crate::{
    chain::{ChainEventSession, ChainRead, DkgChain, RecoveryTransition, SessionScan, TxSubmitter},
    metrics::DkgRunnerMetrics,
    registration::{
        assemble_registered_session, load_or_create_local_registration, RegisteredSession,
    },
    reliable::ScheduledSend,
    session::{start, DkgSession, SessionEffect},
    DkgChainConfig, DkgError, DkgLocalKeyMaterial, DkgValidator,
};

#[path = "runner/registration.rs"]
mod registration_state;

use registration_state::{
    LocalRegistration, LocalRegistrationAction, LocalRegistrationRead, RegistrationStart,
};

pub struct DeliveryOutbound<ST: CertificateSignatureRecoverable> {
    pub to: NodeId<CertificateSignaturePubKey<ST>>,
    pub payload: Bytes,
}

impl<ST: CertificateSignatureRecoverable>
    From<ScheduledSend<NodeId<CertificateSignaturePubKey<ST>>, Bytes>> for DeliveryOutbound<ST>
{
    fn from(send: ScheduledSend<NodeId<CertificateSignaturePubKey<ST>>, Bytes>) -> Self {
        Self {
            to: send.to,
            payload: send.payload,
        }
    }
}

#[derive(RlpEncodable, RlpDecodable)]
pub(crate) struct DeliveryEnvelope {
    pub(crate) epoch: u64,
    pub(crate) payload: Bytes,
}

impl From<DeliveryEnvelope> for Bytes {
    fn from(wire: DeliveryEnvelope) -> Self {
        alloy_rlp::encode(wire).into()
    }
}

impl TryFrom<&[u8]> for DeliveryEnvelope {
    type Error = alloy_rlp::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        alloy_rlp::decode_exact(data)
    }
}

struct ManagedChain {
    io: Arc<dyn DkgChain>,
    local_keys: DkgLocalKeyMaterial,
    submitter: TxSubmitter,
    registration: LocalRegistration,
}

struct ActiveSession<ST>
where
    ST: CertificateSignatureRecoverable,
{
    epoch: Epoch,
    protocol: DkgSession<ST>,
    scan: SessionScan,
}

impl<ST> ActiveSession<ST>
where
    ST: CertificateSignatureRecoverable,
{
    fn new(
        epoch: Epoch,
        party_count: usize,
        recovery_block: SeqNum,
        finalized: SeqNum,
        protocol: DkgSession<ST>,
    ) -> Self {
        let chain_session = ChainEventSession {
            epoch,
            party_count,
            recovery_block,
        };
        info!(
            epoch = epoch.0,
            party_count,
            recovery_block = recovery_block.0,
            "started DKG chain recovery"
        );
        Self {
            epoch,
            protocol,
            scan: SessionScan::new(chain_session, finalized),
        }
    }

    fn next_read(&self, finalized: SeqNum) -> Option<ChainRead> {
        self.scan.next(finalized)
    }

    fn restart_scan(&mut self, recovery_block: SeqNum, finalized: SeqNum) {
        self.scan.restart(recovery_block, finalized);
        info!(
            epoch = self.epoch.0,
            recovery_block = recovery_block.0,
            "restarted DKG chain recovery"
        );
    }

    fn complete_read(&mut self, read: ChainRead) -> RecoveryTransition {
        let transition = self.scan.advance(read);
        if transition == RecoveryTransition::Completed {
            info!(
                epoch = self.epoch.0,
                through_block = read.block().0,
                "completed DKG chain recovery"
            );
        }
        transition
    }
}

struct PendingRegisteredSession<ST>
where
    ST: CertificateSignatureRecoverable,
{
    epoch: Epoch,
    validators: Vec<DkgValidator<ST>>,
    boundary: RegistrationBoundary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionRegistrationRead {
    epoch: Epoch,
    block: SeqNum,
    parties: Vec<alloy_primitives::Address>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationBoundary {
    AwaitingFinalizedBlock,
    Finalized(SeqNum),
}

enum DkgRunnerEvent<ST>
where
    ST: CertificateSignatureRecoverable,
{
    Finalized {
        block: SeqNum,
        next_epoch: Epoch,
    },
    SyncComplete {
        block: SeqNum,
        next_epoch: Epoch,
    },
    StartSession {
        epoch: Epoch,
        validators: Vec<DkgValidator<ST>>,
    },
    Network {
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        message: Bytes,
    },
}

pub struct DkgRunnerInbox<ST>
where
    ST: CertificateSignatureRecoverable,
{
    events: flume::Receiver<DkgRunnerEvent<ST>>,
}

#[derive(Clone)]
pub struct DkgRunnerHandle<ST>
where
    ST: CertificateSignatureRecoverable,
{
    events: Option<flume::Sender<DkgRunnerEvent<ST>>>,
}

impl<ST> DkgRunnerHandle<ST>
where
    ST: CertificateSignatureRecoverable,
{
    pub fn channel() -> (Self, DkgRunnerInbox<ST>) {
        let (events, receiver) = flume::unbounded();
        (
            Self {
                events: Some(events),
            },
            DkgRunnerInbox { events: receiver },
        )
    }

    pub fn disabled() -> Self {
        Self { events: None }
    }

    fn send(&self, event: DkgRunnerEvent<ST>) {
        if self
            .events
            .as_ref()
            .is_some_and(|events| events.send(event).is_err())
        {
            warn!("DKG runner input channel closed");
        }
    }

    pub fn finalized(&self, block: SeqNum, epoch_length: SeqNum) {
        self.send(DkgRunnerEvent::Finalized {
            block,
            next_epoch: block.to_epoch(epoch_length) + Epoch(1),
        });
    }

    pub fn sync_complete(&self, block: SeqNum, epoch_length: SeqNum) {
        self.send(DkgRunnerEvent::SyncComplete {
            block,
            next_epoch: block.to_epoch(epoch_length) + Epoch(1),
        });
    }

    pub fn start_session(&self, epoch: Epoch, validators: Vec<DkgValidator<ST>>) {
        self.send(DkgRunnerEvent::StartSession { epoch, validators });
    }

    pub fn network(&self, sender: NodeId<CertificateSignaturePubKey<ST>>, message: Bytes) {
        self.send(DkgRunnerEvent::Network { sender, message });
    }
}

pub struct DkgRunner<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    self_id: NodeId<CertificateSignaturePubKey<ST>>,
    storage_root: PathBuf,
    pending_outbound: Vec<DeliveryOutbound<ST>>,
    // The previous protocol may still be finishing while the current one runs.
    sessions: [Option<ActiveSession<ST>>; 2],
    latest_started_epoch: Option<Epoch>,
    pending_registered_session: Option<PendingRegisteredSession<ST>>,
    sync_block: Option<SeqNum>,
    latest_finalized: Option<SeqNum>,
    latest_completed_epoch: Option<Epoch>,
    chain: ManagedChain,
    metrics: DkgRunnerMetrics,
}

impl<ST> DkgRunner<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    pub(crate) fn new(
        self_id: NodeId<CertificateSignaturePubKey<ST>>,
        storage_root: PathBuf,
        config: DkgChainConfig,
        chain: Arc<dyn DkgChain>,
    ) -> Result<Self, DkgError> {
        let metrics = DkgRunnerMetrics::new();
        let submitter = TxSubmitter::new(&config, Arc::clone(&chain), metrics.transaction())?;
        let registration = LocalRegistration::new(submitter.signer_address());
        Ok(Self {
            self_id,
            storage_root,
            pending_outbound: Vec::new(),
            sessions: [None, None],
            latest_started_epoch: None,
            pending_registered_session: None,
            sync_block: None,
            latest_finalized: None,
            latest_completed_epoch: None,
            chain: ManagedChain {
                io: chain,
                local_keys: config.local_keys.clone(),
                submitter,
                registration,
            },
            metrics,
        })
    }

    pub fn metrics(&self) -> &ExecutorMetrics {
        self.metrics.executor_metrics()
    }

    pub async fn run(
        mut self,
        inbox: DkgRunnerInbox<ST>,
        outbound: flume::Sender<DeliveryOutbound<ST>>,
    ) -> Result<(), DkgError> {
        let events = inbox.events;
        loop {
            let timer = self.next_timer();
            tokio::select! {
                event = events.recv_async() => match event {
                    Ok(DkgRunnerEvent::Finalized { block, next_epoch }) => {
                        self.prepare_registration(next_epoch);
                        self.notify_finalized(block);
                    }
                    Ok(DkgRunnerEvent::SyncComplete { block, next_epoch }) => {
                        self.prepare_registration(next_epoch);
                        self.notify_sync_complete(block);
                    }
                    Ok(DkgRunnerEvent::StartSession { epoch, validators }) => {
                        if let Err(err) = self.start_chain_registered_session(epoch, validators) {
                            self.metrics.protocol_error();
                            warn!(?err, epoch = epoch.0, "failed to start DKG session");
                        }
                    }
                    Ok(DkgRunnerEvent::Network { sender, message }) => {
                        self.handle_network_message(sender, message)
                    }
                    Err(_) => return Ok(()),
                },
                () = wait_for_timer(timer) => self.handle_timer(Instant::now()),
            }
            for message in self.take_outbound() {
                if outbound.send_async(message).await.is_err() {
                    self.metrics.delivery_error();
                    return Err(DkgError::ChannelClosed("sending DKG network output"));
                }
            }
        }
    }

    /// Opens local registration for the next validator epoch.
    ///
    /// Calls are monotone and idempotent. Advancing the target abandons any
    /// unfinalized registration transaction for the older epoch.
    pub fn prepare_registration(&mut self, epoch: Epoch) {
        let RegistrationStart::Started { previous } = self.chain.registration.start_epoch(epoch)
        else {
            return;
        };
        if let Some(previous) = previous {
            self.chain.submitter.cancel_registration(previous);
        }
        self.settle_chain();
    }

    /// Makes one more finalized block available to the active chain cursor.
    /// This never establishes or changes the recovery snapshot boundary.
    pub fn notify_finalized(&mut self, block: SeqNum) {
        self.record_finalized_head(block);
        self.settle_chain();
    }

    /// Establishes the exact chain-state boundary used for DKG recovery.
    ///
    /// Once a DKG session is known, the runner reads a snapshot at `block`
    /// and then scans every subsequently finalized block in order.
    pub fn notify_sync_complete(&mut self, block: SeqNum) {
        if self.sync_block.is_some_and(|current| current >= block) {
            return;
        }
        self.sync_block = Some(block);
        self.record_finalized_head(block);
        // A later state sync establishes a new exact snapshot boundary for the
        // newest protocol, so its owned cursor must not keep scanning the old one.
        if let Some(session) = self.sessions[1].as_mut() {
            session.restart_scan(
                block,
                self.latest_finalized
                    .expect("synchronized runner has a finalized head"),
            );
        }
        self.settle_chain();
    }

    fn record_finalized_head(&mut self, block: SeqNum) {
        if self.latest_finalized.is_some_and(|latest| block <= latest) {
            return;
        }
        self.latest_finalized = Some(block);
        if let Some(pending) = self.pending_registered_session.as_mut() {
            if pending.boundary == RegistrationBoundary::AwaitingFinalizedBlock {
                pending.boundary = RegistrationBoundary::Finalized(block);
            }
        }
    }

    /// Begins a production DKG session whose public key material is loaded from
    /// the finalized registration contract before the engine is constructed.
    pub fn start_chain_registered_session(
        &mut self,
        epoch: Epoch,
        validators: Vec<DkgValidator<ST>>,
    ) -> Result<(), DkgError> {
        self.close_registration_window(epoch);
        if self
            .latest_started_epoch
            .is_some_and(|started| started >= epoch)
            || self
                .pending_registered_session
                .as_ref()
                .is_some_and(|pending| pending.epoch >= epoch)
        {
            return Ok(());
        }
        self.pending_registered_session = Some(PendingRegisteredSession {
            epoch,
            validators,
            boundary: self.latest_finalized.map_or(
                RegistrationBoundary::AwaitingFinalizedBlock,
                RegistrationBoundary::Finalized,
            ),
        });
        self.settle_chain();
        Ok(())
    }

    fn close_registration_window(&mut self, epoch: Epoch) {
        if self.chain.registration.close(epoch) {
            self.chain.submitter.cancel_registration(epoch);
        }
    }

    fn settle_chain(&mut self) {
        self.reconcile_local_registration();
        self.start_pending_registered_session();
        self.read_chain_events();
        self.update_session_metrics();
    }

    fn reconcile_local_registration(&mut self) {
        if self.sync_block.is_none() {
            return;
        }
        loop {
            let Some(latest) = self.latest_finalized else {
                return;
            };
            let Some(read) = self.chain.registration.next_read(latest) else {
                return;
            };
            match self.execute_local_registration_read(read) {
                Ok(mut registrations) => {
                    debug_assert_eq!(registrations.len(), 1);
                    if let Err(err) =
                        self.apply_local_registration_read(read, registrations.pop().flatten())
                    {
                        self.metrics.chain_error();
                        error!(
                            ?err,
                            epoch = read.epoch.0,
                            block = read.block.0,
                            "failed to process local DKG registration state"
                        );
                        return;
                    }
                    if read.block >= latest {
                        return;
                    }
                }
                Err(DkgError::ChainDataUnavailable { .. }) => {
                    self.chain.registration.read_failed(read);
                    return;
                }
                Err(err) => {
                    self.chain.registration.read_failed(read);
                    self.metrics.chain_error();
                    debug!(?err, epoch = read.epoch.0, block = read.block.0, party = %read.address, "failed to read local DKG registration from finalized state");
                    return;
                }
            }
        }
    }

    fn execute_local_registration_read(
        &self,
        read: LocalRegistrationRead,
    ) -> Result<Vec<Option<RegistrationCall>>, DkgError> {
        self.chain
            .io
            .read_registrations(read.block, read.epoch, &[read.address])
    }

    fn apply_local_registration_read(
        &mut self,
        read: LocalRegistrationRead,
        observed: Option<RegistrationCall>,
    ) -> Result<(), DkgError> {
        let storage_root = self.storage_root.clone();
        if self.chain.registration.epoch() != Some(read.epoch) {
            return Ok(());
        }
        let local = match load_or_create_local_registration(
            &storage_root,
            read.epoch,
            read.address,
            &self.chain.local_keys,
            observed.as_ref(),
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.chain.registration.close(read.epoch);
                return Err(DkgError::operation("load local DKG registration", err));
            }
        };
        failpoint::failpoint!(
            name = "dkg.registration.loaded",
            description =
                "after durable local registration is loaded and before chain reconciliation",
        );

        let action = self
            .chain
            .registration
            .observe(read, observed, local)
            .map_err(|_| DkgError::FinalizedRegistrationConflict {
                address: read.address,
            })?;
        match action {
            LocalRegistrationAction::Ignore => {}
            LocalRegistrationAction::Submit {
                epoch,
                block,
                registration,
            } => self
                .chain
                .submitter
                .submit_registration(epoch, block, registration),
            LocalRegistrationAction::Retry { epoch, block } => {
                self.chain.submitter.retry_registration(epoch, block)
            }
            LocalRegistrationAction::Confirm {
                epoch,
                registration,
            } => self
                .chain
                .submitter
                .confirm_registration(epoch, &registration),
        }
        Ok(())
    }

    fn start_pending_registered_session(&mut self) {
        if self.sync_block.is_none() {
            return;
        }
        let Some(read) = self.next_session_registration_read() else {
            return;
        };
        match self.execute_session_registration_read(&read) {
            Ok(state) => {
                if let Err(err) = self.apply_session_registration_read(read.clone(), state) {
                    self.metrics.protocol_error();
                    error!(
                        ?err,
                        epoch = read.epoch.0,
                        block = read.block.0,
                        "failed to start registered DKG session"
                    );
                }
            }
            Err(DkgError::ChainDataUnavailable { .. }) => {}
            Err(err) => {
                self.metrics.chain_error();
                warn!(
                    ?err,
                    epoch = read.epoch.0,
                    block = read.block.0,
                    "failed to read finalized DKG registrations"
                );
            }
        }
    }

    fn next_session_registration_read(&self) -> Option<SessionRegistrationRead> {
        let pending = self.pending_registered_session.as_ref()?;
        let RegistrationBoundary::Finalized(block) = pending.boundary else {
            return None;
        };
        Some(SessionRegistrationRead {
            epoch: pending.epoch,
            block,
            parties: pending
                .validators
                .iter()
                .map(|validator| validator.address)
                .collect(),
        })
    }

    fn execute_session_registration_read(
        &self,
        read: &SessionRegistrationRead,
    ) -> Result<Vec<Option<RegistrationCall>>, DkgError> {
        self.chain
            .io
            .read_registrations(read.block, read.epoch, &read.parties)
    }

    fn apply_session_registration_read(
        &mut self,
        read: SessionRegistrationRead,
        registrations: Vec<Option<RegistrationCall>>,
    ) -> Result<(), DkgError> {
        let Some(pending) = self
            .pending_registered_session
            .take_if(|pending| pending.epoch == read.epoch)
        else {
            return Ok(());
        };
        debug_assert!(pending.boundary == RegistrationBoundary::Finalized(read.block));
        let local_keys = &self.chain.local_keys;
        let registered = assemble_registered_session(
            read.epoch,
            self.self_id,
            pending.validators,
            local_keys,
            registrations,
        )
        .map_err(|err| DkgError::operation("assemble registered DKG session", err))?;
        self.start_session_at(read.epoch, registered, read.block)
    }

    fn start_session_at(
        &mut self,
        epoch: Epoch,
        registered: RegisteredSession<ST>,
        recovery_block: SeqNum,
    ) -> Result<(), DkgError> {
        let party_count = registered.parties.len();
        if self
            .latest_started_epoch
            .is_some_and(|started| started >= epoch)
        {
            return Ok(());
        }
        let Some(session) = start(epoch, self.self_id, &self.storage_root, registered)? else {
            self.latest_started_epoch = Some(epoch);
            return Ok(());
        };
        self.latest_started_epoch = Some(epoch);
        if let Some(retired) = self.sessions[0].as_ref() {
            self.chain.submitter.retire_epoch(retired.epoch);
        }
        self.sessions.rotate_left(1);
        self.sessions[1] = Some(ActiveSession::new(
            epoch,
            party_count,
            recovery_block,
            self.latest_finalized
                .expect("registered session has a finalized boundary"),
            session,
        ));
        self.metrics.session_started();
        Ok(())
    }

    pub fn handle_timer(&mut self, now: Instant) {
        for index in 0..self.sessions.len() {
            let Some(session) = &mut self.sessions[index] else {
                continue;
            };
            let epoch = session.epoch;
            if session
                .protocol
                .next_timer()
                .is_some_and(|deadline| deadline <= now)
            {
                match session.protocol.handle_timer(now) {
                    Ok(retries) => self.metrics.network_retries(retries),
                    Err(err) => {
                        self.metrics.protocol_error();
                        error!(?err, "failed to process DKG retry timer");
                    }
                }
                self.collect_session_effects(epoch);
            }
        }
        self.update_session_metrics();
    }

    pub fn handle_network_message(
        &mut self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        message: Bytes,
    ) {
        let wire: DeliveryEnvelope = match message.as_ref().try_into() {
            Ok(wire) => wire,
            Err(err) => {
                self.metrics.delivery_error();
                warn!(?err, ?sender, "dropping malformed DKG delivery message");
                return;
            }
        };
        let epoch = Epoch(wire.epoch);
        let Some(session) = self
            .sessions
            .iter_mut()
            .flatten()
            .find(|session| session.epoch == epoch)
        else {
            return;
        };
        if let Err(err) = session
            .protocol
            .handle_network_message(sender, wire.payload)
        {
            self.metrics.protocol_error();
            error!(?err, ?sender, "failed to process DKG network message");
        }
        self.collect_session_effects(epoch);
        self.update_session_metrics();
    }

    pub fn next_timer(&self) -> Option<Instant> {
        self.sessions
            .iter()
            .flatten()
            .filter_map(|session| session.protocol.next_timer())
            .min()
    }

    /// Drains network output produced by direct runner operations.
    pub fn take_outbound(&mut self) -> Vec<DeliveryOutbound<ST>> {
        mem::take(&mut self.pending_outbound)
    }

    fn collect_session_effects(&mut self, epoch: Epoch) {
        let effects = self.take_session_effects(epoch);
        self.dispatch_session_effects(epoch, effects);
    }

    fn take_session_effects(&mut self, epoch: Epoch) -> Vec<SessionEffect<ST>> {
        let Some(session) = self
            .sessions
            .iter_mut()
            .flatten()
            .find(|session| session.epoch == epoch)
        else {
            return Vec::new();
        };
        session.protocol.take_effects()
    }

    fn dispatch_session_effects(&mut self, epoch: Epoch, effects: Vec<SessionEffect<ST>>) {
        // DkgSession exposes no engine effects until chain recovery finishes,
        // so transaction submission does not need a second recovery gate.
        for effect in effects {
            match effect {
                SessionEffect::Network(delivery) => self.pending_outbound.push(delivery),
                SessionEffect::Chain(call) => {
                    failpoint::failpoint!(
                        name = "dkg.chain.call_buffered",
                        description =
                            "after a DKG chain call is buffered and before transaction submission",
                    );
                    self.chain.submitter.submit(epoch, *call);
                }
            }
        }
    }

    fn read_chain_events(&mut self) {
        loop {
            let Some(read) = self.next_chain_event_read() else {
                return;
            };
            let events = match self.execute_chain_event_read(read) {
                Ok(events) => events,
                Err(DkgError::ChainDataUnavailable { .. }) => return,
                Err(err) => {
                    self.metrics.chain_error();
                    warn!(
                        ?err,
                        epoch = read.session().epoch.0,
                        block = read.block().0,
                        "failed to read DKG chain state"
                    );
                    return;
                }
            };
            if let Err(err) = self.apply_chain_event_read(read, events) {
                self.metrics.protocol_error();
                error!(
                    ?err,
                    epoch = read.session().epoch.0,
                    block = read.block().0,
                    "failed to process DKG chain read"
                );
            }
        }
    }

    fn next_chain_event_read(&self) -> Option<ChainRead> {
        let finalized = self.latest_finalized?;
        self.sessions
            .iter()
            .flatten()
            .find_map(|session| session.next_read(finalized))
    }

    fn execute_chain_event_read(&self, read: ChainRead) -> Result<Vec<ChainEvent>, DkgError> {
        self.chain.io.read_events(read)
    }

    fn apply_chain_event_read(
        &mut self,
        read: ChainRead,
        events: Vec<ChainEvent>,
    ) -> Result<(), DkgError> {
        let epoch = read.session().epoch;
        let result_finalized = events
            .iter()
            .any(|event| matches!(event, ChainEvent::DkgResultRecorded { .. }));
        let session = self
            .sessions
            .iter_mut()
            .flatten()
            .find(|session| session.epoch == epoch)
            .ok_or(DkgError::NoActiveSession { epoch })?;
        let recovery_transition = session.complete_read(read);
        for event in events.iter().cloned() {
            session
                .protocol
                .handle_chain_event(event)
                .map_err(|err| DkgError::operation("handle DKG chain event", err))?;
        }
        if recovery_transition == RecoveryTransition::Completed {
            session
                .protocol
                .finish_chain_recovery()
                .map_err(|err| DkgError::operation("finish DKG chain recovery", err))?;
        }
        let effects = self.take_session_effects(epoch);
        // Apply the observed events before their engine-generated calls so
        // recovery cannot resubmit an effect that this same batch finalized.
        self.chain
            .submitter
            .finalized_block(epoch, read.block(), events);
        if result_finalized
            && self
                .latest_completed_epoch
                .is_none_or(|completed| epoch > completed)
        {
            self.latest_completed_epoch = Some(epoch);
            self.metrics.result_finalized();
        }
        self.dispatch_session_effects(epoch, effects);
        Ok(())
    }

    fn update_session_metrics(&self) {
        self.metrics.set_session_state(
            self.sessions.iter().flatten().count(),
            self.sessions
                .iter()
                .flatten()
                .map(|session| session.protocol.pending_retry_count())
                .sum(),
        );
    }
}

async fn wait_for_timer(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, time::Duration};

    use alloy_primitives::Address;
    use monad_crypto::{certificate_signature::CertificateKeyPair, NopKeyPair, NopSignature};

    use super::*;

    #[test]
    fn execution_sync_is_explicit_and_monotone() {
        let self_id = test_nodes(1).pop().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let chain: Arc<dyn DkgChain> = Arc::new(RecordingChain::default());
        let mut runner = DkgRunner::<NopSignature>::new(
            self_id,
            directory.path().to_path_buf(),
            DkgChainConfig::new([1; 32], Address::ZERO, 1),
            chain,
        )
        .unwrap();

        runner.notify_finalized(SeqNum(10));
        assert_eq!(runner.sync_block, None);

        runner.notify_sync_complete(SeqNum(10));
        runner.notify_sync_complete(SeqNum(9));
        runner.notify_sync_complete(SeqNum(10));
        assert_eq!(runner.sync_block, Some(SeqNum(10)));

        runner.notify_finalized(SeqNum(12));
        runner.notify_finalized(SeqNum(11));
        assert_eq!(runner.sync_block, Some(SeqNum(10)));

        runner.notify_sync_complete(SeqNum(11));
        assert_eq!(runner.sync_block, Some(SeqNum(11)));
    }

    #[test]
    fn execution_sync_anchors_epoch_scoped_registration_snapshot() {
        let nodes = test_nodes(4);
        let directory = tempfile::tempdir().unwrap();
        let chain: Arc<dyn DkgChain> = Arc::new(RecordingChain::default());
        let mut runner = DkgRunner::<NopSignature>::new(
            nodes[0],
            directory.path().to_path_buf(),
            DkgChainConfig::new([1; 32], Address::ZERO, 1),
            chain,
        )
        .unwrap();
        let validators = nodes
            .iter()
            .enumerate()
            .map(|(index, node_id)| DkgValidator::<NopSignature> {
                node_id: *node_id,
                address: Address::from([index as u8 + 1; 20]),
                stake: monad_types::Stake(alloy_primitives::U256::from(
                    crate::session::WEI_PER_MON,
                )),
            })
            .collect();

        runner
            .start_chain_registered_session(Epoch(2), validators)
            .unwrap();
        assert_eq!(
            runner.pending_registered_session.as_ref().unwrap().boundary,
            RegistrationBoundary::AwaitingFinalizedBlock
        );

        runner.notify_sync_complete(SeqNum(100));
        let pending = runner.pending_registered_session.as_ref().unwrap();
        assert!(pending.boundary == RegistrationBoundary::Finalized(SeqNum(100)));
    }

    #[test]
    fn newer_session_discards_stale_pending_registration_read() {
        let nodes = test_nodes(1);
        let directory = tempfile::tempdir().unwrap();
        let chain: Arc<dyn DkgChain> = Arc::new(RecordingChain::default());
        let mut runner = DkgRunner::<NopSignature>::new(
            nodes[0],
            directory.path().to_path_buf(),
            DkgChainConfig::new([1; 32], Address::ZERO, 1),
            chain,
        )
        .unwrap();
        let validators = || {
            vec![DkgValidator::<NopSignature> {
                node_id: nodes[0],
                address: Address::from([1; 20]),
                stake: monad_types::Stake(alloy_primitives::U256::from(
                    crate::session::WEI_PER_MON,
                )),
            }]
        };

        runner
            .start_chain_registered_session(Epoch(1), validators())
            .unwrap();
        runner
            .start_chain_registered_session(Epoch(2), validators())
            .unwrap();

        assert_eq!(
            runner
                .pending_registered_session
                .as_ref()
                .map(|pending| pending.epoch),
            Some(Epoch(2))
        );
    }

    #[test]
    fn registered_session_waits_for_chain_snapshot_and_execution_sync() {
        let nodes = test_nodes(4);
        let signing_key = [9; 32];
        let chain_config = DkgChainConfig::new(signing_key, Address::ZERO, 1);
        let addresses = [[4; 20], [1; 20], [3; 20], [2; 20]];
        let registrations = addresses
            .iter()
            .enumerate()
            .map(|(index, address)| {
                let keys = if index == 0 {
                    chain_config.local_keys.clone()
                } else {
                    DkgLocalKeyMaterial::derive([index as u8 + 20; 32])
                };
                keys.registration(Address::from(*address), Epoch(2))
                    .unwrap()
            })
            .collect();
        let chain = Arc::new(RegistrationChain {
            state: registrations,
        });
        let directory = tempfile::tempdir().unwrap();
        let mut runner = DkgRunner::<NopSignature>::new(
            nodes[0],
            directory.path().to_path_buf(),
            chain_config,
            chain,
        )
        .unwrap();
        let validators = nodes
            .iter()
            .zip(addresses)
            .map(|(node_id, address)| DkgValidator::<NopSignature> {
                node_id: *node_id,
                address: Address::from(address),
                stake: monad_types::Stake(alloy_primitives::U256::from(
                    crate::session::WEI_PER_MON,
                )),
            })
            .collect();

        runner.notify_finalized(SeqNum(100));
        runner
            .start_chain_registered_session(Epoch(2), validators)
            .unwrap();
        assert!(runner.sessions[1].is_none());
        runner.notify_sync_complete(SeqNum(90));

        assert_eq!(runner.latest_started_epoch, Some(Epoch(2)));
        assert!(runner
            .sessions
            .iter()
            .flatten()
            .any(|session| session.epoch == Epoch(2)));
    }

    #[test]
    fn local_registration_retries_until_finalized_state_confirms_it() {
        let nodes = test_nodes(1);
        let (transactions, transaction_rx) = flume::unbounded();
        let chain = Arc::new(LocalRegistrationChain {
            registration: Mutex::new(None),
            transactions,
        });
        let directory = tempfile::tempdir().unwrap();
        let mut runner = DkgRunner::<NopSignature>::new(
            nodes[0],
            directory.path().to_path_buf(),
            DkgChainConfig::new([9; 32], Address::ZERO, 1),
            chain.clone(),
        )
        .unwrap();
        runner.prepare_registration(Epoch(2));
        runner.notify_sync_complete(SeqNum(10));
        let first = transaction_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let (address, keys) = {
            let managed = &runner.chain;
            (managed.registration.address(), managed.local_keys.clone())
        };
        let registration =
            load_or_create_local_registration(directory.path(), Epoch(2), address, &keys, None)
                .unwrap();

        runner.notify_finalized(SeqNum(11));
        let retry = transaction_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(retry, first);

        *chain.registration.lock().unwrap() = Some(registration);
        runner.notify_finalized(SeqNum(12));
        runner.notify_finalized(SeqNum(13));
        assert!(transaction_rx.try_recv().is_err());
    }

    #[derive(Default)]
    struct RecordingChain {
        reads: Mutex<Vec<(bool, SeqNum)>>,
    }

    impl DkgChain for RecordingChain {
        fn read_registrations(
            &self,
            block: SeqNum,
            _epoch: Epoch,
            _parties: &[Address],
        ) -> Result<Vec<Option<RegistrationCall>>, crate::DkgError> {
            Err(crate::DkgError::ChainDataUnavailable { block })
        }

        fn read_events(
            &self,
            read: crate::chain::ChainRead,
        ) -> Result<Vec<dkg_protocol::ChainEvent>, crate::DkgError> {
            self.reads.lock().unwrap().push((
                matches!(read, crate::chain::ChainRead::Snapshot(_)),
                read.block(),
            ));
            Ok(Vec::new())
        }

        fn transaction_context(
            &self,
            _block: SeqNum,
            _address: Address,
        ) -> Result<crate::chain::DkgTransactionContext, crate::DkgError> {
            unreachable!()
        }

        fn submit_transaction(
            &self,
            _transaction: alloy_consensus::TxEnvelope,
        ) -> Result<(), crate::DkgError> {
            unreachable!()
        }
    }

    struct RegistrationChain {
        state: Vec<RegistrationCall>,
    }

    struct LocalRegistrationChain {
        registration: Mutex<Option<RegistrationCall>>,
        transactions: flume::Sender<alloy_consensus::TxEnvelope>,
    }

    impl DkgChain for LocalRegistrationChain {
        fn read_registrations(
            &self,
            _block: SeqNum,
            _epoch: Epoch,
            _parties: &[Address],
        ) -> Result<Vec<Option<RegistrationCall>>, crate::DkgError> {
            Ok(vec![*self.registration.lock().unwrap()])
        }

        fn read_events(
            &self,
            _read: crate::chain::ChainRead,
        ) -> Result<Vec<dkg_protocol::ChainEvent>, crate::DkgError> {
            Ok(Vec::new())
        }

        fn transaction_context(
            &self,
            _block: SeqNum,
            _address: Address,
        ) -> Result<crate::chain::DkgTransactionContext, crate::DkgError> {
            Ok(crate::chain::DkgTransactionContext {
                nonce: 0,
                base_fee_per_gas: 0,
            })
        }

        fn submit_transaction(
            &self,
            transaction: alloy_consensus::TxEnvelope,
        ) -> Result<(), crate::DkgError> {
            self.transactions
                .send(transaction)
                .map_err(|_| crate::DkgError::ChannelClosed("recording a test DKG transaction"))
        }
    }

    impl DkgChain for RegistrationChain {
        fn read_registrations(
            &self,
            _block: SeqNum,
            _epoch: Epoch,
            parties: &[Address],
        ) -> Result<Vec<Option<RegistrationCall>>, crate::DkgError> {
            Ok(parties
                .iter()
                .map(|party| {
                    self.state
                        .iter()
                        .find(|registration| Address::from(registration.address.0) == *party)
                        .copied()
                })
                .collect())
        }

        fn read_events(
            &self,
            _read: crate::chain::ChainRead,
        ) -> Result<Vec<dkg_protocol::ChainEvent>, crate::DkgError> {
            Ok(Vec::new())
        }

        fn transaction_context(
            &self,
            _block: SeqNum,
            _address: Address,
        ) -> Result<crate::chain::DkgTransactionContext, crate::DkgError> {
            unreachable!()
        }

        fn submit_transaction(
            &self,
            _transaction: alloy_consensus::TxEnvelope,
        ) -> Result<(), crate::DkgError> {
            unreachable!()
        }
    }

    fn test_nodes(count: u8) -> Vec<NodeId<CertificateSignaturePubKey<NopSignature>>> {
        (0..count)
            .map(|seed| {
                let mut bytes = [seed.saturating_add(1); 32];
                NodeId::new(NopKeyPair::from_bytes(&mut bytes).unwrap().pubkey())
            })
            .collect()
    }
}
