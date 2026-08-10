use std::{mem, path::PathBuf, sync::Arc, time::Instant};

use alloy_rlp::{RlpDecodable, RlpEncodable};
use bytes::Bytes;
use dkg_protocol::RegistrationCall;
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId, SeqNum};
use tracing::{debug, error, warn};

use crate::{
    chain::{ChainEventBatch, ChainEventReader, ChainEventSession, DkgChain, TxSubmitter},
    registration::{assemble_registered_session, load_or_create_local_registration},
    reliable::ScheduledSend,
    session::{start, DkgSession},
    DkgChainConfig, DkgError, DkgLocalKeyMaterial, DkgValidator,
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
    event_reader: ChainEventReader,
    registration: LocalRegistration,
}

struct LocalRegistration {
    address: alloy_primitives::Address,
    epoch: Option<Epoch>,
    unavailable_block: Option<SeqNum>,
    phase: LocalRegistrationPhase,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LocalRegistrationPhase {
    Open,
    Submitted,
    Done,
}

impl LocalRegistration {
    fn new(address: alloy_primitives::Address) -> Self {
        Self {
            address,
            epoch: None,
            unavailable_block: None,
            phase: LocalRegistrationPhase::Done,
        }
    }

    fn start_epoch(&mut self, epoch: Epoch) {
        self.epoch = Some(epoch);
        self.unavailable_block = None;
        self.phase = LocalRegistrationPhase::Open;
    }
}

struct PendingRegisteredSession<ST>
where
    ST: CertificateSignatureRecoverable,
{
    validators: Vec<DkgValidator<ST>>,
    registration_block: Option<SeqNum>,
}

enum DkgRunnerEvent<ST>
where
    ST: CertificateSignatureRecoverable,
{
    ChainProgress {
        block: SeqNum,
        next_epoch: Epoch,
        sync_complete: bool,
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
        self.chain_progress(block, epoch_length, false);
    }

    pub fn sync_complete(&self, block: SeqNum, epoch_length: SeqNum) {
        self.chain_progress(block, epoch_length, true);
    }

    fn chain_progress(&self, block: SeqNum, epoch_length: SeqNum, sync_complete: bool) {
        self.send(DkgRunnerEvent::ChainProgress {
            block,
            next_epoch: block.to_epoch(epoch_length) + Epoch(1),
            sync_complete,
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
    sessions: [Option<(Epoch, DkgSession<ST>)>; 2],
    latest_started_epoch: Option<Epoch>,
    pending_registered_session: Option<(Epoch, PendingRegisteredSession<ST>)>,
    chain_session: Option<(Epoch, usize)>,
    sync_block: Option<SeqNum>,
    latest_finalized: Option<SeqNum>,
    chain: ManagedChain,
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
        let submitter = TxSubmitter::new(&config, Arc::clone(&chain))?;
        let registration = LocalRegistration::new(submitter.signer_address());
        Ok(Self {
            self_id,
            storage_root,
            pending_outbound: Vec::new(),
            sessions: [None, None],
            latest_started_epoch: None,
            pending_registered_session: None,
            chain_session: None,
            sync_block: None,
            latest_finalized: None,
            chain: ManagedChain {
                io: chain,
                local_keys: config.local_keys.clone(),
                submitter,
                event_reader: ChainEventReader::default(),
                registration,
            },
        })
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
                    Ok(DkgRunnerEvent::ChainProgress { block, next_epoch, sync_complete }) => {
                        self.prepare_registration(next_epoch);
                        if sync_complete {
                            self.notify_sync_complete(block);
                        } else {
                            self.notify_finalized(block);
                        }
                    }
                    Ok(DkgRunnerEvent::StartSession { epoch, validators }) => {
                        if let Err(err) = self.start_chain_registered_session(epoch, validators) {
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
                outbound
                    .send_async(message)
                    .await
                    .map_err(|_| DkgError::ChannelClosed("sending DKG network output"))?;
            }
        }
    }

    /// Opens local registration for the next validator epoch.
    ///
    /// Calls are monotone and idempotent. Advancing the target abandons any
    /// unfinalized registration transaction for the older epoch.
    pub fn prepare_registration(&mut self, epoch: Epoch) {
        if self
            .chain
            .registration
            .epoch
            .is_some_and(|current| current >= epoch)
        {
            return;
        }
        if let Some(previous) = self.chain.registration.epoch {
            self.chain.submitter.cancel_registration(previous);
        }
        self.chain.registration.start_epoch(epoch);
        self.settle_chain();
    }

    /// Makes one more finalized block available to the active chain cursor.
    /// This never establishes or changes the recovery snapshot boundary.
    pub fn notify_finalized(&mut self, block: SeqNum) {
        self.record_finalized_head(block);
        self.chain.event_reader.notify_finalized(block);
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
        self.chain.event_reader.notify_finalized(block);
        if let Some((epoch, party_count)) = self.chain_session {
            self.chain.event_reader.start_session(ChainEventSession {
                epoch,
                party_count,
                recovery_block: block,
            });
        }
        self.settle_chain();
    }

    fn record_finalized_head(&mut self, block: SeqNum) {
        if self.latest_finalized.is_some_and(|latest| block <= latest) {
            return;
        }
        self.latest_finalized = Some(block);
        if let Some((_, pending)) = self.pending_registered_session.as_mut() {
            if pending.registration_block.is_none() {
                pending.registration_block = Some(block);
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
                .is_some_and(|(pending, _)| *pending >= epoch)
        {
            return Ok(());
        }
        self.pending_registered_session = Some((
            epoch,
            PendingRegisteredSession {
                validators,
                registration_block: self.latest_finalized,
            },
        ));
        self.settle_chain();
        Ok(())
    }

    fn close_registration_window(&mut self, epoch: Epoch) {
        if self.chain.registration.epoch == Some(epoch) {
            self.chain.submitter.cancel_registration(epoch);
            self.chain.registration.phase = LocalRegistrationPhase::Done;
        }
    }

    fn settle_chain(&mut self) {
        self.reconcile_local_registration();
        self.start_pending_registered_session();
        self.read_chain_events();
    }

    fn reconcile_local_registration(&mut self) {
        if self.sync_block.is_none() {
            return;
        }
        loop {
            let Some(latest) = self.latest_finalized else {
                return;
            };
            let registration = &self.chain.registration;
            let Some(epoch) = registration.epoch else {
                return;
            };
            if registration.phase == LocalRegistrationPhase::Done {
                return;
            }
            let block = registration.unavailable_block.unwrap_or(latest);
            let result =
                self.chain
                    .io
                    .read_registrations(block, epoch, &[self.chain.registration.address]);
            match result {
                Ok(mut registrations) => {
                    self.chain.registration.unavailable_block = None;
                    debug_assert!(registrations.len() <= 1);
                    if let Err(err) =
                        self.accept_local_registration_read(epoch, block, registrations.pop())
                    {
                        error!(
                            ?err,
                            epoch = epoch.0,
                            block = block.0,
                            "failed to process local DKG registration state"
                        );
                        return;
                    }
                    if block >= latest {
                        return;
                    }
                }
                Err(DkgError::ChainDataUnavailable { .. }) => {
                    self.chain.registration.unavailable_block = Some(block);
                    return;
                }
                Err(err) => {
                    let registration = &mut self.chain.registration;
                    registration.unavailable_block = Some(block);
                    debug!(?err, epoch = epoch.0, block = block.0, party = %registration.address, "failed to read local DKG registration from finalized state");
                    return;
                }
            }
        }
    }

    fn accept_local_registration_read(
        &mut self,
        epoch: Epoch,
        block: SeqNum,
        observed: Option<RegistrationCall>,
    ) -> Result<(), DkgError> {
        let storage_root = self.storage_root.clone();
        if self.chain.registration.epoch != Some(epoch) {
            return Ok(());
        }
        let local_bytes = match load_or_create_local_registration(
            &storage_root,
            epoch,
            self.chain.registration.address.into_array(),
            &self.chain.local_keys,
            observed.as_ref(),
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.chain.registration.phase = LocalRegistrationPhase::Done;
                return Err(DkgError::operation("load local DKG registration", err));
            }
        };
        failpoint::failpoint!(
            name = "dkg.registration.loaded",
            description =
                "after durable local registration is loaded and before chain reconciliation",
        );

        if let Some(bytes) = observed {
            self.chain.registration.phase = LocalRegistrationPhase::Done;
            if bytes != local_bytes {
                return Err(DkgError::FinalizedRegistrationConflict {
                    address: self.chain.registration.address,
                });
            }
            self.chain
                .submitter
                .confirm_registration(epoch, &local_bytes);
        } else {
            match self.chain.registration.phase {
                LocalRegistrationPhase::Submitted => {
                    self.chain.submitter.retry_registration(epoch, block);
                }
                LocalRegistrationPhase::Open => {
                    self.chain
                        .submitter
                        .submit_registration(epoch, block, local_bytes);
                    self.chain.registration.phase = LocalRegistrationPhase::Submitted;
                }
                LocalRegistrationPhase::Done => {}
            }
        }
        Ok(())
    }

    fn start_pending_registered_session(&mut self) {
        if self.sync_block.is_none() {
            return;
        }
        let io = Arc::clone(&self.chain.io);
        let Some((epoch, block, parties)) =
            self.pending_registered_session
                .as_ref()
                .and_then(|(epoch, pending)| {
                    pending.registration_block.map(|block| {
                        let parties = pending
                            .validators
                            .iter()
                            .map(|validator| alloy_primitives::Address::from(validator.address))
                            .collect::<Vec<_>>();
                        (*epoch, block, parties)
                    })
                })
        else {
            return;
        };
        match io.read_registrations(block, epoch, &parties) {
            Ok(state) => {
                if let Err(err) = self.accept_registration_snapshot(epoch, state) {
                    error!(
                        ?err,
                        epoch = epoch.0,
                        block = block.0,
                        "failed to start registered DKG session"
                    );
                }
            }
            Err(DkgError::ChainDataUnavailable { .. }) => {}
            Err(err) => warn!(
                ?err,
                epoch = epoch.0,
                block = block.0,
                "failed to read finalized DKG registrations"
            ),
        }
    }

    fn accept_registration_snapshot(
        &mut self,
        epoch: Epoch,
        registrations: Vec<RegistrationCall>,
    ) -> Result<(), DkgError> {
        let Some((_, pending)) = self
            .pending_registered_session
            .take_if(|(pending_epoch, _)| *pending_epoch == epoch)
        else {
            return Ok(());
        };
        let recovery_block = pending
            .registration_block
            .expect("registration read has a finalized block");
        let local_keys = &self.chain.local_keys;
        let registered = assemble_registered_session(
            epoch,
            self.self_id,
            pending.validators,
            local_keys,
            registrations,
        )
        .map_err(|err| DkgError::operation("assemble registered DKG session", err))?;
        self.start_session_at(
            epoch,
            registered.validators,
            registered.key_material,
            Some(recovery_block),
        )
    }

    fn start_session_at(
        &mut self,
        epoch: Epoch,
        validators: Vec<DkgValidator<ST>>,
        key_material: crate::DkgRegisteredKeyMaterial,
        recovery_block: Option<SeqNum>,
    ) -> Result<(), DkgError> {
        let party_count = validators.len();
        if self
            .latest_started_epoch
            .is_some_and(|started| started >= epoch)
        {
            return Ok(());
        }
        let Some(session) = start(
            epoch,
            self.self_id,
            validators,
            &self.storage_root,
            key_material,
        )?
        else {
            self.latest_started_epoch = Some(epoch);
            return Ok(());
        };
        self.latest_started_epoch = Some(epoch);
        if let Some((retired_epoch, _)) = self.sessions[0].as_ref() {
            self.chain.submitter.retire_epoch(*retired_epoch);
        }
        self.sessions.rotate_left(1);
        self.sessions[1] = Some((epoch, session));
        self.start_chain_session(epoch, party_count, recovery_block);
        Ok(())
    }

    fn start_chain_session(
        &mut self,
        epoch: Epoch,
        party_count: usize,
        recovery_block: Option<SeqNum>,
    ) {
        self.chain_session = Some((epoch, party_count));
        if let Some(recovery_block) = recovery_block {
            self.chain.event_reader.start_session(ChainEventSession {
                epoch,
                party_count,
                recovery_block,
            });
        }
    }

    pub fn handle_timer(&mut self, now: Instant) {
        for index in 0..self.sessions.len() {
            let Some((epoch, session)) = &mut self.sessions[index] else {
                continue;
            };
            let epoch = *epoch;
            if session.next_timer().is_some_and(|deadline| deadline <= now) {
                if let Err(err) = session.handle_timer(now) {
                    error!(?err, "failed to process DKG retry timer");
                }
                self.collect_session_effects(epoch);
            }
        }
    }

    pub fn handle_network_message(
        &mut self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        message: Bytes,
    ) {
        let wire: DeliveryEnvelope = match message.as_ref().try_into() {
            Ok(wire) => wire,
            Err(err) => {
                warn!(?err, ?sender, "dropping malformed DKG delivery message");
                return;
            }
        };
        let epoch = Epoch(wire.epoch);
        let Some((_, session)) = self
            .sessions
            .iter_mut()
            .flatten()
            .find(|(session_epoch, _)| *session_epoch == epoch)
        else {
            return;
        };
        if let Err(err) = session.handle_network_message(sender, wire.payload) {
            error!(?err, ?sender, "failed to process DKG network message");
        }
        self.collect_session_effects(epoch);
    }

    pub fn next_timer(&self) -> Option<Instant> {
        self.sessions
            .iter()
            .flatten()
            .filter_map(|(_, session)| session.next_timer())
            .min()
    }

    /// Drains network output produced by direct runner operations.
    pub fn take_outbound(&mut self) -> Vec<DeliveryOutbound<ST>> {
        mem::take(&mut self.pending_outbound)
    }

    fn collect_session_effects(&mut self, epoch: Epoch) {
        let calls = self.take_session_effects(epoch);
        self.submit_chain_calls(epoch, calls);
    }

    fn take_session_effects(&mut self, epoch: Epoch) -> Vec<dkg_protocol::ChainCall> {
        let Some((_, session)) = self
            .sessions
            .iter_mut()
            .flatten()
            .find(|(session_epoch, _)| *session_epoch == epoch)
        else {
            return Vec::new();
        };
        self.pending_outbound
            .extend(session.take_delivery_outbound());
        session.take_chain_calls()
    }

    fn submit_chain_calls(&mut self, epoch: Epoch, calls: Vec<dkg_protocol::ChainCall>) {
        // DkgSession exposes no engine effects until chain recovery finishes,
        // so transaction submission does not need a second recovery gate.
        for call in calls {
            failpoint::failpoint!(
                name = "dkg.chain.call_buffered",
                description =
                    "after a DKG chain call is buffered and before transaction submission",
            );
            self.chain.submitter.submit(epoch, call);
        }
    }

    fn read_chain_events(&mut self) {
        loop {
            let Some(read) = self.chain.event_reader.next_read() else {
                return;
            };
            let events = match self.chain.io.read_events(read) {
                Ok(events) => events,
                Err(DkgError::ChainDataUnavailable { .. }) => return,
                Err(err) => {
                    warn!(
                        ?err,
                        epoch = read.session().epoch.0,
                        block = read.block().0,
                        "failed to read DKG chain state"
                    );
                    return;
                }
            };
            let batch = self.chain.event_reader.complete(read, events);
            if let Err(err) = self.accept_chain_batch(batch) {
                error!(
                    ?err,
                    epoch = read.session().epoch.0,
                    block = read.block().0,
                    "failed to process DKG chain read"
                );
            }
        }
    }

    fn accept_chain_batch(&mut self, batch: ChainEventBatch) -> Result<(), DkgError> {
        let epoch = batch.session.epoch;
        let session = self
            .sessions
            .iter_mut()
            .flatten()
            .find(|(session_epoch, _)| *session_epoch == epoch)
            .map(|(_, session)| session)
            .ok_or(DkgError::NoActiveSession { epoch: epoch.0 })?;
        for event in batch.events.iter().cloned() {
            session
                .handle_chain_event(event)
                .map_err(|err| DkgError::operation("handle DKG chain event", err))?;
        }
        if batch.recovery_complete_after {
            session
                .finish_chain_recovery()
                .map_err(|err| DkgError::operation("finish DKG chain recovery", err))?;
        }
        let calls = self.take_session_effects(epoch);
        // Apply the observed events before their engine-generated calls so
        // recovery cannot resubmit an effect that this same batch finalized.
        self.chain
            .submitter
            .finalized_block(epoch, batch.block, batch.events);
        self.submit_chain_calls(epoch, calls);
        Ok(())
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
                address: [index as u8 + 1; 20],
                stake: monad_types::Stake(alloy_primitives::U256::from(
                    crate::session::WEI_PER_MON,
                )),
            })
            .collect();

        runner
            .start_chain_registered_session(Epoch(2), validators)
            .unwrap();
        assert_eq!(
            runner
                .pending_registered_session
                .as_ref()
                .unwrap()
                .1
                .registration_block,
            None
        );

        runner.notify_sync_complete(SeqNum(100));
        let (_, pending) = runner.pending_registered_session.as_ref().unwrap();
        assert_eq!(pending.registration_block, Some(SeqNum(100)));
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
                address: [1; 20],
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
                .map(|(epoch, _)| *epoch),
            Some(Epoch(2))
        );
    }

    #[test]
    fn boundary_waits_for_sync_then_reads_through_finalized_head() {
        let self_id = test_nodes(1).pop().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let chain = Arc::new(RecordingChain::default());
        let chain_adapter: Arc<dyn DkgChain> = chain.clone();
        let mut runner = DkgRunner::<NopSignature>::new(
            self_id,
            directory.path().to_path_buf(),
            DkgChainConfig::new([1; 32], Address::ZERO, 1),
            chain_adapter,
        )
        .unwrap();
        runner.notify_finalized(SeqNum(12));
        runner.start_chain_session(Epoch(2), 4, None);
        assert!(chain.reads.lock().unwrap().is_empty());

        runner.notify_sync_complete(SeqNum(10));

        assert_eq!(
            *chain.reads.lock().unwrap(),
            vec![(true, SeqNum(10)), (false, SeqNum(11)), (false, SeqNum(12))]
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
                keys.registration(*address, 2).unwrap()
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
                address,
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
            .any(|(epoch, _)| *epoch == Epoch(2)));
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
            (
                managed.registration.address.into_array(),
                managed.local_keys.clone(),
            )
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
        ) -> Result<Vec<RegistrationCall>, crate::DkgError> {
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
        ) -> Result<Vec<RegistrationCall>, crate::DkgError> {
            Ok(self.registration.lock().unwrap().iter().copied().collect())
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
        ) -> Result<Vec<RegistrationCall>, crate::DkgError> {
            Ok(self
                .state
                .iter()
                .filter(|registration| parties.contains(&Address::from(registration.address.0)))
                .copied()
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
