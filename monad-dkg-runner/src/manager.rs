use std::{collections::BTreeMap, mem, path::PathBuf, sync::Arc, time::Instant};

use bytes::Bytes;
use monad_crypto::certificate_signature::{
    CertificateSignaturePubKey, CertificateSignatureRecoverable,
};
use monad_types::{Epoch, NodeId, SeqNum};
use tracing::{debug, error, warn};

use crate::{
    chain::{read_chain, ChainEventBatch, ChainEventReader, ChainEventSession, TxSubmitter},
    protocol::runner::{start, Runner},
    registration::{assemble_registered_session, load_or_create_local_registration},
    session::DkgSessionConfig,
    transport::DkgManagerCommand,
    DeliveryOutbound, DkgChain, DkgChainConfig, DkgError, DkgLocalKeyMaterial,
    DkgLocalRegistrationState, DkgRegistration, DkgValidator,
};

const MAX_RETAINED_DKG_SESSIONS: usize = 2;

struct ManagedChain {
    io: Arc<dyn DkgChain>,
    contract: alloy_primitives::Address,
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

enum DkgManagerEvent<ST>
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

pub struct DkgManagerInbox<ST>
where
    ST: CertificateSignatureRecoverable,
{
    events: flume::Receiver<DkgManagerEvent<ST>>,
}

#[derive(Clone)]
pub struct DkgManagerHandle<ST>
where
    ST: CertificateSignatureRecoverable,
{
    events: flume::Sender<DkgManagerEvent<ST>>,
}

impl<ST> DkgManagerHandle<ST>
where
    ST: CertificateSignatureRecoverable,
{
    pub fn channel() -> (Self, DkgManagerInbox<ST>) {
        let (events, receiver) = flume::unbounded();
        (Self { events }, DkgManagerInbox { events: receiver })
    }

    fn send(&self, event: DkgManagerEvent<ST>) {
        if self.events.send(event).is_err() {
            warn!("DKG manager input channel closed");
        }
    }

    pub fn finalized(&self, block: SeqNum, epoch_length: SeqNum) {
        self.chain_progress(block, epoch_length, false);
    }

    pub fn sync_complete(&self, block: SeqNum, epoch_length: SeqNum) {
        self.chain_progress(block, epoch_length, true);
    }

    fn chain_progress(&self, block: SeqNum, epoch_length: SeqNum, sync_complete: bool) {
        self.send(DkgManagerEvent::ChainProgress {
            block,
            next_epoch: block.to_epoch(epoch_length) + Epoch(1),
            sync_complete,
        });
    }

    pub fn start_session(&self, epoch: Epoch, validators: Vec<DkgValidator<ST>>) {
        self.send(DkgManagerEvent::StartSession { epoch, validators });
    }

    pub fn network(&self, sender: NodeId<CertificateSignaturePubKey<ST>>, message: Bytes) {
        self.send(DkgManagerEvent::Network { sender, message });
    }
}

pub struct DkgManager<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    self_id: NodeId<CertificateSignaturePubKey<ST>>,
    storage_root: PathBuf,
    command_tx: flume::Sender<DkgManagerCommand>,
    command_rx: flume::Receiver<DkgManagerCommand>,
    pending_outbound: Vec<DeliveryOutbound<ST>>,
    sessions: BTreeMap<Epoch, Runner<ST>>,
    latest_started_epoch: Option<Epoch>,
    pending_registered_session: Option<(Epoch, PendingRegisteredSession<ST>)>,
    chain_session: Option<(Epoch, usize)>,
    sync_block: Option<SeqNum>,
    latest_finalized: Option<SeqNum>,
    chain: Option<ManagedChain>,
}

impl<ST> DkgManager<ST>
where
    ST: CertificateSignatureRecoverable + Send + Sync + 'static,
{
    pub fn new(self_id: NodeId<CertificateSignaturePubKey<ST>>, storage_root: PathBuf) -> Self {
        let (command_tx, command_rx) = flume::unbounded();
        Self {
            self_id,
            storage_root,
            command_tx,
            command_rx,
            pending_outbound: Vec::new(),
            sessions: BTreeMap::new(),
            latest_started_epoch: None,
            pending_registered_session: None,
            chain_session: None,
            sync_block: None,
            latest_finalized: None,
            chain: None,
        }
    }

    pub fn new_with_chain(
        self_id: NodeId<CertificateSignaturePubKey<ST>>,
        storage_root: PathBuf,
        config: DkgChainConfig,
        chain: Arc<dyn DkgChain>,
    ) -> Result<Self, DkgError> {
        let mut manager = Self::new(self_id, storage_root);
        let submitter = TxSubmitter::new(&config, Arc::clone(&chain))?;
        let registration = LocalRegistration::new(submitter.signer_address());
        manager.chain = Some(ManagedChain {
            io: chain,
            contract: config.contract,
            local_keys: config.local_keys,
            submitter,
            event_reader: ChainEventReader::default(),
            registration,
        });
        Ok(manager)
    }

    pub async fn run(
        mut self,
        inbox: DkgManagerInbox<ST>,
        outbound: flume::Sender<DeliveryOutbound<ST>>,
    ) -> Result<(), DkgError> {
        let events = inbox.events;
        let commands = self.command_rx.clone();
        loop {
            let timer = self.next_timer();
            tokio::select! {
                event = events.recv_async() => match event {
                    Ok(DkgManagerEvent::ChainProgress { block, next_epoch, sync_complete }) => {
                        self.prepare_registration(next_epoch);
                        if sync_complete {
                            self.notify_sync_complete(block);
                        } else {
                            self.notify_finalized(block);
                        }
                    }
                    Ok(DkgManagerEvent::StartSession { epoch, validators }) => {
                        if let Err(err) = self.start_chain_registered_session(epoch, validators) {
                            warn!(?err, epoch = epoch.0, "failed to start DKG session");
                        }
                    }
                    Ok(DkgManagerEvent::Network { sender, message }) => {
                        self.handle_network_message(sender, message)
                    }
                    Err(_) => return Ok(()),
                },
                command = commands.recv_async() => match command {
                    Ok(command) => self.handle_command(command),
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
        let Some(chain) = self.chain.as_mut() else {
            return;
        };
        if chain
            .registration
            .epoch
            .is_some_and(|current| current >= epoch)
        {
            return;
        }
        if let Some(previous) = chain.registration.epoch {
            chain.submitter.cancel_registration(previous);
        }
        chain.registration.start_epoch(epoch);
        self.schedule_local_registration_read();
    }

    /// Makes one more finalized block available to the active chain cursor.
    /// This never establishes or changes the recovery snapshot boundary.
    pub fn notify_finalized(&mut self, block: SeqNum) {
        if self.record_finalized_head(block) {
            self.schedule_pending_registration_reads();
            self.schedule_local_registration_read();
        }
        if let Some(chain) = self.chain.as_mut() {
            chain.event_reader.notify_finalized(block);
        }
        self.schedule_chain_read();
    }

    /// Establishes the exact chain-state boundary used for DKG recovery.
    ///
    /// Once a DKG session is known, the manager reads a snapshot at `block`
    /// and then scans every subsequently finalized block in order.
    pub fn notify_sync_complete(&mut self, block: SeqNum) {
        if self.sync_block.is_some_and(|current| current >= block) {
            return;
        }
        self.sync_block = Some(block);
        self.record_finalized_head(block);
        if let Some(chain) = self.chain.as_mut() {
            chain.event_reader.notify_finalized(block);
            if let Some((epoch, party_count)) = self.chain_session {
                chain.submitter.start_session(epoch);
                chain.event_reader.start_session(ChainEventSession {
                    epoch,
                    party_count,
                    recovery_block: block,
                });
            }
        }
        self.schedule_chain_read();
        self.schedule_pending_registration_reads();
        self.schedule_local_registration_read();
    }

    fn record_finalized_head(&mut self, block: SeqNum) -> bool {
        if self.latest_finalized.is_some_and(|latest| block <= latest) {
            return false;
        }
        self.latest_finalized = Some(block);
        if let Some((_, pending)) = self.pending_registered_session.as_mut() {
            if pending.registration_block.is_none() {
                pending.registration_block = Some(block);
            }
        }
        true
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
        if self.chain.is_none() {
            return Err(DkgError::Unsupported("DKG registration reads"));
        }
        self.pending_registered_session = Some((
            epoch,
            PendingRegisteredSession {
                validators,
                registration_block: self.latest_finalized,
            },
        ));
        self.schedule_pending_registration_reads();
        Ok(())
    }

    fn close_registration_window(&mut self, epoch: Epoch) {
        let Some(chain) = self.chain.as_mut() else {
            return;
        };
        if chain.registration.epoch == Some(epoch) {
            chain.submitter.cancel_registration(epoch);
            chain.registration.phase = LocalRegistrationPhase::Done;
        }
    }

    fn schedule_local_registration_read(&mut self) {
        if self.sync_block.is_none() {
            return;
        }
        loop {
            let Some(latest) = self.latest_finalized else {
                return;
            };
            let Some((epoch, block, result)) = self.chain.as_ref().and_then(|chain| {
                let registration = &chain.registration;
                let epoch = registration.epoch?;
                (registration.phase != LocalRegistrationPhase::Done).then(|| {
                    let block = registration.unavailable_block.unwrap_or(latest);
                    (
                        epoch,
                        block,
                        chain.io.read_local_registration(
                            block,
                            chain.contract,
                            epoch,
                            registration.address,
                        ),
                    )
                })
            }) else {
                return;
            };
            match result {
                Ok(Some(state)) => {
                    self.chain.as_mut().unwrap().registration.unavailable_block = None;
                    if let Err(err) = self.accept_local_registration_read(epoch, state) {
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
                Ok(None) => {
                    self.chain.as_mut().unwrap().registration.unavailable_block = Some(block);
                    return;
                }
                Err(err) => {
                    let registration = &mut self.chain.as_mut().unwrap().registration;
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
        state: DkgLocalRegistrationState,
    ) -> Result<(), DkgError> {
        let storage_root = self.storage_root.clone();
        let Some(chain) = self.chain.as_mut() else {
            return Ok(());
        };
        if chain.registration.epoch != Some(epoch) {
            return Ok(());
        }
        let observed = state.registration;
        let local_bytes = match load_or_create_local_registration(
            &storage_root,
            epoch,
            chain.registration.address.into_array(),
            chain.local_keys,
            observed.as_deref(),
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                chain.registration.phase = LocalRegistrationPhase::Done;
                return Err(DkgError::operation("load local DKG registration", err));
            }
        };

        if let Some(bytes) = observed {
            chain.registration.phase = LocalRegistrationPhase::Done;
            if bytes.as_ref() != local_bytes.as_slice() {
                return Err(DkgError::FinalizedRegistrationConflict {
                    address: chain.registration.address,
                });
            }
            chain.submitter.confirm_registration(epoch, &local_bytes);
        } else {
            match chain.registration.phase {
                LocalRegistrationPhase::Submitted => {
                    chain.submitter.retry_registration(epoch);
                }
                LocalRegistrationPhase::Open => {
                    chain.submitter.submit_registration(epoch, local_bytes);
                    chain.registration.phase = LocalRegistrationPhase::Submitted;
                }
                LocalRegistrationPhase::Done => {}
            }
        }

        self.schedule_pending_registration_reads();
        Ok(())
    }

    fn schedule_pending_registration_reads(&mut self) {
        if self.sync_block.is_none() {
            return;
        }
        let Some((io, contract)) = self
            .chain
            .as_ref()
            .map(|chain| (Arc::clone(&chain.io), chain.contract))
        else {
            return;
        };
        let Some((epoch, block)) = self
            .pending_registered_session
            .as_ref()
            .and_then(|(epoch, pending)| pending.registration_block.map(|block| (*epoch, block)))
        else {
            return;
        };
        match io.read_registered_parties(block, contract, epoch) {
            Ok(Some(state)) => {
                if let Err(err) = self.accept_registration_snapshot(epoch, state) {
                    error!(
                        ?err,
                        epoch = epoch.0,
                        block = block.0,
                        "failed to start registered DKG session"
                    );
                }
            }
            Ok(None) => {}
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
        registrations: Vec<DkgRegistration>,
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
        let local_keys = self
            .chain
            .as_ref()
            .expect("registered session requires chain integration")
            .local_keys;
        let registered =
            assemble_registered_session(epoch, pending.validators, local_keys, registrations)
                .map_err(|err| DkgError::operation("assemble registered DKG session", err))?;
        let config = DkgSessionConfig {
            epoch,
            validators: registered.validators,
            self_id: self.self_id,
            storage_root: self.storage_root.clone(),
            key_material: registered.key_material,
        };
        self.start_session_at(config, Some(recovery_block))
    }

    fn start_session_at(
        &mut self,
        config: DkgSessionConfig<ST>,
        recovery_block: Option<SeqNum>,
    ) -> Result<(), DkgError> {
        let epoch = config.epoch;
        let party_count = config.validators.len();
        if self
            .latest_started_epoch
            .is_some_and(|started| started >= epoch)
        {
            return Ok(());
        }
        let Some(mut runner) = start(
            config,
            self.command_tx.clone(),
            recovery_block.is_some() && self.chain.is_some(),
        )?
        else {
            self.latest_started_epoch = Some(epoch);
            return Ok(());
        };
        self.pending_outbound
            .extend(runner.take_delivery_outbound());
        self.latest_started_epoch = Some(epoch);
        self.sessions.insert(epoch, runner);
        self.start_chain_session(epoch, party_count, recovery_block);
        self.retire_old_sessions();
        Ok(())
    }

    fn start_chain_session(
        &mut self,
        epoch: Epoch,
        party_count: usize,
        recovery_block: Option<SeqNum>,
    ) {
        self.chain_session = Some((epoch, party_count));
        let Some(chain) = self.chain.as_mut() else {
            return;
        };
        chain.submitter.start_session(epoch);
        if let Some(recovery_block) = recovery_block {
            chain.event_reader.start_session(ChainEventSession {
                epoch,
                party_count,
                recovery_block,
            });
        }
        self.schedule_chain_read();
    }

    fn handle_command(&mut self, command: DkgManagerCommand) {
        let DkgManagerCommand { epoch, call } = command;
        if let Some(chain) = self.chain.as_mut() {
            chain.submitter.submit(epoch, call);
        }
    }

    pub fn handle_timer(&mut self, now: Instant) {
        for session in self.sessions.values_mut() {
            if session.next_timer().is_some_and(|deadline| deadline <= now) {
                if let Err(err) = session.handle_timer(now) {
                    error!(?err, "failed to process DKG retry timer");
                }
                self.pending_outbound
                    .extend(session.take_delivery_outbound());
            }
        }
    }

    pub fn handle_network_message(
        &mut self,
        sender: NodeId<CertificateSignaturePubKey<ST>>,
        message: Bytes,
    ) {
        for session in self.sessions.values_mut() {
            if let Err(err) = session.handle_network_message(sender, message.clone()) {
                error!(?err, ?sender, "failed to process DKG network message");
            }
            self.pending_outbound
                .extend(session.take_delivery_outbound());
        }
    }

    pub fn next_timer(&self) -> Option<Instant> {
        self.sessions.values().filter_map(Runner::next_timer).min()
    }

    /// Drains network output produced by direct manager operations.
    pub fn take_outbound(&mut self) -> Vec<DeliveryOutbound<ST>> {
        mem::take(&mut self.pending_outbound)
    }

    fn schedule_chain_read(&mut self) {
        loop {
            let Some((read, io, contract)) = self.chain.as_ref().and_then(|chain| {
                chain
                    .event_reader
                    .next_read()
                    .map(|read| (read, Arc::clone(&chain.io), chain.contract))
            }) else {
                return;
            };
            let events = match read_chain(io.as_ref(), contract, read) {
                Ok(Some(events)) => events,
                Ok(None) => return,
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
            let batch = match self
                .chain
                .as_mut()
                .expect("chain checked before blocking read")
                .event_reader
                .complete(read, events)
            {
                Ok(batch) => batch,
                Err(err) => {
                    error!(
                        ?err,
                        epoch = read.session().epoch.0,
                        block = read.block().0,
                        "failed to advance DKG chain reader"
                    );
                    return;
                }
            };
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
            .get_mut(&epoch)
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
        self.pending_outbound
            .extend(session.take_delivery_outbound());
        if let Some(chain) = self.chain.as_mut() {
            chain
                .submitter
                .finalized_block(epoch, batch.events, batch.recovery_complete_after);
        }
        Ok(())
    }

    fn retire_old_sessions(&mut self) {
        while self.sessions.len() > MAX_RETAINED_DKG_SESSIONS {
            self.sessions.pop_first().expect("excess DKG session");
        }
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
        let mut manager = DkgManager::<NopSignature>::new(self_id, directory.path().to_path_buf());

        manager.notify_finalized(SeqNum(10));
        assert_eq!(manager.sync_block, None);

        manager.notify_sync_complete(SeqNum(10));
        manager.notify_sync_complete(SeqNum(9));
        manager.notify_sync_complete(SeqNum(10));
        assert_eq!(manager.sync_block, Some(SeqNum(10)));

        manager.notify_finalized(SeqNum(12));
        manager.notify_finalized(SeqNum(11));
        assert_eq!(manager.sync_block, Some(SeqNum(10)));

        manager.notify_sync_complete(SeqNum(11));
        assert_eq!(manager.sync_block, Some(SeqNum(11)));
    }

    #[test]
    fn execution_sync_anchors_epoch_scoped_registration_snapshot() {
        let nodes = test_nodes(4);
        let directory = tempfile::tempdir().unwrap();
        let chain: Arc<dyn DkgChain> = Arc::new(RecordingChain::default());
        let mut manager = DkgManager::<NopSignature>::new_with_chain(
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
            })
            .collect();

        manager
            .start_chain_registered_session(Epoch(2), validators)
            .unwrap();
        assert_eq!(
            manager
                .pending_registered_session
                .as_ref()
                .unwrap()
                .1
                .registration_block,
            None
        );

        manager.notify_sync_complete(SeqNum(100));
        let (_, pending) = manager.pending_registered_session.as_ref().unwrap();
        assert_eq!(pending.registration_block, Some(SeqNum(100)));
    }

    #[test]
    fn newer_session_discards_stale_pending_registration_read() {
        let nodes = test_nodes(1);
        let directory = tempfile::tempdir().unwrap();
        let chain: Arc<dyn DkgChain> = Arc::new(RecordingChain::default());
        let mut manager = DkgManager::<NopSignature>::new_with_chain(
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
            }]
        };

        manager
            .start_chain_registered_session(Epoch(1), validators())
            .unwrap();
        manager
            .start_chain_registered_session(Epoch(2), validators())
            .unwrap();

        assert_eq!(
            manager
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
        let mut manager = DkgManager::<NopSignature>::new_with_chain(
            self_id,
            directory.path().to_path_buf(),
            DkgChainConfig::new([1; 32], Address::ZERO, 1),
            chain_adapter,
        )
        .unwrap();
        manager.notify_finalized(SeqNum(12));
        manager.start_chain_session(Epoch(2), 4, None);
        assert!(chain.reads.lock().unwrap().is_empty());

        manager.notify_sync_complete(SeqNum(10));

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
                    chain_config.local_keys
                } else {
                    DkgLocalKeyMaterial::derive([index as u8 + 20; 32])
                };
                crate::DkgRegistration {
                    address: Address::from(*address),
                    bytes: keys.registration_bytes(*address, 2).unwrap().into(),
                }
            })
            .collect();
        let chain = Arc::new(RegistrationChain {
            state: registrations,
        });
        let directory = tempfile::tempdir().unwrap();
        let mut manager = DkgManager::<NopSignature>::new_with_chain(
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
            })
            .collect();

        manager.notify_finalized(SeqNum(100));
        manager
            .start_chain_registered_session(Epoch(2), validators)
            .unwrap();
        assert!(manager.sessions.is_empty());
        manager.notify_sync_complete(SeqNum(90));

        assert_eq!(manager.latest_started_epoch, Some(Epoch(2)));
        assert!(manager.sessions.contains_key(&Epoch(2)));
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
        let mut manager = DkgManager::<NopSignature>::new_with_chain(
            nodes[0],
            directory.path().to_path_buf(),
            DkgChainConfig::new([9; 32], Address::ZERO, 1),
            chain.clone(),
        )
        .unwrap();
        manager.prepare_registration(Epoch(2));
        manager.notify_sync_complete(SeqNum(10));
        let first = transaction_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let (address, keys) = {
            let managed = manager.chain.as_ref().unwrap();
            (
                managed.registration.address.into_array(),
                managed.local_keys,
            )
        };
        let registration =
            load_or_create_local_registration(directory.path(), Epoch(2), address, keys, None)
                .unwrap();

        manager.notify_finalized(SeqNum(11));
        let retry = transaction_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(retry, first);

        *chain.registration.lock().unwrap() = Some(registration);
        manager.notify_finalized(SeqNum(12));
        manager.notify_finalized(SeqNum(13));
        assert!(transaction_rx.try_recv().is_err());
    }

    #[derive(Default)]
    struct RecordingChain {
        reads: Mutex<Vec<(bool, SeqNum)>>,
    }

    impl DkgChain for RecordingChain {
        fn read_recovery_state(
            &self,
            block: SeqNum,
            _contract: Address,
            _epoch: Epoch,
            _party_count: usize,
        ) -> Result<Option<Vec<dkg_protocol::ChainEvent>>, crate::DkgError> {
            self.reads.lock().unwrap().push((true, block));
            Ok(Some(Vec::new()))
        }

        fn read_finalized_events(
            &self,
            block: SeqNum,
            _contract: Address,
            _epoch: Epoch,
            _party_count: usize,
        ) -> Result<Option<Vec<dkg_protocol::ChainEvent>>, crate::DkgError> {
            self.reads.lock().unwrap().push((false, block));
            Ok(Some(Vec::new()))
        }
    }

    struct RegistrationChain {
        state: Vec<DkgRegistration>,
    }

    struct LocalRegistrationChain {
        registration: Mutex<Option<Vec<u8>>>,
        transactions: flume::Sender<alloy_consensus::TxEnvelope>,
    }

    impl DkgChain for LocalRegistrationChain {
        fn read_local_registration(
            &self,
            _block: SeqNum,
            _contract: Address,
            _epoch: Epoch,
            _party: Address,
        ) -> Result<Option<crate::DkgLocalRegistrationState>, crate::DkgError> {
            let state = crate::DkgLocalRegistrationState {
                registration: self.registration.lock().unwrap().clone().map(Into::into),
            };
            Ok(Some(state))
        }

        fn transaction_context(
            &self,
            _address: Address,
        ) -> Result<crate::DkgTransactionContext, crate::DkgError> {
            Ok(crate::DkgTransactionContext {
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
        fn read_local_registration(
            &self,
            _block: SeqNum,
            _contract: Address,
            _epoch: Epoch,
            _party: Address,
        ) -> Result<Option<crate::DkgLocalRegistrationState>, crate::DkgError> {
            Ok(Some(crate::DkgLocalRegistrationState {
                registration: None,
            }))
        }

        fn read_registered_parties(
            &self,
            _block: SeqNum,
            _contract: Address,
            _epoch: Epoch,
        ) -> Result<Option<Vec<DkgRegistration>>, crate::DkgError> {
            Ok(Some(self.state.clone()))
        }

        fn read_recovery_state(
            &self,
            _block: SeqNum,
            _contract: Address,
            _epoch: Epoch,
            _party_count: usize,
        ) -> Result<Option<Vec<dkg_protocol::ChainEvent>>, crate::DkgError> {
            Ok(Some(Vec::new()))
        }

        fn read_finalized_events(
            &self,
            _block: SeqNum,
            _contract: Address,
            _epoch: Epoch,
            _party_count: usize,
        ) -> Result<Option<Vec<dkg_protocol::ChainEvent>>, crate::DkgError> {
            Ok(Some(Vec::new()))
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
