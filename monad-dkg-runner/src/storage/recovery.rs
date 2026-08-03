//! DKG recovery policy layered on the generic append-only WAL.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};

use bytes::Bytes;
use dkg_protocol::DkgMessageId;
use monad_types::Epoch;
use thiserror::Error;

use super::record::{
    EngineSeed, IncomingMessageRecord, OutgoingMessageRecord, RecoveryRecord, WalCodecError,
    ENGINE_SEED_BYTES,
};
use crate::wal::{DurableWal, WalConfig, WalError, FRAME_HEADER_LEN};

const DEFAULT_MAX_EPOCHS: usize = 2;
const PREALLOCATE_ENV: &str = "MONAD_DKG_RECOVERY_WAL_PREALLOCATE_BYTES";
const MAX_RECOVERY_RECORD_BYTES: u32 = 64 * 1024 * 1024 + 1;
const WAL_PREALLOCATE_ALIGNMENT: u64 = 4096;
pub(crate) const DEFAULT_RECOVERY_WAL_PREALLOCATE_BYTES: u64 = (MAX_RECOVERY_RECORD_BYTES as u64
    + FRAME_HEADER_LEN as u64)
    .div_ceil(WAL_PREALLOCATE_ALIGNMENT)
    * WAL_PREALLOCATE_ALIGNMENT;

#[derive(Debug, Error)]
pub(crate) enum RecoveryWalError {
    #[error(transparent)]
    Wal(#[from] WalError<WalCodecError>),
    #[error("{operation} DKG recovery WAL {path} failed: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("generate DKG engine seed failed: {0}")]
    Random(#[source] getrandom::Error),
    #[error("DKG recovery WAL contains protocol records but no engine seed")]
    MissingSeed,
    #[error("conflicting DKG engine seed records in recovery WAL")]
    ConflictingSeed,
    #[error("conflicting DKG registration records in recovery WAL")]
    ConflictingRegistration,
    #[error("empty DKG registration record in recovery WAL")]
    EmptyRegistration,
    #[error("conflicting DKG outbox records for message ID {0:?}")]
    ConflictingOutbox(DkgMessageId),
    #[error("create DKG registration failed")]
    Registration(#[source] Box<crate::DkgError>),
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> RecoveryWalError {
    RecoveryWalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryWalConfig {
    pub(crate) preallocate_bytes: u64,
    pub(crate) max_epochs: usize,
}

impl Default for RecoveryWalConfig {
    fn default() -> Self {
        let preallocate_bytes = std::env::var(PREALLOCATE_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_RECOVERY_WAL_PREALLOCATE_BYTES);
        Self {
            preallocate_bytes,
            max_epochs: DEFAULT_MAX_EPOCHS,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RecoveryWal {
    wal: DurableWal<RecoveryRecord>,
}

impl RecoveryWal {
    pub(crate) fn open(
        root: &Path,
        epoch: Epoch,
        config: RecoveryWalConfig,
    ) -> Result<(Self, RecoveryState), RecoveryWalError> {
        fs::create_dir_all(root).map_err(|err| io_error("create root for", root, err))?;
        retain_recent_epoch_wals(root, epoch, config.max_epochs)?;
        let (wal, records) = DurableWal::open(
            &recovery_wal_path(root, epoch),
            WalConfig {
                max_record_bytes: MAX_RECOVERY_RECORD_BYTES,
                preallocate_bytes: config.preallocate_bytes,
            },
        )?;
        Ok((Self { wal }, RecoveryState::from_records(records)?))
    }

    pub(super) fn append(&mut self, record: &RecoveryRecord) -> Result<(), RecoveryWalError> {
        self.wal.append(record).map_err(Into::into)
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        self.wal.path()
    }
}

#[derive(Debug, Default)]
pub(crate) struct RecoveryState {
    pub(crate) engine_seed: Option<EngineSeed>,
    pub(crate) registration: Option<Bytes>,
    pub(crate) outbox: BTreeMap<DkgMessageId, OutgoingMessageRecord>,
    pub(crate) incoming: BTreeSet<IncomingMessageRecord>,
}

impl RecoveryState {
    #[cfg(test)]
    pub(crate) fn load(path: &Path) -> Result<Self, RecoveryWalError> {
        Self::from_records(DurableWal::read(path, MAX_RECOVERY_RECORD_BYTES)?)
    }

    fn from_records(records: Vec<RecoveryRecord>) -> Result<Self, RecoveryWalError> {
        let mut state = Self::default();
        for record in records {
            match record {
                RecoveryRecord::Seed(seed) => state.insert_engine_seed(seed)?,
                RecoveryRecord::Registration(registration) => {
                    state.insert_registration(registration)?
                }
                RecoveryRecord::Outgoing(record) => state.insert_outbox(record)?,
                RecoveryRecord::Incoming(record) => {
                    state.incoming.insert(record);
                }
            }
        }
        Ok(state)
    }

    pub(crate) fn load_or_create_engine_seed(
        &mut self,
        wal: &mut RecoveryWal,
    ) -> Result<EngineSeed, RecoveryWalError> {
        if let Some(seed) = self.engine_seed {
            return Ok(seed);
        }
        if !self.outbox.is_empty() || !self.incoming.is_empty() {
            return Err(RecoveryWalError::MissingSeed);
        }

        let mut seed = [0; ENGINE_SEED_BYTES];
        getrandom::getrandom(&mut seed).map_err(RecoveryWalError::Random)?;
        wal.append(&RecoveryRecord::Seed(seed))?;
        self.engine_seed = Some(seed);
        Ok(seed)
    }

    pub(crate) fn load_or_create_registration(
        &mut self,
        wal: &mut RecoveryWal,
        create: impl FnOnce() -> Result<Vec<u8>, crate::DkgError>,
    ) -> Result<Vec<u8>, RecoveryWalError> {
        if let Some(registration) = &self.registration {
            return Ok(registration.to_vec());
        }
        let registration =
            Bytes::from(create().map_err(|err| RecoveryWalError::Registration(Box::new(err)))?);
        if registration.is_empty() {
            return Err(RecoveryWalError::EmptyRegistration);
        }
        wal.append(&RecoveryRecord::Registration(registration.clone()))?;
        self.registration = Some(registration.clone());
        Ok(registration.to_vec())
    }

    fn insert_engine_seed(&mut self, seed: EngineSeed) -> Result<(), RecoveryWalError> {
        match self.engine_seed {
            Some(existing) if existing != seed => Err(RecoveryWalError::ConflictingSeed),
            Some(_) => Ok(()),
            None => {
                self.engine_seed = Some(seed);
                Ok(())
            }
        }
    }

    fn insert_registration(&mut self, registration: Bytes) -> Result<(), RecoveryWalError> {
        match &self.registration {
            Some(existing) if existing != &registration => {
                Err(RecoveryWalError::ConflictingRegistration)
            }
            Some(_) => Ok(()),
            None if registration.is_empty() => Err(RecoveryWalError::EmptyRegistration),
            None => {
                self.registration = Some(registration);
                Ok(())
            }
        }
    }

    fn insert_outbox(&mut self, record: OutgoingMessageRecord) -> Result<(), RecoveryWalError> {
        let Some(existing) = self.outbox.get_mut(&record.message_id) else {
            self.outbox.insert(record.message_id.clone(), record);
            return Ok(());
        };
        if existing.payload != record.payload {
            return Err(RecoveryWalError::ConflictingOutbox(record.message_id));
        }
        existing.recipients.extend(record.recipients);
        Ok(())
    }
}

fn recovery_wal_path(root: &Path, epoch: Epoch) -> PathBuf {
    root.join(format!("dkg-recovery-{}.wal", epoch.0))
}

pub(crate) fn recovery_epochs(root: &Path) -> Result<Vec<Epoch>, RecoveryWalError> {
    Ok(recovery_wals(root)?
        .into_iter()
        .map(|(epoch, _)| epoch)
        .collect())
}

fn retain_recent_epoch_wals(
    root: &Path,
    current_epoch: Epoch,
    max_epochs: usize,
) -> Result<(), RecoveryWalError> {
    if max_epochs == 0 {
        return Ok(());
    }
    let epochs = recovery_wals(root)?;
    let newer_count = epochs
        .iter()
        .filter(|(epoch, _)| *epoch > current_epoch)
        .count();
    let previous_to_keep = max_epochs.saturating_sub(1 + newer_count);
    let expired = epochs
        .into_iter()
        .rev()
        .filter(|(epoch, _)| *epoch < current_epoch)
        .skip(previous_to_keep);
    for (_, path) in expired {
        fs::remove_file(&path).map_err(|err| io_error("remove old", &path, err))?;
    }
    Ok(())
}

fn recovery_wals(root: &Path) -> Result<Vec<(Epoch, PathBuf)>, RecoveryWalError> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(io_error("read root for", root, err)),
    };
    let mut epochs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| io_error("read root entry for", root, err))?;
        let Some(epoch) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix("dkg-recovery-"))
            .and_then(|name| name.strip_suffix(".wal"))
            .and_then(|epoch| epoch.parse::<u64>().ok())
            .map(Epoch)
        else {
            continue;
        };
        epochs.push((epoch, entry.path()));
    }
    epochs.sort_unstable_by_key(|(epoch, _)| *epoch);
    Ok(epochs)
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
