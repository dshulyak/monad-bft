use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Write},
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use bytes::{BufMut, Bytes, BytesMut};
use dkg_protocol::DkgMessageId;
use monad_types::Epoch;
use thiserror::Error;

use super::record::{
    DeliveryCompletionRecord, EngineSeed, IncomingMessageRecord, OutgoingMessageRecord,
    RecoveryRecord, WalCodecError, ENGINE_SEED_BYTES,
};
const DEFAULT_MAX_EPOCHS: usize = 2;
const PREALLOCATE_ENV: &str = "MONAD_DKG_RECOVERY_WAL_PREALLOCATE_BYTES";
const WAL_RECORD_MAGIC: &[u8; 4] = b"DKGW";
const WAL_RECORD_HEADER_LEN: usize = 25;
const WAL_RECORD_CHECKSUM_LEN: usize = 16;
const MAX_WAL_RECORD_PAYLOAD_BYTES: u32 = 64 * 1024 * 1024;
const WAL_PREALLOCATE_ALIGNMENT: u64 = 4096;
pub(crate) const DEFAULT_RECOVERY_WAL_PREALLOCATE_BYTES: u64 =
    (MAX_WAL_RECORD_PAYLOAD_BYTES as u64 + WAL_RECORD_HEADER_LEN as u64)
        .div_ceil(WAL_PREALLOCATE_ALIGNMENT)
        * WAL_PREALLOCATE_ALIGNMENT;

#[derive(Debug, Error)]
pub(crate) enum RecoveryWalError {
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
    #[error("encode DKG recovery WAL record failed: {0}")]
    Encode(#[source] WalCodecError),
    #[error("decode DKG recovery WAL {path} record at offset {offset} failed: {source}")]
    Decode {
        path: PathBuf,
        offset: usize,
        #[source]
        source: WalCodecError,
    },
    #[error("create DKG registration failed")]
    Registration(#[source] Box<crate::DkgError>),
    #[error("DKG recovery WAL preallocation size {bytes} exceeds off_t range for {path}")]
    PreallocationSize { bytes: u64, path: PathBuf },
    #[cfg(not(target_os = "linux"))]
    #[error("DKG recovery WAL preallocation requires Linux fallocate syscall for {0}")]
    UnsupportedPreallocation(PathBuf),
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> RecoveryWalError {
    RecoveryWalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn encode_frame(record: &RecoveryRecord) -> Result<Bytes, WalCodecError> {
    let (kind, payload) = record.encode()?;
    let len =
        u32::try_from(payload.len()).map_err(|_| WalCodecError::LengthOverflow("WAL payload"))?;
    if len > MAX_WAL_RECORD_PAYLOAD_BYTES {
        return Err(WalCodecError::Invalid("oversized WAL payload"));
    }
    let mut frame = BytesMut::with_capacity(WAL_RECORD_HEADER_LEN + payload.len());
    frame.put_slice(WAL_RECORD_MAGIC);
    frame.put_u8(kind);
    frame.put_u32_le(len);
    frame.put_slice(&checksum(kind, len, &payload));
    frame.put_slice(&payload);
    Ok(frame.freeze())
}

fn checksum(kind: u8, len: u32, payload: &[u8]) -> [u8; WAL_RECORD_CHECKSUM_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WAL_RECORD_MAGIC);
    hasher.update(&[kind]);
    hasher.update(&len.to_le_bytes());
    hasher.update(payload);
    hasher.finalize().as_bytes()[..WAL_RECORD_CHECKSUM_LEN]
        .try_into()
        .unwrap()
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
    path: PathBuf,
    file: File,
}

impl RecoveryWal {
    pub(crate) fn open(
        root: &Path,
        epoch: Epoch,
        config: RecoveryWalConfig,
    ) -> Result<(Self, RecoveryState), RecoveryWalError> {
        fs::create_dir_all(root).map_err(|err| io_error("create root for", root, err))?;
        retain_recent_epoch_wals(root, epoch, config.max_epochs)?;

        let path = recovery_wal_path(root, epoch);
        let existed = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(&path)
            .map_err(|err| io_error("open", &path, err))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| io_error("secure", &path, err))?;
        if !existed && config.preallocate_bytes > 0 {
            preallocate_empty_file(&file, &path, config.preallocate_bytes)?;
        }
        let (records, valid_len) = scan_wal_records(&path)?;
        repair_wal_tail(&path, &file, valid_len)?;
        let recovery = RecoveryState::from_records(records)?;

        Ok((Self { path, file }, recovery))
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn append(&mut self, entry: &RecoveryRecord) -> Result<(), RecoveryWalError> {
        let frame = encode_frame(entry).map_err(RecoveryWalError::Encode)?;
        self.file
            .write_all(&frame)
            .map_err(|err| io_error("append", &self.path, err))?;
        self.file
            .flush()
            .map_err(|err| io_error("flush", &self.path, err))?;
        self.file
            .sync_data()
            .map_err(|err| io_error("sync", &self.path, err))
    }
}

#[derive(Debug, Default)]
pub(crate) struct RecoveryState {
    pub(crate) engine_seed: Option<EngineSeed>,
    pub(crate) registration: Option<Bytes>,
    pub(crate) outbox: BTreeMap<DkgMessageId, OutgoingMessageRecord>,
    pub(crate) incoming: BTreeSet<IncomingMessageRecord>,
    pub(crate) delivery_completions: BTreeSet<DeliveryCompletionRecord>,
}

impl RecoveryState {
    #[cfg(test)]
    pub(crate) fn load(path: &Path) -> Result<Self, RecoveryWalError> {
        Self::from_records(scan_wal_records(path)?.0)
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
                RecoveryRecord::Completion(record) => {
                    state.delivery_completions.insert(record);
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
        if !self.outbox.is_empty()
            || !self.incoming.is_empty()
            || !self.delivery_completions.is_empty()
        {
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

fn repair_wal_tail(path: &Path, file: &File, valid_len: u64) -> Result<(), RecoveryWalError> {
    let current_len = file
        .metadata()
        .map_err(|err| io_error("read metadata for", path, err))?
        .len();
    if valid_len == current_len {
        return Ok(());
    }
    file.set_len(valid_len)
        .map_err(|err| io_error("truncate torn", path, err))?;
    file.sync_data()
        .map_err(|err| io_error("sync truncated", path, err))
}

fn scan_wal_records(path: &Path) -> Result<(Vec<RecoveryRecord>, u64), RecoveryWalError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => Bytes::from(bytes),
        Err(err) if err.kind() == ErrorKind::NotFound => Bytes::new(),
        Err(err) => return Err(io_error("read", path, err)),
    };
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while bytes.len().saturating_sub(offset) >= WAL_RECORD_HEADER_LEN {
        let header = &bytes[offset..offset + WAL_RECORD_HEADER_LEN];
        if &header[..4] != WAL_RECORD_MAGIC {
            break;
        }
        let kind = header[4];
        let len = u32::from_le_bytes(header[5..9].try_into().unwrap());
        let total_len = WAL_RECORD_HEADER_LEN + len as usize;
        if total_len > bytes.len() - offset || len > MAX_WAL_RECORD_PAYLOAD_BYTES {
            break;
        }
        let payload_start = offset + WAL_RECORD_HEADER_LEN;
        let payload = bytes.slice(payload_start..offset + total_len);
        if header[9..WAL_RECORD_HEADER_LEN] != checksum(kind, len, &payload) {
            break;
        }
        records.push(RecoveryRecord::decode(kind, payload).map_err(|source| {
            RecoveryWalError::Decode {
                path: path.to_path_buf(),
                offset,
                source,
            }
        })?);
        offset += total_len;
    }
    Ok((records, offset as u64))
}

pub(crate) fn recovery_wal_path(root: &Path, epoch: Epoch) -> PathBuf {
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

#[cfg(target_os = "linux")]
fn preallocate_empty_file(file: &File, path: &Path, bytes: u64) -> Result<(), RecoveryWalError> {
    let len = libc::off_t::try_from(bytes).map_err(|_| RecoveryWalError::PreallocationSize {
        bytes,
        path: path.to_path_buf(),
    })?;
    let status = unsafe {
        libc::syscall(
            libc::SYS_fallocate,
            file.as_raw_fd(),
            libc::FALLOC_FL_KEEP_SIZE,
            0 as libc::off_t,
            len,
        )
    };
    if status == 0 {
        return Ok(());
    }
    Err(io_error(
        "preallocate with fallocate",
        path,
        io::Error::last_os_error(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn preallocate_empty_file(_file: &File, path: &Path, _bytes: u64) -> Result<(), RecoveryWalError> {
    Err(RecoveryWalError::UnsupportedPreallocation(
        path.to_path_buf(),
    ))
}

#[cfg(test)]
#[path = "wal_tests.rs"]
mod tests;
