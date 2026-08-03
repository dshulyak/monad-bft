//! Generic crash-safe append-only log.

use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Write},
    marker::PhantomData,
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use bytes::{Buf, BufMut};
use thiserror::Error;
use zeroize::Zeroizing;

const CHECKSUM_LEN: usize = 16;
pub(crate) const FRAME_HEADER_LEN: usize = 4 + size_of::<u32>() + CHECKSUM_LEN;

pub(crate) trait WalRecord: Sized {
    type Error: Error + Send + Sync + 'static;

    const MAGIC: [u8; 4];

    fn encode<B: BufMut>(&self, output: &mut B) -> Result<(), Self::Error>;

    fn decode<B: Buf>(input: &mut B) -> Result<Self, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WalConfig {
    pub(crate) max_record_bytes: u32,
    pub(crate) preallocate_bytes: u64,
}

#[derive(Debug, Error)]
pub(crate) enum WalError<E>
where
    E: Error + Send + Sync + 'static,
{
    #[error("{operation} WAL {path} failed: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("encode WAL record failed: {0}")]
    Encode(#[source] E),
    #[error("decode WAL {path} record at offset {offset} failed: {source}")]
    Decode {
        path: PathBuf,
        offset: usize,
        #[source]
        source: E,
    },
    #[error("WAL record is {bytes} bytes; maximum supported is {maximum}")]
    RecordTooLarge { bytes: usize, maximum: u32 },
    #[error("WAL preallocation size {bytes} exceeds off_t range for {path}")]
    PreallocationSize { bytes: u64, path: PathBuf },
    #[cfg(not(target_os = "linux"))]
    #[error("WAL preallocation requires Linux fallocate syscall for {0}")]
    UnsupportedPreallocation(PathBuf),
}

impl<E> WalError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DurableWal<R>
where
    R: WalRecord,
{
    path: PathBuf,
    file: File,
    config: WalConfig,
    record: PhantomData<fn() -> R>,
}

impl<R> DurableWal<R>
where
    R: WalRecord,
{
    pub(crate) fn open(
        path: &Path,
        config: WalConfig,
    ) -> Result<(Self, Vec<R>), WalError<R::Error>> {
        let existed = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)
            .map_err(|err| WalError::io("open", path, err))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| WalError::io("secure", path, err))?;
        if !existed && config.preallocate_bytes > 0 {
            preallocate_empty_file(&file, path, config.preallocate_bytes)?;
        }
        let (records, valid_len) = scan_records::<R>(path, config.max_record_bytes)?;
        repair_tail(path, &file, valid_len)?;

        Ok((
            Self {
                path: path.to_path_buf(),
                file,
                config,
                record: PhantomData,
            },
            records,
        ))
    }

    #[cfg(test)]
    pub(crate) fn read(path: &Path, max_record_bytes: u32) -> Result<Vec<R>, WalError<R::Error>> {
        scan_records::<R>(path, max_record_bytes).map(|(records, _)| records)
    }

    pub(crate) fn append(&mut self, record: &R) -> Result<(), WalError<R::Error>> {
        let mut payload = Zeroizing::new(Vec::new());
        record.encode(&mut *payload).map_err(WalError::Encode)?;
        let len = u32::try_from(payload.len()).map_err(|_| WalError::RecordTooLarge {
            bytes: payload.len(),
            maximum: self.config.max_record_bytes,
        })?;
        if len > self.config.max_record_bytes {
            return Err(WalError::RecordTooLarge {
                bytes: payload.len(),
                maximum: self.config.max_record_bytes,
            });
        }

        self.write_all(&R::MAGIC)?;
        self.write_all(&len.to_le_bytes())?;
        self.write_all(&checksum::<R>(len, &payload))?;
        self.write_all(&payload)?;
        self.file
            .flush()
            .map_err(|err| WalError::io("flush", &self.path, err))?;
        self.file
            .sync_data()
            .map_err(|err| WalError::io("sync", &self.path, err))
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), WalError<R::Error>> {
        self.file
            .write_all(bytes)
            .map_err(|err| WalError::io("append", &self.path, err))
    }
}

fn checksum<R: WalRecord>(len: u32, payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&R::MAGIC);
    hasher.update(&len.to_le_bytes());
    hasher.update(payload);
    hasher.finalize().as_bytes()[..CHECKSUM_LEN]
        .try_into()
        .unwrap()
}

fn scan_records<R>(path: &Path, max_record_bytes: u32) -> Result<(Vec<R>, u64), WalError<R::Error>>
where
    R: WalRecord,
{
    let bytes = match fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(err) if err.kind() == ErrorKind::NotFound => Zeroizing::new(Vec::new()),
        Err(err) => return Err(WalError::io("read", path, err)),
    };
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while bytes.len().saturating_sub(offset) >= FRAME_HEADER_LEN {
        let header = &bytes[offset..offset + FRAME_HEADER_LEN];
        if header[..4] != R::MAGIC {
            break;
        }
        let len = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let total_len = FRAME_HEADER_LEN + len as usize;
        if len > max_record_bytes || total_len > bytes.len() - offset {
            break;
        }
        let payload_start = offset + FRAME_HEADER_LEN;
        let payload = &bytes[payload_start..offset + total_len];
        if header[8..FRAME_HEADER_LEN] != checksum::<R>(len, payload) {
            break;
        }
        let mut input = payload;
        records.push(R::decode(&mut input).map_err(|source| WalError::Decode {
            path: path.to_path_buf(),
            offset,
            source,
        })?);
        offset += total_len;
    }
    Ok((records, offset as u64))
}

fn repair_tail<R>(path: &Path, file: &File, valid_len: u64) -> Result<(), WalError<R>>
where
    R: Error + Send + Sync + 'static,
{
    let current_len = file
        .metadata()
        .map_err(|err| WalError::io("read metadata for", path, err))?
        .len();
    if valid_len == current_len {
        return Ok(());
    }
    file.set_len(valid_len)
        .map_err(|err| WalError::io("truncate torn", path, err))?;
    file.sync_data()
        .map_err(|err| WalError::io("sync truncated", path, err))
}

#[cfg(target_os = "linux")]
fn preallocate_empty_file<E>(file: &File, path: &Path, bytes: u64) -> Result<(), WalError<E>>
where
    E: Error + Send + Sync + 'static,
{
    let len = libc::off_t::try_from(bytes).map_err(|_| WalError::PreallocationSize {
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
    Err(WalError::io(
        "preallocate with fallocate",
        path,
        io::Error::last_os_error(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn preallocate_empty_file<E>(_file: &File, path: &Path, _bytes: u64) -> Result<(), WalError<E>>
where
    E: Error + Send + Sync + 'static,
{
    Err(WalError::UnsupportedPreallocation(path.to_path_buf()))
}

#[cfg(test)]
mod tests;
