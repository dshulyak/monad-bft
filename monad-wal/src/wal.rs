// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{
    collections::VecDeque,
    fmt::Debug,
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use monad_types::Serializable;
use tracing::debug;

use crate::WALError;

/// Header prepended to each event in the log
pub(crate) type EventHeaderType = u32;
pub(crate) type EventTimestampType = u32;
pub(crate) const EVENT_HEADER_LEN: usize =
    std::mem::size_of::<EventTimestampType>() + std::mem::size_of::<EventHeaderType>();

/// Default chunk size. 1GB.
pub(crate) const DEFAULT_CHUNK_SIZE: u64 = 1024 * 1024 * 1024;
pub(crate) const DEFAULT_CHUNKS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscoveredChunk {
    pub path: PathBuf,
    pub timestamp: u64,
    pub generation: u64,
}

#[derive(Debug)]
struct ActiveChunkState {
    path: PathBuf,
    timestamp: u64,
    generation: u64,
    used_len: u64,
    handle: File,
}

impl ActiveChunkState {
    fn metadata(&self) -> DiscoveredChunk {
        DiscoveredChunk {
            path: self.path.clone(),
            timestamp: self.timestamp,
            generation: self.generation,
        }
    }

    fn into_discovered_chunk(self) -> DiscoveredChunk {
        DiscoveredChunk {
            path: self.path,
            timestamp: self.timestamp,
            generation: self.generation,
        }
    }
}

/// Config for a write-ahead-log
#[derive(Clone)]
pub struct WALoggerConfig<M> {
    file_path: PathBuf,

    /// option for fsync after write. There is a cost to doing
    /// an fsync so its left configurable
    sync: bool,
    chunks: usize,
    chunk_size: u64,

    _marker: PhantomData<M>,
}

impl<M> WALoggerConfig<M>
where
    M: Serializable<Bytes> + Debug,
{
    pub fn new(file_path: PathBuf, sync: bool) -> Self {
        Self {
            file_path,
            sync,
            chunks: DEFAULT_CHUNKS,
            chunk_size: DEFAULT_CHUNK_SIZE,
            _marker: PhantomData,
        }
    }

    pub fn with_chunks(mut self, chunks: usize) -> Self {
        self.chunks = chunks;
        self
    }

    pub fn with_chunk_size(mut self, chunk_size: u64) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    // this definition of the build function means that we can only have one type of message in this WAL
    // should enforce this in `push`/have WALogger parametrized by the message type
    pub fn build(self) -> Result<WALogger<M>, WALError> {
        if self.chunks == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wal chunks must be greater than zero",
            )
            .into());
        }

        let discovered = discover_chunks(&self.file_path)?;
        let timestamp = fresh_timestamp_after(discovered.last().map(|chunk| chunk.timestamp))?;
        let (current, rotated, next_generation) = match discovered.len() {
            0 => initialize_chunks(&self.file_path, timestamp, self.chunks, self.chunk_size)?,
            found if found == self.chunks => restore_chunks(
                &self.file_path,
                timestamp,
                discovered,
                self.chunks,
                self.chunk_size,
            )?,
            found => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "expected {} wal chunks on startup, found {}",
                        self.chunks, found
                    ),
                )
                .into());
            }
        };

        Ok(WALogger {
            _marker: PhantomData,
            file_path: self.file_path,
            timestamp,
            next_generation,
            current,
            rotated,
            chunks: self.chunks,
            chunk_size: self.chunk_size,
            sync: self.sync,
        })
    }
}

/// Write-ahead-logger that Serializes Events to an append-only-file
#[derive(Debug)]
pub struct WALogger<M> {
    _marker: PhantomData<M>,
    file_path: PathBuf,
    timestamp: u64,
    next_generation: u64,
    current: ActiveChunkState,
    rotated: VecDeque<DiscoveredChunk>,
    chunks: usize,
    chunk_size: u64,
    sync: bool,
}

impl<M> WALogger<M>
where
    M: Serializable<Bytes> + Debug,
{
    fn next_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation += 1;
        generation
    }

    pub fn push(&mut self, message: &M) -> Result<(), WALError> {
        let msg_buf = message.serialize();
        if msg_buf.len() > EventHeaderType::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serialized wal event exceeds u32 header size",
            )
            .into());
        }
        let msg_len = (EVENT_HEADER_LEN + msg_buf.len()) as u64;
        if msg_len > self.chunk_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serialized wal event exceeds chunk_size",
            )
            .into());
        }

        let next_offset = self.current.used_len + msg_len;
        if next_offset > self.chunk_size {
            self.rotate()?;
        }

        let timestamp_buf = event_timestamp(self.current.timestamp).to_le_bytes();
        let len_buf = (msg_buf.len() as EventHeaderType).to_le_bytes();
        self.current.handle.write_all(&timestamp_buf)?;
        self.current.handle.write_all(&len_buf)?;
        self.current.handle.write_all(&msg_buf)?;
        self.current.used_len += msg_len;
        write_chunk_end_marker(
            &mut self.current.handle,
            self.current.timestamp,
            self.current.used_len,
            self.chunk_size,
        )?;

        if self.sync {
            self.current.handle.sync_all()?;
        }
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), WALError> {
        if self.chunks == 1 {
            if !self.rotated.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "wal rotation invariant broken: single-chunk wal has rotated chunks",
                )
                .into());
            }

            let generation = self.next_generation();
            self.current = reuse_chunk(
                &self.file_path,
                self.current.metadata(),
                self.timestamp,
                generation,
                self.chunk_size,
            )?;
            return Ok(());
        }

        if self.rotated.len() + 1 != self.chunks {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "wal rotation invariant broken: expected {} chunks, found {}",
                    self.chunks,
                    self.rotated.len() + 1
                ),
            )
            .into());
        }

        let generation = self.next_generation();
        let next = self
            .rotated
            .pop_front()
            .expect("rotated must contain a reusable chunk");
        let previous = std::mem::replace(
            &mut self.current,
            reuse_chunk(
                &self.file_path,
                next,
                self.timestamp,
                generation,
                self.chunk_size,
            )?,
        );
        self.rotated.push_back(previous.into_discovered_chunk());
        Ok(())
    }
}

pub(crate) fn discover_chunks(file_path: &Path) -> Result<Vec<DiscoveredChunk>, WALError> {
    let mut chunks = discover_chunk_metadata(file_path)?;
    chunks.sort_by_key(|chunk| (chunk.timestamp, chunk.generation));
    Ok(chunks)
}

fn discover_chunk_metadata(file_path: &Path) -> Result<Vec<DiscoveredChunk>, WALError> {
    let Some(file_name) = file_path.file_name() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "wal path must include a file name",
        )
        .into());
    };
    let Some(file_name) = file_name.to_str() else {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "wal path must be valid utf-8").into(),
        );
    };
    let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
    let chunk_prefix = format!("{file_name}_");

    let mut chunks = Vec::new();
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(chunks),
        Err(err) => return Err(err.into()),
    };

    for entry in entries {
        let entry = entry?;
        if let Some(chunk) = discover_chunk(entry, &chunk_prefix)? {
            chunks.push(chunk);
        }
    }

    chunks.sort_by_key(|chunk| (chunk.timestamp, chunk.generation));
    Ok(chunks)
}

fn discover_chunk(
    entry: fs::DirEntry,
    chunk_prefix: &str,
) -> Result<Option<DiscoveredChunk>, WALError> {
    let path = entry.path();
    let entry_type = entry.file_type()?;
    if !entry_type.is_file() {
        debug!(path = %path.display(), "skipping non-file wal entry");
        return Ok(None);
    }

    let entry_name = entry.file_name();
    let Some(entry_name) = entry_name.to_str() else {
        debug!(path = %path.display(), "skipping wal entry with non-utf8 name");
        return Ok(None);
    };
    let Some((timestamp, generation)) = entry_name
        .strip_prefix(chunk_prefix)
        .and_then(|suffix| suffix.split_once('.'))
        .and_then(|(timestamp, generation)| {
            Some((
                timestamp.parse::<u64>().ok()?,
                generation.parse::<u64>().ok()?,
            ))
        })
    else {
        debug!(path = %path.display(), "skipping non-wal directory entry");
        return Ok(None);
    };

    Ok(Some(DiscoveredChunk {
        path,
        timestamp,
        generation,
    }))
}

pub(crate) fn chunk_path(file_path: &Path, timestamp: u64, generation: u64) -> PathBuf {
    let mut chunk_path = file_path.as_os_str().to_os_string();
    chunk_path.push(format!("_{timestamp}.{generation}"));
    chunk_path.into()
}

pub(crate) fn chunk_timestamp(path: &Path) -> Result<u64, WALError> {
    let file_name = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "wal chunk path must be valid utf-8",
            )
        })?;
    let timestamp = file_name
        .rsplit_once('_')
        .and_then(|(_, suffix)| suffix.split_once('.'))
        .and_then(|(timestamp, _)| timestamp.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid wal chunk name"))?;
    Ok(timestamp)
}

pub(crate) fn event_timestamp(timestamp: u64) -> EventTimestampType {
    timestamp as EventTimestampType
}

fn current_timestamp() -> Result<u64, WALError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        .as_millis()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wal timestamp overflow").into())
}

fn fresh_timestamp_after(previous: Option<u64>) -> Result<u64, WALError> {
    let Some(previous) = previous else {
        return current_timestamp();
    };

    loop {
        let timestamp = current_timestamp()?;
        if timestamp > previous {
            return Ok(timestamp);
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn create_chunk(
    file_path: &Path,
    timestamp: u64,
    generation: u64,
    chunk_size: u64,
) -> Result<ActiveChunkState, WALError> {
    let path = chunk_path(file_path, timestamp, generation);
    let mut handle = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    preallocate_chunk(&handle, chunk_size)?;
    handle.seek(SeekFrom::Start(0))?;
    Ok(ActiveChunkState {
        path,
        timestamp,
        generation,
        used_len: 0,
        handle,
    })
}

fn initialize_chunks(
    file_path: &Path,
    timestamp: u64,
    chunks: usize,
    chunk_size: u64,
) -> Result<(ActiveChunkState, VecDeque<DiscoveredChunk>, u64), WALError> {
    let current = create_chunk(file_path, timestamp, 0, chunk_size)?;
    let rotated = (1..chunks as u64)
        .map(|generation| {
            create_chunk(file_path, timestamp, generation, chunk_size)
                .map(ActiveChunkState::into_discovered_chunk)
        })
        .collect::<Result<VecDeque<_>, _>>()?;
    Ok((current, rotated, chunks as u64))
}

fn restore_chunks(
    file_path: &Path,
    timestamp: u64,
    mut discovered: Vec<DiscoveredChunk>,
    configured_chunks: usize,
    chunk_size: u64,
) -> Result<(ActiveChunkState, VecDeque<DiscoveredChunk>, u64), WALError> {
    if discovered.len() != configured_chunks {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected {} wal chunks on restore, found {}",
                configured_chunks,
                discovered.len()
            ),
        )
        .into());
    }
    validate_chunk_sizes(&discovered, chunk_size)?;

    let current = reuse_chunk(file_path, discovered.remove(0), timestamp, 0, chunk_size)?;
    let rotated = discovered.into();
    Ok((current, rotated, 1))
}

fn reuse_chunk(
    file_path: &Path,
    chunk: DiscoveredChunk,
    timestamp: u64,
    generation: u64,
    chunk_size: u64,
) -> Result<ActiveChunkState, WALError> {
    let path = chunk_path(file_path, timestamp, generation);
    if path != chunk.path {
        fs::rename(&chunk.path, &path)?;
    }
    let mut handle = reopen_chunk(&path, chunk_size)?;
    write_chunk_end_marker(&mut handle, timestamp, 0, chunk_size)?;
    Ok(ActiveChunkState {
        path,
        timestamp,
        generation,
        used_len: 0,
        handle,
    })
}

fn validate_chunk_sizes(chunks: &[DiscoveredChunk], chunk_size: u64) -> Result<(), WALError> {
    for chunk in chunks {
        let actual_size = chunk.path.metadata()?.len();
        if actual_size != chunk_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected wal chunk {} to have size {}, found {}",
                    chunk.path.display(),
                    chunk_size,
                    actual_size
                ),
            )
            .into());
        }
    }
    Ok(())
}

fn reopen_chunk(path: &Path, chunk_size: u64) -> Result<File, WALError> {
    let actual_size = path.metadata()?.len();
    if actual_size != chunk_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected wal chunk {} to have size {}, found {}",
                path.display(),
                chunk_size,
                actual_size
            ),
        )
        .into());
    }

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

fn write_chunk_end_marker(
    file: &mut File,
    timestamp: u64,
    used_len: u64,
    chunk_size: u64,
) -> Result<(), WALError> {
    file.seek(SeekFrom::Start(used_len))?;
    if used_len + EVENT_HEADER_LEN as u64 <= chunk_size {
        let timestamp_buf = event_timestamp(timestamp).to_le_bytes();
        let len_buf = 0u32.to_le_bytes();
        file.write_all(&timestamp_buf)?;
        file.write_all(&len_buf)?;
        file.seek(SeekFrom::Start(used_len))?;
    }
    Ok(())
}

fn preallocate_chunk(file: &File, chunk_size: u64) -> Result<(), WALError> {
    #[cfg(unix)]
    {
        let chunk_size: libc::off_t = chunk_size.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "wal chunk_size does not fit into off_t",
            )
        })?;
        let err = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, chunk_size) };
        if err == 0 {
            return Ok(());
        }
        if err != libc::EOPNOTSUPP && err != libc::ENOSYS {
            return Err(io::Error::from_raw_os_error(err).into());
        }
    }

    file.set_len(chunk_size)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::{array::TryFromSliceError, path::Path};

    use bytes::Bytes;
    use monad_types::{Deserializable, Serializable};

    use crate::{
        reader::{WALClient, WALClientConfig, WALReader, WALReaderConfig},
        wal::{
            chunk_path, discover_chunks, event_timestamp, EventHeaderType, WALogger,
            WALoggerConfig, EVENT_HEADER_LEN,
        },
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestEvent {
        data: u64,
    }

    impl Serializable<Bytes> for TestEvent {
        fn serialize(&self) -> Bytes {
            self.data.to_be_bytes().to_vec().into()
        }
    }

    impl Deserializable<[u8]> for TestEvent {
        type ReadError = TryFromSliceError;

        fn deserialize(message: &[u8]) -> Result<Self, Self::ReadError> {
            let buf: [u8; 8] = message.try_into()?;
            Ok(Self {
                data: u64::from_be_bytes(buf),
            })
        }
    }

    #[derive(Debug, PartialEq, Eq, Default)]
    struct VecState {
        events: Vec<TestEvent>,
    }

    impl VecState {
        fn update(&mut self, event: TestEvent) {
            self.events.push(event);
        }
    }

    fn generate_test_events(num: u64) -> Vec<TestEvent> {
        (0..num).map(|i| TestEvent { data: i }).collect()
    }

    fn wal_file_names(dir: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().unwrap().is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn wal_timestamps(dir: &Path) -> Vec<u64> {
        let mut timestamps = wal_file_names(dir)
            .into_iter()
            .map(|name| {
                name.strip_prefix("wal_")
                    .and_then(|suffix| suffix.split_once('.'))
                    .map(|(timestamp, _)| timestamp.parse::<u64>().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        timestamps.sort();
        timestamps.dedup();
        timestamps
    }

    fn serialize_event(timestamp: u64, event: &TestEvent) -> Vec<u8> {
        let payload = Serializable::<Bytes>::serialize(event);
        let mut buf = Vec::with_capacity(EVENT_HEADER_LEN + payload.len());
        buf.extend_from_slice(&event_timestamp(timestamp).to_le_bytes());
        buf.extend_from_slice(&(payload.len() as EventHeaderType).to_le_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    #[test]
    fn load_events() {
        // setup
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let input1 = generate_test_events(10);

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log1_path = tmpdir.path().join("wal");
        let logger1_config = WALoggerConfig::new(
            log1_path.clone(),
            false, // sync
        );

        let mut logger1: WALogger<TestEvent> = logger1_config.build().unwrap();
        let mut state1 = VecState::default();

        // driver loop (simulate executor by iterating events)
        for event in input1.into_iter() {
            logger1.push(&event).unwrap();

            state1.update(event);
        }

        // read events from the wal, assert equal
        let logger2_config = WALClientConfig::new(log1_path);
        let mut logger2: WALClient<TestEvent> = logger2_config.build().unwrap();
        let mut state2 = VecState::default();
        while let Ok(event) = logger2.load_one() {
            state2.update(event);
        }
        assert_eq!(state1, state2);
    }

    #[test]
    fn preallocates_all_chunks_on_first_init() {
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let logger: WALogger<TestEvent> = WALoggerConfig::new(log_path.clone(), false)
            .with_chunks(3)
            .build()
            .unwrap();
        drop(logger);

        let discovered = discover_chunks(&log_path).unwrap();
        assert_eq!(discovered.len(), 3);
        assert_eq!(
            discovered
                .iter()
                .map(|chunk| chunk.generation)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(wal_file_names(tmpdir.path()).len(), 3);
        assert_eq!(wal_timestamps(tmpdir.path()).len(), 1);
    }

    #[test]
    fn rotate_wal() {
        // setup
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let serialized_event_len = EVENT_HEADER_LEN + payload_len;
        let num_events_per_file = 3;
        let chunk_size = (serialized_event_len * num_events_per_file) as u64;
        let logger_config = WALoggerConfig::new(log_path.clone(), false)
            .with_chunks(2)
            .with_chunk_size(chunk_size);

        let num_total_events = 8;
        let events = generate_test_events(num_total_events as u64);

        let mut logger: WALogger<TestEvent> = logger_config.build().unwrap();

        for event in events {
            logger.push(&event).unwrap();
        }

        assert_eq!(logger.current.generation, 3);
        assert_eq!(logger.rotated.len(), 1);
        assert_eq!(logger.rotated.front().unwrap().generation, 2);

        let wal_files = wal_file_names(tmpdir.path());
        assert_eq!(wal_files.len(), 2);
        assert!(wal_files.iter().all(|name| name.starts_with("wal_")));
        assert!(wal_files.iter().any(|name| name.ends_with(".2")));
        assert!(wal_files.iter().any(|name| name.ends_with(".3")));
        assert_eq!(wal_timestamps(tmpdir.path()).len(), 1);

        let mut reader: WALClient<TestEvent> = WALClientConfig::new(log_path).build().unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.load_one().ok()).collect();
        assert_eq!(
            events,
            generate_test_events(8)
                .into_iter()
                .skip(3)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn restart_moves_to_next_preallocated_chunk() {
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let chunk_size = (EVENT_HEADER_LEN + payload_len) as u64 * 3;

        let logger_config = || {
            WALoggerConfig::new(log_path.clone(), false)
                .with_chunks(2)
                .with_chunk_size(chunk_size)
        };

        {
            let mut logger: WALogger<TestEvent> = logger_config().build().unwrap();
            for event in generate_test_events(5) {
                logger.push(&event).unwrap();
            }
        }

        {
            let mut logger: WALogger<TestEvent> = logger_config().build().unwrap();
            assert_eq!(logger.current.used_len, 0);
            assert_eq!(logger.rotated.len(), 1);

            logger.push(&TestEvent { data: 5 }).unwrap();
            logger.push(&TestEvent { data: 6 }).unwrap();
        }

        let mut reader: WALClient<TestEvent> = WALClientConfig::new(log_path).build().unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.load_one().ok()).collect();
        assert_eq!(
            events,
            generate_test_events(7)
                .into_iter()
                .skip(3)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn startup_requires_exact_chunk_count() {
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let chunk_size = (EVENT_HEADER_LEN + payload_len) as u64 * 3;

        {
            let mut logger: WALogger<TestEvent> = WALoggerConfig::new(log_path.clone(), false)
                .with_chunks(3)
                .with_chunk_size(chunk_size)
                .build()
                .unwrap();
            for event in generate_test_events(8) {
                logger.push(&event).unwrap();
            }
        }

        let err = WALoggerConfig::<TestEvent>::new(log_path.clone(), false)
            .with_chunks(2)
            .with_chunk_size(chunk_size)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            crate::WALError::IOError(ref io_err) if io_err.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn startup_requires_exact_chunk_size() {
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let large_chunk_size = (EVENT_HEADER_LEN + payload_len) as u64 * 3;
        let small_chunk_size = (EVENT_HEADER_LEN + payload_len) as u64;

        {
            let mut logger: WALogger<TestEvent> = WALoggerConfig::new(log_path.clone(), false)
                .with_chunks(2)
                .with_chunk_size(large_chunk_size)
                .build()
                .unwrap();
            for event in generate_test_events(5) {
                logger.push(&event).unwrap();
            }
        }

        let err = WALoggerConfig::<TestEvent>::new(log_path.clone(), false)
            .with_chunks(2)
            .with_chunk_size(small_chunk_size)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            crate::WALError::IOError(ref io_err) if io_err.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn reader_stops_at_preallocated_tail() {
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let chunk_size = (EVENT_HEADER_LEN + payload_len) as u64 * 4;

        let mut logger: WALogger<TestEvent> = WALoggerConfig::new(log_path, false)
            .with_chunk_size(chunk_size)
            .build()
            .unwrap();
        for event in generate_test_events(2) {
            logger.push(&event).unwrap();
        }
        let path = logger.current.path.clone();
        drop(logger);

        let mut reader: WALReader<TestEvent> = WALReaderConfig::new(path).build().unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.load_one().ok()).collect();
        assert_eq!(events, generate_test_events(2));
    }

    #[test]
    fn single_chunk_keeps_latest_events() {
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let serialized_event_len = EVENT_HEADER_LEN + payload_len;
        let chunk_size = (serialized_event_len * 3) as u64;

        let mut logger: WALogger<TestEvent> = WALoggerConfig::new(log_path.clone(), false)
            .with_chunks(1)
            .with_chunk_size(chunk_size)
            .build()
            .unwrap();
        for event in generate_test_events(5) {
            logger.push(&event).unwrap();
        }

        assert_eq!(logger.current.generation, 1);
        assert!(logger.rotated.is_empty());

        let wal_files = wal_file_names(tmpdir.path());
        assert_eq!(wal_files.len(), 1);
        assert!(wal_files[0].starts_with("wal_"));
        assert!(wal_files[0].ends_with(".1"));

        let mut reader: WALClient<TestEvent> = WALClientConfig::new(log_path).build().unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.load_one().ok()).collect();
        assert_eq!(
            events,
            generate_test_events(5)
                .into_iter()
                .skip(3)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn supports_more_than_two_chunks() {
        use std::fs::create_dir_all;

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let serialized_event_len = EVENT_HEADER_LEN + payload_len;
        let chunk_size = (serialized_event_len * 3) as u64;

        let mut logger: WALogger<TestEvent> = WALoggerConfig::new(log_path.clone(), false)
            .with_chunks(3)
            .with_chunk_size(chunk_size)
            .build()
            .unwrap();
        for event in generate_test_events(11) {
            logger.push(&event).unwrap();
        }

        assert_eq!(logger.current.generation, 5);
        assert_eq!(logger.rotated.len(), 2);
        assert_eq!(logger.rotated.front().unwrap().generation, 3);
        assert_eq!(logger.rotated.back().unwrap().generation, 4);

        let wal_files = wal_file_names(tmpdir.path());
        assert_eq!(wal_files.len(), 3);
        assert!(wal_files.iter().all(|name| name.starts_with("wal_")));
        assert!(wal_files.iter().any(|name| name.ends_with(".3")));
        assert!(wal_files.iter().any(|name| name.ends_with(".4")));
        assert!(wal_files.iter().any(|name| name.ends_with(".5")));

        let mut reader: WALClient<TestEvent> = WALClientConfig::new(log_path).build().unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.load_one().ok()).collect();
        assert_eq!(
            events,
            generate_test_events(11)
                .into_iter()
                .skip(3)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn reader_keeps_going_past_incomplete_chunks() {
        use std::fs::{create_dir_all, write};

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        write(
            chunk_path(&log_path, 1, 0),
            serialize_event(1, &TestEvent { data: 1 }),
        )
        .unwrap();
        write(chunk_path(&log_path, 1, 1), [0x08, 0x00]).unwrap();
        write(
            chunk_path(&log_path, 1, 2),
            serialize_event(1, &TestEvent { data: 2 }),
        )
        .unwrap();

        let mut reader: WALClient<TestEvent> = WALClientConfig::new(log_path).build().unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.load_one().ok()).collect();
        assert_eq!(events, vec![TestEvent { data: 1 }, TestEvent { data: 2 }]);
    }

    #[test]
    fn reader_stops_at_older_timestamp() {
        use std::fs::{create_dir_all, write};

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        let mut buf = serialize_event(7, &TestEvent { data: 1 });
        buf.extend_from_slice(&serialize_event(6, &TestEvent { data: 2 }));
        write(chunk_path(&log_path, 7, 7), buf).unwrap();

        let mut reader: WALClient<TestEvent> = WALClientConfig::new(log_path).build().unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.load_one().ok()).collect();
        assert_eq!(events, vec![TestEvent { data: 1 }]);
    }

    #[test]
    fn reader_orders_chunks_by_timestamp_and_generation() {
        use std::fs::{create_dir_all, write};

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");

        write(
            chunk_path(&log_path, 2, 1),
            serialize_event(2, &TestEvent { data: 3 }),
        )
        .unwrap();
        write(
            chunk_path(&log_path, 1, 0),
            serialize_event(1, &TestEvent { data: 1 }),
        )
        .unwrap();
        write(
            chunk_path(&log_path, 2, 0),
            serialize_event(2, &TestEvent { data: 2 }),
        )
        .unwrap();

        let mut reader: WALClient<TestEvent> = WALClientConfig::new(log_path).build().unwrap();
        let events: Vec<_> = std::iter::from_fn(|| reader.load_one().ok()).collect();
        assert_eq!(
            events,
            vec![
                TestEvent { data: 1 },
                TestEvent { data: 2 },
                TestEvent { data: 3 },
            ]
        );
    }

    #[test]
    fn reopened_rotated_chunks_follow_timestamp_generation_order() {
        use std::fs::{create_dir_all, File};

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");
        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let chunk_size = (EVENT_HEADER_LEN + payload_len) as u64 * 3;

        for file_name in ["wal_2.1", "wal_1.0", "wal_2.0"] {
            File::create(tmpdir.path().join(file_name))
                .unwrap()
                .set_len(chunk_size)
                .unwrap();
        }

        let logger: WALogger<TestEvent> = WALoggerConfig::new(log_path, false)
            .with_chunks(3)
            .with_chunk_size(chunk_size)
            .build()
            .unwrap();

        assert_eq!(logger.current.generation, 0);
        assert_eq!(
            logger
                .rotated
                .iter()
                .map(|chunk| (chunk.timestamp, chunk.generation))
                .collect::<Vec<_>>(),
            vec![(2, 0), (2, 1)]
        );
    }

    #[test]
    fn restart_reuses_discovered_empty_chunk() {
        use std::fs::{create_dir_all, File};

        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();
        create_dir_all(tmpdir.path()).unwrap();
        let log_path = tmpdir.path().join("wal");
        let payload_len = Serializable::<Bytes>::serialize(&TestEvent { data: 0 }).len();
        let chunk_size = (EVENT_HEADER_LEN + payload_len) as u64 * 3;

        File::create(tmpdir.path().join("wal_1.0"))
            .unwrap()
            .set_len(chunk_size)
            .unwrap();
        File::create(tmpdir.path().join("wal_2.0"))
            .unwrap()
            .set_len(chunk_size)
            .unwrap();

        let mut logger: WALogger<TestEvent> = WALoggerConfig::new(log_path.clone(), false)
            .with_chunks(2)
            .with_chunk_size(chunk_size)
            .build()
            .unwrap();
        logger.push(&TestEvent { data: 1 }).unwrap();
        drop(logger);

        let discovered = discover_chunks(&log_path).unwrap();
        assert_eq!(discovered.len(), 2);
        assert_eq!(discovered[0].timestamp, 2);
        assert_eq!(discovered[0].generation, 0);
        assert!(discovered[1].timestamp > 2);
        assert_eq!(discovered[1].generation, 0);

        let wal_files = wal_file_names(tmpdir.path());
        assert!(wal_files.iter().any(|name| name == "wal_2.0"));
        assert!(!wal_files.iter().any(|name| name == "wal_1.0"));
    }
}
