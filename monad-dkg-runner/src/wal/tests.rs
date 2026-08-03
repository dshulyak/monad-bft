use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::PermissionsExt,
};

use thiserror::Error;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestRecord(Vec<u8>);

#[derive(Debug, Error)]
#[error("test codec error")]
struct TestCodecError;

impl WalRecord for TestRecord {
    type Error = TestCodecError;

    const MAGIC: [u8; 4] = *b"TWAL";

    fn encode<B: BufMut>(&self, output: &mut B) -> Result<(), Self::Error> {
        output.put_slice(&self.0);
        Ok(())
    }

    fn decode<B: Buf>(input: &mut B) -> Result<Self, Self::Error> {
        Ok(Self(input.copy_to_bytes(input.remaining()).to_vec()))
    }
}

fn config() -> WalConfig {
    WalConfig {
        max_record_bytes: 1024,
        preallocate_bytes: 0,
    }
}

#[test]
fn reopens_records_in_append_order() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("records.wal");
    let (mut wal, records) = DurableWal::<TestRecord>::open(&path, config()).unwrap();
    assert!(records.is_empty());

    wal.append(&TestRecord(vec![1])).unwrap();
    wal.append(&TestRecord(vec![2, 3])).unwrap();
    drop(wal);

    let (_, records) = DurableWal::<TestRecord>::open(&path, config()).unwrap();
    assert_eq!(records, vec![TestRecord(vec![1]), TestRecord(vec![2, 3])]);
}

#[test]
fn preallocates_without_growing_logical_size() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("records.wal");
    let (wal, _) = DurableWal::<TestRecord>::open(
        &path,
        WalConfig {
            preallocate_bytes: 4096,
            ..config()
        },
    )
    .unwrap();

    assert_eq!(fs::metadata(wal.path()).unwrap().len(), 0);
    assert_eq!(
        fs::metadata(wal.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn rejects_oversized_records() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("records.wal");
    let (mut wal, _) = DurableWal::<TestRecord>::open(
        &path,
        WalConfig {
            max_record_bytes: 1,
            preallocate_bytes: 0,
        },
    )
    .unwrap();

    assert!(matches!(
        wal.append(&TestRecord(vec![1, 2])),
        Err(WalError::RecordTooLarge { .. })
    ));
}

#[test]
fn open_truncates_a_torn_tail() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("records.wal");
    let (mut wal, _) = DurableWal::<TestRecord>::open(&path, config()).unwrap();
    wal.append(&TestRecord(vec![1, 2, 3])).unwrap();
    let valid_len = fs::metadata(&path).unwrap().len();
    drop(wal);

    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"torn")
        .unwrap();

    let (_, records) = DurableWal::<TestRecord>::open(&path, config()).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), valid_len);
    assert_eq!(records, vec![TestRecord(vec![1, 2, 3])]);
}

#[test]
fn open_truncates_a_bad_checksum_tail() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("records.wal");
    let (mut wal, _) = DurableWal::<TestRecord>::open(&path, config()).unwrap();
    wal.append(&TestRecord(vec![1])).unwrap();
    let first_len = fs::metadata(&path).unwrap().len();
    wal.append(&TestRecord(vec![2])).unwrap();
    drop(wal);

    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(first_len + FRAME_HEADER_LEN as u64))
        .unwrap();
    file.write_all(b"x").unwrap();
    file.sync_data().unwrap();

    let (_, records) = DurableWal::<TestRecord>::open(&path, config()).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), first_len);
    assert_eq!(records, vec![TestRecord(vec![1])]);
}
