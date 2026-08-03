use dkg_core::PartyId;
use dkg_protocol::{DkgMessageId, DkgMessageKey};

use super::*;
fn message_id(value: u8) -> DkgMessageId {
    DkgMessageId::single(DkgMessageKey::Ladder {
        sender: PartyId(value.into()),
        level: 1,
    })
}

fn incoming(value: u8) -> IncomingMessageRecord {
    IncomingMessageRecord {
        source: PartyId(value.into()),
        message_id: message_id(value),
        payload: vec![value].into(),
    }
}

fn open_wal(root: &Path, epoch: u64) -> RecoveryWal {
    RecoveryWal::open(
        root,
        Epoch(epoch),
        RecoveryWalConfig {
            preallocate_bytes: 0,
            max_epochs: 2,
        },
    )
    .unwrap()
    .0
}

#[test]
fn default_preallocation_covers_one_maximum_record() {
    let maximum_record_bytes = u64::from(MAX_RECOVERY_RECORD_BYTES) + FRAME_HEADER_LEN as u64;

    assert!(DEFAULT_RECOVERY_WAL_PREALLOCATE_BYTES >= maximum_record_bytes);
    assert_eq!(
        DEFAULT_RECOVERY_WAL_PREALLOCATE_BYTES % WAL_PREALLOCATE_ALIGNMENT,
        0
    );
    assert!(
        DEFAULT_RECOVERY_WAL_PREALLOCATE_BYTES < maximum_record_bytes + WAL_PREALLOCATE_ALIGNMENT
    );
}

#[test]
fn wal_rejects_conflicting_engine_seed_records() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = open_wal(dir.path(), 8);
    wal.append(&RecoveryRecord::Seed([0x11; ENGINE_SEED_BYTES]))
        .unwrap();
    wal.append(&RecoveryRecord::Seed([0x22; ENGINE_SEED_BYTES]))
        .unwrap();

    let err = RecoveryState::load(wal.path()).unwrap_err();
    assert!(matches!(err, RecoveryWalError::ConflictingSeed));
}

#[test]
fn wal_creates_and_reuses_one_engine_seed() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = open_wal(dir.path(), 7);
    let path = wal.path().to_path_buf();

    let first = RecoveryState::default()
        .load_or_create_engine_seed(&mut wal)
        .unwrap();
    let second = RecoveryState::load(&path)
        .unwrap()
        .load_or_create_engine_seed(&mut wal)
        .unwrap();

    assert_eq!(first, second);
    assert_ne!(first, [0; ENGINE_SEED_BYTES]);
    assert_eq!(
        DurableWal::<RecoveryRecord>::read(&path, MAX_RECOVERY_RECORD_BYTES)
            .unwrap()
            .iter()
            .filter(|record| matches!(record, RecoveryRecord::Seed(_)))
            .count(),
        1
    );
}

#[test]
fn wal_rejects_protocol_records_without_engine_seed() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = open_wal(dir.path(), 7);
    wal.append(&RecoveryRecord::Incoming(incoming(1))).unwrap();
    let path = wal.path().to_path_buf();

    let err = RecoveryState::load(&path)
        .unwrap()
        .load_or_create_engine_seed(&mut wal)
        .unwrap_err();

    assert!(matches!(err, RecoveryWalError::MissingSeed));
}

#[test]
fn wal_reuses_one_registration_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = open_wal(dir.path(), 8);
    let path = wal.path().to_path_buf();
    let mut state = RecoveryState::load(&path).unwrap();
    let first = state
        .load_or_create_registration(&mut wal, || Ok(vec![0xAA, 0xBB]))
        .unwrap();

    let mut restarted = RecoveryState::load(&path).unwrap();
    let second = restarted
        .load_or_create_registration(&mut wal, || Ok(vec![0xCC]))
        .unwrap();

    assert_eq!(first, vec![0xAA, 0xBB]);
    assert_eq!(second, first);
    assert_eq!(restarted.registration, Some(first.into()));
}

#[test]
fn wal_rejects_conflicting_registration_records() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = open_wal(dir.path(), 8);
    wal.append(&RecoveryRecord::Registration(vec![0xAA, 0xBB].into()))
        .unwrap();
    wal.append(&RecoveryRecord::Registration(vec![0xCC, 0xDD].into()))
        .unwrap();

    let err = RecoveryState::load(wal.path()).unwrap_err();
    assert!(matches!(err, RecoveryWalError::ConflictingRegistration));
}

#[test]
fn wal_loads_outgoing_message_records() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = open_wal(dir.path(), 8);

    let record = OutgoingMessageRecord {
        message_id: message_id(42),
        recipients: [PartyId(2), PartyId(3)].into_iter().collect(),
        payload: vec![0xAA, 0xBB, 0xCC].into(),
    };
    wal.append(&RecoveryRecord::Outgoing(record.clone()))
        .unwrap();

    let loaded = RecoveryState::load(wal.path()).unwrap();
    assert_eq!(loaded.outbox.len(), 1);
    assert_eq!(loaded.outbox.get(&message_id(42)), Some(&record));
}

#[test]
fn wal_loads_incoming_messages() {
    let dir = tempfile::tempdir().unwrap();
    let mut wal = open_wal(dir.path(), 8);

    let incoming = incoming(2);
    wal.append(&RecoveryRecord::Incoming(incoming.clone()))
        .unwrap();

    let loaded = RecoveryState::load(wal.path()).unwrap();
    assert_eq!(loaded.incoming.len(), 1);
    assert!(loaded.incoming.contains(&incoming));
}

#[test]
fn wal_rotation_keeps_at_most_two_epochs() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("dkg-recovery-1.wal"), b"old\n").unwrap();
    fs::write(dir.path().join("dkg-recovery-2.wal"), b"older\n").unwrap();

    let wal = open_wal(dir.path(), 3);

    assert!(!dir.path().join("dkg-recovery-1.wal").exists());
    assert!(dir.path().join("dkg-recovery-2.wal").exists());
    assert!(wal.path().exists());
}

#[test]
fn wal_rotation_does_not_delete_newer_epochs() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("dkg-recovery-7.wal"), b"newer\n").unwrap();
    fs::write(dir.path().join("dkg-recovery-8.wal"), b"newest\n").unwrap();

    let wal = open_wal(dir.path(), 6);

    assert!(wal.path().exists());
    assert!(dir.path().join("dkg-recovery-7.wal").exists());
    assert!(dir.path().join("dkg-recovery-8.wal").exists());

    open_wal(dir.path(), 7);
    assert!(!dir.path().join("dkg-recovery-6.wal").exists());
    assert!(dir.path().join("dkg-recovery-7.wal").exists());
    assert!(dir.path().join("dkg-recovery-8.wal").exists());
}

#[test]
fn lists_recoverable_epochs_in_order() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("dkg-recovery-9.wal"), []).unwrap();
    fs::write(dir.path().join("dkg-recovery-7.wal"), []).unwrap();
    fs::write(dir.path().join("unrelated"), []).unwrap();

    assert_eq!(
        recovery_epochs(dir.path()).unwrap(),
        vec![Epoch(7), Epoch(9)]
    );
    assert!(recovery_epochs(&dir.path().join("missing"))
        .unwrap()
        .is_empty());
}
