use std::collections::{BTreeSet, HashMap};

use bytes::Bytes;
use dkg_core::PartyId;
use dkg_protocol::{
    DkgMessage, DkgMessageError, DkgMessageId, DkgMessageIdentity, DkgMessageKey,
    DkgMessagePersistence,
};
use thiserror::Error;
use tracing::warn;

use super::{
    record::{IncomingMessageRecord, OutgoingMessageRecord, RecoveryRecord},
    recovery::{RecoveryState, RecoveryWal, RecoveryWalError},
};

#[derive(Debug, Error)]
pub(crate) enum MessageStoreError {
    #[error("classify DKG message failed")]
    Classification(#[source] DkgMessageError),
    #[error("construct DKG message ID failed")]
    MessageId(#[source] DkgMessageError),
    #[error("retrieval messages must be unicast")]
    RetrievalMustBeUnicast,
    #[error("DKG delivery message ID {0:?} is already assigned")]
    DeliveryIdCollision(DkgMessageId),
    #[error("DKG message has inconsistent persistence policy")]
    InconsistentPersistence,
    #[error("DKG message has no recipients")]
    NoRecipients,
    #[error(transparent)]
    Wal(#[from] RecoveryWalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IncomingStatus {
    New,
    Duplicate,
    Conflict,
}

pub(crate) struct DkgMessageStore {
    self_party: PartyId,
    party_count: usize,
    max_ladder_level: u64,
    wal: RecoveryWal,
    incoming: Vec<IncomingMessageRecord>,
    incoming_by_key: HashMap<DkgMessageKey, usize>,
    outgoing_by_key: HashMap<DkgMessageKey, DkgMessageId>,
    outgoing_by_id: HashMap<DkgMessageId, Option<OutgoingMessageRecord>>,
}

impl DkgMessageStore {
    pub(crate) fn load(
        self_party: PartyId,
        party_count: usize,
        max_ladder_level: u64,
        wal: RecoveryWal,
        recovery: RecoveryState,
    ) -> Self {
        let mut store = Self {
            self_party,
            party_count,
            max_ladder_level,
            wal,
            incoming: Vec::new(),
            incoming_by_key: HashMap::new(),
            outgoing_by_key: HashMap::new(),
            outgoing_by_id: HashMap::new(),
        };
        for record in recovery.outbox.into_values() {
            store.load_outgoing(record);
        }
        for record in recovery.incoming {
            store.load_incoming(record);
        }
        store
    }

    pub(crate) fn incoming_records(&self) -> Vec<IncomingMessageRecord> {
        sorted_records(self.incoming.iter())
    }

    pub(crate) fn outgoing_records(&self) -> Vec<OutgoingMessageRecord> {
        sorted_records(self.outgoing_by_id.values().filter_map(Option::as_ref))
    }

    pub(crate) fn accept_incoming(
        &mut self,
        record: IncomingMessageRecord,
        identity: &DkgMessageIdentity,
    ) -> Result<IncomingStatus, MessageStoreError> {
        let status = self.incoming_status(&record, identity);
        if status != IncomingStatus::New {
            return Ok(status);
        }
        if identity.persistence == DkgMessagePersistence::Durable {
            self.wal.append(&RecoveryRecord::Incoming(record.clone()))?;
            self.index_incoming(record, identity.keys.iter().copied());
            failpoint::failpoint!(
                name = "dkg.peer.input_persisted",
                description =
                    "after durable peer ingress and before generated effects are dispatched",
            );
        }
        Ok(IncomingStatus::New)
    }

    pub(crate) fn incoming_status(
        &self,
        record: &IncomingMessageRecord,
        identity: &DkgMessageIdentity,
    ) -> IncomingStatus {
        if identity.persistence != DkgMessagePersistence::Durable {
            return IncomingStatus::New;
        }
        if identity.message_id() != record.message_id {
            return IncomingStatus::Conflict;
        }
        let existing = identity
            .keys
            .iter()
            .find_map(|key| self.incoming_by_key.get(key))
            .map(|&index| &self.incoming[index]);
        match existing {
            None => IncomingStatus::New,
            Some(existing) if existing.payload == record.payload => IncomingStatus::Duplicate,
            Some(_) => IncomingStatus::Conflict,
        }
    }

    pub(crate) fn accept_outgoing(
        &mut self,
        recipients: BTreeSet<PartyId>,
        message: DkgMessage,
    ) -> Result<Option<(DkgMessageId, Bytes)>, MessageStoreError> {
        let (keys, persistence) = self.classify_outgoing(&recipients, &message)?;
        let message_id =
            DkgMessageId::new(keys.iter().copied()).map_err(MessageStoreError::MessageId)?;
        let payload = message.into_bytes();
        let accepted = match persistence {
            DkgMessagePersistence::Durable => self.accept_durable_outgoing(
                OutgoingMessageRecord {
                    message_id: message_id.clone(),
                    recipients,
                    payload: payload.clone(),
                },
                keys,
            ),
            DkgMessagePersistence::Ephemeral => {
                self.accept_ephemeral_outgoing(message_id.clone(), recipients.len(), keys)
            }
        }?;
        Ok(accepted.then_some((message_id, payload)))
    }

    fn accept_ephemeral_outgoing(
        &mut self,
        message_id: DkgMessageId,
        recipient_count: usize,
        keys: BTreeSet<DkgMessageKey>,
    ) -> Result<bool, MessageStoreError> {
        if recipient_count != 1 || keys.len() != 1 {
            return Err(MessageStoreError::RetrievalMustBeUnicast);
        }
        let key = *keys.first().unwrap();
        if self.outgoing_by_key.contains_key(&key) {
            return Ok(false);
        }
        if self.outgoing_by_id.contains_key(&message_id) {
            return Err(MessageStoreError::DeliveryIdCollision(message_id));
        }
        self.outgoing_by_key.insert(key, message_id.clone());
        self.outgoing_by_id.insert(message_id, None);
        Ok(true)
    }

    fn accept_durable_outgoing(
        &mut self,
        record: OutgoingMessageRecord,
        keys: BTreeSet<DkgMessageKey>,
    ) -> Result<bool, MessageStoreError> {
        if keys
            .iter()
            .any(|key| self.outgoing_by_key.contains_key(key))
        {
            return Ok(false);
        }
        if self.outgoing_by_id.contains_key(&record.message_id) {
            return Err(MessageStoreError::DeliveryIdCollision(record.message_id));
        }

        self.wal.append(&RecoveryRecord::Outgoing(record.clone()))?;
        self.index_outgoing(record, keys);
        failpoint::failpoint!(
            name = "dkg.network.outgoing_persisted",
            description = "after durable DKG output and before network delivery is queued",
        );
        Ok(true)
    }

    fn classify_outgoing(
        &self,
        recipients: &BTreeSet<PartyId>,
        message: &DkgMessage,
    ) -> Result<(BTreeSet<DkgMessageKey>, DkgMessagePersistence), MessageStoreError> {
        if recipients.is_empty() {
            return Err(MessageStoreError::NoRecipients);
        }
        let mut keys = BTreeSet::new();
        let mut persistence = None;
        for recipient in recipients {
            let identity = self.identity(self.self_party, *recipient, message)?;
            if persistence.is_some_and(|value| value != identity.persistence) {
                return Err(MessageStoreError::InconsistentPersistence);
            }
            persistence = Some(identity.persistence);
            keys.extend(identity.keys);
        }
        Ok((keys, persistence.unwrap()))
    }

    pub(crate) fn clear_ephemeral(&mut self) {
        self.outgoing_by_id.retain(|_, record| record.is_some());
        let outgoing = &self.outgoing_by_id;
        self.outgoing_by_key
            .retain(|_, message_id| outgoing.contains_key(message_id));
    }

    #[cfg(test)]
    pub(crate) fn incoming_count(&self) -> usize {
        self.incoming.len()
    }

    pub(crate) fn classify(
        &self,
        source: PartyId,
        target: PartyId,
        payload: &[u8],
    ) -> Result<DkgMessageIdentity, MessageStoreError> {
        let message = DkgMessage::decode(Bytes::copy_from_slice(payload))
            .map_err(MessageStoreError::Classification)?;
        self.identity(source, target, &message)
    }

    pub(crate) fn identity(
        &self,
        source: PartyId,
        target: PartyId,
        message: &DkgMessage,
    ) -> Result<DkgMessageIdentity, MessageStoreError> {
        message
            .identity(source, target, self.party_count, self.max_ladder_level)
            .map_err(MessageStoreError::Classification)
    }

    fn index_outgoing(
        &mut self,
        record: OutgoingMessageRecord,
        keys: impl IntoIterator<Item = DkgMessageKey>,
    ) {
        let message_id = record.message_id.clone();
        for key in keys {
            self.outgoing_by_key.insert(key, message_id.clone());
        }
        self.outgoing_by_id.insert(message_id, Some(record));
    }

    fn index_incoming(
        &mut self,
        record: IncomingMessageRecord,
        keys: impl IntoIterator<Item = DkgMessageKey>,
    ) {
        let index = self.incoming.len();
        for key in keys {
            self.incoming_by_key.insert(key, index);
        }
        self.incoming.push(record);
    }

    fn load_outgoing(&mut self, record: OutgoingMessageRecord) {
        let Ok(message) = DkgMessage::decode(record.payload.clone()) else {
            warn!(message_id = ?record.message_id, "skipping invalid persisted outgoing DKG message");
            return;
        };
        let Ok((keys, DkgMessagePersistence::Durable)) =
            self.classify_outgoing(&record.recipients, &message)
        else {
            warn!(message_id = ?record.message_id, "skipping invalid persisted outgoing DKG message");
            return;
        };
        if DkgMessageId::new(keys.iter().copied()).ok().as_ref() != Some(&record.message_id) {
            warn!(message_id = ?record.message_id, "skipping persisted outgoing DKG message with mismatched ID");
            return;
        }
        if keys
            .iter()
            .any(|key| self.outgoing_by_key.contains_key(key))
        {
            warn!(message_id = ?record.message_id, "skipping conflicting persisted outgoing DKG semantic slot");
            return;
        }
        self.index_outgoing(record, keys);
    }

    fn load_incoming(&mut self, record: IncomingMessageRecord) {
        let Ok(identity) = self.classify(record.source, self.self_party, &record.payload) else {
            return;
        };
        if identity.persistence != DkgMessagePersistence::Durable
            || identity
                .keys
                .iter()
                .any(|key| self.incoming_by_key.contains_key(key))
        {
            warn!(message_id = ?record.message_id, "skipping invalid persisted incoming DKG message");
            return;
        }
        self.index_incoming(record, identity.keys);
    }
}

fn sorted_records<'a, T: Clone + Ord + 'a>(records: impl Iterator<Item = &'a T>) -> Vec<T> {
    let mut records = records.cloned().collect::<Vec<_>>();
    records.sort_unstable();
    records
}

#[cfg(test)]
#[path = "message_store_tests.rs"]
mod tests;
