use std::collections::BTreeSet;

use bytes::Bytes;
use dkg_core::PartyId;
use dkg_protocol::{
    DkgMessage, DkgMessageError, DkgMessageId, DkgMessageKey, DkgMessagePersistence,
};
use thiserror::Error;
use tracing::warn;

use crate::{
    reliable::{
        IncomingRecord, IncomingStatus, MessageIdentity, MessagePersistence, MessageStore,
        MessageStoreError as ReliableStoreError, OutgoingRecord,
    },
    storage::{RecoveryState, RecoveryWal, RecoveryWalError},
};

#[derive(Debug, Error)]
pub(crate) enum MessageStoreError {
    #[error("classify DKG message failed")]
    Classification(#[source] DkgMessageError),
    #[error("construct DKG message ID failed")]
    MessageId(#[source] DkgMessageError),
    #[error("retrieval messages must be unicast")]
    RetrievalMustBeUnicast,
    #[error("DKG message has inconsistent persistence policy")]
    InconsistentPersistence,
    #[error("DKG message has no recipients")]
    NoRecipients,
    #[error(transparent)]
    Reliable(#[from] ReliableStoreError<DkgMessageId, RecoveryWalError>),
}

pub(super) struct DkgMessageStore {
    self_party: PartyId,
    party_count: usize,
    max_ladder_level: u64,
    store: MessageStore<PartyId, DkgMessageId, DkgMessageKey, Bytes, RecoveryWal>,
}

impl DkgMessageStore {
    pub(super) fn load(
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
            store: MessageStore::new(wal),
        };
        for record in recovery.outbox.into_values() {
            let Ok(message) = DkgMessage::decode(record.payload.clone()) else {
                warn!(message_id = ?record.message_id, "skipping malformed persisted outgoing DKG message");
                continue;
            };
            let Ok(identity) = store.outgoing_identity(&record.recipients, &message) else {
                warn!(message_id = ?record.message_id, "skipping invalid persisted outgoing DKG message");
                continue;
            };
            if !store.store.restore_outgoing(record, &identity) {
                warn!(message_id = ?identity.message_id, "skipping conflicting persisted outgoing DKG message");
            }
        }
        for record in recovery.incoming {
            let Ok(identity) = store.classify(record.source, self_party, &record.payload) else {
                warn!(message_id = ?record.message_id, "skipping invalid persisted incoming DKG message");
                continue;
            };
            if !store.store.restore_incoming(record, &identity) {
                warn!(message_id = ?identity.message_id, "skipping conflicting persisted incoming DKG message");
            }
        }
        store
    }

    pub(super) fn incoming_records(&self) -> Vec<IncomingRecord<PartyId, DkgMessageId, Bytes>> {
        self.store.incoming_records()
    }

    pub(super) fn outgoing_records(&self) -> Vec<OutgoingRecord<PartyId, DkgMessageId, Bytes>> {
        self.store.outgoing_records()
    }

    pub(super) fn accept_incoming(
        &mut self,
        record: IncomingRecord<PartyId, DkgMessageId, Bytes>,
        identity: &MessageIdentity<DkgMessageId, DkgMessageKey>,
    ) -> Result<IncomingStatus, MessageStoreError> {
        let status = self.store.accept_incoming(record, identity)?;
        if status == IncomingStatus::New && identity.persistence == MessagePersistence::Durable {
            failpoint::failpoint!(
                name = "dkg.peer.input_persisted",
                description =
                    "after durable peer ingress and before generated effects are dispatched",
            );
        }
        Ok(status)
    }

    pub(super) fn incoming_status(
        &self,
        record: &IncomingRecord<PartyId, DkgMessageId, Bytes>,
        identity: &MessageIdentity<DkgMessageId, DkgMessageKey>,
    ) -> IncomingStatus {
        self.store.incoming_status(record, identity)
    }

    pub(super) fn accept_outgoing(
        &mut self,
        recipients: BTreeSet<PartyId>,
        message: DkgMessage,
    ) -> Result<Option<(DkgMessageId, Bytes)>, MessageStoreError> {
        let identity = self.outgoing_identity(&recipients, &message)?;
        if identity.persistence == MessagePersistence::Ephemeral
            && (recipients.len() != 1 || identity.keys.len() != 1)
        {
            return Err(MessageStoreError::RetrievalMustBeUnicast);
        }
        let message_id = identity.message_id.clone();
        let payload = message.into_bytes();
        let accepted = self.store.accept_outgoing(
            OutgoingRecord {
                message_id: message_id.clone(),
                recipients,
                payload: payload.clone(),
            },
            &identity,
        )?;
        if accepted && identity.persistence == MessagePersistence::Durable {
            failpoint::failpoint!(
                name = "dkg.network.outgoing_persisted",
                description = "after durable DKG output and before network delivery is queued",
            );
        }
        Ok(accepted.then_some((message_id, payload)))
    }

    pub(super) fn clear_ephemeral(&mut self) {
        self.store.clear_ephemeral();
    }

    #[cfg(test)]
    pub(super) fn incoming_count(&self) -> usize {
        self.store.incoming_count()
    }

    pub(super) fn classify(
        &self,
        source: PartyId,
        target: PartyId,
        payload: &[u8],
    ) -> Result<MessageIdentity<DkgMessageId, DkgMessageKey>, MessageStoreError> {
        let message = DkgMessage::decode(Bytes::copy_from_slice(payload))
            .map_err(MessageStoreError::Classification)?;
        self.identity(source, target, &message)
    }

    pub(super) fn identity(
        &self,
        source: PartyId,
        target: PartyId,
        message: &DkgMessage,
    ) -> Result<MessageIdentity<DkgMessageId, DkgMessageKey>, MessageStoreError> {
        let identity = message
            .identity(source, target, self.party_count, self.max_ladder_level)
            .map_err(MessageStoreError::Classification)?;
        Ok(MessageIdentity {
            message_id: identity.message_id(),
            keys: identity.keys.into_iter().collect(),
            persistence: persistence(identity.persistence),
        })
    }

    fn outgoing_identity(
        &self,
        recipients: &BTreeSet<PartyId>,
        message: &DkgMessage,
    ) -> Result<MessageIdentity<DkgMessageId, DkgMessageKey>, MessageStoreError> {
        if recipients.is_empty() {
            return Err(MessageStoreError::NoRecipients);
        }
        let mut keys = BTreeSet::new();
        let mut message_persistence = None;
        for recipient in recipients {
            let identity = message
                .identity(
                    self.self_party,
                    *recipient,
                    self.party_count,
                    self.max_ladder_level,
                )
                .map_err(MessageStoreError::Classification)?;
            if message_persistence.is_some_and(|value| value != identity.persistence) {
                return Err(MessageStoreError::InconsistentPersistence);
            }
            message_persistence = Some(identity.persistence);
            keys.extend(identity.keys);
        }
        Ok(MessageIdentity {
            message_id: DkgMessageId::new(keys.iter().copied())
                .map_err(MessageStoreError::MessageId)?,
            keys,
            persistence: persistence(message_persistence.unwrap()),
        })
    }
}

fn persistence(value: DkgMessagePersistence) -> MessagePersistence {
    match value {
        DkgMessagePersistence::Durable => MessagePersistence::Durable,
        DkgMessagePersistence::Ephemeral => MessagePersistence::Ephemeral,
    }
}

#[cfg(test)]
#[path = "message_store_tests.rs"]
mod tests;
