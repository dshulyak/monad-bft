use std::collections::BTreeSet;

use bytes::Bytes;
use dkg_core::PartyId;
use dkg_protocol::{DkgMessage, DkgMessageError, DkgMessageId, DkgMessageKey};
use thiserror::Error;
use tracing::warn;

use crate::{
    reliable::{
        DurableMessageStore, DurableStoreError as GenericStoreError, IncomingRecord,
        IncomingStatus, MessageIdentity, OutgoingRecord,
    },
    storage::{RecoveryState, RecoveryWal, RecoveryWalError},
};

#[derive(Debug, Error)]
pub(crate) enum DkgDurableStoreError {
    #[error("classify DKG message failed")]
    Classification(#[source] DkgMessageError),
    #[error("construct DKG message ID failed")]
    MessageId(#[source] DkgMessageError),
    #[error("sync message cannot use durable message storage")]
    SyncMessage,
    #[error("DKG message has no recipients")]
    NoRecipients,
    #[error(transparent)]
    Reliable(#[from] GenericStoreError<DkgMessageId, RecoveryWalError>),
}

pub(super) struct DkgDurableStore {
    self_party: PartyId,
    party_count: usize,
    max_ladder_level: u64,
    store: DurableMessageStore<PartyId, DkgMessageId, DkgMessageKey, Bytes, RecoveryWal>,
}

impl DkgDurableStore {
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
            store: DurableMessageStore::new(wal),
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
    ) -> Result<IncomingStatus, DkgDurableStoreError> {
        let status = self.store.accept_incoming(record, identity)?;
        if status == IncomingStatus::New {
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
    ) -> Result<Option<(DkgMessageId, Bytes)>, DkgDurableStoreError> {
        let identity = self.outgoing_identity(&recipients, &message)?;
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
        if accepted {
            failpoint::failpoint!(
                name = "dkg.network.outgoing_persisted",
                description = "after durable DKG output and before network delivery is queued",
            );
        }
        Ok(accepted.then_some((message_id, payload)))
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
    ) -> Result<MessageIdentity<DkgMessageId, DkgMessageKey>, DkgDurableStoreError> {
        let message = DkgMessage::decode(Bytes::copy_from_slice(payload))
            .map_err(DkgDurableStoreError::Classification)?;
        self.identity(source, target, &message)
    }

    pub(super) fn identity(
        &self,
        source: PartyId,
        target: PartyId,
        message: &DkgMessage,
    ) -> Result<MessageIdentity<DkgMessageId, DkgMessageKey>, DkgDurableStoreError> {
        if message.kind().is_sync() {
            return Err(DkgDurableStoreError::SyncMessage);
        }
        let identity = message
            .identity(source, target, self.party_count, self.max_ladder_level)
            .map_err(DkgDurableStoreError::Classification)?;
        Ok(MessageIdentity {
            message_id: identity.message_id(),
            keys: identity.keys.into_iter().collect(),
        })
    }

    fn outgoing_identity(
        &self,
        recipients: &BTreeSet<PartyId>,
        message: &DkgMessage,
    ) -> Result<MessageIdentity<DkgMessageId, DkgMessageKey>, DkgDurableStoreError> {
        if recipients.is_empty() {
            return Err(DkgDurableStoreError::NoRecipients);
        }
        let mut keys = BTreeSet::new();
        for recipient in recipients {
            let identity = self.identity(self.self_party, *recipient, message)?;
            keys.extend(identity.keys);
        }
        Ok(MessageIdentity {
            message_id: DkgMessageId::new(keys.iter().copied())
                .map_err(DkgDurableStoreError::MessageId)?,
            keys,
        })
    }
}

#[cfg(test)]
#[path = "message_store_tests.rs"]
mod tests;
