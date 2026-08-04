//! Durable semantic message deduplication with persistence-before-accept ordering.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Debug,
    hash::Hash,
};

use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct IncomingRecord<Peer, MessageId, Payload> {
    pub(crate) source: Peer,
    pub(crate) message_id: MessageId,
    pub(crate) payload: Payload,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct OutgoingRecord<Peer, MessageId, Payload> {
    pub(crate) message_id: MessageId,
    pub(crate) recipients: BTreeSet<Peer>,
    pub(crate) payload: Payload,
}

pub(crate) struct MessageIdentity<MessageId, MessageKey> {
    pub(crate) message_id: MessageId,
    pub(crate) keys: BTreeSet<MessageKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IncomingStatus {
    New,
    Duplicate,
    Conflict,
}

pub(crate) trait MessageJournal<Peer, MessageId, Payload> {
    type Error;

    fn append_incoming(
        &mut self,
        record: &IncomingRecord<Peer, MessageId, Payload>,
    ) -> Result<(), Self::Error>;

    fn append_outgoing(
        &mut self,
        record: &OutgoingRecord<Peer, MessageId, Payload>,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Error)]
pub(crate) enum DurableStoreError<MessageId: Debug, JournalError> {
    #[error("durable message ID {0:?} is already assigned")]
    MessageIdCollision(MessageId),
    #[error("append reliable message journal failed: {0}")]
    Journal(#[source] JournalError),
}

pub(crate) struct DurableMessageStore<Peer, MessageId, MessageKey, Payload, Journal> {
    journal: Journal,
    incoming: BTreeMap<MessageId, IncomingRecord<Peer, MessageId, Payload>>,
    incoming_by_key: HashMap<MessageKey, MessageId>,
    outgoing_by_key: HashMap<MessageKey, MessageId>,
    outgoing_by_id: BTreeMap<MessageId, OutgoingRecord<Peer, MessageId, Payload>>,
}

impl<Peer, MessageId, MessageKey, Payload, Journal>
    DurableMessageStore<Peer, MessageId, MessageKey, Payload, Journal>
where
    Peer: Copy + Ord,
    MessageId: Clone + Debug + Hash + Ord,
    MessageKey: Copy + Hash + Ord,
    Payload: Clone + Eq,
    Journal: MessageJournal<Peer, MessageId, Payload>,
{
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            incoming: BTreeMap::new(),
            incoming_by_key: HashMap::new(),
            outgoing_by_key: HashMap::new(),
            outgoing_by_id: BTreeMap::new(),
        }
    }

    pub(crate) fn incoming_records(&self) -> Vec<IncomingRecord<Peer, MessageId, Payload>> {
        self.incoming.values().cloned().collect()
    }

    pub(crate) fn outgoing_records(&self) -> Vec<OutgoingRecord<Peer, MessageId, Payload>> {
        self.outgoing_by_id.values().cloned().collect()
    }

    pub(crate) fn accept_incoming(
        &mut self,
        record: IncomingRecord<Peer, MessageId, Payload>,
        identity: &MessageIdentity<MessageId, MessageKey>,
    ) -> Result<IncomingStatus, DurableStoreError<MessageId, Journal::Error>> {
        let status = self.incoming_status(&record, identity);
        if status != IncomingStatus::New {
            return Ok(status);
        }
        self.journal
            .append_incoming(&record)
            .map_err(DurableStoreError::Journal)?;
        self.index_incoming(record, identity.keys.iter().copied());
        Ok(IncomingStatus::New)
    }

    pub(crate) fn incoming_status(
        &self,
        record: &IncomingRecord<Peer, MessageId, Payload>,
        identity: &MessageIdentity<MessageId, MessageKey>,
    ) -> IncomingStatus {
        if identity.message_id != record.message_id {
            return IncomingStatus::Conflict;
        }
        match identity
            .keys
            .iter()
            .find_map(|key| self.incoming_by_key.get(key))
            .map(|message_id| {
                self.incoming
                    .get(message_id)
                    .expect("reliable incoming key references a message")
            }) {
            None => IncomingStatus::New,
            Some(existing) if existing.payload == record.payload => IncomingStatus::Duplicate,
            Some(_) => IncomingStatus::Conflict,
        }
    }

    pub(crate) fn accept_outgoing(
        &mut self,
        record: OutgoingRecord<Peer, MessageId, Payload>,
        identity: &MessageIdentity<MessageId, MessageKey>,
    ) -> Result<bool, DurableStoreError<MessageId, Journal::Error>> {
        if identity
            .keys
            .iter()
            .any(|key| self.outgoing_by_key.contains_key(key))
        {
            return Ok(false);
        }
        if self.outgoing_by_id.contains_key(&record.message_id) {
            return Err(DurableStoreError::MessageIdCollision(record.message_id));
        }

        self.journal
            .append_outgoing(&record)
            .map_err(DurableStoreError::Journal)?;
        self.index_outgoing(record, identity.keys.iter().copied());
        Ok(true)
    }

    pub(crate) fn restore_incoming(
        &mut self,
        record: IncomingRecord<Peer, MessageId, Payload>,
        identity: &MessageIdentity<MessageId, MessageKey>,
    ) -> bool {
        if identity.message_id != record.message_id
            || self.incoming.contains_key(&record.message_id)
            || identity
                .keys
                .iter()
                .any(|key| self.incoming_by_key.contains_key(key))
        {
            return false;
        }
        self.index_incoming(record, identity.keys.iter().copied());
        true
    }

    pub(crate) fn restore_outgoing(
        &mut self,
        record: OutgoingRecord<Peer, MessageId, Payload>,
        identity: &MessageIdentity<MessageId, MessageKey>,
    ) -> bool {
        if identity.message_id != record.message_id
            || self.outgoing_by_id.contains_key(&record.message_id)
            || identity
                .keys
                .iter()
                .any(|key| self.outgoing_by_key.contains_key(key))
        {
            return false;
        }
        self.index_outgoing(record, identity.keys.iter().copied());
        true
    }

    #[cfg(test)]
    pub(crate) fn incoming_count(&self) -> usize {
        self.incoming.len()
    }

    fn index_outgoing(
        &mut self,
        record: OutgoingRecord<Peer, MessageId, Payload>,
        keys: impl IntoIterator<Item = MessageKey>,
    ) {
        let message_id = record.message_id.clone();
        for key in keys {
            self.outgoing_by_key.insert(key, message_id.clone());
        }
        self.outgoing_by_id.insert(message_id, record);
    }

    fn index_incoming(
        &mut self,
        record: IncomingRecord<Peer, MessageId, Payload>,
        keys: impl IntoIterator<Item = MessageKey>,
    ) {
        let message_id = record.message_id.clone();
        for key in keys {
            self.incoming_by_key.insert(key, message_id.clone());
        }
        self.incoming.insert(message_id, record);
    }
}
