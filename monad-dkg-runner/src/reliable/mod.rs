//! Generic at-least-once delivery scheduling.
//!
//! [`RetryScheduler`] resends messages until protocol evidence makes them
//! obsolete. Persistence, wire framing, and peer authentication remain
//! protocol concerns.

use std::{
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap},
    hash::Hash,
    marker::PhantomData,
    time::{Duration, Instant},
};

use rand::Rng;
use thiserror::Error;

pub(crate) trait ObsolescencePolicy {
    type Scope;
    type Evidence: Ord;

    fn obsolete(scope: &Self::Scope, evidence: &Self::Evidence) -> bool;
}

#[derive(Clone, Copy)]
pub(crate) struct RetryConfig {
    initial: Duration,
    step: Duration,
    max: Duration,
    max_jitter: Duration,
}

impl RetryConfig {
    pub(crate) const fn new(
        initial: Duration,
        step: Duration,
        max: Duration,
        max_jitter: Duration,
    ) -> Self {
        Self {
            initial,
            step,
            max,
            max_jitter,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
#[error("message ID reused with different payload or obsolescence scope")]
pub(crate) struct EnqueueError;

pub(crate) struct ScheduledSend<Peer, Payload> {
    pub(crate) to: Peer,
    pub(crate) payload: Payload,
}

pub(crate) struct RetryScheduler<Peer, MessageId, Payload, Policy>
where
    Policy: ObsolescencePolicy,
{
    config: RetryConfig,
    messages: HashMap<MessageId, PendingMessage<Peer, Payload, Policy::Scope>>,
    deadlines: BTreeSet<(Instant, MessageId, Peer)>,
    evidence: BTreeSet<Policy::Evidence>,
    policy: PhantomData<Policy>,
}

impl<Peer, MessageId, Payload, Policy> RetryScheduler<Peer, MessageId, Payload, Policy>
where
    Peer: Copy + Ord,
    MessageId: Clone + Hash + Ord,
    Payload: Clone + Eq,
    Policy: ObsolescencePolicy,
    Policy::Scope: Eq,
{
    pub(crate) fn new(config: RetryConfig) -> Self {
        Self {
            config,
            messages: HashMap::new(),
            deadlines: BTreeSet::new(),
            evidence: BTreeSet::new(),
            policy: PhantomData,
        }
    }

    pub(crate) fn next_timer(&self) -> Option<Instant> {
        self.deadlines.first().map(|(deadline, _, _)| *deadline)
    }

    pub(crate) fn retry_due(&mut self, now: Instant) -> Vec<ScheduledSend<Peer, Payload>> {
        let mut sends = Vec::new();
        while self
            .deadlines
            .first()
            .is_some_and(|(deadline, _, _)| *deadline <= now)
        {
            let (deadline, message_id, to) = self
                .deadlines
                .pop_first()
                .expect("checked reliable retry deadline");
            let message = self
                .messages
                .get_mut(&message_id)
                .expect("scheduled reliable message exists");
            let recipient = message
                .recipients
                .get_mut(&to)
                .expect("scheduled reliable recipient exists");
            assert_eq!(recipient.deadline, deadline);
            let retry_delay = recipient
                .retry_delay
                .saturating_add(self.config.step)
                .min(self.config.max);
            let next_deadline = now + retry_delay + retry_jitter(self.config, retry_delay);
            recipient.retry_delay = retry_delay;
            recipient.deadline = next_deadline;
            sends.push(ScheduledSend {
                to,
                payload: message.payload.clone(),
            });
            self.deadlines.insert((next_deadline, message_id, to));
        }
        sends
    }

    pub(crate) fn enqueue(
        &mut self,
        message_id: MessageId,
        recipients: impl IntoIterator<Item = Peer>,
        payload: Payload,
        scope: Option<Policy::Scope>,
        now: Instant,
    ) -> Result<Vec<ScheduledSend<Peer, Payload>>, EnqueueError> {
        if scope.as_ref().is_some_and(|scope| {
            self.evidence
                .iter()
                .any(|evidence| Policy::obsolete(scope, evidence))
        }) {
            return Ok(Vec::new());
        }

        let recipients = recipients.into_iter().collect::<BTreeSet<_>>();
        if recipients.is_empty() {
            return Ok(Vec::new());
        }

        let message = match self.messages.entry(message_id.clone()) {
            Entry::Vacant(entry) => entry.insert(PendingMessage {
                payload: payload.clone(),
                scope,
                recipients: BTreeMap::new(),
            }),
            Entry::Occupied(entry) => {
                if entry.get().payload != payload || entry.get().scope != scope {
                    return Err(EnqueueError);
                }
                entry.into_mut()
            }
        };

        let new_recipients = recipients
            .into_iter()
            .filter(|to| !message.recipients.contains_key(to))
            .collect::<Vec<_>>();
        let mut sends = Vec::new();
        for to in new_recipients {
            let deadline =
                now + self.config.initial + retry_jitter(self.config, self.config.initial);
            self.messages
                .get_mut(&message_id)
                .expect("reliable message inserted above")
                .recipients
                .insert(to, PendingRecipient::new(self.config, deadline));
            self.deadlines.insert((deadline, message_id.clone(), to));
            sends.push(ScheduledSend {
                to,
                payload: payload.clone(),
            });
        }
        Ok(sends)
    }

    pub(crate) fn observe(&mut self, evidence: Policy::Evidence) {
        let mut removed_deadlines = Vec::new();
        self.messages.retain(|message_id, message| {
            let obsolete = message
                .scope
                .as_ref()
                .is_some_and(|scope| Policy::obsolete(scope, &evidence));
            if obsolete {
                removed_deadlines.extend(
                    message
                        .recipients
                        .iter()
                        .map(|(&to, recipient)| (recipient.deadline, message_id.clone(), to)),
                );
            }
            !obsolete
        });
        for deadline in removed_deadlines {
            self.deadlines.remove(&deadline);
        }
        self.evidence.insert(evidence);
    }

    pub(crate) fn complete(&mut self, message_id: &MessageId) {
        let Some(message) = self.messages.remove(message_id) else {
            return;
        };
        for (to, recipient) in message.recipients {
            self.deadlines
                .remove(&(recipient.deadline, message_id.clone(), to));
        }
    }
}

struct PendingMessage<Peer, Payload, Scope> {
    payload: Payload,
    scope: Option<Scope>,
    recipients: BTreeMap<Peer, PendingRecipient>,
}

struct PendingRecipient {
    deadline: Instant,
    retry_delay: Duration,
}

impl PendingRecipient {
    fn new(config: RetryConfig, deadline: Instant) -> Self {
        Self {
            deadline,
            retry_delay: config.initial,
        }
    }
}

fn retry_jitter(config: RetryConfig, retry_delay: Duration) -> Duration {
    let max_jitter_ms = (retry_delay / 5)
        .min(config.max_jitter)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    Duration::from_millis(rand::thread_rng().gen_range(0..=max_jitter_ms))
}

#[cfg(test)]
mod tests;
