//! Generic at-least-once submission state machine.

use std::collections::{BTreeMap, BTreeSet};

pub(super) enum PreparedState<Prepared> {
    Current,
    Replace(Prepared),
    Obsolete,
}

pub(super) trait SubmissionStrategy<Key, Value> {
    type Prepared;
    type Error;

    fn refresh(
        &self,
        key: &Key,
        value: &Value,
        prepared: Option<&Self::Prepared>,
    ) -> Result<PreparedState<Self::Prepared>, Self::Error>;

    fn submit(&self, prepared: &Self::Prepared) -> Result<(), Self::Error>;
}

pub(super) enum Attempt<Key, Value, Error> {
    Idle,
    Retired { key: Key, value: Value },
    RefreshFailed { key: Key, error: Error },
    Submitted { key: Key },
    SubmitFailed { key: Key, error: Error },
}

pub(super) struct ReliableSubmitter<Strategy, Key, Value>
where
    Strategy: SubmissionStrategy<Key, Value>,
{
    strategy: Strategy,
    pending: BTreeMap<Key, Value>,
    prepared: Option<(Key, Strategy::Prepared)>,
    finalized: BTreeSet<Key>,
}

impl<Strategy, Key, Value> ReliableSubmitter<Strategy, Key, Value>
where
    Strategy: SubmissionStrategy<Key, Value>,
    Key: Clone + Ord,
{
    pub(super) fn new(strategy: Strategy) -> Self {
        Self {
            strategy,
            pending: BTreeMap::new(),
            prepared: None,
            finalized: BTreeSet::new(),
        }
    }

    pub(super) fn strategy(&self) -> &Strategy {
        &self.strategy
    }

    pub(super) fn strategy_mut(&mut self) -> &mut Strategy {
        &mut self.strategy
    }

    pub(super) fn enqueue(&mut self, key: Key, value: Value) -> bool {
        if self.finalized.contains(&key) || self.pending.contains_key(&key) {
            return false;
        }
        self.pending.insert(key, value);
        true
    }

    pub(super) fn confirm(&mut self, key: Key) {
        self.finalized.insert(key.clone());
        self.remove_pending(&key);
    }

    pub(super) fn retain(&mut self, keep: impl Fn(&Key) -> bool) {
        self.pending.retain(|key, _| keep(key));
        self.finalized.retain(&keep);
        self.clear_orphaned_prepared();
    }

    pub(super) fn remove_where(&mut self, remove: impl Fn(&Key) -> bool) {
        self.pending.retain(|key, _| !remove(key));
        self.clear_orphaned_prepared();
    }

    pub(super) fn pending_keys(&self, include: impl Fn(&Key) -> bool) -> Vec<Key> {
        self.pending
            .keys()
            .filter(|key| include(key))
            .cloned()
            .collect()
    }

    pub(super) fn pending(&self, key: &Key) -> Option<&Value> {
        self.pending.get(key)
    }

    pub(super) fn prepared(&self, key: &Key) -> Option<&Strategy::Prepared> {
        self.prepared
            .as_ref()
            .filter(|(prepared_key, _)| prepared_key == key)
            .map(|(_, prepared)| prepared)
    }

    pub(super) fn attempt(
        &mut self,
        keys: impl IntoIterator<Item = Key>,
    ) -> Attempt<Key, Value, Strategy::Error> {
        let keys = keys.into_iter().collect::<Vec<_>>();
        let key = match &self.prepared {
            Some((key, _)) if keys.contains(key) => key.clone(),
            Some(_) => return Attempt::Idle,
            None => match keys.iter().find(|key| self.pending.contains_key(key)) {
                Some(key) => (*key).clone(),
                None => return Attempt::Idle,
            },
        };
        let value = self
            .pending
            .get(&key)
            .expect("selected reliable submission remains pending");
        let prepared = self.prepared.as_ref().map(|(_, prepared)| prepared);
        match self.strategy.refresh(&key, value, prepared) {
            Ok(PreparedState::Current) => {
                assert!(
                    prepared.is_some(),
                    "current reliable submission is prepared"
                );
            }
            Ok(PreparedState::Replace(replacement)) => {
                self.prepared = Some((key.clone(), replacement));
            }
            Ok(PreparedState::Obsolete) => {
                self.prepared = None;
                let value = self
                    .pending
                    .remove(&key)
                    .expect("obsolete reliable submission remains pending");
                self.finalized.insert(key.clone());
                return Attempt::Retired { key, value };
            }
            Err(error) => return Attempt::RefreshFailed { key, error },
        }

        let prepared = &self
            .prepared
            .as_ref()
            .expect("refreshed reliable submission is prepared")
            .1;
        match self.strategy.submit(prepared) {
            Ok(()) => Attempt::Submitted { key },
            Err(error) => Attempt::SubmitFailed { key, error },
        }
    }

    fn remove_pending(&mut self, key: &Key) {
        self.pending.remove(key);
        if self
            .prepared
            .as_ref()
            .is_some_and(|(prepared_key, _)| prepared_key == key)
        {
            self.prepared = None;
        }
    }

    fn clear_orphaned_prepared(&mut self) {
        if self
            .prepared
            .as_ref()
            .is_some_and(|(key, _)| !self.pending.contains_key(key))
        {
            self.prepared = None;
        }
    }
}
