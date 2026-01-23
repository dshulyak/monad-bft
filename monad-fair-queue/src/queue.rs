use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, VecDeque},
    fmt::{Debug, Display},
    hash::Hash,
};

use crate::{Identity, IdentityScore, PushError};

struct IdentityState<T> {
    queue: VecDeque<T>,
    score: f64,
    finish_time: f64,
    in_heap: bool,
}

struct HeapEntry<Id> {
    finish_time: f64,
    id: Id,
}

impl<Id: Eq> PartialEq for HeapEntry<Id> {
    fn eq(&self, other: &Self) -> bool {
        self.finish_time == other.finish_time && self.id == other.id
    }
}

impl<Id: Eq> Eq for HeapEntry<Id> {}

impl<Id: Eq> PartialOrd for HeapEntry<Id> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Id: Eq> Ord for HeapEntry<Id> {
    fn cmp(&self, other: &Self) -> Ordering {
        other.finish_time.total_cmp(&self.finish_time)
    }
}

struct Pool<Id, T> {
    identities: HashMap<Id, IdentityState<T>>,
    heap: BinaryHeap<HeapEntry<Id>>,
    virtual_time: f64,
    total_items: usize,
    max_size: usize,
    per_id_limit: usize,
}

impl<Id: Hash + Eq + Clone + Debug + Display, T> Pool<Id, T> {
    fn new(per_id_limit: usize, max_size: usize) -> Self {
        Self {
            identities: HashMap::new(),
            heap: BinaryHeap::new(),
            virtual_time: 0.0,
            total_items: 0,
            max_size,
            per_id_limit,
        }
    }

    fn push(&mut self, id: Id, item: T, score: f64) -> Result<(), PushError<Id>> {
        let score = score.min(100.0);

        if self.total_items >= self.max_size {
            return Err(PushError::Full {
                size: self.total_items,
                max_size: self.max_size,
            });
        }

        let was_empty = self
            .identities
            .get(&id)
            .map(|s| s.queue.is_empty())
            .unwrap_or(true);

        let id_state = self
            .identities
            .entry(id.clone())
            .or_insert_with(|| IdentityState {
                queue: VecDeque::new(),
                score,
                finish_time: self.virtual_time,
                in_heap: false,
            });
        id_state.score = score;

        if id_state.queue.len() >= self.per_id_limit {
            return Err(PushError::PerIdLimitExceeded {
                id,
                limit: self.per_id_limit,
            });
        }

        id_state.queue.push_back(item);
        self.total_items += 1;

        if was_empty && !id_state.in_heap {
            id_state.finish_time = self.virtual_time;
            id_state.in_heap = true;
            self.heap.push(HeapEntry {
                finish_time: id_state.finish_time,
                id,
            });
        }

        Ok(())
    }

    fn pop(&mut self) -> Option<(Id, T)> {
        while let Some(entry) = self.heap.pop() {
            let Some(id_state) = self.identities.get_mut(&entry.id) else {
                continue;
            };

            if id_state.queue.is_empty() {
                id_state.in_heap = false;
                continue;
            }

            let item = id_state
                .queue
                .pop_front()
                .expect("queue checked non-empty above");
            self.total_items -= 1;
            self.virtual_time = entry.finish_time;
            id_state.finish_time += 1.0 / id_state.score;

            if id_state.queue.is_empty() {
                id_state.in_heap = false;
                self.identities.remove(&entry.id);
            } else {
                self.heap.push(HeapEntry {
                    finish_time: id_state.finish_time,
                    id: entry.id.clone(),
                });
            }

            return Some((entry.id, item));
        }
        None
    }

    fn len(&self) -> usize {
        self.total_items
    }

    fn is_empty(&self) -> bool {
        self.total_items == 0
    }
}

#[derive(Debug, Clone)]
pub struct FairQueueBuilder {
    per_id_limit: usize,
    max_size: usize,
    regular_per_id_limit: usize,
    regular_max_size: usize,
    regular_bandwidth_pct: u8,
}

impl Default for FairQueueBuilder {
    fn default() -> Self {
        Self {
            per_id_limit: 10_000,
            max_size: 20_000,
            regular_per_id_limit: 1_000,
            regular_max_size: 20_000,
            regular_bandwidth_pct: 10,
        }
    }
}

impl FairQueueBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn per_id_limit(mut self, limit: usize) -> Self {
        self.per_id_limit = limit;
        self
    }

    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    pub fn regular_per_id_limit(mut self, limit: usize) -> Self {
        self.regular_per_id_limit = limit;
        self
    }

    pub fn regular_max_size(mut self, size: usize) -> Self {
        self.regular_max_size = size;
        self
    }

    pub fn regular_bandwidth_pct(mut self, pct: u8) -> Self {
        self.regular_bandwidth_pct = pct.min(100);
        self
    }

    pub fn build<S: IdentityScore, U, T>(self, scorer: S) -> FairQueue<S, U, T>
    where
        S::Identity: Hash + Eq + Clone + Debug + Display,
        U: Hash + Eq + Clone + Debug + Display,
    {
        assert!(self.per_id_limit > 0, "per_id_limit must be > 0");
        assert!(self.max_size > 0, "max_size must be > 0");
        assert!(
            self.regular_per_id_limit > 0,
            "regular_per_id_limit must be > 0"
        );
        assert!(self.regular_max_size > 0, "regular_max_size must be > 0");

        FairQueue {
            priority_pool: Pool::new(self.per_id_limit, self.max_size),
            regular_pool: Pool::new(self.regular_per_id_limit, self.regular_max_size),
            scorer,
            regular_bandwidth_pct: self.regular_bandwidth_pct,
            pop_counter: 0,
        }
    }
}

pub struct FairQueue<S: IdentityScore, U, T> {
    priority_pool: Pool<Identity<S::Identity, U>, T>,
    regular_pool: Pool<Identity<S::Identity, U>, T>,
    scorer: S,
    regular_bandwidth_pct: u8,
    pop_counter: u8,
}

impl<S: IdentityScore, U, T> FairQueue<S, U, T>
where
    S::Identity: Hash + Eq + Clone + Debug + Display,
    U: Hash + Eq + Clone + Debug + Display,
{
    pub fn push(
        &mut self,
        id: Identity<S::Identity, U>,
        item: T,
    ) -> Result<(), PushError<Identity<S::Identity, U>>> {
        let score = match &id {
            Identity::Authenticated(identity) => self.scorer.score(identity),
            Identity::Unauthenticated(_) => 0.0,
        };
        if score > 0.0 {
            self.priority_pool.push(id, item, score)
        } else {
            self.regular_pool.push(id, item, 1.0)
        }
    }

    pub fn pop(&mut self) -> Option<(Identity<S::Identity, U>, T)> {
        self.pop_counter = (self.pop_counter + 1) % 100;
        let try_regular_first = self.pop_counter < self.regular_bandwidth_pct;

        if try_regular_first {
            self.regular_pool.pop().or_else(|| self.priority_pool.pop())
        } else {
            self.priority_pool.pop().or_else(|| self.regular_pool.pop())
        }
    }

    pub fn len(&self) -> usize {
        self.priority_pool.len() + self.regular_pool.len()
    }

    pub fn is_empty(&self) -> bool {
        self.priority_pool.is_empty() && self.regular_pool.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::*;

    use super::*;

    #[derive(Clone)]
    struct TestScorer {
        scores: HashMap<u32, f64>,
    }

    impl IdentityScore for TestScorer {
        type Identity = u32;

        fn score(&self, identity: &Self::Identity) -> f64 {
            self.scores.get(identity).copied().unwrap_or(0.0)
        }
    }

    type TestQueue = FairQueue<TestScorer, u32, u32>;

    fn make_queue(scorer: TestScorer) -> TestQueue {
        FairQueueBuilder::new()
            .per_id_limit(100)
            .max_size(10000)
            .regular_per_id_limit(100)
            .regular_max_size(10000)
            .build(scorer)
    }

    proptest! {
        #[test]
        fn conservation(ops in prop::collection::vec(
            prop_oneof![
                (0u32..10, 0u32..1000).prop_map(|(id, val)| (true, id, val)),
                (0u32..10, 0u32..1000).prop_map(|(id, val)| (false, id, val)),
            ],
            0..100
        )) {
            let scorer = TestScorer { scores: (0..100).map(|id| (id, 1.0)).collect() };
            let mut queue = make_queue(scorer);
            let mut count = 0usize;

            for (auth, id, val) in ops {
                let identity = if auth {
                    Identity::Authenticated(id)
                } else {
                    Identity::Unauthenticated(id)
                };
                if queue.push(identity, val).is_ok() {
                    count += 1;
                }
            }

            let mut popped = 0;
            while queue.pop().is_some() {
                popped += 1;
            }
            prop_assert_eq!(popped, count);
        }

        #[test]
        fn proportional_bandwidth(score_ratio in 2u32..10, cycles in 10usize..50) {
            let scores: HashMap<u32, f64> = [(0, score_ratio as f64), (1, 1.0)].into_iter().collect();
            let scorer = TestScorer { scores };

            let mut queue: TestQueue = FairQueueBuilder::new()
                .per_id_limit(10000)
                .max_size(100000)
                .regular_bandwidth_pct(0)
                .build(scorer);

            let items = cycles * (score_ratio as usize + 1) * 10;
            for i in 0..items {
                queue.push(Identity::Authenticated(0), i as u32).unwrap();
                queue.push(Identity::Authenticated(1), (i + 100000) as u32).unwrap();
            }

            let total_pops = cycles * (score_ratio as usize + 1);
            let mut counts: HashMap<u32, usize> = HashMap::new();
            for _ in 0..total_pops {
                if let Some((Identity::Authenticated(id), _)) = queue.pop() {
                    *counts.entry(id).or_default() += 1;
                }
            }

            let id0 = counts.get(&0).copied().unwrap_or(0);
            let id1 = counts.get(&1).copied().unwrap_or(0);
            let expected = score_ratio as f64 / (score_ratio as f64 + 1.0);
            let actual = id0 as f64 / (id0 + id1) as f64;

            prop_assert!((actual - expected).abs() < 0.05);
        }

        #[test]
        fn regular_bandwidth_split(regular_pct in 5u8..50) {
            let scorer = TestScorer { scores: [(0, 1.0)].into_iter().collect() };
            let mut queue: TestQueue = FairQueueBuilder::new()
                .per_id_limit(10000)
                .max_size(100000)
                .regular_per_id_limit(10000)
                .regular_max_size(100000)
                .regular_bandwidth_pct(regular_pct)
                .build(scorer);

            for i in 0..10000u32 {
                queue.push(Identity::Authenticated(0), i).unwrap();
                queue.push(Identity::Unauthenticated(1), i + 100000).unwrap();
            }

            let total_pops = 1000;
            let mut priority_count = 0;
            let mut regular_count = 0;
            for _ in 0..total_pops {
                match queue.pop() {
                    Some((Identity::Authenticated(_), _)) => priority_count += 1,
                    Some((Identity::Unauthenticated(_), _)) => regular_count += 1,
                    None => break,
                }
            }

            let expected_regular = regular_pct as f64 / 100.0;
            let actual_regular = regular_count as f64 / (priority_count + regular_count) as f64;

            prop_assert!((actual_regular - expected_regular).abs() < 0.05);
        }
    }
}
