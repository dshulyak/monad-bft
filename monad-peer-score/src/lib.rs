use std::{
    hash::Hash,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use lru::LruCache;

// --- Config ---

#[derive(Debug, Clone)]
pub struct ScoreConfig {
    pub min_time_for_score: Duration,
    pub max_identities: usize,
    pub max_time_weight: f64,
    pub time_weight_unit: Duration,
    pub decay_half_life: Duration,
}

impl Default for ScoreConfig {
    fn default() -> Self {
        Self {
            min_time_for_score: Duration::from_secs(5 * 60),
            max_identities: 100_000,
            max_time_weight: 10.0,
            time_weight_unit: Duration::from_secs(3600),
            decay_half_life: Duration::from_secs(30 * 60),
        }
    }
}

// --- Clock ---

pub trait Clock: Clone + Send + Sync {
    fn now(&self) -> Instant;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StdClock;

impl Clock for StdClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod mock {
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use super::Clock;

    #[derive(Clone)]
    pub struct MockClock {
        base: Instant,
        offset_nanos: Arc<AtomicU64>,
    }

    impl MockClock {
        pub fn new() -> Self {
            Self {
                base: Instant::now(),
                offset_nanos: Arc::new(AtomicU64::new(0)),
            }
        }

        pub fn advance(&self, duration: Duration) {
            self.offset_nanos
                .fetch_add(duration.as_nanos() as u64, Ordering::SeqCst);
        }
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            let offset = Duration::from_nanos(self.offset_nanos.load(Ordering::SeqCst));
            self.base + offset
        }
    }
}

// --- Scorer ---

pub trait IdentityScore {
    type Identity;
    fn score(&self, identity: &Self::Identity) -> f64;
}

struct IdentityState {
    contribution_count: u64,
    first_seen: Instant,
    last_activity: Instant,
}

struct SharedState<I> {
    identities: LruCache<I, IdentityState>,
    config: ScoreConfig,
}

pub struct ScoreProvider<I, C> {
    state: Arc<Mutex<SharedState<I>>>,
    clock: C,
}

pub struct ScoreReader<I, C> {
    state: Arc<Mutex<SharedState<I>>>,
    clock: C,
}

impl<I, C: Clone> Clone for ScoreReader<I, C> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            clock: self.clock.clone(),
        }
    }
}

pub fn create_scorer<I: Hash + Eq, C: Clock + Clone>(
    config: ScoreConfig,
    clock: C,
) -> (ScoreProvider<I, C>, ScoreReader<I, C>) {
    assert!(config.max_identities > 0, "max_identities must be > 0");
    assert!(
        !config.time_weight_unit.is_zero(),
        "time_weight_unit must be > 0"
    );
    assert!(
        !config.decay_half_life.is_zero(),
        "decay_half_life must be > 0"
    );
    let capacity = NonZeroUsize::new(config.max_identities).unwrap();
    let state = Arc::new(Mutex::new(SharedState {
        identities: LruCache::new(capacity),
        config,
    }));
    let provider = ScoreProvider {
        state: Arc::clone(&state),
        clock: clock.clone(),
    };
    let reader = ScoreReader { state, clock };
    (provider, reader)
}

impl<I: Hash + Eq, C: Clock> ScoreProvider<I, C> {
    pub fn record_contribution(&self, identity: I) {
        let now = self.clock.now();
        let mut state = self.state.lock().unwrap();

        if let Some(id_state) = state.identities.get_mut(&identity) {
            id_state.contribution_count += 1;
            id_state.last_activity = now;
        } else {
            state.identities.push(
                identity,
                IdentityState {
                    contribution_count: 1,
                    first_seen: now,
                    last_activity: now,
                },
            );
        }
    }
}

impl<I: Hash + Eq, C: Clock> ScoreReader<I, C> {
    pub fn score(&self, identity: &I) -> f64 {
        let now = self.clock.now();
        let state = self.state.lock().unwrap();

        state
            .identities
            .peek(identity)
            .map(|id_state| compute_score(id_state, &state.config, now))
            .unwrap_or(0.0)
    }
}

fn compute_score(id_state: &IdentityState, config: &ScoreConfig, now: Instant) -> f64 {
    let time_known = now.duration_since(id_state.first_seen);
    if time_known < config.min_time_for_score {
        return 0.0;
    }

    let time_weight = (time_known.as_secs_f64() / config.time_weight_unit.as_secs_f64())
        .min(config.max_time_weight);
    let base_score = id_state.contribution_count as f64 * time_weight;

    let idle_time = now.duration_since(id_state.last_activity);
    let decay_factor = 0.5_f64.powf(idle_time.as_secs_f64() / config.decay_half_life.as_secs_f64());

    base_score * decay_factor
}

impl<I: Hash + Eq + Send, C: Clock + Send> IdentityScore for ScoreReader<I, C> {
    type Identity = I;

    fn score(&self, identity: &Self::Identity) -> f64 {
        self.score(identity)
    }
}

#[cfg(test)]
mod tests {
    use mock::MockClock;

    use super::*;

    #[test]
    fn new_identity_has_zero_score() {
        let clock = MockClock::new();
        let (_, reader) = create_scorer::<u32, _>(ScoreConfig::default(), clock);
        assert_eq!(reader.score(&1), 0.0);
    }

    #[test]
    fn score_after_min_time() {
        let clock = MockClock::new();
        let (provider, reader) = create_scorer::<u32, _>(ScoreConfig::default(), clock.clone());

        provider.record_contribution(1);
        assert_eq!(reader.score(&1), 0.0);

        clock.advance(Duration::from_secs(3600));
        assert!(reader.score(&1) > 0.0);
    }

    #[test]
    fn linear_growth() {
        let config = ScoreConfig {
            min_time_for_score: Duration::ZERO,
            decay_half_life: Duration::from_secs(365 * 24 * 3600),
            ..Default::default()
        };
        let clock = MockClock::new();
        let (provider, reader) = create_scorer::<u32, _>(config, clock.clone());

        for _ in 0..10 {
            provider.record_contribution(1);
        }
        clock.advance(Duration::from_secs(3600));
        let score_10 = reader.score(&1);

        for _ in 0..90 {
            provider.record_contribution(1);
        }
        let score_100 = reader.score(&1);

        assert!((score_100 / score_10 - 10.0).abs() < 0.001);
    }

    #[test]
    fn time_weight_caps() {
        let config = ScoreConfig {
            min_time_for_score: Duration::ZERO,
            max_time_weight: 5.0,
            decay_half_life: Duration::from_secs(365 * 24 * 3600),
            ..Default::default()
        };
        let clock = MockClock::new();
        let (provider, reader) = create_scorer::<u32, _>(config, clock.clone());

        provider.record_contribution(1);

        clock.advance(Duration::from_secs(10 * 3600));
        let score_10h = reader.score(&1);

        provider.record_contribution(1);

        clock.advance(Duration::from_secs(20 * 3600));
        let score_30h = reader.score(&1);

        assert!(
            (score_30h / score_10h - 2.0).abs() < 0.1,
            "score should double with 2x contributions when time_weight capped: {} vs {}",
            score_10h,
            score_30h
        );
    }

    #[test]
    fn clone_shares_state() {
        let clock = MockClock::new();
        let (provider, reader) = create_scorer::<u32, _>(ScoreConfig::default(), clock.clone());
        let reader_clone = reader.clone();

        provider.record_contribution(1);
        clock.advance(Duration::from_secs(3600));

        assert!(reader.score(&1) > 0.0);
        assert!(reader_clone.score(&1) > 0.0);
    }

    #[test]
    fn is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<ScoreProvider<u32, StdClock>>();
        assert_sync::<ScoreProvider<u32, StdClock>>();
        assert_send::<ScoreReader<u32, StdClock>>();
        assert_sync::<ScoreReader<u32, StdClock>>();
    }

    #[test]
    fn score_decays_with_inactivity() {
        let config = ScoreConfig {
            min_time_for_score: Duration::ZERO,
            max_time_weight: 1.0,
            time_weight_unit: Duration::from_secs(1),
            decay_half_life: Duration::from_secs(1800),
            ..Default::default()
        };
        let clock = MockClock::new();
        let (provider, reader) = create_scorer::<u32, _>(config, clock.clone());

        provider.record_contribution(1);
        clock.advance(Duration::from_secs(100));
        provider.record_contribution(1);
        let score_active = reader.score(&1);

        clock.advance(Duration::from_secs(1800));
        let score_after_half_life = reader.score(&1);

        let ratio = score_after_half_life / score_active;
        assert!(
            (ratio - 0.5).abs() < 0.05,
            "ratio should be ~0.5: {}",
            ratio
        );
    }

    #[test]
    fn lru_eviction_on_capacity() {
        let config = ScoreConfig {
            max_identities: 3,
            min_time_for_score: Duration::ZERO,
            time_weight_unit: Duration::from_secs(1),
            decay_half_life: Duration::from_secs(365 * 24 * 3600),
            ..Default::default()
        };
        let clock = MockClock::new();
        let (provider, reader) = create_scorer::<u32, _>(config, clock.clone());

        provider.record_contribution(1);
        provider.record_contribution(2);
        provider.record_contribution(3);
        clock.advance(Duration::from_secs(100));

        assert!(reader.score(&1) > 0.0);
        assert!(reader.score(&2) > 0.0);
        assert!(reader.score(&3) > 0.0);

        provider.record_contribution(4);
        clock.advance(Duration::from_secs(100));

        assert_eq!(reader.score(&1), 0.0, "identity 1 should be evicted");
        assert!(reader.score(&2) > 0.0);
        assert!(reader.score(&3) > 0.0);
        assert!(reader.score(&4) > 0.0, "identity 4 should have score");
    }

    #[test]
    fn lru_promotes_on_contribution() {
        let config = ScoreConfig {
            max_identities: 3,
            min_time_for_score: Duration::ZERO,
            time_weight_unit: Duration::from_secs(1),
            decay_half_life: Duration::from_secs(365 * 24 * 3600),
            ..Default::default()
        };
        let clock = MockClock::new();
        let (provider, reader) = create_scorer::<u32, _>(config, clock.clone());

        provider.record_contribution(1);
        provider.record_contribution(2);
        provider.record_contribution(3);

        provider.record_contribution(1);

        provider.record_contribution(4);
        clock.advance(Duration::from_secs(100));

        assert!(
            reader.score(&1) > 0.0,
            "identity 1 should still exist (was promoted)"
        );
        assert_eq!(reader.score(&2), 0.0, "identity 2 should be evicted");
        assert!(reader.score(&3) > 0.0);
        assert!(reader.score(&4) > 0.0);
    }
}
