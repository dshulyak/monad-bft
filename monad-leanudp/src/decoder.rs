use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    hash::Hash,
    time::{Duration, Instant},
};

use bytes::Bytes;
use thiserror::Error;
use tracing::debug;
use zerocopy::FromBytes;

use crate::{Config, FragmentPolicy, IdentityScore, PacketHeader, LEANUDP_HEADER_SIZE};

pub trait Clock: Clone {
    fn now(&self) -> Instant;
}

#[derive(Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeOutcome {
    Pending,
    Complete(Bytes),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("packet too short: {actual} bytes, need {required}")]
    InvalidHeaderSize { actual: usize, required: usize },

    #[error("invalid header")]
    InvalidHeader,

    #[error("fragment payload {actual} exceeds max {max}")]
    FragmentPayloadTooLarge { actual: usize, max: usize },

    #[error("identity at message limit ({max})")]
    IdentityLimitExceeded { max: usize },

    #[error("duplicate fragment msg_id={msg_id} seq={seq_num}")]
    DuplicateFragment { msg_id: u32, seq_num: u8 },

    #[error("too many fragments: {count} exceeds max {max}")]
    TooManyFragments { count: usize, max: usize },

    #[error("conflicting END marker: expected {expected} fragments, got {actual}")]
    ConflictingEndMarker { expected: u16, actual: u16 },

    #[error("pool full")]
    PoolFull,
}

struct MessageState {
    fragments: BTreeMap<u8, Bytes>,
    total_frags: Option<u16>,
}

impl MessageState {
    fn new() -> Self {
        Self {
            fragments: BTreeMap::new(),
            total_frags: None,
        }
    }

    fn total_size(&self) -> usize {
        self.fragments.values().map(|f| f.len()).sum()
    }

    fn is_complete(&self) -> bool {
        self.total_frags == Some(self.fragments.len() as u16)
    }

    fn extract(self) -> Bytes {
        let mut buf = Vec::with_capacity(self.total_size());
        for (_, frag) in self.fragments {
            buf.extend_from_slice(&frag);
        }
        Bytes::from(buf)
    }
}

struct PoolConfig {
    max_messages: usize,
    max_fragments_per_message: usize,
    max_fragment_payload: usize,
    max_messages_per_identity: usize,
    message_timeout: Duration,
}

impl PoolConfig {
    fn from_config(config: &Config, max_messages: usize) -> Self {
        Self {
            max_messages,
            max_fragments_per_message: config.max_fragments_per_message,
            max_fragment_payload: config.max_fragment_payload,
            max_messages_per_identity: config.max_messages_per_identity,
            message_timeout: config.message_timeout,
        }
    }
}

struct MessagePool<I, C> {
    messages: HashMap<(I, u32), MessageState>,
    identity_message_counts: HashMap<I, usize>,
    lru_queue: VecDeque<(Instant, I, u32)>,
    cfg: PoolConfig,
    clock: C,
}

impl<I: Eq + Hash + Clone, C: Clock> MessagePool<I, C> {
    fn new(cfg: PoolConfig, clock: C) -> Self {
        Self {
            messages: HashMap::new(),
            identity_message_counts: HashMap::new(),
            lru_queue: VecDeque::new(),
            cfg,
            clock,
        }
    }

    fn decode(&mut self, identity: I, packet: Bytes) -> Result<DecodeOutcome, DecodeError> {
        let now = self.clock.now();
        if packet.len() < LEANUDP_HEADER_SIZE {
            return Err(DecodeError::InvalidHeaderSize {
                actual: packet.len(),
                required: LEANUDP_HEADER_SIZE,
            });
        }

        let header = PacketHeader::read_from_bytes(&packet[..LEANUDP_HEADER_SIZE])
            .map_err(|_| DecodeError::InvalidHeader)?;

        let msg_id = header.msg_id();
        let seq_num = header.seq_num();
        let fragment_type = header.fragment_type();
        let data = packet.slice(LEANUDP_HEADER_SIZE..);

        if data.len() > self.cfg.max_fragment_payload {
            return Err(DecodeError::FragmentPayloadTooLarge {
                actual: data.len(),
                max: self.cfg.max_fragment_payload,
            });
        }

        let key = (identity.clone(), msg_id);

        if !self.messages.contains_key(&key) {
            let identity_count = self
                .identity_message_counts
                .get(&identity)
                .copied()
                .unwrap_or(0);
            if identity_count >= self.cfg.max_messages_per_identity {
                return Err(DecodeError::IdentityLimitExceeded {
                    max: self.cfg.max_messages_per_identity,
                });
            }
            if self.messages.len() >= self.cfg.max_messages && !self.evict_one_expired() {
                return Err(DecodeError::PoolFull);
            }
            self.messages.insert(key.clone(), MessageState::new());
            *self
                .identity_message_counts
                .entry(identity.clone())
                .or_insert(0) += 1;
            self.lru_queue
                .push_back((now + self.cfg.message_timeout, identity, msg_id));
        }

        {
            let state = self
                .messages
                .get_mut(&key)
                .expect("message was just inserted or confirmed to exist");

            if state.fragments.contains_key(&seq_num) {
                return Err(DecodeError::DuplicateFragment { msg_id, seq_num });
            }

            let fragment_count = state.fragments.len();
            if fragment_count >= self.cfg.max_fragments_per_message {
                let max = self.cfg.max_fragments_per_message;
                self.remove_message(&key);
                return Err(DecodeError::TooManyFragments {
                    count: fragment_count + 1,
                    max,
                });
            }

            if fragment_type.is_end() {
                let new_total = u16::from(seq_num) + 1;
                if let Some(existing) = state.total_frags {
                    if existing != new_total {
                        self.remove_message(&key);
                        return Err(DecodeError::ConflictingEndMarker {
                            expected: existing,
                            actual: new_total,
                        });
                    }
                } else {
                    state.total_frags = Some(new_total);
                }
            }

            state.fragments.insert(seq_num, data);

            if !state.is_complete() {
                return Ok(DecodeOutcome::Pending);
            }
        }

        let msg = self.extract_message(&key);
        Ok(DecodeOutcome::Complete(msg))
    }

    fn remove_message(&mut self, key: &(I, u32)) -> Option<MessageState> {
        let state = self.messages.remove(key)?;
        let identity = &key.0;
        if let Some(count) = self.identity_message_counts.get_mut(identity) {
            *count -= 1;
            if *count == 0 {
                self.identity_message_counts.remove(identity);
            }
        }
        Some(state)
    }

    fn evict_one_expired(&mut self) -> bool {
        let now = self.clock.now();
        while let Some(&(deadline, ref identity, msg_id)) = self.lru_queue.front() {
            if deadline > now {
                return false;
            }
            let key = (identity.clone(), msg_id);
            self.lru_queue.pop_front();
            if self.messages.contains_key(&key) {
                debug!(msg_id, "evicting expired message");
                self.remove_message(&key);
                return true;
            }
        }
        false
    }

    fn extract_message(&mut self, key: &(I, u32)) -> Bytes {
        let state = self
            .remove_message(key)
            .expect("message must exist when extracting");
        state.extract()
    }

    fn message_count(&self) -> usize {
        self.messages.len()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DecoderStats {
    pub priority_messages: usize,
    pub regular_messages: usize,
}

pub struct Decoder<I, P, C>
where
    I: Eq + Hash + Clone,
    P: IdentityScore<Identity = I>,
    C: Clock,
{
    priority_pool: MessagePool<I, C>,
    regular_pool: MessagePool<I, C>,
    identity_score: P,
}

impl<I, P> Decoder<I, P, SystemClock>
where
    I: Eq + Hash + Clone,
    P: IdentityScore<Identity = I>,
{
    pub(crate) fn new(config: &Config, identity_score: P) -> Self {
        Self::with_clock(config, identity_score, SystemClock)
    }
}

impl<I, P, C> Decoder<I, P, C>
where
    I: Eq + Hash + Clone,
    P: IdentityScore<Identity = I>,
    C: Clock,
{
    pub(crate) fn with_clock(config: &Config, identity_score: P, clock: C) -> Self {
        Self {
            priority_pool: MessagePool::new(
                PoolConfig::from_config(config, config.max_priority_messages),
                clock.clone(),
            ),
            regular_pool: MessagePool::new(
                PoolConfig::from_config(config, config.max_regular_messages),
                clock,
            ),
            identity_score,
        }
    }

    pub fn decode(&mut self, identity: I, packet: Bytes) -> Result<DecodeOutcome, DecodeError> {
        let is_priority = self.identity_score.score(&identity) == FragmentPolicy::Prioritized;
        let pool = if is_priority {
            &mut self.priority_pool
        } else {
            &mut self.regular_pool
        };

        pool.decode(identity, packet)
    }

    pub fn stats(&self) -> DecoderStats {
        DecoderStats {
            priority_messages: self.priority_pool.message_count(),
            regular_messages: self.regular_pool.message_count(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use bytes::BufMut;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::{FragmentType, MAX_FRAGMENTS};

    #[derive(Clone)]
    struct MockClock(std::rc::Rc<Cell<Instant>>);

    impl MockClock {
        fn new() -> Self {
            Self(std::rc::Rc::new(Cell::new(Instant::now())))
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            self.0.get()
        }
    }

    struct TestIdentityScore(Vec<u64>);

    impl IdentityScore for TestIdentityScore {
        type Identity = u64;
        fn score(&self, id: &u64) -> FragmentPolicy {
            if self.0.contains(id) {
                FragmentPolicy::Prioritized
            } else {
                FragmentPolicy::Regular
            }
        }
    }

    struct TestDecoder {
        inner: Decoder<u64, TestIdentityScore, MockClock>,
        clock: MockClock,
    }

    impl TestDecoder {
        fn new() -> Self {
            Self::with_config(Config {
                max_fragment_payload: 1400,
                max_priority_messages: 10,
                max_regular_messages: 5,
                max_fragments_per_message: MAX_FRAGMENTS,
                max_messages_per_identity: 10,
                message_timeout: Duration::from_millis(400),
                score_threshold: 1.0,
            })
        }

        fn with_config(config: Config) -> Self {
            Self::with_config_and_priority(config, &[])
        }

        fn priority(ids: &[u64]) -> Self {
            Self::with_config_and_priority(
                Config {
                    max_fragment_payload: 1400,
                    max_priority_messages: 10,
                    max_regular_messages: 5,
                    max_fragments_per_message: MAX_FRAGMENTS,
                    max_messages_per_identity: 10,
                    message_timeout: Duration::from_millis(400),
                    score_threshold: 1.0,
                },
                ids,
            )
        }

        fn with_config_and_priority(config: Config, priority_ids: &[u64]) -> Self {
            let clock = MockClock::new();
            let inner = Decoder::with_clock(
                &config,
                TestIdentityScore(priority_ids.to_vec()),
                clock.clone(),
            );
            Self { inner, clock }
        }

        fn decode(&mut self, id: u64, packet: Bytes) -> Result<DecodeOutcome, DecodeError> {
            self.inner.decode(id, packet)
        }

        fn stats(&self) -> DecoderStats {
            self.inner.stats()
        }

        fn advance_ms(&self, ms: u64) {
            self.clock
                .0
                .set(self.clock.0.get() + Duration::from_millis(ms));
        }
    }

    fn pkt(msg_id: u32, seq: u8, frag_type: FragmentType, data: &[u8]) -> Bytes {
        let header = PacketHeader::new(msg_id, seq, frag_type);
        let mut buf = bytes::BytesMut::with_capacity(LEANUDP_HEADER_SIZE + data.len());
        buf.put_slice(header.as_bytes());
        buf.put_slice(data);
        buf.freeze()
    }

    use FragmentType::{Complete, End, Middle, Start};

    #[test]
    fn test_decode_single_message() {
        let mut d = TestDecoder::priority(&[1000]);
        assert_eq!(
            d.decode(1000, pkt(0, 0, Complete, b"hello")),
            Ok(DecodeOutcome::Complete(Bytes::from_static(b"hello")))
        );
        assert_eq!(d.stats().priority_messages, 0);
    }

    #[test]
    fn test_decode_priority_vs_regular() {
        let mut d = TestDecoder::priority(&[1000, 1001]);
        let _ = d.decode(1000, pkt(0, 0, Start, b"p1"));
        let _ = d.decode(2000, pkt(0, 0, Start, b"r1"));
        let _ = d.decode(1001, pkt(0, 0, Start, b"p2"));
        let _ = d.decode(2001, pkt(0, 0, Start, b"r2"));
        assert_eq!(d.stats().priority_messages, 2);
        assert_eq!(d.stats().regular_messages, 2);
    }

    #[test]
    fn test_pool_full_evicts_expired() {
        let mut d = TestDecoder::new();
        for i in 0..5 {
            assert_eq!(
                d.decode(2000 + i, pkt(i as u32, 0, Start, b"x")),
                Ok(DecodeOutcome::Pending)
            );
        }
        assert_eq!(d.stats().regular_messages, 5);
        d.advance_ms(500);
        assert_eq!(
            d.decode(3000, pkt(100, 0, Start, b"x")),
            Ok(DecodeOutcome::Pending)
        );
        assert_eq!(d.stats().regular_messages, 5);
    }

    #[test]
    fn test_pool_full_returns_error_when_not_expired() {
        let mut d = TestDecoder::new();
        for i in 0..5 {
            assert_eq!(
                d.decode(2000 + i, pkt(i as u32, 0, Start, b"x")),
                Ok(DecodeOutcome::Pending)
            );
        }
        d.advance_ms(100);
        assert_eq!(
            d.decode(3000, pkt(100, 0, Start, b"x")),
            Err(DecodeError::PoolFull)
        );
        assert_eq!(d.stats().regular_messages, 5);
    }

    #[test]
    fn test_multi_fragment_reassembly() {
        let mut d = TestDecoder::priority(&[1000]);
        assert_eq!(
            d.decode(1000, pkt(0, 0, Start, b"hel")),
            Ok(DecodeOutcome::Pending)
        );
        assert_eq!(
            d.decode(1000, pkt(0, 1, Middle, b"lo ")),
            Ok(DecodeOutcome::Pending)
        );
        assert_eq!(
            d.decode(1000, pkt(0, 2, End, b"world")),
            Ok(DecodeOutcome::Complete(Bytes::from_static(b"hello world")))
        );
    }

    #[test]
    fn test_same_msg_id_different_senders() {
        let mut d = TestDecoder::new();
        let _ = d.decode(1000, pkt(0, 0, Start, b"A"));
        let _ = d.decode(2000, pkt(0, 0, Start, b"B"));
        assert_eq!(d.stats().regular_messages, 2);
        assert_eq!(
            d.decode(1000, pkt(0, 1, End, b"1")),
            Ok(DecodeOutcome::Complete(Bytes::from_static(b"A1")))
        );
        assert_eq!(
            d.decode(2000, pkt(0, 1, End, b"2")),
            Ok(DecodeOutcome::Complete(Bytes::from_static(b"B2")))
        );
    }

    #[test]
    fn test_out_of_order_fragments() {
        let mut d = TestDecoder::priority(&[1000]);
        let _ = d.decode(1000, pkt(0, 2, End, b"C"));
        let _ = d.decode(1000, pkt(0, 0, Start, b"A"));
        assert_eq!(
            d.decode(1000, pkt(0, 1, Middle, b"B")),
            Ok(DecodeOutcome::Complete(Bytes::from_static(b"ABC")))
        );
    }

    #[test]
    fn test_duplicate_fragment_returns_error() {
        let mut d = TestDecoder::priority(&[1000]);
        let _ = d.decode(1000, pkt(0, 0, Start, b"A"));
        assert_eq!(
            d.decode(1000, pkt(0, 0, Start, b"X")),
            Err(DecodeError::DuplicateFragment {
                msg_id: 0,
                seq_num: 0
            })
        );
        assert_eq!(
            d.decode(1000, pkt(0, 1, End, b"B")),
            Ok(DecodeOutcome::Complete(Bytes::from_static(b"AB")))
        );
    }

    #[test]
    fn test_too_many_fragments() {
        let mut d = TestDecoder::with_config(Config {
            max_fragments_per_message: 2,
            ..Config::default()
        });
        let _ = d.decode(1000, pkt(0, 0, Start, b"A"));
        let _ = d.decode(1000, pkt(0, 1, Middle, b"B"));
        assert_eq!(
            d.decode(1000, pkt(0, 2, End, b"C")),
            Err(DecodeError::TooManyFragments { count: 3, max: 2 })
        );
        assert_eq!(d.stats().priority_messages, 0);
    }

    #[test]
    fn test_short_packet_returns_error() {
        let mut d = TestDecoder::new();
        assert_eq!(
            d.decode(1000, Bytes::from_static(b"short")),
            Err(DecodeError::InvalidHeaderSize {
                actual: 5,
                required: 6
            })
        );
    }

    #[test]
    fn test_conflicting_end_markers_returns_error() {
        let mut d = TestDecoder::priority(&[1000]);
        let _ = d.decode(1000, pkt(0, 0, Start, b"A"));
        let _ = d.decode(1000, pkt(0, 2, End, b"C"));
        assert_eq!(d.stats().priority_messages, 1);
        assert_eq!(
            d.decode(1000, pkt(0, 5, End, b"X")),
            Err(DecodeError::ConflictingEndMarker {
                expected: 3,
                actual: 6
            })
        );
        assert_eq!(d.stats().priority_messages, 0);
    }

    #[test]
    fn test_oversized_fragment_returns_error() {
        let mut d = TestDecoder::with_config(Config {
            max_fragment_payload: 10,
            ..Config::default()
        });
        assert_eq!(
            d.decode(1000, pkt(0, 0, Complete, b"this is way too long")),
            Err(DecodeError::FragmentPayloadTooLarge {
                actual: 20,
                max: 10
            })
        );
    }

    #[test]
    fn test_per_identity_message_limit() {
        let mut d = TestDecoder::with_config_and_priority(
            Config {
                max_messages_per_identity: 3,
                ..Config::default()
            },
            &[1000],
        );
        let _ = d.decode(1000, pkt(0, 0, Start, b"A"));
        let _ = d.decode(1000, pkt(1, 0, Start, b"B"));
        let _ = d.decode(1000, pkt(2, 0, Start, b"C"));
        assert_eq!(d.stats().priority_messages, 3);
        assert_eq!(
            d.decode(1000, pkt(3, 0, Start, b"D")),
            Err(DecodeError::IdentityLimitExceeded { max: 3 })
        );
        assert_eq!(
            d.decode(1000, pkt(0, 1, End, b"1")),
            Ok(DecodeOutcome::Complete(Bytes::from_static(b"A1")))
        );
        assert_eq!(d.stats().priority_messages, 2);
        assert_eq!(
            d.decode(1000, pkt(3, 0, Start, b"D")),
            Ok(DecodeOutcome::Pending)
        );
    }

    #[test]
    fn test_per_identity_limit_independent_per_identity() {
        let mut d = TestDecoder::with_config(Config {
            max_messages_per_identity: 2,
            ..Config::default()
        });
        let _ = d.decode(1000, pkt(0, 0, Start, b"A"));
        let _ = d.decode(1000, pkt(1, 0, Start, b"B"));
        let _ = d.decode(2000, pkt(0, 0, Start, b"X"));
        let _ = d.decode(2000, pkt(1, 0, Start, b"Y"));
        assert_eq!(d.stats().regular_messages, 4);
        assert_eq!(
            d.decode(1000, pkt(2, 0, Start, b"C")),
            Err(DecodeError::IdentityLimitExceeded { max: 2 })
        );
        assert_eq!(
            d.decode(2000, pkt(2, 0, Start, b"Z")),
            Err(DecodeError::IdentityLimitExceeded { max: 2 })
        );
        assert_eq!(
            d.decode(3000, pkt(0, 0, Start, b"N")),
            Ok(DecodeOutcome::Pending)
        );
        assert_eq!(d.stats().regular_messages, 5);
    }
}
