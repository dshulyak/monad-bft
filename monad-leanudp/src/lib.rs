mod decoder;
mod encoder;

use std::{hash::Hash, time::Duration};

pub use decoder::{Clock, DecodeError, DecodeOutcome, Decoder, DecoderStats, SystemClock};
use encoder::MAX_FRAGMENTS;
pub use encoder::{EncodeError, Encoder};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, LE, U32};

pub(crate) const LEANUDP_HEADER_SIZE: usize = PacketHeader::SIZE;

const WIREAUTH_HEADER_SIZE: usize = 32;
const DEFAULT_MTU: usize = 1400;
const DEFAULT_MESSAGE_TIMEOUT: Duration = Duration::from_millis(400);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FragmentType {
    Start,
    Middle,
    End,
    Complete,
}

impl FragmentType {
    #[inline]
    pub fn from_flags(is_start: bool, is_end: bool) -> Self {
        match (is_start, is_end) {
            (true, true) => Self::Complete,
            (true, false) => Self::Start,
            (false, true) => Self::End,
            (false, false) => Self::Middle,
        }
    }

    #[inline]
    pub fn is_start(self) -> bool {
        matches!(self, Self::Start | Self::Complete)
    }

    #[inline]
    pub fn is_end(self) -> bool {
        matches!(self, Self::End | Self::Complete)
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PacketHeader {
    msg_id: U32<LE>,
    seq_num: u8,
    flags: u8,
}

impl PacketHeader {
    pub const SIZE: usize = 6;
    const START_FLAG: u8 = 0x01;
    const END_FLAG: u8 = 0x02;

    #[inline]
    pub(crate) fn new(msg_id: u32, seq_num: u8, fragment_type: FragmentType) -> Self {
        let mut flags = 0u8;
        if fragment_type.is_start() {
            flags |= Self::START_FLAG;
        }
        if fragment_type.is_end() {
            flags |= Self::END_FLAG;
        }
        Self {
            msg_id: U32::new(msg_id),
            seq_num,
            flags,
        }
    }

    #[inline]
    pub(crate) fn msg_id(&self) -> u32 {
        self.msg_id.get()
    }

    #[inline]
    pub(crate) fn seq_num(&self) -> u8 {
        self.seq_num
    }

    #[inline]
    pub(crate) fn fragment_type(&self) -> FragmentType {
        let is_start = self.flags & Self::START_FLAG != 0;
        let is_end = self.flags & Self::END_FLAG != 0;
        FragmentType::from_flags(is_start, is_end)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub max_fragment_payload: usize,
    pub max_priority_messages: usize,
    pub max_regular_messages: usize,
    pub max_fragments_per_message: usize,
    pub max_messages_per_identity: usize,
    pub message_timeout: Duration,
    pub score_threshold: f64,
}

impl Config {
    pub fn max_payload_for_mtu(mtu: usize) -> usize {
        mtu.saturating_sub(WIREAUTH_HEADER_SIZE + PacketHeader::SIZE)
    }

    fn validate(&self) {
        assert!(
            self.max_fragment_payload > 0,
            "max_fragment_payload must be > 0"
        );
        assert!(
            self.max_fragments_per_message > 0 && self.max_fragments_per_message <= MAX_FRAGMENTS,
            "max_fragments_per_message must be in 1..={MAX_FRAGMENTS}"
        );
        assert!(
            self.max_messages_per_identity > 0,
            "max_messages_per_identity must be > 0"
        );
        assert!(
            !self.message_timeout.is_zero(),
            "message_timeout must be > 0"
        );
        assert!(
            self.score_threshold.is_finite(),
            "score_threshold must be finite"
        );
    }

    pub fn build<I, P>(self, identity_score: P) -> (Encoder, Decoder<I, P, SystemClock>)
    where
        I: Eq + Hash + Clone,
        P: IdentityScore<Identity = I>,
    {
        self.build_with_clock(identity_score, SystemClock)
    }

    pub fn build_with_clock<I, P, C>(
        self,
        identity_score: P,
        clock: C,
    ) -> (Encoder, Decoder<I, P, C>)
    where
        I: Eq + Hash + Clone,
        P: IdentityScore<Identity = I>,
        C: Clock,
    {
        self.validate();
        let encoder = Encoder::new(&self);
        let decoder = Decoder::with_clock(&self, identity_score, clock);
        (encoder, decoder)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_fragment_payload: Self::max_payload_for_mtu(DEFAULT_MTU),
            max_priority_messages: 10_000,
            max_regular_messages: 1_000,
            max_fragments_per_message: MAX_FRAGMENTS,
            max_messages_per_identity: 10,
            message_timeout: DEFAULT_MESSAGE_TIMEOUT,
            score_threshold: 1.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FragmentPolicy {
    #[default]
    Regular,
    Prioritized,
}

pub trait IdentityScore: Send + Sync {
    type Identity;

    fn score(&self, identity: &Self::Identity) -> FragmentPolicy;
}

impl<T> IdentityScore for T
where
    T: monad_peer_score::IdentityScore + Send + Sync,
    T::Identity: Send + Sync,
{
    type Identity = T::Identity;

    fn score(&self, identity: &Self::Identity) -> FragmentPolicy {
        if monad_peer_score::IdentityScore::score(self, identity) > 0.0 {
            FragmentPolicy::Prioritized
        } else {
            FragmentPolicy::Regular
        }
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::FromBytes;

    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.max_fragment_payload, 1362);
        assert_eq!(config.max_priority_messages, 10_000);
        assert_eq!(config.max_regular_messages, 1_000);
        assert_eq!(config.max_fragments_per_message, MAX_FRAGMENTS);
        assert_eq!(config.max_messages_per_identity, 10);
        assert_eq!(config.message_timeout, Duration::from_millis(400));
        assert_eq!(config.score_threshold, 1.0);
    }

    #[test]
    fn test_max_payload_for_mtu() {
        assert_eq!(Config::max_payload_for_mtu(1500), 1462);
        assert_eq!(Config::max_payload_for_mtu(1400), 1362);
        assert_eq!(Config::max_payload_for_mtu(576), 538);
    }

    #[test]
    fn test_policy_default() {
        assert_eq!(FragmentPolicy::default(), FragmentPolicy::Regular);
    }

    #[test]
    fn test_header_size() {
        assert_eq!(LEANUDP_HEADER_SIZE, 6);
        assert_eq!(std::mem::size_of::<PacketHeader>(), PacketHeader::SIZE);
    }

    #[test]
    fn test_header_fragment_types() {
        let start = PacketHeader::new(1, 0, FragmentType::Start);
        assert_eq!(start.fragment_type(), FragmentType::Start);
        assert!(start.fragment_type().is_start());
        assert!(!start.fragment_type().is_end());

        let end = PacketHeader::new(1, 5, FragmentType::End);
        assert_eq!(end.fragment_type(), FragmentType::End);
        assert!(!end.fragment_type().is_start());
        assert!(end.fragment_type().is_end());

        let complete = PacketHeader::new(1, 0, FragmentType::Complete);
        assert_eq!(complete.fragment_type(), FragmentType::Complete);
        assert!(complete.fragment_type().is_start());
        assert!(complete.fragment_type().is_end());

        let middle = PacketHeader::new(1, 2, FragmentType::Middle);
        assert_eq!(middle.fragment_type(), FragmentType::Middle);
        assert!(!middle.fragment_type().is_start());
        assert!(!middle.fragment_type().is_end());
    }

    #[test]
    fn test_header_roundtrip() {
        let original = PacketHeader::new(0xDEADBEEF, 255, FragmentType::Complete);
        let bytes = original.as_bytes();
        let parsed = PacketHeader::read_from_bytes(bytes).unwrap();
        assert_eq!(parsed.msg_id(), 0xDEADBEEF);
        assert_eq!(parsed.seq_num(), 255);
        assert_eq!(parsed.fragment_type(), FragmentType::Complete);
    }

    #[test]
    fn test_msg_id_field() {
        let header = PacketHeader::new(123456789, 42, FragmentType::Middle);
        assert_eq!(header.msg_id(), 123456789);
        assert_eq!(header.seq_num(), 42);
    }
}
