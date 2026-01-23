use bytes::Bytes;
use thiserror::Error;

use crate::{Config, FragmentType, PacketHeader};

pub(crate) const MAX_FRAGMENTS: usize = 256;

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("payload too large: {payload_len} bytes requires {fragment_count} fragments, max is {MAX_FRAGMENTS}")]
    PayloadTooLarge {
        payload_len: usize,
        fragment_count: usize,
    },
}

#[derive(Debug)]
pub struct Encoder {
    max_fragment_payload: usize,
    next_msg_id: u32,
}

impl Encoder {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            max_fragment_payload: config.max_fragment_payload,
            next_msg_id: 0,
        }
    }

    pub fn fragment(&mut self, payload: Bytes) -> Result<FragmentIter, EncodeError> {
        let count = self.fragment_count(payload.len());

        if count > MAX_FRAGMENTS {
            return Err(EncodeError::PayloadTooLarge {
                payload_len: payload.len(),
                fragment_count: count,
            });
        }

        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);

        Ok(FragmentIter {
            payload,
            max_payload: self.max_fragment_payload,
            msg_id,
            current: 0,
            count,
        })
    }

    pub fn max_payload_size(&self) -> usize {
        self.max_fragment_payload * MAX_FRAGMENTS
    }

    fn fragment_count(&self, payload_len: usize) -> usize {
        if payload_len == 0 {
            return 1;
        }
        payload_len.div_ceil(self.max_fragment_payload)
    }
}

#[derive(Debug)]
pub struct FragmentIter {
    payload: Bytes,
    max_payload: usize,
    msg_id: u32,
    current: usize,
    count: usize,
}

impl Iterator for FragmentIter {
    type Item = (PacketHeader, Bytes);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.count {
            return None;
        }

        let i = self.current;
        let start = i.saturating_mul(self.max_payload);
        let end = start
            .saturating_add(self.max_payload)
            .min(self.payload.len());
        let data = self.payload.slice(start..end);

        let seq_num = i as u8;
        let is_start = i == 0;
        let is_end = i == self.count - 1;
        let header = PacketHeader::new(
            self.msg_id,
            seq_num,
            FragmentType::from_flags(is_start, is_end),
        );

        self.current += 1;
        Some((header, data))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count - self.current;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FragmentIter {}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(data: &[u8]) -> Bytes {
        Bytes::copy_from_slice(data)
    }

    fn test_encoder(max_fragment_payload: usize) -> Encoder {
        Encoder::new(&Config {
            max_fragment_payload,
            ..Config::default()
        })
    }

    #[test]
    fn test_encoder_single() {
        let mut encoder = test_encoder(1000);
        let payload = b(b"hello");

        let fragments: Vec<_> = encoder.fragment(payload).unwrap().collect();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].0.msg_id(), 0);
        assert_eq!(fragments[0].0.seq_num(), 0);
        assert_eq!(fragments[0].0.fragment_type(), FragmentType::Complete);
        assert_eq!(fragments[0].1.as_ref(), b"hello");
    }

    #[test]
    fn test_encoder_multi() {
        let mut encoder = test_encoder(1000);
        let payload = Bytes::from(vec![0u8; 2500]);

        let fragments: Vec<_> = encoder.fragment(payload).unwrap().collect();
        assert_eq!(fragments.len(), 3);

        assert_eq!(fragments[0].0.msg_id(), 0);
        assert_eq!(fragments[0].0.seq_num(), 0);
        assert_eq!(fragments[0].0.fragment_type(), FragmentType::Start);
        assert_eq!(fragments[0].1.len(), 1000);

        assert_eq!(fragments[1].0.msg_id(), 0);
        assert_eq!(fragments[1].0.seq_num(), 1);
        assert_eq!(fragments[1].0.fragment_type(), FragmentType::Middle);
        assert_eq!(fragments[1].1.len(), 1000);

        assert_eq!(fragments[2].0.msg_id(), 0);
        assert_eq!(fragments[2].0.seq_num(), 2);
        assert_eq!(fragments[2].0.fragment_type(), FragmentType::End);
        assert_eq!(fragments[2].1.len(), 500);
    }

    #[test]
    fn test_encoder_msg_id_increments() {
        let mut encoder = test_encoder(1000);

        let fragments1: Vec<_> = encoder.fragment(b(b"msg1")).unwrap().collect();
        let fragments2: Vec<_> = encoder.fragment(b(b"msg2")).unwrap().collect();
        let fragments3: Vec<_> = encoder.fragment(b(b"msg3")).unwrap().collect();

        assert_eq!(fragments1[0].0.msg_id(), 0);
        assert_eq!(fragments2[0].0.msg_id(), 1);
        assert_eq!(fragments3[0].0.msg_id(), 2);
    }

    #[test]
    fn test_encoder_payload_too_large() {
        let mut encoder = test_encoder(1000);
        let payload = Bytes::from(vec![0u8; 257 * 1000]);

        let result = encoder.fragment(payload);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncodeError::PayloadTooLarge { .. }
        ));
    }

    #[test]
    fn test_encoder_max_fragments() {
        let mut encoder = test_encoder(1000);
        let payload = Bytes::from(vec![0u8; 256 * 1000]);

        let fragments: Vec<_> = encoder.fragment(payload).unwrap().collect();
        assert_eq!(fragments.len(), 256);
        assert_eq!(fragments[255].0.seq_num(), 255);
    }

    #[test]
    fn test_encoder_msg_id_wraps() {
        let mut encoder = test_encoder(1000);
        encoder.next_msg_id = u32::MAX;

        let fragments1: Vec<_> = encoder.fragment(b(b"msg1")).unwrap().collect();
        let fragments2: Vec<_> = encoder.fragment(b(b"msg2")).unwrap().collect();

        assert_eq!(fragments1[0].0.msg_id(), u32::MAX);
        assert_eq!(fragments2[0].0.msg_id(), 0);
    }
}
