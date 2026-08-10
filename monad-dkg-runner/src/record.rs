use std::{collections::BTreeSet, fmt};

use alloy_rlp::{RlpDecodable, RlpEncodable};
use bytes::{Buf, BufMut, Bytes};
use dkg_core::PartyId;
use dkg_protocol::{DkgDeliveryPolicy, DkgMessage, DkgMessageError, DkgMessageKind};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::wal::WalRecord;

pub(crate) const ENGINE_SEED_BYTES: usize = 32;

/// A protocol message that is safe to retain in the recovery WAL.
///
/// The research engine exposes one message enum for durable traffic, retryable
/// sync requests, and one-shot sync responses. Keep that distinction typed in
/// the runner so ephemeral traffic cannot accidentally enter recovery state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DurableDkgMessage(DkgMessage);

impl DurableDkgMessage {
    pub(crate) fn decode(bytes: Bytes) -> Result<Self, DurableMessageError> {
        DkgMessage::decode(bytes)?.try_into()
    }

    pub(crate) fn as_message(&self) -> &DkgMessage {
        &self.0
    }

    pub(crate) fn into_message(self) -> DkgMessage {
        self.0
    }

    pub(crate) fn as_bytes(&self) -> &Bytes {
        self.0.as_bytes()
    }
}

impl TryFrom<DkgMessage> for DurableDkgMessage {
    type Error = DurableMessageError;

    fn try_from(message: DkgMessage) -> Result<Self, Self::Error> {
        if message.delivery_policy() != DkgDeliveryPolicy::Durable {
            return Err(DurableMessageError::Ephemeral(message.kind()));
        }
        Ok(Self(message))
    }
}

#[derive(Debug, Error)]
pub(crate) enum DurableMessageError {
    #[error(transparent)]
    Decode(#[from] DkgMessageError),
    #[error("{0:?} is not a durable DKG message")]
    Ephemeral(DkgMessageKind),
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct EngineSeed([u8; ENGINE_SEED_BYTES]);

impl EngineSeed {
    pub(crate) const fn new(bytes: [u8; ENGINE_SEED_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) fn to_bytes(&self) -> [u8; ENGINE_SEED_BYTES] {
        self.0
    }
}

impl AsRef<[u8]> for EngineSeed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EngineSeed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for EngineSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EngineSeed([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IncomingRecord {
    pub(crate) source: PartyId,
    pub(crate) message: DurableDkgMessage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutgoingRecord {
    pub(crate) recipients: BTreeSet<PartyId>,
    pub(crate) message: DurableDkgMessage,
}

#[derive(Debug)]
pub(super) enum RecoveryRecord {
    Seed(EngineSeed),
    Registration(Bytes),
    Outgoing(OutgoingRecord),
    Incoming(IncomingRecord),
}

#[derive(Debug, Error)]
pub(crate) enum WalCodecError {
    #[error("invalid {0} record")]
    Invalid(&'static str),
    #[error("unknown record kind {0}")]
    UnknownRecordKind(u8),
    #[error("invalid RLP: {0}")]
    Rlp(#[from] alloy_rlp::Error),
    #[error("invalid DKG message: {0}")]
    Message(#[from] DurableMessageError),
}

impl WalRecord for RecoveryRecord {
    type Error = WalCodecError;

    const MAGIC: [u8; 4] = *b"DKGW";

    fn encode<B: BufMut>(&self, output: &mut B) -> Result<(), Self::Error> {
        let (kind, payload) = match self {
            Self::Seed(seed) => (1, Bytes::copy_from_slice(seed.as_ref())),
            Self::Registration(bytes) if !bytes.is_empty() => (2, bytes.clone()),
            Self::Registration(_) => return Err(WalCodecError::Invalid("registration")),
            Self::Outgoing(record) => (
                3,
                alloy_rlp::encode(OutgoingWire {
                    recipients: record.recipients.iter().map(|party| party.0).collect(),
                    payload: record.message.as_bytes().clone(),
                })
                .into(),
            ),
            Self::Incoming(record) => (
                4,
                alloy_rlp::encode(IncomingWire {
                    source: record.source.0,
                    payload: record.message.as_bytes().clone(),
                })
                .into(),
            ),
        };
        output.put_u8(kind);
        output.put_slice(&payload);
        Ok(())
    }

    fn decode<B: Buf>(input: &mut B) -> Result<Self, Self::Error> {
        if !input.has_remaining() {
            return Err(WalCodecError::Invalid("empty"));
        }
        let kind = input.get_u8();
        let payload = input.copy_to_bytes(input.remaining());
        Ok(match kind {
            1 if payload.len() == ENGINE_SEED_BYTES => {
                Self::Seed(EngineSeed::new(payload.as_ref().try_into().unwrap()))
            }
            1 => return Err(WalCodecError::Invalid("engine seed")),
            2 if !payload.is_empty() => Self::Registration(payload),
            2 => return Err(WalCodecError::Invalid("registration")),
            3 => {
                let wire = alloy_rlp::decode_exact::<OutgoingWire>(&payload)?;
                let recipient_count = wire.recipients.len();
                let recipients = wire
                    .recipients
                    .into_iter()
                    .map(PartyId)
                    .collect::<BTreeSet<_>>();
                if recipients.len() != recipient_count {
                    return Err(WalCodecError::Invalid("outgoing message"));
                }
                Self::Outgoing(OutgoingRecord {
                    recipients,
                    message: DurableDkgMessage::decode(wire.payload)?,
                })
            }
            4 => {
                let wire = alloy_rlp::decode_exact::<IncomingWire>(&payload)?;
                Self::Incoming(IncomingRecord {
                    source: PartyId(wire.source),
                    message: DurableDkgMessage::decode(wire.payload)?,
                })
            }
            kind => return Err(WalCodecError::UnknownRecordKind(kind)),
        })
    }
}

#[derive(RlpEncodable, RlpDecodable)]
struct IncomingWire {
    source: u32,
    payload: Bytes,
}

#[derive(RlpEncodable, RlpDecodable)]
struct OutgoingWire {
    recipients: Vec<u32>,
    payload: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_message_rejects_ephemeral_protocol_traffic() {
        let request = DkgMessage::PcRetrievalRequest {
            dealer: PartyId(0),
            bytes: Bytes::new(),
        };

        assert!(matches!(
            DurableDkgMessage::try_from(request),
            Err(DurableMessageError::Ephemeral(
                DkgMessageKind::PcRetrievalRequest
            ))
        ));
    }
}
