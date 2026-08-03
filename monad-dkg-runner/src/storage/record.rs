use std::collections::BTreeSet;

use alloy_rlp::{RlpDecodable, RlpEncodable};
use bytes::{Buf, BufMut, Bytes};
use dkg_core::PartyId;
use dkg_protocol::{DkgMessageCodecError, DkgMessageId};
use thiserror::Error;

use crate::wal::WalRecord;

pub(crate) const ENGINE_SEED_BYTES: usize = 32;
pub(crate) type EngineSeed = [u8; ENGINE_SEED_BYTES];

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct OutgoingMessageRecord {
    pub(crate) message_id: DkgMessageId,
    pub(crate) recipients: BTreeSet<PartyId>,
    pub(crate) payload: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct IncomingMessageRecord {
    pub(crate) source: PartyId,
    pub(crate) message_id: DkgMessageId,
    pub(crate) payload: Bytes,
}

#[derive(Debug)]
pub(super) enum RecoveryRecord {
    Seed(EngineSeed),
    Registration(Bytes),
    Outgoing(OutgoingMessageRecord),
    Incoming(IncomingMessageRecord),
}

#[derive(Debug, Error)]
pub(crate) enum WalCodecError {
    #[error("invalid {0} record")]
    Invalid(&'static str),
    #[error("unknown record kind {0}")]
    UnknownRecordKind(u8),
    #[error("invalid DKG message key: {0}")]
    MessageKey(#[from] DkgMessageCodecError),
    #[error("invalid RLP: {0}")]
    Rlp(#[from] alloy_rlp::Error),
}

impl WalRecord for RecoveryRecord {
    type Error = WalCodecError;

    const MAGIC: [u8; 4] = *b"DKGW";

    fn encode<B: BufMut>(&self, output: &mut B) -> Result<(), Self::Error> {
        let (kind, payload) = match self {
            Self::Seed(seed) => (1, Bytes::copy_from_slice(seed)),
            Self::Registration(bytes) if !bytes.is_empty() => (2, bytes.clone()),
            Self::Registration(_) => return Err(WalCodecError::Invalid("registration")),
            Self::Outgoing(record) => (3, encode_outgoing(record)),
            Self::Incoming(record) => (4, encode_incoming(record)),
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
                Self::Seed(payload.as_ref().try_into().unwrap())
            }
            1 => return Err(WalCodecError::Invalid("engine seed")),
            2 if !payload.is_empty() => Self::Registration(payload),
            2 => return Err(WalCodecError::Invalid("registration")),
            3 => Self::Outgoing(decode_outgoing(payload)?),
            4 => Self::Incoming(decode_incoming(payload)?),
            kind => return Err(WalCodecError::UnknownRecordKind(kind)),
        })
    }
}

#[derive(RlpEncodable, RlpDecodable)]
struct IncomingWire {
    source: u32,
    message_id: Bytes,
    payload: Bytes,
}

#[derive(RlpEncodable, RlpDecodable)]
struct OutgoingWire {
    message_id: Bytes,
    recipients: Vec<u32>,
    payload: Bytes,
}

fn encode_incoming(record: &IncomingMessageRecord) -> Bytes {
    alloy_rlp::encode(IncomingWire {
        source: record.source.0,
        message_id: record.message_id.encode(),
        payload: record.payload.clone(),
    })
    .into()
}

fn encode_outgoing(record: &OutgoingMessageRecord) -> Bytes {
    alloy_rlp::encode(OutgoingWire {
        message_id: record.message_id.encode(),
        recipients: record.recipients.iter().map(|party| party.0).collect(),
        payload: record.payload.clone(),
    })
    .into()
}

fn decode_incoming(payload: Bytes) -> Result<IncomingMessageRecord, WalCodecError> {
    let wire = alloy_rlp::decode_exact::<IncomingWire>(&payload)?;
    Ok(IncomingMessageRecord {
        source: PartyId(wire.source),
        message_id: DkgMessageId::decode(&wire.message_id)?,
        payload: wire.payload,
    })
}

fn decode_outgoing(payload: Bytes) -> Result<OutgoingMessageRecord, WalCodecError> {
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
    Ok(OutgoingMessageRecord {
        message_id: DkgMessageId::decode(&wire.message_id)?,
        recipients,
        payload: wire.payload,
    })
}
