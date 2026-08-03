use std::error::Error as StdError;

use alloy_primitives::Address;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DkgError {
    #[error("{operation} failed")]
    Operation {
        operation: &'static str,
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("{0} is not supported")]
    Unsupported(&'static str),
    #[error("DKG channel closed while {0}")]
    ChannelClosed(&'static str),
    #[error("DKG requires at least {minimum} validators, received {actual}")]
    InsufficientValidators { actual: usize, minimum: usize },
    #[error("registration contract {actual} does not match configured DKG contract {expected}")]
    RegistrationContractMismatch { expected: Address, actual: Address },
    #[error("DKG result epoch {actual} does not match submission epoch {expected}")]
    ResultEpochMismatch { expected: u64, actual: u64 },
    #[error("duplicate validator in DKG party map")]
    DuplicateValidator,
    #[error("finalized DKG registration for {address} conflicts with the recovery WAL")]
    FinalizedRegistrationConflict { address: Address },
    #[error("no active DKG session for epoch {epoch}")]
    NoActiveSession { epoch: u64 },
}

impl DkgError {
    pub fn operation(
        operation: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Operation {
            operation,
            source: Box::new(source),
        }
    }
}
