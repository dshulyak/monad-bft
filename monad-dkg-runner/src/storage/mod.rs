//! Crash-safe local state used to reproduce protocol messages after restart.

mod record;
mod recovery;

pub(crate) use record::EngineSeed;
pub(crate) use recovery::{
    recovery_epochs, RecoveryState, RecoveryWal, RecoveryWalConfig, RecoveryWalError,
};
