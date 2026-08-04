mod chain;
mod error;
mod manager;
mod protocol;
mod registration;
mod reliable;
mod session;
mod storage;
mod transport;
mod wal;

const MAX_RETAINED_DKG_SESSIONS: usize = 2;

#[cfg(test)]
mod registration_tests;

pub use chain::{new_triedb_manager, DkgChainConfig};
pub use error::DkgError;
pub use manager::{DkgManager, DkgManagerHandle, DkgManagerInbox};
pub use session::{DkgLocalKeyMaterial, DkgValidator};
pub use transport::DeliveryOutbound;

pub fn recovery_epochs(root: &std::path::Path) -> Result<Vec<monad_types::Epoch>, DkgError> {
    storage::recovery_epochs(root)
        .map_err(|err| DkgError::operation("list DKG recovery epochs", err))
}

pub const DKG_FAILPOINT_NAMES: [&str; 7] = [
    "dkg.chain.call_buffered",
    "dkg.chain.event_buffered",
    "dkg.network.outgoing_persisted",
    "dkg.peer.engine_applied",
    "dkg.peer.input_persisted",
    "dkg.registration.loaded",
    "dkg.session.seed_persisted",
];

#[cfg(test)]
#[test]
fn registers_all_dkg_failpoints() {
    let registered = failpoint::Registry::global()
        .list()
        .into_iter()
        .filter_map(|point| point.name.starts_with("dkg.").then_some(point.name))
        .collect::<Vec<_>>();
    assert_eq!(registered, DKG_FAILPOINT_NAMES);
}
