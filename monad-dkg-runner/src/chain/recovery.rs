//! Finalized-chain cursor owned by the DKG manager.
//!
//! The manager performs each chain read synchronously and advances the cursor
//! only after that read succeeds.

use std::collections::BTreeMap;

use dkg_protocol::ChainEvent;
use monad_types::{Epoch, SeqNum};
use tracing::info;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChainEventSession {
    pub epoch: Epoch,
    pub party_count: usize,
    pub recovery_block: SeqNum,
}

#[derive(Debug)]
pub(crate) struct ChainEventBatch {
    pub session: ChainEventSession,
    pub block: SeqNum,
    pub events: Vec<ChainEvent>,
    pub recovery_complete_after: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChainRead {
    Snapshot(ChainEventSession),
    Block(SeqNum, ChainEventSession),
}

impl ChainRead {
    pub(crate) fn session(self) -> ChainEventSession {
        match self {
            Self::Snapshot(session) | Self::Block(_, session) => session,
        }
    }

    pub(crate) fn block(self) -> SeqNum {
        match self {
            Self::Snapshot(session) => session.recovery_block,
            Self::Block(block, _) => block,
        }
    }
}

#[derive(Default)]
pub(crate) struct ChainEventReader {
    finalized: Option<SeqNum>,
    scans: BTreeMap<Epoch, SessionScan>,
}

impl ChainEventReader {
    pub(crate) fn notify_finalized(&mut self, block: SeqNum) {
        self.finalized = Some(self.finalized.map_or(block, |latest| latest.max(block)));
    }

    pub(crate) fn start_session(&mut self, session: ChainEventSession) {
        self.scans
            .insert(session.epoch, SessionScan::new(session, self.finalized));
        while self.scans.len() > crate::MAX_RETAINED_DKG_SESSIONS {
            let (epoch, _) = self.scans.pop_first().expect("excess scan");
            info!(epoch = epoch.0, "retired old DKG chain cursor");
        }
        info!(
            epoch = session.epoch.0,
            party_count = session.party_count,
            recovery_block = session.recovery_block.0,
            "started DKG chain recovery"
        );
    }

    pub(crate) fn next_read(&self) -> Option<ChainRead> {
        self.scans.values().find_map(|scan| {
            let latest = self
                .finalized
                .unwrap_or(scan.session.recovery_block)
                .max(scan.session.recovery_block);
            scan.next(latest)
        })
    }

    pub(crate) fn complete(&mut self, read: ChainRead, events: Vec<ChainEvent>) -> ChainEventBatch {
        let session = read.session();
        let scan = self
            .scans
            .get_mut(&session.epoch)
            .expect("blocking DKG read keeps its cursor alive");
        let recovery_complete_after = scan.advance(read);
        if recovery_complete_after {
            info!(
                epoch = session.epoch.0,
                through_block = read.block().0,
                "completed DKG chain recovery"
            );
        }
        ChainEventBatch {
            session,
            block: read.block(),
            events,
            recovery_complete_after,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SessionScan {
    session: ChainEventSession,
    snapshot_pending: bool,
    next_block: Option<SeqNum>,
    recovery_through: SeqNum,
    recovery_complete: bool,
}

impl SessionScan {
    fn new(session: ChainEventSession, finalized: Option<SeqNum>) -> Self {
        Self {
            session,
            snapshot_pending: true,
            next_block: session.recovery_block.0.checked_add(1).map(SeqNum),
            recovery_through: finalized.map_or(session.recovery_block, |head| {
                head.max(session.recovery_block)
            }),
            recovery_complete: false,
        }
    }

    fn next(self, latest: SeqNum) -> Option<ChainRead> {
        if self.snapshot_pending {
            Some(ChainRead::Snapshot(self.session))
        } else {
            self.next_block
                .filter(|block| *block <= latest)
                .map(|block| ChainRead::Block(block, self.session))
        }
    }

    fn advance(&mut self, read: ChainRead) -> bool {
        let processed = match read {
            ChainRead::Snapshot(_) => {
                self.snapshot_pending = false;
                self.session.recovery_block
            }
            ChainRead::Block(block, _) => {
                self.next_block = block.0.checked_add(1).map(SeqNum);
                block
            }
        };
        let complete =
            !self.recovery_complete && !self.snapshot_pending && processed >= self.recovery_through;
        self.recovery_complete |= complete;
        complete
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
