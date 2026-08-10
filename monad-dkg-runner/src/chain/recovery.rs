//! Typestate machine for finalized-chain recovery.
//!
//! Every session follows this flow:
//!
//! ```text
//! Snapshot ── no backlog ───────────────▶ Live
//!     └────── finalized backlog ──▶ Catchup ──▶ Live
//! ```
//!
//! Snapshot permits exactly one recovery snapshot at the session boundary.
//! If finalized blocks existed when the session started, Catchup then scans
//! each of them in order. Live follows newly finalized blocks and can never
//! report initial recovery completion again.
//!
//! Phase-specific fields live on their phase types, and transitions consume the
//! old phase. This prevents invalid combinations such as a completed snapshot
//! that is still marked pending, or a live cursor retaining a catchup boundary.

use monad_types::SeqNum;

use super::{ChainEventSession, ChainRead};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionScan {
    session: ChainEventSession,
    phase: SessionPhase,
}

impl SessionScan {
    pub(crate) fn new(session: ChainEventSession, finalized: SeqNum) -> Self {
        Self {
            session,
            phase: SessionPhase::Snapshot(SnapshotPhase {
                recovery_through: finalized.max(session.recovery_block),
            }),
        }
    }

    pub(crate) fn next(self, latest: SeqNum) -> Option<ChainRead> {
        self.phase
            .next(self.session, latest.max(self.session.recovery_block))
    }

    pub(crate) fn restart(&mut self, recovery_block: SeqNum, finalized: SeqNum) {
        *self = Self::new(
            ChainEventSession {
                recovery_block,
                ..self.session
            },
            finalized,
        );
    }

    pub(crate) fn advance(&mut self, read: ChainRead) -> bool {
        let (phase, recovery_complete) = self.phase.complete(self.session, read);
        self.phase = phase;
        recovery_complete
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionPhase {
    Snapshot(SnapshotPhase),
    Catchup(CatchupPhase),
    Live(LivePhase),
}

impl SessionPhase {
    fn next(self, session: ChainEventSession, latest: SeqNum) -> Option<ChainRead> {
        match self {
            Self::Snapshot(_) => Some(ChainRead::Snapshot(session)),
            Self::Catchup(phase) => phase
                .next(latest)
                .map(|block| ChainRead::Block(block, session)),
            Self::Live(phase) => phase
                .next(latest)
                .map(|block| ChainRead::Block(block, session)),
        }
    }

    fn complete(self, session: ChainEventSession, read: ChainRead) -> (Self, bool) {
        assert_eq!(
            read.session(),
            session,
            "completed DKG chain read belongs to its session"
        );
        match (self, read) {
            (Self::Snapshot(phase), ChainRead::Snapshot(_)) => phase.complete(session),
            (Self::Catchup(phase), ChainRead::Block(block, _)) => phase.complete(block),
            (Self::Live(phase), ChainRead::Block(block, _)) => {
                (Self::Live(phase.complete(block)), false)
            }
            _ => panic!("completed DKG chain read matches its recovery phase"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Reads the contract snapshot at the session's recovery boundary exactly once.
struct SnapshotPhase {
    recovery_through: SeqNum,
}

impl SnapshotPhase {
    fn complete(self, session: ChainEventSession) -> (SessionPhase, bool) {
        let blocks = BlockCursor::after(session.recovery_block);
        if session.recovery_block >= self.recovery_through {
            (SessionPhase::Live(LivePhase { blocks }), true)
        } else {
            (
                SessionPhase::Catchup(CatchupPhase {
                    blocks,
                    recovery_through: self.recovery_through,
                }),
                false,
            )
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Replays the finalized backlog captured when the session started.
struct CatchupPhase {
    blocks: BlockCursor,
    recovery_through: SeqNum,
}

impl CatchupPhase {
    fn next(self, latest: SeqNum) -> Option<SeqNum> {
        self.blocks.next(latest)
    }

    fn complete(self, block: SeqNum) -> (SessionPhase, bool) {
        let blocks = self.blocks.complete(block);
        if block >= self.recovery_through {
            (SessionPhase::Live(LivePhase { blocks }), true)
        } else {
            (
                SessionPhase::Catchup(Self {
                    blocks,
                    recovery_through: self.recovery_through,
                }),
                false,
            )
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Follows blocks finalized after the initial snapshot and backlog are complete.
struct LivePhase {
    blocks: BlockCursor,
}

impl LivePhase {
    fn next(self, latest: SeqNum) -> Option<SeqNum> {
        self.blocks.next(latest)
    }

    fn complete(self, block: SeqNum) -> Self {
        Self {
            blocks: self.blocks.complete(block),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockCursor {
    next: Option<SeqNum>,
}

impl BlockCursor {
    fn after(block: SeqNum) -> Self {
        Self {
            next: block.0.checked_add(1).map(SeqNum),
        }
    }

    fn next(self, latest: SeqNum) -> Option<SeqNum> {
        self.next.filter(|block| *block <= latest)
    }

    fn complete(self, block: SeqNum) -> Self {
        assert_eq!(
            self.next,
            Some(block),
            "completed DKG block matches the recovery cursor"
        );
        Self::after(block)
    }
}
