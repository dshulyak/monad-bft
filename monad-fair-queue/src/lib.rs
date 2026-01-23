mod queue;

use std::fmt::{Debug, Display};

pub use monad_peer_score::IdentityScore;
pub use queue::{FairQueue, FairQueueBuilder};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identity<I, U> {
    Authenticated(I),
    Unauthenticated(U),
}

impl<I: Display, U: Display> Display for Identity<I, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Identity::Authenticated(i) => write!(f, "auth({i})"),
            Identity::Unauthenticated(u) => write!(f, "unauth({u})"),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum PushError<Id: Debug + Display> {
    #[error("per-id limit exceeded for {id}: {limit}")]
    PerIdLimitExceeded { id: Id, limit: usize },
    #[error("queue full: {size}/{max_size}")]
    Full { size: usize, max_size: usize },
}
