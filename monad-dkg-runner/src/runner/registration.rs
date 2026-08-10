use alloy_primitives::Address;
use dkg_protocol::RegistrationCall;
use monad_types::{Epoch, SeqNum};

pub(super) struct LocalRegistration {
    address: Address,
    state: LocalRegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalRegistrationState {
    Idle,
    Open {
        epoch: Epoch,
        unavailable_block: Option<SeqNum>,
    },
    Submitted {
        epoch: Epoch,
        unavailable_block: Option<SeqNum>,
    },
    Done {
        epoch: Epoch,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LocalRegistrationRead {
    pub(super) address: Address,
    pub(super) epoch: Epoch,
    pub(super) block: SeqNum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LocalRegistrationAction {
    Ignore,
    Submit {
        epoch: Epoch,
        block: SeqNum,
        registration: RegistrationCall,
    },
    Retry {
        epoch: Epoch,
        block: SeqNum,
    },
    Confirm {
        epoch: Epoch,
        registration: RegistrationCall,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RegistrationConflict;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RegistrationStart {
    Ignored,
    Started { previous: Option<Epoch> },
}

impl LocalRegistration {
    pub(super) fn new(address: Address) -> Self {
        Self {
            address,
            state: LocalRegistrationState::Idle,
        }
    }

    #[cfg(test)]
    pub(super) fn address(&self) -> Address {
        self.address
    }

    pub(super) fn epoch(&self) -> Option<Epoch> {
        self.state.epoch()
    }

    /// Opens `epoch` and identifies an older transaction epoch that must be cancelled.
    pub(super) fn start_epoch(&mut self, epoch: Epoch) -> RegistrationStart {
        if self.epoch().is_some_and(|current| current >= epoch) {
            return RegistrationStart::Ignored;
        }
        let previous = self.epoch();
        self.state = LocalRegistrationState::Open {
            epoch,
            unavailable_block: None,
        };
        RegistrationStart::Started { previous }
    }

    pub(super) fn close(&mut self, epoch: Epoch) -> bool {
        if self.epoch() != Some(epoch) {
            return false;
        }
        self.state = LocalRegistrationState::Done { epoch };
        true
    }

    pub(super) fn next_read(&self, latest: SeqNum) -> Option<LocalRegistrationRead> {
        let (epoch, unavailable_block) = self.state.active()?;
        Some(LocalRegistrationRead {
            address: self.address,
            epoch,
            block: unavailable_block.unwrap_or(latest),
        })
    }

    pub(super) fn read_failed(&mut self, read: LocalRegistrationRead) {
        if self.epoch() == Some(read.epoch) {
            self.state.set_unavailable_block(Some(read.block));
        }
    }

    pub(super) fn observe(
        &mut self,
        read: LocalRegistrationRead,
        observed: Option<RegistrationCall>,
        local: RegistrationCall,
    ) -> Result<LocalRegistrationAction, RegistrationConflict> {
        debug_assert_eq!(read.address, self.address);
        if self.epoch() != Some(read.epoch) {
            return Ok(LocalRegistrationAction::Ignore);
        }
        self.state.set_unavailable_block(None);

        if let Some(observed) = observed {
            self.state = LocalRegistrationState::Done { epoch: read.epoch };
            if observed != local {
                return Err(RegistrationConflict);
            }
            return Ok(LocalRegistrationAction::Confirm {
                epoch: read.epoch,
                registration: local,
            });
        }

        Ok(match self.state {
            LocalRegistrationState::Open { .. } => {
                self.state = LocalRegistrationState::Submitted {
                    epoch: read.epoch,
                    unavailable_block: None,
                };
                LocalRegistrationAction::Submit {
                    epoch: read.epoch,
                    block: read.block,
                    registration: local,
                }
            }
            LocalRegistrationState::Submitted { .. } => LocalRegistrationAction::Retry {
                epoch: read.epoch,
                block: read.block,
            },
            LocalRegistrationState::Idle | LocalRegistrationState::Done { .. } => {
                LocalRegistrationAction::Ignore
            }
        })
    }
}

impl LocalRegistrationState {
    fn epoch(self) -> Option<Epoch> {
        match self {
            Self::Idle => None,
            Self::Open { epoch, .. } | Self::Submitted { epoch, .. } | Self::Done { epoch } => {
                Some(epoch)
            }
        }
    }

    fn active(self) -> Option<(Epoch, Option<SeqNum>)> {
        match self {
            Self::Open {
                epoch,
                unavailable_block,
            }
            | Self::Submitted {
                epoch,
                unavailable_block,
            } => Some((epoch, unavailable_block)),
            Self::Idle | Self::Done { .. } => None,
        }
    }

    fn set_unavailable_block(&mut self, block: Option<SeqNum>) {
        match self {
            Self::Open {
                unavailable_block, ..
            }
            | Self::Submitted {
                unavailable_block, ..
            } => *unavailable_block = block,
            Self::Idle | Self::Done { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use dkg_core::Address as DkgAddress;
    use dkg_crypto::SecpPointBytes;
    use dkg_protocol::QcVerifier;

    use super::*;

    #[test]
    fn registration_transitions_depend_only_on_observations() {
        let address = Address::repeat_byte(0x11);
        let local = registration(address);
        let mut state = LocalRegistration::new(address);

        assert_eq!(
            state.start_epoch(Epoch(7)),
            RegistrationStart::Started { previous: None }
        );
        let first = state.next_read(SeqNum(10)).unwrap();
        assert!(matches!(
            state.observe(first, None, local).unwrap(),
            LocalRegistrationAction::Submit { .. }
        ));

        let retry = state.next_read(SeqNum(11)).unwrap();
        assert!(matches!(
            state.observe(retry, None, local).unwrap(),
            LocalRegistrationAction::Retry { .. }
        ));

        let confirmed = state.next_read(SeqNum(12)).unwrap();
        assert!(matches!(
            state.observe(confirmed, Some(local), local).unwrap(),
            LocalRegistrationAction::Confirm { .. }
        ));
        assert!(state.next_read(SeqNum(13)).is_none());
    }

    #[test]
    fn unavailable_read_is_retried_at_the_same_block() {
        let mut state = LocalRegistration::new(Address::repeat_byte(0x11));
        state.start_epoch(Epoch(7));
        let read = state.next_read(SeqNum(10)).unwrap();

        state.read_failed(read);

        assert_eq!(state.next_read(SeqNum(12)), Some(read));
    }

    fn registration(address: Address) -> RegistrationCall {
        RegistrationCall {
            address: DkgAddress(address.into_array()),
            qc_verifier: QcVerifier::try_from([1; 20]).unwrap(),
            receiver_public_key: SecpPointBytes([2; 33]),
            receiver_proof_nonce: 0,
            receiver_proof: [3; 64],
        }
    }
}
