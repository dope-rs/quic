use crate::conn::Epoch;

pub(super) enum State {
    Handshaking,
    Complete,
    Failed,
}

pub(super) enum Early {
    Unavailable,
    Offered,
    Rejected,
}

/// TLS progress and the CRYPTO levels admitted by each transition.
pub(super) struct Progress {
    pub(super) read: Epoch,
    pub(super) write: Epoch,
    pub(super) state: State,
    pub(super) early: Early,
}

impl Progress {
    pub(super) const fn new() -> Self {
        Self {
            read: Epoch::Initial,
            write: Epoch::Initial,
            state: State::Handshaking,
            early: Early::Unavailable,
        }
    }
}
