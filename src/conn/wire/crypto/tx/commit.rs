use crate::conn;
use crate::conn::output::delivery;
use crate::conn::wire::crypto::tx::stores;
use std::num::NonZero;

pub(in crate::conn) struct Commit(pub(in crate::conn::wire::crypto::tx) State);

pub(in crate::conn::wire::crypto::tx) enum State {
    Fresh {
        epoch: conn::Epoch,
        record: delivery::Crypto,
    },
    Ready {
        record: delivery::Crypto,
        key: stores::Key,
        rest: Option<delivery::Crypto>,
    },
    Probe {
        record: delivery::Crypto,
        key: stores::Key,
        carriers: NonZero<u16>,
    },
}

impl Commit {
    pub(in crate::conn) const fn record(&self) -> delivery::Crypto {
        match &self.0 {
            State::Fresh { record, .. }
            | State::Ready { record, .. }
            | State::Probe { record, .. } => *record,
        }
    }
}
