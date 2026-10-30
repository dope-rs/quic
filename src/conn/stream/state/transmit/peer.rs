use crate::conn::output::control::kind;
use crate::conn::stream::state::transmit::{log::journal, queue};

pub(in crate::conn) struct Peer {
    pub(in crate::conn) data_credit: queue::Credit<kind::DataBlocked>,
    total_sent: u64,
}

impl Peer {
    pub(in crate::conn) fn new(credit: queue::Credit<kind::DataBlocked>) -> Self {
        Self {
            data_credit: credit,
            total_sent: 0,
        }
    }

    pub(in crate::conn) fn budget(&self, fresh: u64) -> u64 {
        let Some(sent) = self.total_sent.checked_add(fresh) else {
            return 0;
        };
        self.data_credit.limit().get().saturating_sub(sent)
    }

    pub(in crate::conn) const fn total_sent(&self) -> u64 {
        self.total_sent
    }

    pub(in crate::conn) fn sent(credit: journal::Credit<'_>) {
        let (peer, total) = credit.into_parts();
        peer.total_sent = total;
    }

    pub(in crate::conn) fn reject_early(&mut self) {
        self.total_sent = 0;
    }
}
