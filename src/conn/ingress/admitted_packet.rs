use std::time;

use crate::conn;
use crate::conn::recovery;
use crate::pn_space;
use crate::stream;

/// An authenticated packet whose number is fresh for its epoch.
///
/// The exclusive connection borrow keeps the admission check stable until
/// commit. Dropping the value aborts admission without touching receive
/// history; consuming it through `commit` records the packet exactly once.
#[must_use = "an admitted packet must be committed or deliberately dropped"]
pub(super) struct AdmittedPacket<'connection, const DOMAIN: u8, B: stream::ReceiveBuffer> {
    connection: &'connection mut crate::conn::session::Connection<DOMAIN, B>,
    epoch: conn::Epoch,
    fresh: pn_space::Fresh,
    discarded: recovery::epochs::Discarded,
}

impl<'connection, const DOMAIN: u8, B: stream::ReceiveBuffer>
    AdmittedPacket<'connection, DOMAIN, B>
{
    pub(super) fn begin(
        connection: &'connection mut crate::conn::session::Connection<DOMAIN, B>,
        epoch: conn::Epoch,
        pn: u64,
    ) -> Option<Self> {
        let fresh = connection.received[epoch as usize].admit(pn)?;
        Some(Self {
            connection,
            epoch,
            fresh,
            discarded: recovery::epochs::Discarded::default(),
        })
    }

    pub(super) fn state(
        &mut self,
    ) -> (
        &mut crate::conn::session::Connection<DOMAIN, B>,
        &mut recovery::epochs::Discarded,
    ) {
        (&mut *self.connection, &mut self.discarded)
    }

    pub(super) fn close(&mut self) {
        self.connection.egress.state = crate::conn::State::Closed;
    }

    pub(super) fn commit(self, ack_eliciting: bool, now: time::Instant) {
        let Self {
            connection,
            epoch,
            fresh,
            discarded,
        } = self;
        connection.received[epoch as usize].commit(fresh, ack_eliciting, now);
        discarded.apply(&mut connection.received);
        connection.egress.last_activity = now;
        connection.egress.ack_eliciting_sent_since_last_receive = false;
    }
}
