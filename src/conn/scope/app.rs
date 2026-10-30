use o3::buffer;
use std::time;

use dope::core::driver::schedule::clock;

use crate::{conn, stream};

/// Application scheduling auth for one connection turn.
#[repr(transparent)]
pub struct App<
    'access,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
> {
    machine: &'access mut conn::Machine<DOMAIN, B, D>,
}

impl<const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    App<'_, DOMAIN, B, RECONCILE, D>
{
    pub(super) fn new(
        machine: &mut conn::Machine<DOMAIN, B, D>,
    ) -> App<'_, DOMAIN, B, RECONCILE, D> {
        App { machine }
    }

    pub fn set_ready(&mut self, ready: bool) {
        let ready = ready && !self.machine.is_closing();
        self.machine.peer.reconcile.set_ready(ready);
    }

    pub fn ready(&mut self) {
        self.set_ready(true);
    }

    pub fn idle(&mut self) {
        self.set_ready(false);
    }

    fn sync_at(&mut self, deadline: Option<time::Instant>) -> conn::Mutation {
        let mutation = self.machine.set_deadline(deadline);
        if mutation != conn::Mutation::Unchanged {
            self.machine
                .record::<RECONCILE>(conn::Effects::DEADLINE_EXACT);
        }
        mutation
    }

    pub fn sync<'d>(&mut self, deadline: Option<clock::Deadline<'d>>) -> conn::Mutation {
        self.sync_at(deadline.map(clock::Deadline::into_raw))
    }
}
