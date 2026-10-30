use crate::{conn, errors, stream};
use conn::output;
use o3::buffer;
use std::time;

/// Connection lifetime commands.
#[repr(transparent)]
pub struct Life<
    'access,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
> {
    machine: &'access mut conn::Machine<DOMAIN, B, D>,
}

impl<const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Life<'_, DOMAIN, B, RECONCILE, D>
{
    pub(super) fn new(
        machine: &mut conn::Machine<DOMAIN, B, D>,
    ) -> Life<'_, DOMAIN, B, RECONCILE, D> {
        Life { machine }
    }

    pub(crate) fn expire(&mut self, now: time::Instant) {
        if self
            .machine
            .deadline()
            .is_none_or(|deadline| deadline > now)
        {
            return;
        }
        self.machine.peer.application_deadline = None;
        self.machine.peer.application_timeout = true;
        self.machine.peer.reconcile.set_ready(true);
    }

    pub fn close(&mut self, code: errors::Code, reason: Vec<u8>) {
        if let Some(change) = self
            .machine
            .queue_close(output::PendingClose::application(code, reason))
        {
            self.machine.record::<RECONCILE>(change.effects().bits());
        }
    }
}
