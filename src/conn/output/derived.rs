use std::mem;

use o3::depot::capacity::Count;

use crate::conn::output::control;
use crate::conn::wire::path;
use crate::wire::stream::Initiator;

const HANDSHAKE_DONE: u8 = 1 << 0;
const NEW_CONNECTION_IDS: u8 = 1 << 1;

/// Durable owner-local work that survives bounded-control backpressure.
#[derive(Default)]
#[repr(transparent)]
pub(in crate::conn) struct Derived(u8);

impl Derived {
    pub(super) fn is_pending(&self) -> bool {
        self.0 != 0
    }

    pub(super) fn is_sendable(&self, path: &path::State, control: &control::Pending) -> bool {
        let room = control.available();
        let done = control.done_slots();
        let cids = path.local.work(control);
        self.0 & HANDSHAKE_DONE != 0 && done.raw() != 0 && done <= room
            || self.0 & NEW_CONNECTION_IDS != 0 && cids.fits(room)
    }

    pub(in crate::conn) fn establish(&mut self, local: Initiator, cids: Count) {
        if matches!(local, Initiator::Server) {
            self.0 |= HANDSHAKE_DONE;
        }
        self.advertise(cids);
    }

    pub(in crate::conn) fn advertise(&mut self, cids: Count) {
        if cids.raw() != 0 {
            self.0 |= NEW_CONNECTION_IDS;
        }
    }

    pub(super) fn reconcile(
        &mut self,
        path: &mut path::State,
        control: &mut control::Pending,
    ) -> Result<(), control::Admission> {
        if self.0 == 0 {
            return Ok(());
        }
        if self.0 & HANDSHAKE_DONE != 0 {
            control.try_done()?;
            self.0 &= !HANDSHAKE_DONE;
        }
        if self.0 & NEW_CONNECTION_IDS != 0 {
            path.local.plan(control).queue()?;
            self.0 &= !NEW_CONNECTION_IDS;
        }
        Ok(())
    }
}

const _: () = {
    assert!(mem::size_of::<Derived>() == 1);
    assert!(!mem::needs_drop::<Derived>());
};
