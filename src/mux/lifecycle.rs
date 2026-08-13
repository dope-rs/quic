use dope::core::driver::schedule;

use crate::conn;
use crate::stream::ReceiveBuffer;

use super::routing::SlotOps as _;
use super::{DIRECT_DRIVE_BUDGET, Handler, Router};

#[derive(Default)]
pub(super) struct State {
    pub(super) shutting_down: bool,
    pub(super) cursor: usize,
}

pub struct Shutdown<'a, 'tls, H, P, const DOMAIN: u8, B: ReceiveBuffer = Vec<u8>>
where
    H: Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    mux: &'a mut Router<'tls, H, P, DOMAIN, B>,
}

impl<'a, 'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    Shutdown<'a, 'tls, H, P, DOMAIN, B>
{
    pub(super) fn new(mux: &'a mut Router<'tls, H, P, DOMAIN, B>) -> Self {
        Self { mux }
    }

    pub fn bounded(&mut self) -> bool {
        self.begin();
        for _ in 0..DIRECT_DRIVE_BUDGET {
            if !self.step_inner() {
                break;
            }
        }
        self.complete()
    }

    pub(crate) fn begin(&mut self) {
        if self.mux.lifecycle.shutting_down {
            return;
        }
        self.mux.lifecycle.shutting_down = true;
        self.mux.lifecycle.cursor = 0;
    }

    pub(crate) fn step<'turn, 'd>(
        &mut self,
        _permit: schedule::ApplicationPermit<'turn, 'd>,
    ) -> bool {
        debug_assert!(self.mux.lifecycle.shutting_down);
        if !self.mux.lifecycle.shutting_down {
            return false;
        }
        self.step_inner()
    }

    pub(crate) fn complete(&self) -> bool {
        self.mux.lifecycle.shutting_down
            && self.mux.lifecycle.cursor == self.mux.registry.entries.len()
            && self.mux.outgoing.pending.is_empty()
            && self.mux.outgoing.recycled.is_empty()
            && self.mux.outgoing.batch.is_none()
            && self.mux.registry.indexes.reset.len() == 0
    }

    fn step_inner(&mut self) -> bool {
        if self.mux.lifecycle.cursor < self.mux.registry.entries.len() {
            let index = self.mux.lifecycle.cursor;
            self.mux.lifecycle.cursor += 1;
            if self.mux.registry.entries[index].slot.is_some() {
                let handle = self.mux.handle_for_index(index);
                let removed = self.mux.remove_slot(handle);
                debug_assert!(removed);
            }
            return true;
        }
        if super::output::Queue::new(self.mux).pop().is_some() {
            return true;
        }
        if self.mux.outgoing.recycled.pop().is_some() {
            return true;
        }
        if self.mux.outgoing.batch.take().is_some() {
            return true;
        }
        false
    }
}
