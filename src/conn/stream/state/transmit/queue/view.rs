use o3::buffer;

use crate::conn::stream::state::transmit::queue;
use crate::stream::outbound;

/// Read-only projection of one queue's capacity and retained byte ownership.
pub(in crate::conn) struct View<'a, D: buffer::raw::Segment>(&'a queue::Map<D>);

impl<'a, D: buffer::raw::Segment> View<'a, D> {
    pub(super) fn new(queue: &'a queue::Map<D>) -> Self {
        Self(queue)
    }

    pub(in crate::conn) fn pending(&self) -> usize {
        self.0.data.pending
    }

    pub(in crate::conn) fn vacancy(&self) -> usize {
        self.0.core.available()
    }

    pub(in crate::conn) fn has_pending(&self) -> bool {
        self.0.core.length() != 0
    }

    pub(in crate::conn) fn used(&self) -> outbound::Charge {
        self.0.data.budget.used(&self.0.data.buffers)
    }

    pub(in crate::conn) fn resident(&self) -> usize {
        self.0.data.budget.resident()
    }

    pub(in crate::conn) fn cached(&self) -> usize {
        self.0.data.buffers.resident()
    }
}
