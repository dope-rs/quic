use std::mem;

use o3::buffer::{self, resident::Shared};

use crate::conn::stream::state::transmit::{self, queue};

#[repr(transparent)]
pub struct Usage<'a, D: buffer::raw::Segment> {
    queue: queue::View<'a, D>,
}

impl<'a, D: buffer::raw::Segment> Usage<'a, D> {
    pub(super) fn new(state: &'a transmit::State<D>) -> Self {
        Self {
            queue: state.map().view(),
        }
    }

    pub fn wire_bytes(&self) -> usize {
        self.queue.used().wire_bytes
    }

    pub fn resident(&self) -> usize {
        self.queue.used().resident_bytes
    }

    pub fn active(&self) -> usize {
        self.queue.resident()
    }

    pub fn cached(&self) -> usize {
        self.queue.cached()
    }

    pub fn segments(&self) -> usize {
        self.queue.used().segments
    }
}

const _: () = assert!(mem::size_of::<Usage<'_, Shared<'_>>>() == mem::size_of::<usize>());
