use o3::buffer::{self, segments};

use crate::stream::{outbound, send};

/// One atomic stream admission containing contiguous or segmented storage.
pub struct Parts<O: buffer::raw::Segment> {
    pub(crate) first: send::Buffer<O>,
    pub(crate) tail: Option<send::Tail<O>>,
    pub(crate) boundary: send::Boundary,
}

impl<O: buffer::raw::Segment> Parts<O> {
    pub fn new(
        first: send::Buffer<O>,
        second: Option<send::Buffer<O>>,
        boundary: send::Boundary,
    ) -> Self {
        Self {
            first,
            tail: second.map(send::Tail::Buffer),
            boundary,
        }
    }

    /// Moves one retained segment chain into an atomic stream append.
    pub fn from_chain(
        first: send::Buffer<O>,
        chain: segments::Many<O>,
        boundary: send::Boundary,
    ) -> Self {
        Self {
            first,
            tail: Some(send::Tail::Chain(chain)),
            boundary,
        }
    }

    pub fn into_tail(self) -> (send::Buffer<O>, Option<send::Tail<O>>, send::Boundary) {
        (self.first, self.tail, self.boundary)
    }

    pub(crate) fn recycle_into(self, buffers: &mut outbound::BufferCache) {
        self.first.recycle_into(buffers);
        if let Some(tail) = self.tail {
            match tail {
                send::Tail::Buffer(buffer) => buffer.recycle_into(buffers),
                send::Tail::Chain(chain) => drop(chain),
            }
        }
    }
}
