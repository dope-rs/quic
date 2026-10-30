//! Retransmittable stream storage tied to its retained owner lifetime.

use crate::stream::outbound;
use o3::buffer::{self, storage::inline, write::consume};
use o3::depot::capacity;

pub mod admit;
mod copied;
mod parts;
pub mod raw;
mod tail;
pub use copied::Copied;
pub use parts::Parts;
pub use tail::Tail;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Boundary {
    #[default]
    More,
    End,
}

/// Exact queue demand of one atomic stream admission.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Demand {
    pub(crate) wire_bytes: usize,
    pub(crate) resident_bytes: usize,
    pub(crate) segments: usize,
    pub(crate) chunks: capacity::Count,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overflow {
    Wire {
        left: usize,
        right: usize,
    },
    Resident {
        left: usize,
        right: usize,
    },
    Segments {
        left: usize,
        right: usize,
    },
    Chunks {
        left: capacity::Count,
        right: capacity::Count,
    },
}

impl Default for Demand {
    fn default() -> Self {
        Self::new(0, 0, 0, capacity::Count::EMPTY)
    }
}

impl Demand {
    pub const fn new(
        wire: usize,
        resident: usize,
        segments: usize,
        chunks: capacity::Count,
    ) -> Self {
        Self {
            wire_bytes: wire,
            resident_bytes: resident,
            segments,
            chunks,
        }
    }

    pub fn try_add(self, other: Self) -> Result<Self, Overflow> {
        Ok(Self {
            wire_bytes: self
                .wire_bytes
                .checked_add(other.wire_bytes)
                .ok_or(Overflow::Wire {
                    left: self.wire_bytes,
                    right: other.wire_bytes,
                })?,
            resident_bytes: self
                .resident_bytes
                .checked_add(other.resident_bytes)
                .ok_or(Overflow::Resident {
                    left: self.resident_bytes,
                    right: other.resident_bytes,
                })?,
            segments: self
                .segments
                .checked_add(other.segments)
                .ok_or(Overflow::Segments {
                    left: self.segments,
                    right: other.segments,
                })?,
            chunks: capacity::Count::new(self.chunks.raw().checked_add(other.chunks.raw()).ok_or(
                Overflow::Chunks {
                    left: self.chunks,
                    right: other.chunks,
                },
            )?),
        })
    }

    pub(crate) fn buffer<O: buffer::raw::Segment>(buffer: &Buffer<O>) -> Self {
        let charge = outbound::Charge::for_buffer(buffer);
        Self::new(
            charge.wire_bytes,
            charge.resident_bytes,
            charge.segments,
            capacity::Count::new(charge.segments as u32),
        )
    }
}

const _: () = {
    assert!(size_of::<Boundary>() == size_of::<bool>());
    assert!(align_of::<Boundary>() == align_of::<bool>());
};

/// Retransmittable stream storage with exact retained-owner lifetime.
pub enum Buffer<O: buffer::raw::Segment> {
    Inline(inline::Bytes),
    /// Connection-owned allocation eligible for internal cache recycling.
    #[doc(hidden)]
    Copied(Copied),
    Owned(Vec<u8>),
    Retained(O),
}

impl<O: buffer::raw::Segment> Buffer<O> {
    pub fn inline(bytes: &[u8]) -> Result<Self, consume::Error> {
        inline::Bytes::from_slice(bytes).map(Self::Inline)
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline(bytes) => bytes.as_ref(),
            Self::Copied(bytes) => bytes.as_slice(),
            Self::Owned(bytes) => bytes,
            Self::Retained(bytes) => bytes.as_ref(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    pub fn resident(&self) -> usize {
        match self {
            Self::Inline(_) => 0,
            Self::Copied(bytes) => bytes.resident(),
            Self::Owned(bytes) => bytes.capacity(),
            Self::Retained(bytes) => buffer::Residency::resident(bytes),
        }
    }

    pub(in crate::stream) fn recycle_into(self, buffers: &mut outbound::BufferCache) {
        if let Self::Copied(owner) = self {
            buffers.recycle(owner);
        }
    }
}
