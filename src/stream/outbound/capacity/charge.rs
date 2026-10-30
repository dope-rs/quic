use crate::stream::{self, send};
use o3::buffer;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Charge {
    pub(crate) wire_bytes: usize,
    pub(crate) resident_bytes: usize,
    pub(crate) segments: usize,
}

impl Charge {
    pub(crate) fn for_buffer<O: buffer::raw::Segment>(buffer: &send::Buffer<O>) -> Self {
        if buffer.is_empty() {
            return Self::default();
        }
        Self {
            wire_bytes: buffer.len(),
            resident_bytes: buffer.resident(),
            segments: 1,
        }
    }

    /// Allocation-free lower bound for the borrowed-send convenience path.
    pub(crate) fn for_copy(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::default();
        }
        Self {
            wire_bytes: bytes.len(),
            resident_bytes: usize::from(bytes.len() > stream::INLINE_SEND_CAPACITY) * bytes.len(),
            segments: 1,
        }
    }
}
