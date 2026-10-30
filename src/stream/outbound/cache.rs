use o3::{
    alloc::{self, VecExt as _},
    buffer::{self, storage::inline},
};

use crate::stream::send;

const SLOTS: usize = 2;
const BYTES: usize = 8 * 1024;

/// Tiny per-connection cache for copied convenience-send allocations.
/// Ownership-transfer sends remain excluded and release at their terminal boundary.
pub(crate) struct BufferCache {
    slots: [Option<Vec<u8>>; SLOTS],
}

impl BufferCache {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { None }; SLOTS],
        }
    }

    /// Copies bytes into an internal owner, consuming a fitting cached owner
    /// when one is available.
    pub(crate) fn copy<O: buffer::raw::Segment>(
        &mut self,
        bytes: &[u8],
    ) -> Result<send::Buffer<O>, alloc::Error> {
        if let Ok(inline) = inline::Bytes::from_slice(bytes) {
            return Ok(send::Buffer::Inline(inline));
        }

        let fitting = self
            .slots
            .iter_mut()
            .filter(|slot| {
                slot.as_ref()
                    .is_some_and(|buffer| buffer.capacity() >= bytes.len())
            })
            .min_by_key(|slot| slot.as_ref().map(Vec::capacity));
        let mut buffer = match fitting.and_then(Option::take) {
            Some(buffer) => buffer,
            None => Vec::try_new(bytes.len())?,
        };
        buffer.clear();
        buffer.extend_from_slice(bytes);
        Ok(send::Buffer::Copied(send::Copied::new(buffer)))
    }

    pub(in crate::stream) fn recycle(&mut self, buffer: send::Copied) {
        let mut buffer = buffer.into_vec();
        let capacity = buffer.capacity();
        if capacity == 0 || capacity > BYTES || self.resident() + capacity > BYTES {
            return;
        }
        let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) else {
            return;
        };
        buffer.clear();
        *slot = Some(buffer);
    }

    /// Evicts cached allocations until their complete logical capacity fits
    /// under `maximum`.
    pub(crate) fn trim_to(&mut self, maximum: usize) {
        let [first, second] = &mut self.slots;
        let left = first.as_ref().map_or(0, Vec::capacity);
        let right = second.as_ref().map_or(0, Vec::capacity);
        if left + right <= maximum {
            return;
        }
        let (largest, smallest, rest) = if left > right {
            (first, second, right)
        } else {
            (second, first, left)
        };
        *largest = None;
        if rest > maximum {
            *smallest = None;
        }
    }

    pub(crate) fn resident(&self) -> usize {
        self.slots.iter().flatten().map(Vec::capacity).sum()
    }
}

const _: () = assert!(BYTES <= usize::MAX / SLOTS);
const _: () =
    assert!(std::mem::size_of::<BufferCache>() == SLOTS * std::mem::size_of::<Option<Vec<u8>>>());
