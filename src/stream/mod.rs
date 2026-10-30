use crate::conn::stream::state::receive::recv::map::ready::{self, Segments};
use crate::errors::detail;
use dope::net::link;
use egress::data;
pub use extent::Extent;
use link::egress;
use o3::mem::Rejected;
use o3::{
    alloc,
    buffer::{
        self,
        bytes::bounded,
        resident,
        storage::{self, inline},
    },
    depot::capacity,
    mem::rc,
};
use o3::{alloc::VecExt as _, buffer::write::consume::Consume as _};
pub use payload::Payload;
use std::{mem, ops};
use storage::{provided, range};

mod extent;
mod payload;

pub(crate) mod outbound;
pub mod release;
pub(crate) mod retain;
pub mod send;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capacity {
    Allocation {
        error: alloc::Error,
        requested: usize,
    },
    Overflow {
        current: usize,
        additional: usize,
    },
    Limit {
        required: usize,
        available: usize,
    },
    Range(range::Error),
    Retain(rc::Error),
    Count(capacity::Error),
}

impl Capacity {
    pub(crate) fn rejected<T>(rejected: Rejected<T, range::Error>) -> Self {
        let (_, error) = rejected.into_parts();
        Self::Range(error)
    }
}

impl From<detail::Ranges> for Capacity {
    fn from(error: detail::Ranges) -> Self {
        let detail::Ranges::Ranges {
            current,
            additional: added,
            capacity,
        } = error;
        match current.checked_add(added) {
            Some(required) => Self::Limit {
                required,
                available: capacity,
            },
            None => Self::Overflow {
                current,
                additional: added,
            },
        }
    }
}

/// Successful projection carrying the exact requested receive extent.
#[doc(hidden)]
#[repr(transparent)]
pub struct Projection<B>(B);

impl<B> Projection<B> {
    fn new(bytes: B) -> Self {
        Self(bytes)
    }

    pub(crate) fn into_inner(self) -> B {
        self.0
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Projection<B> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Physical organization of one receive source.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum Layout {
    Full,
    Compact,
}

/// Receive storage exposing accepted ranges while preserving packet ownership.
/// Its `AsRef<[u8]>` length remains stable while the value is owned.
pub trait Recv: AsRef<[u8]> + Sized {
    #[doc(hidden)]
    type Ready: ready::raw::Queue<Self>;
    #[doc(hidden)]
    fn layout(&self) -> Layout;
    fn try_copy(bytes: &[u8]) -> Result<Self, Capacity>;
    fn from_vec(bytes: Vec<u8>) -> Self;
    fn try_slice(&self, extent: Extent) -> Result<Projection<Self>, Capacity>;
    fn try_project(self, extent: Extent) -> Result<Projection<Self>, Capacity>;
    fn into_suffix(self, max: usize) -> Self;
}

/// Moves a QUIC segment into the canonical lifetime-branded payload owner
/// without an intermediate `Vec`.
pub trait Retain<'d>: Recv {
    fn try_retain(&mut self) -> Result<resident::Shared<'d>, alloc::Exhausted>;
}

impl Recv for Vec<u8> {
    type Ready = Vec<u8>;

    fn layout(&self) -> Layout {
        Layout::Full
    }

    fn try_copy(bytes: &[u8]) -> Result<Self, Capacity> {
        let mut owned = Vec::try_new(bytes.len()).map_err(|error| Capacity::Allocation {
            error,
            requested: bytes.len(),
        })?;
        owned.extend_from_slice(bytes);
        Ok(owned)
    }

    fn from_vec(bytes: Vec<u8>) -> Self {
        bytes
    }

    fn try_slice(&self, extent: Extent) -> Result<Projection<Self>, Capacity> {
        Ok(Projection::new(try_copied_range(self, extent.range())?))
    }

    fn try_project(self, extent: Extent) -> Result<Projection<Self>, Capacity> {
        Ok(Projection::new(try_owned_range(self, extent.range())?))
    }

    fn into_suffix(mut self, max: usize) -> Self {
        let count = max.min(self.len());
        if count != 0 {
            buffer::raw::Store::advance_max(&mut self, count);
        }
        self
    }
}

impl<'d> Retain<'d> for Vec<u8> {
    fn try_retain(&mut self) -> Result<resident::Shared<'d>, alloc::Exhausted> {
        let owner = storage::Shared::try_from(self)?;
        Ok(resident::Shared::from(owner))
    }
}

pub(crate) fn try_copied_range(
    bytes: &[u8],
    range: ops::Range<usize>,
) -> Result<Vec<u8>, Capacity> {
    let bound = bytes.len();
    let Some(bytes) = bytes.get(range.clone()) else {
        return Err(Capacity::Range(range::Error::new(range, bound)));
    };
    <Vec<u8> as Recv>::try_copy(bytes)
}

fn try_owned_range(mut bytes: Vec<u8>, range: ops::Range<usize>) -> Result<Vec<u8>, Capacity> {
    buffer::raw::Slice::try_with(&mut bytes, range, buffer::raw::Store::project)
        .map_err(Capacity::Range)?;
    Ok(bytes)
}

pub const INLINE_SEND_CAPACITY: usize = inline::CAPACITY;

const _: () = assert!(mem::size_of::<Extent>() == mem::size_of::<u64>());
const _: () = {
    assert!(mem::size_of::<Projection<Vec<u8>>>() == mem::size_of::<Vec<u8>>());
    assert!(
        mem::size_of::<Projection<RecvBuffer<'static>>>() == mem::size_of::<RecvBuffer<'static>>()
    );
};
const _: () = {
    assert!(mem::size_of::<send::Buffer<resident::Shared<'static>>>() == 32);
    assert!(
        mem::align_of::<send::Buffer<resident::Shared<'static>>>() == mem::align_of::<Vec<u8>>()
    );
};

const _: () = assert!(mem::size_of::<send::Copied>() == mem::size_of::<Vec<u8>>());
const _: () = assert!(mem::size_of::<outbound::Sender>() == 7 * mem::size_of::<usize>());

/// Receive storage retaining its original driver lifetime.
///
/// A scoped selection cannot be applied through a different receive borrow.
pub struct RecvBuffer<'d, const ADAPTIVE: bool = true> {
    storage: RecvStorage<'d>,
}

enum RecvStorage<'d> {
    Owned(Vec<u8>),
    Compact(storage::Shared),
    Retained(storage::Shared<Option<provided::Account<'d>>>),
    Bound(bounded::Value<storage::Shared<Option<provided::Account<'d>>>>),
}

impl<'d, const ADAPTIVE: bool> RecvBuffer<'d, ADAPTIVE> {
    pub(crate) fn compact(bytes: storage::Shared) -> Self {
        Self {
            storage: RecvStorage::Compact(bytes),
        }
    }

    pub(crate) fn retained(bytes: storage::Shared<Option<provided::Account<'d>>>) -> Self {
        Self {
            storage: RecvStorage::Retained(bytes),
        }
    }

    pub(crate) fn bounded(
        bytes: bounded::Value<storage::Shared<Option<provided::Account<'d>>>>,
    ) -> Self {
        Self {
            storage: RecvStorage::Bound(bytes),
        }
    }

    pub fn len(&self) -> usize {
        self.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    pub(crate) fn try_take(&mut self) -> Result<Vec<u8>, Capacity> {
        match &mut self.storage {
            RecvStorage::Owned(bytes) => Ok(mem::take(bytes)),
            RecvStorage::Compact(bytes) => Vec::<u8>::try_copy(bytes.as_ref()),
            RecvStorage::Retained(bytes) => Vec::<u8>::try_copy(bytes.as_ref()),
            RecvStorage::Bound(bytes) => Vec::<u8>::try_copy(bytes.as_ref()),
        }
    }

    pub fn release(self) {
        drop(self);
    }

    /// Removes an already delivered prefix without replacing the retained
    /// owner. This is the in-place half of Store-to-Ready node transfer.
    pub(crate) fn advance(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        match &mut self.storage {
            RecvStorage::Owned(bytes) => {
                let count = max.min(bytes.len());
                let left = bytes.len() - count;
                bytes.copy_within(count.., 0);
                bytes.truncate(left);
                count
            }
            RecvStorage::Compact(bytes) => bytes.consume_max(max),
            RecvStorage::Retained(bytes) => bytes.consume_max(max),
            RecvStorage::Bound(bytes) => bytes.consume_max(max),
        }
    }
}

impl<const ADAPTIVE: bool> AsRef<[u8]> for RecvBuffer<'_, ADAPTIVE> {
    fn as_ref(&self) -> &[u8] {
        match &self.storage {
            RecvStorage::Owned(bytes) => bytes,
            RecvStorage::Compact(bytes) => bytes.as_ref(),
            RecvStorage::Retained(bytes) => bytes.as_ref(),
            RecvStorage::Bound(bytes) => bytes.as_ref(),
        }
    }
}

// SAFETY: shared access preserves every variant's retained byte extent;
// changing its contents or range requires an exclusive receive-buffer borrow.
unsafe impl<const ADAPTIVE: bool> buffer::raw::Source for &mut RecvBuffer<'_, ADAPTIVE> {}

impl<const ADAPTIVE: bool> buffer::Residency for RecvBuffer<'_, ADAPTIVE> {
    /// Bytes held by the complete backing allocation. Compact fallback owners
    /// report their exact packet-level accepted-byte capacity; driver owners
    /// report the receive-slot capacity they retain.
    fn resident(&self) -> usize {
        match &self.storage {
            RecvStorage::Owned(bytes) => bytes.capacity(),
            RecvStorage::Compact(bytes) => bytes.resident(),
            RecvStorage::Retained(bytes) => bytes.resident(),
            RecvStorage::Bound(bytes) => bytes.resident(),
        }
    }
}

impl<'d, const ADAPTIVE: bool> Recv for RecvBuffer<'d, ADAPTIVE> {
    type Ready = Segments;

    fn layout(&self) -> Layout {
        match self.storage {
            RecvStorage::Compact(_) => Layout::Compact,
            RecvStorage::Owned(_) | RecvStorage::Retained(_) | RecvStorage::Bound(_) => {
                Layout::Full
            }
        }
    }

    fn try_copy(bytes: &[u8]) -> Result<Self, Capacity> {
        Ok(Self {
            storage: RecvStorage::Owned(Vec::<u8>::try_copy(bytes)?),
        })
    }

    fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            storage: RecvStorage::Owned(bytes),
        }
    }

    fn try_slice(&self, extent: Extent) -> Result<Projection<Self>, Capacity> {
        let range = extent.range();
        Ok(Projection::new(match &self.storage {
            RecvStorage::Owned(bytes) => Self::from_vec(try_copied_range(bytes, range)?),
            RecvStorage::Compact(bytes) => {
                let bytes = bytes.try_clone().map_err(Capacity::Retain)?;
                let bytes = bytes.project(range).map_err(Capacity::rejected)?;
                Self::compact(bytes)
            }
            RecvStorage::Retained(bytes) => {
                let bytes = bytes.try_clone().map_err(Capacity::Retain)?;
                let bytes = bytes.project(range).map_err(Capacity::rejected)?;
                Self {
                    storage: RecvStorage::Retained(bytes),
                }
            }
            RecvStorage::Bound(bytes) => {
                let bytes = bytes.try_clone().map_err(Capacity::Retain)?;
                let bytes = bytes.project(range).map_err(Capacity::rejected)?;
                Self {
                    storage: RecvStorage::Bound(bytes),
                }
            }
        }))
    }

    fn try_project(self, extent: Extent) -> Result<Projection<Self>, Capacity> {
        let range = extent.range();
        Ok(Projection::new(match self.storage {
            RecvStorage::Owned(bytes) => Self::from_vec(try_owned_range(bytes, range)?),
            RecvStorage::Compact(bytes) => {
                let bytes = bytes.project(range).map_err(Capacity::rejected)?;
                Self::compact(bytes)
            }
            RecvStorage::Retained(bytes) => {
                let bytes = bytes.project(range).map_err(Capacity::rejected)?;
                Self {
                    storage: RecvStorage::Retained(bytes),
                }
            }
            RecvStorage::Bound(bytes) => {
                let bytes = bytes.project(range).map_err(Capacity::rejected)?;
                Self {
                    storage: RecvStorage::Bound(bytes),
                }
            }
        }))
    }

    fn into_suffix(mut self, max: usize) -> Self {
        self.advance(max);
        self
    }
}

// SAFETY: each variant owns the immutable bytes exposed by RecvBuffer.
unsafe impl<const ADAPTIVE: bool> buffer::raw::Store for &mut RecvBuffer<'_, ADAPTIVE> {
    fn empty() -> Option<Self> {
        None
    }

    fn restrict(slice: buffer::raw::Slice<'_, '_, Self>) {
        use buffer::raw::{Slice, Store};

        let (buffer, range) = slice.into_parts();
        match &mut buffer.storage {
            RecvStorage::Owned(bytes) => {
                // SAFETY: the variant exposes the unchanged bytes of this owner.
                Store::project(unsafe { Slice::from_parts(bytes, range) });
            }
            RecvStorage::Compact(bytes) => {
                // SAFETY: the variant exposes the unchanged bytes of this owner.
                Store::project(unsafe { Slice::from_parts(bytes, range) });
            }
            RecvStorage::Retained(bytes) => {
                // SAFETY: the variant exposes the unchanged bytes and driver lifetime.
                Store::project(unsafe { Slice::from_parts(bytes, range) });
            }
            RecvStorage::Bound(bytes) => {
                // SAFETY: the variant exposes the unchanged bytes and driver lifetime.
                Store::project(unsafe { Slice::from_parts(bytes, range) });
            }
        }
    }
}

impl<'d, const ADAPTIVE: bool> Retain<'d> for RecvBuffer<'d, ADAPTIVE> {
    fn try_retain(&mut self) -> Result<resident::Shared<'d>, alloc::Exhausted> {
        match &mut self.storage {
            RecvStorage::Owned(bytes) => bytes.try_retain(),
            RecvStorage::Compact(bytes) => Ok(resident::Shared::from(mem::take(bytes))),
            RecvStorage::Retained(bytes) => Ok(resident::Shared::from(mem::replace(
                bytes,
                storage::Shared::<Option<provided::Account<'d>>>::new(),
            ))),
            RecvStorage::Bound(bytes) => Ok(resident::Shared::from(mem::take(bytes))),
        }
    }
}

// SAFETY: every representation owns or retains its complete immutable receive
// backing. Moving RecvBuffer does not move those bytes, shared access cannot
// mutate them, and retained packets carry the driver-domain lifetime.
unsafe impl<'d, const ADAPTIVE: bool> data::raw::StableOwner<'d> for RecvBuffer<'d, ADAPTIVE> {}

const _: () = {
    assert!(
        mem::size_of::<storage::Shared<Option<provided::Account<'static>>>>()
            == 3 * mem::size_of::<usize>()
    );
    assert!(
        mem::align_of::<storage::Shared<Option<provided::Account<'static>>>>()
            == mem::align_of::<usize>()
    );
    assert!(mem::size_of::<RecvBuffer<'static>>() == 4 * mem::size_of::<usize>());
};
const _: () = {
    assert!(
        mem::size_of::<RecvBuffer<'static, true>>() == mem::size_of::<RecvBuffer<'static, false>>()
    );
};
