//! Demand-backed connection journal storage with stable generational identity.

use o3::depot;
use o3::depot::{arena::slab::key, index};
pub(in crate::conn) use plan::Plan;

pub(in crate::conn) mod capacity;
pub(in crate::conn) mod compact;
pub(in crate::conn) mod demand;
mod plan;

#[repr(transparent)]
pub(in crate::conn) struct Key<Tag>(key::Handle<Tag>);

impl<Tag> Key<Tag> {
    pub(in crate::conn) const fn new(key: key::Handle<Tag>) -> Self {
        Self(key)
    }

    pub(in crate::conn) const fn handle(self) -> key::Handle<Tag> {
        self.0
    }

    pub(in crate::conn) const fn index(self) -> u32 {
        self.0.index()
    }
    pub(in crate::conn) const fn generation(self) -> u32 {
        self.0.generation().get()
    }
}

impl<Tag> Clone for Key<Tag> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<Tag> Copy for Key<Tag> {}
impl<Tag> PartialEq for Key<Tag> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<Tag> Eq for Key<Tag> {}

// SAFETY: the wrapped slab handle owns the complete validated raw-key contract.
unsafe impl<Tag> depot::raw::Key for Key<Tag> {
    type Raw = u64;
    type Live = Self;

    const VACANT: Self::Raw = 0;

    fn index(self) -> usize {
        self.index() as usize
    }

    fn into_raw(self) -> Self::Raw {
        depot::raw::Key::into_raw(self.0)
    }

    fn from_raw(raw: index::Stored<Self>) -> Self {
        // SAFETY: Key and its Handle emit the same live identities; wrapping
        // the rebuilt Handle restores the exact original Key identity.
        unsafe { Self(<key::Handle<Tag> as depot::raw::Key>::rebuild(raw)) }
    }

    fn decode(raw: Self::Raw) -> Option<Self> {
        <key::Handle<Tag> as depot::raw::Key>::decode(raw).map(Self)
    }

    fn into_live(self) -> Self::Live {
        self
    }

    fn from_live(live: Self::Live) -> Self {
        live
    }
}

const _: () = {
    assert!(std::mem::size_of::<Key<()>>() == std::mem::size_of::<u64>());
    assert!(std::mem::size_of::<Option<Key<()>>>() == std::mem::size_of::<u64>());
    assert!(!std::mem::needs_drop::<Key<()>>());
};
