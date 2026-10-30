use crate::conn::output::control::{self, owner};
use o3::depot;
use o3::depot::{arena::slab::key, index};

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub(in crate::conn::output::control) struct Key(key::Handle<control::Tag, { owner::MAX }>);

impl Key {
    pub(in crate::conn::output::control::journal::storage) fn new(
        inner: key::Handle<control::Tag, { owner::MAX }>,
    ) -> Self {
        Self(inner)
    }

    pub(in crate::conn::output::control) fn index(self) -> usize {
        self.0.index() as usize
    }
}

// SAFETY: Key losslessly wraps one slab owner handle and delegates its complete
// generation-bearing representation, vacancy, and stable index unchanged.
unsafe impl depot::raw::Key for Key {
    type Raw = <key::Handle<control::Tag, { owner::MAX }> as depot::raw::Key>::Raw;
    type Live = Self;

    const VACANT: Self::Raw =
        <key::Handle<control::Tag, { owner::MAX }> as depot::raw::Key>::VACANT;

    fn index(self) -> usize {
        self.0.index() as usize
    }

    fn into_raw(self) -> Self::Raw {
        <key::Handle<control::Tag, { owner::MAX }> as depot::raw::Key>::into_raw(self.0)
    }

    fn from_raw(raw: index::Stored<Self>) -> Self {
        // SAFETY: Key and its Handle emit the same live identities; wrapping
        // the rebuilt Handle restores the exact original Key identity.
        unsafe {
            Self(<key::Handle<control::Tag, { owner::MAX }> as depot::raw::Key>::rebuild(raw))
        }
    }

    fn decode(raw: Self::Raw) -> Option<Self> {
        <key::Handle<control::Tag, { owner::MAX }> as depot::raw::Key>::decode(raw).map(Self)
    }

    fn into_live(self) -> Self::Live {
        self
    }

    fn from_live(live: Self::Live) -> Self {
        live
    }
}
