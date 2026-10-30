use std::mem;

use o3::depot::arena::slab::key;

use crate::conn::output::control::revision;

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub(in crate::conn) struct Key(key::Parts<{ revision::MAX }>);

impl Key {
    pub(in crate::conn::output::control) const fn new(
        parts: key::Parts<{ revision::MAX }>,
    ) -> Self {
        Self(parts)
    }

    pub(in crate::conn::output::control) const fn parts(self) -> key::Parts<{ revision::MAX }> {
        self.0
    }

    pub(in crate::conn) const fn index(self) -> usize {
        self.0.index() as usize
    }
}

const _: () = assert!(mem::size_of::<Option<Key>>() == mem::size_of::<u64>());
