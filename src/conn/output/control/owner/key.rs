use std::{marker, num};

use o3::depot::arena::slab::key;

use crate::conn::output::control::owner;

#[repr(transparent)]
pub(in crate::conn) struct Key<Kind> {
    inner: key::Parts<{ owner::MAX }>,
    kind: marker::PhantomData<fn() -> Kind>,
}

impl<Kind> Key<Kind> {
    pub(in crate::conn::output::control) const fn new(inner: key::Parts<{ owner::MAX }>) -> Self {
        Self {
            inner,
            kind: marker::PhantomData,
        }
    }

    pub(in crate::conn::output::control) const fn inner(self) -> key::Parts<{ owner::MAX }> {
        self.inner
    }

    pub(in crate::conn::output::control) const fn into_raw(self) -> u64 {
        self.inner.into_raw().get()
    }

    pub(in crate::conn::output::control) const fn from_raw(raw: u64) -> Option<Self> {
        let raw = match num::NonZero::<u64>::new(raw) {
            Some(raw) => raw,
            None => return None,
        };
        match key::Parts::from_raw(raw) {
            Some(inner) => Some(Self::new(inner)),
            None => None,
        }
    }
}

impl<Kind> Clone for Key<Kind> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Kind> Copy for Key<Kind> {}

impl<Kind> PartialEq for Key<Kind> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<Kind> Eq for Key<Kind> {}
