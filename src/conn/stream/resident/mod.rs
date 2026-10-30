mod origin;
mod owner;
pub(in crate::conn) mod slot;
mod tag;
mod view;

pub use origin::Origin;
pub use owner::Owner;
pub use tag::Tag;
pub use view::View;

use std::{marker, num};

use o3::{base::marker::ThreadBound, depot::map::resident};

use crate::wire::stream;

pub(in crate::conn::stream) const MAX_GENERATION: u32 = u32::MAX >> 1;

/// A generational coordinate in one connection's resident registry.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Key(pub(in crate::conn::stream) resident::Key<MAX_GENERATION>);

impl Key {
    #[doc(hidden)]
    pub const fn from_raw(raw: num::NonZero<u64>) -> Option<Self> {
        match resident::Key::from_raw(raw) {
            Some(key) => Some(Self(key)),
            None => None,
        }
    }

    #[doc(hidden)]
    pub const fn raw(self) -> num::NonZero<u64> {
        self.0.raw()
    }
}

/// Inert resident coordinates. The connection [`Origin`] is retained once by the owner.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Local {
    id: stream::Id,
    key: Key,
    thread: marker::PhantomData<ThreadBound>,
}

impl Local {
    #[doc(hidden)]
    pub const fn new(id: stream::Id, key: Key) -> Self {
        Self {
            id,
            key,
            thread: marker::PhantomData,
        }
    }

    pub const fn id(self) -> stream::Id {
        self.id
    }

    #[doc(hidden)]
    pub const fn key(self) -> Key {
        self.key
    }
}

/// Resident stream auth branded to one lexical connection scope.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle<'conn> {
    local: Local,
    invariant: marker::PhantomData<fn(&'conn mut ()) -> &'conn mut ()>,
}

impl<'conn> Handle<'conn> {
    pub(in crate::conn) const fn new(local: Local) -> Self {
        Self {
            local,
            invariant: marker::PhantomData,
        }
    }

    pub const fn id(self) -> stream::Id {
        self.local.id()
    }

    #[doc(hidden)]
    pub const fn local(self) -> Local {
        self.local
    }
}

/// A retained resident origin belongs to another connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Foreign {
    expected: Origin,
    found: Origin,
}

impl Foreign {
    pub(super) const fn new(owner: Origin, found: Origin) -> Self {
        Self {
            expected: owner,
            found,
        }
    }

    pub const fn expected(self) -> Origin {
        self.expected
    }

    pub const fn found(self) -> Origin {
        self.found
    }
}

/// A retained resident coordinate no longer names its original generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stale {
    local: Local,
    actual: Option<Key>,
}

impl Stale {
    pub(in crate::conn) const fn new(local: Local, actual: Option<Key>) -> Self {
        Self { local, actual }
    }

    pub const fn local(self) -> Local {
        self.local
    }

    pub const fn actual(self) -> Option<Key> {
        self.actual
    }
}

/// A recoverable failure while operating on a resident stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Stream(super::Error),
    Stale(Stale),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Exhausted {
    pub(super) next: u64,
    pub(super) maximum: u64,
}

impl Exhausted {
    pub const fn next(self) -> u64 {
        self.next
    }

    pub const fn maximum(self) -> u64 {
        self.maximum
    }
}

const _: () = assert!(size_of::<Key>() == size_of::<u64>());
const _: () = assert!(size_of::<Option<Key>>() == size_of::<u64>());
const _: () = assert!(size_of::<Local>() == 2 * size_of::<u64>());
const _: () = assert!(size_of::<Handle<'static>>() == size_of::<Local>());
const _: () = assert!(size_of::<Option<Handle<'static>>>() == size_of::<Handle<'static>>());
const _: () = assert!(size_of::<Origin>() == size_of::<u64>());
const _: () = assert!(size_of::<Owner<'static>>() == 0);
