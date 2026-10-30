//! Thread-local connection identities and execution brands.

use std::{cell, convert, hash, marker, mem, num, time};

use dope::{
    core::driver::{self, schedule::clock, schedule::ready::task::owner},
    manifold::network::datagram::send::owners,
};
use driver::route::KeyTag;
use o3::base::marker::ThreadBound;

thread_local! {
    static NEXT_DOMAIN: cell::Cell<u64> = const { cell::Cell::new(1) };
}

/// Process-lifetime execution brand used by standalone muxes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Static;

/// Invariant brand for one installed driver lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Driver<'d>(marker::PhantomData<fn(&'d mut ()) -> &'d mut ()>);

/// Monotonic observation selected by one execution identity.
#[doc(hidden)]
pub trait Temporal: Copy + Eq + hash::Hash {
    type Observation: Copy + Into<time::Instant>;
    type Queued<const ID: u8>: Copy + Eq + hash::Hash;
    type Flight<const ID: u8>: Copy + Eq + hash::Hash;
}

impl Temporal for Static {
    type Observation = time::Instant;
    type Queued<const ID: u8> = convert::Infallible;
    type Flight<const ID: u8> = convert::Infallible;
}

impl<'d> Temporal for Driver<'d> {
    type Observation = clock::Moment<'d>;
    type Queued<const ID: u8> = owners::Queued<'d, KeyTag<ID>>;
    type Flight<const ID: u8> = owners::Flight<'d, KeyTag<ID>>;
}

/// Thread-bound runtime identity.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::conn) struct Local<Value> {
    value: Value,
    thread: marker::PhantomData<ThreadBound>,
}

impl<Value> Local<Value> {
    pub(in crate::conn) const fn new(value: Value) -> Self {
        Self {
            value,
            thread: marker::PhantomData,
        }
    }

    pub(in crate::conn) const fn value(&self) -> &Value {
        &self.value
    }

    pub(in crate::conn) const fn value_mut(&mut self) -> &mut Value {
        &mut self.value
    }
}

impl Local<num::NonZero<u64>> {
    pub(in crate::conn) fn allocate(next: &cell::Cell<u64>, maximum: u64) -> Option<Self> {
        let current = num::NonZero::new(next.get())?;
        if current.get() > maximum {
            return None;
        }
        next.set(if current.get() == maximum {
            0
        } else {
            current.get() + 1
        });
        Some(Self::new(current))
    }
}

/// One endpoint identity within an execution and route domain.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Domain<I = Static, const ID: u8 = 0> {
    value: Local<num::NonZero<u64>>,
    brand: marker::PhantomData<fn(I) -> I>,
}

impl<const ID: u8> Domain<Static, ID> {
    pub fn new() -> Option<Self> {
        NEXT_DOMAIN.with(Self::allocate)
    }
}

impl<'d, const ID: u8> Domain<Driver<'d>, ID> {
    pub(crate) fn for_driver(_: &driver::Context<'_, 'd>) -> Option<Self> {
        NEXT_DOMAIN.with(Self::allocate)
    }
}

impl<I, const ID: u8> Domain<I, ID> {
    fn allocate(next: &cell::Cell<u64>) -> Option<Self> {
        Some(Self {
            value: Local::allocate(next, u64::MAX)?,
            brand: marker::PhantomData,
        })
    }

    pub const fn handle(self, position: num::NonZero<u32>, epoch: u32) -> Handle<I, ID> {
        Handle {
            domain: self,
            position,
            epoch,
        }
    }
}

/// Complete connection generation within one endpoint domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Handle<I = Static, const ID: u8 = 0> {
    domain: Domain<I, ID>,
    position: num::NonZero<u32>,
    epoch: u32,
}

impl<I, const ID: u8> owner::Identity for Handle<I, ID> {
    fn parts(self) -> (owner::Lane, owner::Generation) {
        (
            owner::Lane::from(self.position),
            owner::Generation::from_u32(self.epoch),
        )
    }
}

impl<I, const ID: u8> Handle<I, ID> {
    pub const fn position(self) -> num::NonZero<u32> {
        self.position
    }

    pub const fn index(self) -> u32 {
        self.position.get() - 1
    }

    pub const fn generation(self) -> u32 {
        self.epoch
    }

    pub const fn domain(self) -> Domain<I, ID> {
        self.domain
    }

    pub(crate) fn belongs_to(self, domain: Domain<I, ID>) -> bool {
        self.domain.value == domain.value
    }
}

const _: () = {
    assert!(mem::size_of::<<Static as Temporal>::Observation>() == mem::size_of::<time::Instant>());
    assert!(
        mem::size_of::<<Driver<'static> as Temporal>::Observation>()
            == mem::size_of::<time::Instant>()
    );
    assert!(
        mem::align_of::<<Driver<'static> as Temporal>::Observation>()
            == mem::align_of::<time::Instant>()
    );
    assert!(!mem::needs_drop::<<Driver<'static> as Temporal>::Observation>());
    assert!(mem::size_of::<Domain>() == mem::size_of::<u64>());
    assert!(mem::size_of::<Handle>() == 2 * mem::size_of::<u64>());
    assert!(mem::size_of::<Option<Handle>>() == mem::size_of::<Handle>());
    assert!(!mem::needs_drop::<Handle>());
};
