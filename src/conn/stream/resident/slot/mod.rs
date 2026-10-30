use std::{marker, num::NonZero};

use o3::{base::num::Generation, depot::queue::indexed::keyed};
pub(in crate::conn::stream::resident::slot) use occupied::Projected;
pub(in crate::conn) use occupied::{Activity, Occupied};
pub(in crate::conn) use table::Table;

use crate::{conn, wire::stream};
use conn::stream::Count;

pub(in crate::conn) mod plane;
pub(in crate::conn) mod store;

#[derive(Clone, Copy)]
struct Index(NonZero<u32>);

impl Index {
    fn new(raw: u32, len: usize) -> Option<Self> {
        let index = raw as usize;
        (index < len).then_some(Self(NonZero::<u32>::MIN.saturating_add(raw)))
    }

    const fn get(self) -> usize {
        self.raw() as usize
    }

    const fn raw(self) -> u32 {
        self.0.get() - 1
    }
}

#[derive(Clone, Copy)]
struct Free(Index);

/// Compact availability: zero is occupied; one terminates a free chain.
#[derive(Clone, Copy)]
struct Vacancy(Option<NonZero<u32>>);

impl Vacancy {
    const OCCUPIED: Self = Self(None);

    fn free(next: Option<Free>) -> Self {
        Self(Some(next.map_or(NonZero::<u32>::MIN, |free| {
            free.0.0.saturating_add(1)
        })))
    }

    fn next(self) -> Option<Free> {
        self.0
            .and_then(|next| NonZero::new(next.get() - 1))
            .map(|raw| Free(Index(raw)))
    }

    fn is_free(self) -> bool {
        self.0.is_some()
    }
}
const MAX_GENERATION: u32 = u32::MAX;

pub(in crate::conn) trait Reusable {
    type Init;

    fn new(init: Self::Init) -> Self;
    fn reuse(&mut self, init: Self::Init);
}

pub(in crate::conn) trait Recycle {
    type Value: Reusable;

    fn recycle(self, value: &mut Self::Value);
}

#[repr(transparent)]
pub(in crate::conn) struct Id<Side>(stream::Id, marker::PhantomData<fn() -> Side>);

impl<Side> Id<Side> {
    pub(in crate::conn) const fn new(id: stream::Id) -> Self {
        Self(id, marker::PhantomData)
    }

    pub(in crate::conn) const fn id(self) -> stream::Id {
        self.0
    }
}

impl<Side> Clone for Id<Side> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Side> Copy for Id<Side> {}

#[repr(transparent)]
#[derive(Debug)]
pub(in crate::conn) struct Handle<Side>(NonZero<u64>, marker::PhantomData<fn() -> Side>);

impl<Side> Handle<Side> {
    fn new(index: u32, epoch: u32) -> Self {
        let encoded = NonZero::<u64>::MIN.saturating_add(u64::from(index));
        let raw = encoded | (u64::from(epoch) << 32);
        Self(raw, marker::PhantomData)
    }

    pub(super) const fn from_raw(raw: NonZero<u64>) -> Self {
        Self(raw, marker::PhantomData)
    }

    pub(in crate::conn) const fn raw(self) -> NonZero<u64> {
        self.0
    }

    pub(in crate::conn) const fn index(self) -> u32 {
        (self.0.get() as u32) - 1
    }

    pub(in crate::conn) const fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }
}

impl<Side> Clone for Handle<Side> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Side> Copy for Handle<Side> {}

impl<Side> PartialEq for Handle<Side> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<Side> Eq for Handle<Side> {}

struct Node<Side, Value, Auxiliary> {
    id: stream::Id,
    generation: Generation<MAX_GENERATION>,
    value: Value,
    link: keyed::Link<Handle<Side>>,
    vacancy: Vacancy,
    auxiliary: Auxiliary,
}

#[derive(Clone, Copy)]
pub(in crate::conn) struct Capacity(u32);

impl Capacity {
    pub(in crate::conn) const fn new(counts: [Count; 3]) -> Self {
        const {
            assert!(3 * conn::MAX_STREAMS < (u32::MAX as u64 >> 1));
            assert!(3 * conn::MAX_STREAMS <= usize::MAX as u64);
        }
        Self((counts[0].get() + counts[1].get() + counts[2].get()) as u32)
    }

    pub(in crate::conn) const fn get(self) -> usize {
        self.0 as usize
    }
}

pub(in crate::conn) struct Resolved<'a, Side, Value, Auxiliary> {
    id: stream::Id,
    value: &'a Value,
    auxiliary: &'a Auxiliary,
    side: marker::PhantomData<fn() -> Side>,
}

impl<'a, Side, Value, Auxiliary> Resolved<'a, Side, Value, Auxiliary> {
    pub(in crate::conn) const fn id(&self) -> stream::Id {
        self.id
    }

    pub(in crate::conn) const fn value(&self) -> &'a Value {
        self.value
    }

    pub(in crate::conn) const fn auxiliary(&self) -> &'a Auxiliary {
        self.auxiliary
    }
}

const _: () = assert!(std::mem::size_of::<Id<()>>() == std::mem::size_of::<u64>());
const _: () = assert!(std::mem::size_of::<Handle<()>>() == std::mem::size_of::<u64>());
const _: () = assert!(std::mem::size_of::<Option<Handle<()>>>() == std::mem::size_of::<u64>());
const _: () = assert!(
    std::mem::size_of::<Occupied<'static, (), (), ()>>() == 2 * std::mem::size_of::<usize>()
);
const _: () =
    assert!(std::mem::size_of::<Generation<MAX_GENERATION>>() == std::mem::size_of::<u32>());

const _: () = assert!(std::mem::size_of::<Option<Index>>() == 4);
const _: () = assert!(std::mem::size_of::<Vacancy>() == 4);
const _: () = assert!(std::mem::size_of::<Option<Free>>() == 4);
const _: () = assert!(std::mem::size_of::<Node<(), u64, u64>>() == 40);

mod key;
mod occupied;
mod table;
