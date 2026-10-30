use crate::conn::stream::Count;
use crate::conn::stream::event::queue::readable;
use crate::conn::stream::resident::{
    self,
    slot::{self, plane, store},
};
use crate::conn::stream::state::receive::{credits, recv};
use crate::conn::stream::state::resident::Table;
use crate::conn::{self, id, life::options};
use crate::stream::{Projection, Recv};
use crate::wire::{ranges::inserts, stream};
use o3::{alloc, depot};
use scope::Preparation;
use std::mem;

pub(in crate::conn) use active::Active;
pub(in crate::conn::stream::state::receive) use entries::DeliveryRead;
pub(in crate::conn) use entries::{Occupied, Resolved, Slot, Vacant};
pub(in crate::conn) use loan::{Credit, Held, Loan, Merge};
pub(in crate::conn) use slots::Slots;

mod active;
mod entries;
mod loan;
pub(crate) mod ready;
mod recycle;
pub(in crate::conn) mod scope;
mod slots;
pub(crate) mod views;

pub(super) const MAX_INDEX: u32 = (1 << 30) - 2;

#[derive(Debug)]
pub(in crate::conn) struct Side;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Delivery {
    Applied,
    Stale,
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(in crate::conn) struct Id(slot::Id<Side>);

impl Id {
    pub(in crate::conn) fn new(id: stream::Id) -> Self {
        Self(slot::Id::new(id))
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) struct Handle(id::Local<slot::Handle<Side>>);

impl Handle {
    fn from_storage(handle: slot::Handle<Side>) -> Self {
        Self(id::Local::new(handle))
    }
}

#[derive(Clone, Copy)]
pub(in crate::conn) struct Limit(slot::Capacity);

impl Limit {
    pub(in crate::conn) const fn new(counts: [Count; 3]) -> Self {
        const { assert!(3 * conn::MAX_STREAMS <= MAX_INDEX as u64) };
        Self(slot::Capacity::new(counts))
    }
}

pub(in crate::conn) struct Map<B: Recv> {
    core: store::Pool<Side, recv::Entry<B>, Option<readable::Handle>, plane::HeadOnly>,
    ranges: depot::raw::Arena<Node<B>, Tag>,
    meta: credits::Meta,
}

impl<B: Recv> Map<B> {
    pub(in crate::conn) fn try_new(
        capacity: Limit,
        ranges: options::Parts,
        meta: credits::Meta,
    ) -> Result<Self, alloc::Error> {
        Ok(Self {
            core: store::Pool::try_new(capacity.0)?,
            ranges: depot::raw::Arena::try_new(ranges)?,
            meta,
        })
    }

    pub(in crate::conn) fn meta(&self) -> &credits::Meta {
        &self.meta
    }

    pub(in crate::conn) fn mark_data(&mut self) {
        self.meta.mark_data();
    }

    pub(in crate::conn) fn clear_data(&mut self) {
        self.meta.clear_data();
    }

    pub(in crate::conn) fn mark_streams(&mut self, dir: stream::Direction) {
        self.meta.mark_streams(dir);
    }

    pub(in crate::conn) fn clear_stream(&mut self, dir: stream::Direction) {
        self.meta.clear_stream(dir);
    }

    pub(in crate::conn) fn parts(&mut self) -> Slots<'_, B> {
        Slots {
            core: &mut self.core,
            arena: &self.ranges,
        }
    }

    pub(in crate::conn) fn find(&self, id: Id, registry: &Table) -> Option<Resolved<'_, B>> {
        let (_, slot) = registry.read().find::<false>(id.0.id())?;
        self.current(slot)
    }

    pub(in crate::conn) fn find_key(
        &self,
        key: resident::Key,
        registry: &Table,
    ) -> Option<Resolved<'_, B>> {
        let slot = registry.read().slot::<false>(key)?;
        self.current(slot)
    }

    pub(in crate::conn) fn try_find(
        &self,
        local: resident::Local,
        registry: &Table,
    ) -> Result<Option<Resolved<'_, B>>, resident::Stale> {
        Ok(registry
            .read()
            .try_slot(local)?
            .and_then(|slot| self.current(slot)))
    }

    fn current(&self, slot: u32) -> Option<Resolved<'_, B>> {
        self.core.current(slot).map(|entry| Resolved {
            entry,
            arena: &self.ranges,
        })
    }

    pub(in crate::conn) fn deliver(
        &mut self,
        registry: &mut Table,
        key: resident::Key,
        event: readable::Handle,
        id: stream::Id,
    ) -> Delivery {
        let Some(slot) = registry.read().slot::<false>(key) else {
            return Delivery::Stale;
        };
        let Some(entry) = self.core.bind_at(slot) else {
            return Delivery::Stale;
        };
        let mut occupied = Occupied {
            entry,
            arena: &self.ranges,
        };
        if occupied.entry.id() != id {
            return Delivery::Stale;
        }
        let position = occupied.entry.position_mut();
        if *position != Some(event) {
            return Delivery::Stale;
        }
        *position = None;
        let Some(event) = registry.event::<false>().held(key, id) else {
            return Delivery::Stale;
        };
        event.release();
        Delivery::Applied
    }

    pub(in crate::conn) fn front(&mut self) -> Option<Active<'_, B>> {
        self.core.front().map(|inner| Active { inner })
    }

    pub(in crate::conn) fn len(&self) -> usize {
        self.core.length()
    }

    pub(in crate::conn) fn has_ready(&self, admit: impl Fn(stream::Id) -> bool) -> bool {
        self.core.iter().any(|entry| admit(entry.id()))
    }

    pub(in crate::conn) fn scope<R>(
        &mut self,
        table: &mut Table,
        storage: &mut scope::Storage,
        run: impl for<'id, 'table> FnOnce(Preparation<'_, 'id, 'table, B>) -> R,
    ) -> R {
        self.core.scope(|core| {
            table.scope(|table| run(Preparation::new(core, &self.ranges, table, storage)))
        })
    }
}

const _: () = {
    assert!(mem::size_of::<Id>() == mem::size_of::<u64>());
    assert!(!mem::needs_drop::<Id>());
    assert!(mem::size_of::<Handle>() == mem::size_of::<u64>());
    assert!(mem::size_of::<Option<Handle>>() == mem::size_of::<u64>());
    assert!(!mem::needs_drop::<Handle>());
};
const _: () = assert!(
    std::mem::size_of::<Map<Vec<u8>>>()
        == std::mem::size_of::<
            store::Pool<Side, recv::Entry<Vec<u8>>, Option<readable::Handle>, plane::HeadOnly>,
        >() + std::mem::size_of::<depot::raw::Arena<Node<Vec<u8>>, Tag>>()
            + std::mem::size_of::<credits::Meta>()
);

pub enum Tag {}

pub struct Node<B> {
    start: u64,
    pub(in crate::conn::stream::state::receive::recv::map) bytes: B,
}

impl<B: Recv> Node<B> {
    pub(in crate::conn::stream::state::receive::recv::map) fn piece(
        part: inserts::Part,
        bytes: Projection<B>,
    ) -> Self {
        Self {
            start: part.start(),
            bytes: bytes.into_inner(),
        }
    }

    pub(in crate::conn::stream::state::receive::recv::map) fn ready(bytes: B) -> Self {
        Self { start: 0, bytes }
    }

    pub(in crate::conn::stream::state::receive::recv::map) const fn start(&self) -> u64 {
        self.start
    }

    /// The owning projection retains Part's bounded width; ready nodes start at zero.
    pub(in crate::conn::stream::state::receive::recv::map) fn end(&self) -> u64 {
        self.start + self.bytes.as_ref().len() as u64
    }

    pub(in crate::conn::stream::state::receive::recv::map) fn bytes(&self) -> &B {
        &self.bytes
    }

    pub(in crate::conn::stream::state::receive::recv::map) fn into_bytes(self) -> B {
        self.bytes
    }
}

const _: () = assert!(mem::size_of::<Node<Vec<u8>>>() == mem::size_of::<(u64, Vec<u8>)>());
