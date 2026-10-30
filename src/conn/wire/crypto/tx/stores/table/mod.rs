use crate::conn::{
    self,
    machine::storage::{capacity, compact},
    output::delivery,
    wire::crypto::tx::{
        self,
        stores::{Entry, Flight, Key, Phase, Status, phases},
    },
};
use o3::depot;
use o3::depot::index::Initialized;
use o3::{
    alloc,
    base::num::Generation,
    depot::{
        capacity::Count,
        index,
        queue::{indexed::keyed, links},
    },
};
use occupied::{Borrowed, Occupied, Projected};
pub(in crate::conn) use prepared::Prepared;
use std::{marker, mem, num};

mod occupied;
mod prepared;

enum Delivery {}

pub(in crate::conn::wire::crypto::tx) struct Slots {
    entries: compact::Table<Entry, Generation, Delivery>,
    order: [Ends; 3],
}

/// Exact endpoints of one epoch's order chain. Both are empty together;
/// only insertion and acknowledged-head consumption can change this pair.
#[derive(Clone, Copy)]
struct Ends {
    head: Option<Key>,
    tail: Option<Key>,
}

impl Ends {
    const EMPTY: Self = Self {
        head: None,
        tail: None,
    };
}

struct Head<'a> {
    slots: &'a mut Slots,
    key: Key,
    epoch: conn::Epoch,
}

struct Fresh<'a, P = ()> {
    entry: Occupied<'a, P>,
    order: &'a mut Ends,
}

struct Neighbor<'b, 'a, P> {
    entry: &'b mut Occupied<'a, P>,
    key: Key,
}

pub(in crate::conn::wire::crypto::tx) struct Lost<'a>(Occupied<'a>);

impl Slots {
    pub(in crate::conn::wire::crypto::tx::stores) fn acknowledge(
        &mut self,
        handle: delivery::Handle<delivery::Crypto>,
        ready: &mut tx::Ready,
        flights: &mut tx::Flights,
    ) -> Option<conn::Epoch> {
        let index = u32::try_from(handle.index()).ok()?;
        let entry = Occupied(self.entries.entry_mut(index)?);
        if entry.key().handle() != handle {
            return None;
        }
        let epoch = entry.get().epoch;
        match entry.get().status.phase() {
            Phase::Acknowledged => return None,
            Phase::Queued => {
                // SAFETY: the native generation still names the acknowledged
                // bytes; Queued owns this epoch's ready membership exclusively.
                unsafe {
                    keyed::Slot::from_source(depot::raw::Proof::new(Slot {
                        entry,
                        source: epoch.bind_mut(&mut ready.0),
                    }))
                }
                .remove()
                .release();
                return Some(epoch);
            }
            Phase::InFlight => {}
        }
        let key = entry.key();
        // SAFETY: this original occupied flight selects its epoch's queue;
        // both loans remain held until detachment and acknowledgement commit.
        let member = unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(Slot {
                entry,
                source: epoch.bind_mut(&mut flights.chains),
            }))
        };
        let next = member.successor().map(|live| {
            let live = unsafe { live.map(|(removal, index)| (&removal.entry, index)) };
            Occupied::project(live).0
        });
        member.remove().release();
        if *epoch.bind(&flights.probes) == Some(key) {
            *epoch.bind_mut(&mut flights.probes) = next;
        }
        Some(epoch)
    }

    pub(in crate::conn::wire::crypto::tx::stores) fn lose(
        &mut self,
        handle: delivery::Handle<delivery::Crypto>,
    ) -> Option<Lost<'_>> {
        let index = u32::try_from(handle.index()).ok()?;
        let mut slot = Occupied(self.entries.entry_mut(index)?);
        if slot.key().handle() != handle {
            return None;
        }
        let flight = phases::InFlight::new(slot.get())?;
        if let Some(carriers) = num::NonZero::new(flight.carriers().get() - 1) {
            slot.get_mut().status = Status::flight(carriers);
            return None;
        }
        Some(Lost(slot))
    }

    pub(in crate::conn::wire::crypto::tx::stores) fn try_new(
        limit: capacity::Capacity<capacity::Crypto>,
    ) -> Result<Self, alloc::Error> {
        Ok(Self {
            entries: compact::Table::try_new(Count::new(limit.as_u32()))?,
            order: [Ends::EMPTY; 3],
        })
    }

    pub(in crate::conn::wire::crypto::tx::stores) fn clear(&mut self, epoch: conn::Epoch) {
        *epoch.bind_mut(&mut self.order) = Ends::EMPTY;
        for index in 0..self.initialized() {
            if let Some((_, entry)) = self.bind(index)
                && entry.get().epoch == epoch
            {
                entry.remove();
            }
        }
    }

    pub(in crate::conn::wire::crypto::tx::stores) fn reclaim(
        &mut self,
        epoch: conn::Epoch,
    ) -> Option<u64> {
        let mut end = None;
        while let Some(key) = epoch.bind(&self.order).head {
            let head = Head {
                slots: self,
                key,
                epoch,
            };
            let Some(offset) = head.reclaim() else {
                break;
            };
            end = Some(offset);
        }
        end
    }

    pub(in crate::conn::wire::crypto::tx::stores) fn project<P>(
        live: depot::raw::Proof<(&Self, links::Index), Initialized<P>>,
    ) -> (Key, &Entry) {
        let live = unsafe { live.map(|(slots, index)| (&slots.entries, index)) };
        let (key, entry) = compact::Table::project(live);
        (
            Key::from_parts(key.index() as u16, key.generation().get()),
            entry,
        )
    }

    fn bind(&mut self, index: usize) -> Option<(Key, Occupied<'_>)> {
        let index = u32::try_from(index).ok()?;
        let entry = Occupied(self.entries.entry_mut(index)?);
        Some((entry.key(), entry))
    }

    fn initialized(&self) -> usize {
        self.entries.initialized().get()
    }
}

impl Lost<'_> {
    pub(in crate::conn::wire::crypto::tx) fn epoch(&self) -> conn::Epoch {
        self.0.get().epoch
    }

    pub(in crate::conn::wire::crypto::tx) fn transfer(
        self,
        source: &mut keyed::Fifo<Key, Flight>,
        target: &mut keyed::Fifo<Key, Flight>,
    ) -> (Key, Option<Key>) {
        let key = self.0.key();
        // SAFETY: the original occupied slot has one remaining flight carrier;
        // its epoch selects these disjoint queues in the same delivery owner.
        let member = unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(Transfer::<tx::Flights> {
                entry: self.0,
                source,
                target,
                stage: marker::PhantomData,
            }))
        };
        let next = member.successor().map(|live| {
            let live = unsafe { live.map(|(transfer, index)| (&transfer.entry, index)) };
            Occupied::project(live).0
        });
        member.transfer().release();
        (key, next)
    }
}

struct Transfer<'q, 'a, Q, P = ()> {
    entry: Occupied<'a, P>,
    source: &'q mut keyed::Fifo<Key, Flight>,
    target: &'q mut keyed::Fifo<Key, Flight>,
    stage: marker::PhantomData<fn(Q) -> Q>,
}

// SAFETY: the selected slot and its epoch's distinct queues retain their
// original exclusive borrows; only consuming transitions can change them.
unsafe impl<Q, P> depot::raw::KeyOwner<Flight> for Transfer<'_, '_, Q, P> {
    type Key = Key;
    type Fifo = keyed::Fifo<Key, Flight>;

    fn parts(&self) -> (Key, &keyed::Link<Key, Flight>) {
        depot::raw::KeyBorrow::parts(Borrowed(&self.entry))
    }

    fn fifo(&self) -> &keyed::Fifo<Key, Flight> {
        self.source
    }

    fn entry<'b>(
        live: depot::raw::Proof<(&'b Self, links::Index), Initialized<Flight>>,
    ) -> keyed::Entry<'b, Key, Flight> {
        let live = unsafe { live.map(|(transfer, index)| (&transfer.entry, index)) };
        keyed::Entry::from_source(Projected(live))
    }
}

// SAFETY: the same detached link moves with both original exclusive queue loans.
unsafe impl<'q, 'a, P> depot::raw::KeyRoute<Flight> for Transfer<'q, 'a, tx::Flights, P> {
    type Target = Transfer<'q, 'a, tx::Ready, P>;

    unsafe fn route(self) -> Self::Target {
        Transfer {
            entry: self.entry,
            source: self.target,
            target: self.source,
            stage: marker::PhantomData,
        }
    }
}

// SAFETY: this transition is consumed once after insertion in the ready queue.
unsafe impl<P> depot::raw::KeyFinish<true, Flight> for Transfer<'_, '_, tx::Ready, P> {
    type Output = ();

    unsafe fn finish(mut self) {
        self.entry.get_mut().status = Status::queued();
    }
}

// SAFETY: the detached ready link retains its original destination queue loan.
unsafe impl<'q, 'a, P> depot::raw::KeyRoute<Flight> for Transfer<'q, 'a, tx::Ready, P> {
    type Target = Transfer<'q, 'a, tx::Flights, P>;

    unsafe fn route(self) -> Self::Target {
        Transfer {
            entry: self.entry,
            source: self.target,
            target: self.source,
            stage: marker::PhantomData,
        }
    }
}

// SAFETY: membership in the destination flight queue is consumed with the slot.
unsafe impl<P> depot::raw::KeyFinish<true, Flight> for Transfer<'_, '_, tx::Flights, P> {
    type Output = ();

    unsafe fn finish(mut self) {
        self.entry.get_mut().status = Status::flight(num::NonZero::<u16>::MIN);
    }
}

struct Slot<'q, 'a, P = ()> {
    entry: Occupied<'a, P>,
    source: &'q mut keyed::Fifo<Key, Flight>,
}

// SAFETY: the original occupied flight and its epoch queue remain exclusively borrowed.
unsafe impl<P> depot::raw::KeyOwner<Flight> for Slot<'_, '_, P> {
    type Key = Key;
    type Fifo = keyed::Fifo<Key, Flight>;

    fn parts(&self) -> (Key, &keyed::Link<Key, Flight>) {
        depot::raw::KeyBorrow::parts(Borrowed(&self.entry))
    }

    fn fifo(&self) -> &keyed::Fifo<Key, Flight> {
        self.source
    }

    fn entry<'b>(
        live: depot::raw::Proof<(&'b Self, links::Index), Initialized<Flight>>,
    ) -> keyed::Entry<'b, Key, Flight> {
        let live = unsafe { live.map(|(removal, index)| (&removal.entry, index)) };
        keyed::Entry::from_source(Projected(live))
    }
}

// SAFETY: acknowledgement consumes vacancy and the same occupied slot exactly once.
unsafe impl<P> depot::raw::KeyFinish<false, Flight> for Slot<'_, '_, P> {
    type Output = ();

    unsafe fn finish(mut self) {
        self.entry.get_mut().status = Status::acknowledged();
    }
}

// SAFETY: releasing membership retains the exact occupied slot and original table.
unsafe impl<'a, P> depot::raw::KeyFinish<true, Flight> for Slot<'_, 'a, P> {
    type Output = Occupied<'a, P>;
    unsafe fn finish(self) -> Self::Output {
        self.entry
    }
}

impl Head<'_> {
    fn reclaim(self) -> Option<u64> {
        let live = index::Access::read(&self);
        let live = unsafe { live.map(|(head, index)| (&*head.slots, index)) };
        if !matches!(Slots::project(live).1.status.phase(), Phase::Acknowledged) {
            return None;
        }
        let live = index::Access::into_live(self);
        let live = unsafe {
            live.map(|(head, index)| {
                (
                    (
                        &mut head.slots.entries,
                        head.epoch.bind_mut(&mut head.slots.order),
                    ),
                    index,
                )
            })
        };
        let (entry, order) = compact::Table::take(live);
        order.head = entry.order_next;
        if order.head.is_none() {
            order.tail = None;
        }
        Some(entry.record.end())
    }
}

// SAFETY: the order root and native table remain exclusively owned by Head;
// only acknowledged-head consumption can advance the root or remove the slot.
unsafe impl depot::raw::Source for Head<'_> {
    type Key = links::Index;
    fn key(&self) -> Self::Key {
        unsafe {
            <links::Index as depot::raw::Word>::from_offset(<Key as depot::raw::Key>::index(
                self.key,
            ))
        }
    }
}

impl<P> Fresh<'_, P> {
    fn append(mut self, flights: &mut tx::Flights) -> delivery::Handle<delivery::Crypto> {
        let key = self.entry.key();
        if let Some(tail) = self.order.tail {
            let live = index::Access::into_live(Neighbor {
                entry: &mut self.entry,
                key: tail,
            });
            let live = unsafe { live.map(|(owner, index)| (&mut owner.entry.0, index)) };
            compact::Occupied::update(live).order_next = Some(key);
        } else {
            self.order.head = Some(key);
        }
        self.order.tail = Some(key);
        let epoch = self.entry.get().epoch;
        let handle = key.handle();
        // SAFETY: fresh insertion retains the original detached slot through
        // order linkage and insertion into its epoch's flight queue.
        unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(Slot {
                entry: self.entry,
                source: epoch.bind_mut(&mut flights.chains),
            }))
        }
        .push::<false>();
        handle
    }
}

// SAFETY: only the retained order endpoint constructs this neighbor; the native
// occupied guard keeps its exact table, generation, and initialization alive.
unsafe impl<P> depot::raw::Source<P> for Neighbor<'_, '_, P> {
    type Key = links::Index;
    fn key(&self) -> Self::Key {
        unsafe {
            <links::Index as depot::raw::Word>::from_offset(<Key as depot::raw::Key>::index(
                self.key,
            ))
        }
    }
}

const _: () = {
    assert!(mem::size_of::<Occupied<'static>>() == 16);
    assert!(mem::size_of::<Lost<'static>>() == 16);
    assert!(mem::size_of::<Option<Lost<'static>>>() == 16);
    assert!(mem::size_of::<Transfer<'static, 'static, tx::Flights>>() == 32);
    assert!(mem::size_of::<Transfer<'static, 'static, tx::Ready>>() == 32);
    assert!(mem::size_of::<Slot<'static, 'static>>() == 24);
};
