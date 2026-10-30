use crate::conn::{
    self,
    machine::storage::capacity,
    output::delivery,
    wire::crypto::tx::{self, commit},
};
use o3::depot;
use o3::{
    alloc,
    depot::{
        index,
        queue::{indexed::keyed, links},
    },
};
use std::{marker, mem, num::NonZero};
use table::Slots;

mod phases;
pub(super) mod table;

use phases::Phase;
pub(super) use phases::Status;

pub(super) struct Entry {
    pub(in crate::conn::wire::crypto::tx) epoch: conn::Epoch,
    pub(in crate::conn::wire::crypto::tx) record: delivery::Crypto,
    pub(in crate::conn::wire::crypto::tx) status: Status,
    pub(in crate::conn::wire::crypto::tx) flight: keyed::Link<Key, Flight>,
    pub(in crate::conn::wire::crypto::tx) order_next: Option<Key>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct Key(NonZero<u64>);

pub(super) enum Flight {}

impl Key {
    pub(in crate::conn::wire::crypto::tx::stores) fn from_parts(index: u16, epoch: u32) -> Self {
        let raw = (u64::from(epoch) << 16) | (u64::from(index) + 1);
        Self(NonZero::<u64>::MIN.saturating_add(raw - 1))
    }

    pub(in crate::conn::wire::crypto::tx::stores) fn handle(
        self,
    ) -> delivery::Handle<delivery::Crypto> {
        delivery::Handle::from_slot(
            <Self as depot::raw::Key>::index(self) as u16,
            (self.0.get() >> 16) as u32,
        )
    }
}

// SAFETY: the nonzero representation losslessly preserves the exact compact
// owner generation and encoded index; zero alone is reserved for vacancy.
unsafe impl depot::raw::Key for Key {
    type Raw = u64;
    type Live = Self;

    const VACANT: Self::Raw = 0;

    fn index(self) -> usize {
        usize::from((self.0.get() as u16) - 1)
    }

    fn into_raw(self) -> Self::Raw {
        self.0.get()
    }

    fn from_raw(raw: index::Stored<Self>) -> Self {
        // SAFETY: Stored proves this identity was emitted by a live compact Key.
        let raw = raw.into_raw();
        let raw = unsafe { NonZero::<u64>::new_unchecked(raw) };
        Self(raw)
    }

    fn decode(raw: Self::Raw) -> Option<Self> {
        NonZero::<u64>::new(raw)
            .filter(|raw| raw.get() as u16 != 0 && raw.get() >> 48 == 0)
            .map(Self)
    }

    fn into_live(self) -> Self::Live {
        self
    }

    fn from_live(live: Self::Live) -> Self {
        live
    }
}

pub(super) struct Acknowledged {
    pub(in crate::conn::wire::crypto::tx) epoch: conn::Epoch,
    pub(in crate::conn::wire::crypto::tx) reclaim: Option<u64>,
}

/// Owns CRYPTO generations and the epoch-selected flight topology.
/// In-flight entries have one link; removal detaches it before generation reuse.
pub(super) struct Set {
    pub(in crate::conn::wire::crypto::tx::stores) slots: Slots,
    pub(in crate::conn::wire::crypto::tx::stores) ready: tx::Ready,
    pub(in crate::conn::wire::crypto::tx::stores) flights: tx::Flights,
}

struct View<'a, P> {
    owner: &'a Set,
    fifo: &'a keyed::Fifo<Key, Flight>,
    plane: marker::PhantomData<P>,
}

struct Probe<'a> {
    owner: &'a Set,
    key: Key,
}

impl<'a, P> View<'a, P> {
    fn first(self) -> Option<(Key, &'a Entry)> {
        let live = keyed::Fifo::first(self)?;
        let live = unsafe { live.map(|(view, index)| (&view.owner.slots, index)) };
        Some(Slots::project(live))
    }
}

// SAFETY: the original Set permanently pairs these epoch FIFOs with its slots;
// the immutable owner loan prevents queue mutation, removal, and generation reuse.
unsafe impl<P> depot::raw::KeySource<Flight> for View<'_, P> {
    type Key = Key;
    fn fifo(&self) -> &keyed::Fifo<Key, Flight> {
        self.fifo
    }
}

// SAFETY: only Set's retained flight cursor constructs Probe. The exact entry
// has an initialized InFlight payload. Every removal or transfer requires an
// exclusive Set loan and advances this cursor before another Probe can exist.
unsafe impl depot::raw::Source<tx::Flights> for Probe<'_> {
    type Key = links::Index;
    fn key(&self) -> Self::Key {
        unsafe {
            <links::Index as depot::raw::Word>::from_offset(<Key as depot::raw::Key>::index(
                self.key,
            ))
        }
    }
}

impl Set {
    pub(in crate::conn::wire::crypto::tx) fn try_new(
        limit: capacity::Capacity<capacity::Crypto>,
    ) -> Result<Self, alloc::Error> {
        Ok(Self {
            slots: Slots::try_new(limit)?,
            ready: tx::Ready::new(),
            flights: tx::Flights::new(),
        })
    }

    pub(in crate::conn::wire::crypto::tx) fn has_ready(&self, epoch: conn::Epoch) -> bool {
        !epoch.bind(&self.ready.0).is_empty()
    }

    pub(in crate::conn::wire::crypto::tx) fn ready(
        &self,
        epoch: conn::Epoch,
    ) -> Option<(Key, delivery::Crypto)> {
        let (key, entry) = View::<tx::Ready> {
            owner: self,
            fifo: epoch.bind(&self.ready.0),
            plane: marker::PhantomData,
        }
        .first()?;
        Some((key, entry.record))
    }

    pub(in crate::conn::wire::crypto::tx) fn probe(
        &self,
        epoch: conn::Epoch,
    ) -> Option<tx::Commit> {
        let key = (*epoch.bind(&self.flights.probes))?;
        let live = index::Access::into_live(Probe { owner: self, key });
        let (key, flight) = phases::InFlight::project(live);
        Some(tx::Commit(commit::State::Probe {
            key,
            record: flight.record(),
            carriers: flight.carriers().checked_add(1)?,
        }))
    }

    pub(in crate::conn::wire::crypto::tx) fn acknowledge(
        &mut self,
        handle: delivery::Handle<delivery::Crypto>,
    ) -> Option<Acknowledged> {
        let epoch = self
            .slots
            .acknowledge(handle, &mut self.ready, &mut self.flights)?;
        Some(Acknowledged {
            epoch,
            reclaim: self.slots.reclaim(epoch),
        })
    }

    pub(in crate::conn::wire::crypto::tx) fn lose(
        &mut self,
        handle: delivery::Handle<delivery::Crypto>,
    ) {
        let Some(slot) = self.slots.lose(handle) else {
            return;
        };
        self.ready.lose(&mut self.flights, slot);
    }

    pub(in crate::conn::wire::crypto::tx) fn arm_probes(&mut self, epoch: conn::Epoch) {
        *epoch.bind_mut(&mut self.flights.probes) = View::<tx::Flights> {
            owner: self,
            fifo: epoch.bind(&self.flights.chains),
            plane: marker::PhantomData,
        }
        .first()
        .map(|entry| entry.0);
    }

    pub(in crate::conn::wire::crypto::tx) fn clear(&mut self, epoch: conn::Epoch) {
        self.ready.clear(epoch);
        self.flights.clear(epoch);
        self.slots.clear(epoch);
    }
}

const _: () = {
    assert!(usize::BITS <= u64::BITS);
    assert!(mem::size_of::<Entry>() == 5 * mem::size_of::<usize>());
    assert!(mem::size_of::<Slots>() == 9 * mem::size_of::<usize>());
    assert!(mem::size_of::<Set>() == 18 * mem::size_of::<usize>());
    assert!(mem::size_of::<View<'static, tx::Ready>>() == 2 * mem::size_of::<usize>());
    assert!(mem::size_of::<Option<View<'static, tx::Ready>>>() == 2 * mem::size_of::<usize>());
    assert!(mem::size_of::<View<'static, tx::Flights>>() == 2 * mem::size_of::<usize>());
};
