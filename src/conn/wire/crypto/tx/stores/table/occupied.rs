use crate::conn::{
    machine::storage::compact,
    output::delivery,
    wire::crypto::tx::{
        self,
        stores::table::{Delivery, Entry, Flight, Key, Transfer},
    },
};
use o3::base::num::Generation;
use o3::depot;
use o3::depot::index::Initialized;
use o3::depot::queue::{indexed::keyed, links};
use std::marker;

pub(super) struct Occupied<'a, P = ()>(
    pub(super) compact::Occupied<'a, Entry, Generation, Delivery, P>,
);

#[repr(transparent)]
pub(super) struct Borrowed<'b, 'a, P>(pub(super) &'b Occupied<'a, P>);

#[repr(transparent)]
pub(super) struct Projected<'b, 'a, P>(
    pub(super) depot::raw::Proof<(&'b Occupied<'a, P>, links::Index), Initialized<Flight>>,
);

// SAFETY: the occupied loan retains this initialized flight's exact generation and link.
unsafe impl<'b, P> depot::raw::KeyBorrow<'b, Flight> for Borrowed<'b, '_, P> {
    type Key = Key;

    fn parts(self) -> (Key, &'b keyed::Link<Key, Flight>) {
        (self.0.key(), &self.0.get().flight)
    }
}

// SAFETY: the live witness retains this exact initialized neighbor and original table loan.
unsafe impl<'b, P> depot::raw::KeyBorrow<'b, Flight> for Projected<'b, '_, P> {
    type Key = Key;

    fn parts(self) -> (Key, &'b keyed::Link<Key, Flight>) {
        let (key, entry) = Occupied::project(self.0);
        (key, &entry.flight)
    }
}

impl<P> Occupied<'_, P> {
    pub(super) fn send(
        mut self,
        source: &mut keyed::Fifo<Key, Flight>,
        target: &mut keyed::Fifo<Key, Flight>,
        record: delivery::Crypto,
    ) {
        self.get_mut().record = record;
        // SAFETY: the retained queued slot owns these epoch queues through flight commit.
        unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(Transfer::<tx::Ready, P> {
                entry: self,
                source,
                target,
                stage: marker::PhantomData,
            }))
        }
        .transfer()
        .release();
    }

    pub(super) fn key(&self) -> Key {
        let key = self.0.key();
        Key::from_parts(key.index() as u16, key.generation().get())
    }

    pub(super) fn project(
        live: depot::raw::Proof<(&Self, links::Index), Initialized<Flight>>,
    ) -> (Key, &Entry) {
        let live = unsafe { live.map(|(entry, index)| (&entry.0, index)) };
        let (key, entry) = compact::Occupied::project(live);
        (
            Key::from_parts(key.index() as u16, key.generation().get()),
            entry,
        )
    }

    pub(super) fn get(&self) -> &Entry {
        self.0.get()
    }

    pub(super) fn get_mut(&mut self) -> &mut Entry {
        self.0.get_mut()
    }

    pub(super) fn remove(self) {
        self.0.discard();
    }
}
