mod changes;
use crate::conn::{
    machine::storage::{capacity, demand},
    output::{
        control::{
            self,
            journal::{self, storage},
        },
        delivery,
    },
};
use changes::{Action, Relation};
pub(in crate::conn) use changes::{Batch, Cid};
use control::{owner, revision};
pub(in crate::conn::output::control) use entry::Entry;
pub(in crate::conn::output::control) use key::Key;
use o3::depot;
use o3::depot::index::Initialized;
use o3::depot::{
    arena::slab::key::{Generation, Handle, Parts},
    capacity::Count,
    queue::{indexed::keyed, links},
};
pub(in crate::conn::output::control) use status::Status;
use std::{mem, ops};

mod entry;
mod key;
mod slots;
use slots::Insert;
pub(in crate::conn::output::control) use slots::Occupied;
pub(in crate::conn::output::control::journal) use slots::Projected;
mod status;

/// One occupied slot whose next revision has already been committed.
#[must_use]
#[repr(transparent)]
pub(in crate::conn::output::control) struct Revision<T>(T);

impl<T> ops::Deref for Revision<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> ops::DerefMut for Revision<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

struct Slot {
    revision: Generation<{ revision::MAX }>,
    value: Entry,
}

/// A shared view of occupied journal values and both exact identities.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn::output::control) struct View<'a>(
    &'a demand::Table<Slot, control::Tag, { owner::MAX }>,
);
type Native<'a, P = ()> = demand::Occupied<'a, Slot, control::Tag, { owner::MAX }, P>;

impl Slot {
    fn new(index: links::Index, record: delivery::Control) -> Self {
        Self {
            revision: Generation::MIN,
            value: Entry {
                record,
                status: storage::Status::Queued,
                hook: keyed::Link::from(index),
            },
        }
    }
}

impl<'a> View<'a> {
    pub(in crate::conn::output::control::journal) fn project(
        live: depot::raw::Proof<(Self, links::Index), Initialized<()>>,
    ) -> (Key, revision::Key, &'a Entry) {
        let live = unsafe { live.map(|(view, index)| (view.0.entries(), index)) };
        let (owner, slot) = demand::Entries::project(live);
        let revision = revision::Key::new(Parts::new(owner.index(), slot.revision));
        (Key::new(owner), revision, &slot.value)
    }

    pub(in crate::conn::output::control) fn owner(
        &self,
        parts: Parts<{ owner::MAX }>,
    ) -> Option<&'a Entry> {
        let (cur, slot) = self.0.entries().entry(parts.index())?;
        (cur.parts() == parts).then_some(&slot.value)
    }

    fn bytes(&self) -> usize {
        self.0.bytes()
    }
}
/// Demand-backed dual-identity values and their exclusively owned queue accounting.
pub(in crate::conn) struct Set {
    slots: demand::Table<Slot, control::Tag, { owner::MAX }>,
    topology: journal::Queues,
}

impl Set {
    pub(in crate::conn::output::control) fn new(
        limit: capacity::Capacity<capacity::Control>,
    ) -> Self {
        Self {
            slots: demand::Table::with_limit(Count::new(limit.as_u32())),
            topology: journal::Queues::new(),
        }
    }

    pub(in crate::conn::output::control) fn view(&self) -> View<'_> {
        View(&self.slots)
    }

    pub(in crate::conn::output::control) fn topology(&self) -> &journal::Queues {
        &self.topology
    }

    pub(in crate::conn) fn available(&self) -> Count {
        self.slots.remaining()
    }

    pub(in crate::conn) fn contains<Kind>(&self, owner: Option<owner::Key<Kind>>) -> bool {
        owner.is_some_and(|owner| self.view().owner(owner.inner()).is_some())
    }

    pub(in crate::conn) fn remove<Kind>(&mut self, owner: &mut Option<owner::Key<Kind>>) {
        let Some(owner) = owner.take() else {
            return;
        };
        let Some(slot) = self.owner(owner) else {
            return;
        };
        slot.remove();
    }

    pub(in crate::conn::output::control) fn bytes(&self) -> usize {
        self.view().bytes()
    }

    pub(in crate::conn::output::control) fn try_insert(
        &mut self,
        record: delivery::Control,
    ) -> Result<Occupied<'_, delivery::Control>, control::Admission> {
        Ok(self.try_prepare(record)?.commit())
    }

    fn try_prepare(&mut self, record: delivery::Control) -> Result<Insert<'_>, control::Admission> {
        let records = Count::new(1);
        self.slots
            .try_grow(records)
            .map_err(|reason| control::Admission { records, reason })?
            .commit();
        Ok(Insert { set: self, record })
    }

    pub(in crate::conn::output::control) fn try_queue<Kind>(
        &mut self,
        owner: &mut Option<owner::Key<Kind>>,
        record: delivery::Control,
    ) -> Result<(), control::Admission> {
        let action = match Relation::classify(self, *owner, record) {
            Relation::Current => return Ok(()),
            Relation::Change(action) => action,
        };
        let records = Count::new(action.admission());
        self.slots
            .try_grow(records)
            .map_err(|reason| control::Admission { records, reason })?
            .commit();
        match action {
            Action::Revise { index, next } => {
                // SAFETY: the first classification retains this exact slot and next revision
                // under the unchanged exclusive set and original owner loan.
                let live = unsafe {
                    depot::raw::Proof::<(_, _), Initialized<Kind>>::new(((&mut *self, ()), index))
                };
                let (mut slot, ()) = Self::project(live);
                slot.slot.get_mut().revision = next;
                slot.replace(record);
            }
            Action::Recycle(index) | Action::Retire(index) => {
                // SAFETY: the owned classified action still denotes this set's live member.
                let live = unsafe {
                    depot::raw::Proof::<(_, _), Initialized<Kind>>::new(((&mut *self, ()), index))
                };
                let (slot, ()) = Self::project(live);
                slot.remove();
                *owner = Some(Insert { set: self, record }.commit().owner());
            }
            Action::Insert => *owner = Some(Insert { set: self, record }.commit().owner()),
        }
        Ok(())
    }

    pub(in crate::conn::output::control) fn arm_probes(&mut self, epoch: crate::conn::Epoch) {
        let cycle = epoch.bind_mut(&mut self.topology.flights.probe_round);
        if let Some(next) = cycle.checked_add(1) {
            *cycle = next;
        } else {
            for index in 0..self.slots.initialized().raw() {
                let Some(mut slot) = self.slots.entry_at(index) else {
                    continue;
                };
                if let storage::Status::InFlight {
                    probe_round: round, ..
                } = &mut slot.get_mut().value.status
                {
                    *round = 0;
                }
            }
            *cycle = 1;
        }
        let chain = epoch.bind(&self.topology.flights.in_flight);
        let cursor = epoch.bind_mut(&mut self.topology.flights.probe_cursor);
        let front = keyed::Fifo::first(journal::Front {
            entries: View(&self.slots),
            chain,
        });
        *cursor = front.map(|live| {
            let live = unsafe { live.map(|(front, index)| (front.entries, index)) };
            View::project(live).0
        });
    }

    pub(in crate::conn::output::control) fn owner<Kind>(
        &mut self,
        owner: owner::Key<Kind>,
    ) -> Option<Occupied<'_>> {
        let parts = owner.inner();
        let key = Handle::from_parts(parts);
        match self.slots.entry(key) {
            demand::Entry::Occupied(slot) => Some(Occupied {
                slot,
                queues: &mut self.topology,
            }),
            demand::Entry::Stale(_) => None,
        }
    }

    pub(in crate::conn::output::control) fn revision(
        &mut self,
        rev: revision::Key,
    ) -> Option<Occupied<'_>> {
        let parts = rev.parts();
        let entry = self.slots.entry_at(parts.index())?;
        if entry.get().revision != parts.generation() {
            return None;
        }
        Some(Occupied {
            slot: entry,
            queues: &mut self.topology,
        })
    }

    pub(in crate::conn::output::control) fn project<'a, C, P>(
        live: depot::raw::Proof<((&'a mut Self, C), links::Index), Initialized<P>>,
    ) -> (Occupied<'a, P>, C) {
        let live = unsafe {
            live.map(|((set, context), index)| {
                ((&mut set.slots, (&mut set.topology, context)), index)
            })
        };
        let (slot, (queues, context)) = demand::Occupied::project(live);
        (Occupied { slot, queues }, context)
    }
}

const _: () = {
    assert!(mem::size_of::<Set>() == 232);
    assert!(
        mem::size_of::<Insert<'static>>()
            == mem::size_of::<&Set>() + mem::size_of::<delivery::Control>()
    );
    assert!(mem::size_of::<Occupied<'static>>() == 24);
    assert!(mem::size_of::<Occupied<'static, delivery::Control>>() == 24);
    assert!(mem::size_of::<Revision<Occupied<'static>>>() == 24);
};
