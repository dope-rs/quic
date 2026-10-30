use o3::depot;
use o3::depot::index::Initialized;
use o3::depot::queue::{indexed::keyed, links};
use std::num::NonZero;

use crate::conn;
use crate::conn::machine::storage::demand;
use crate::conn::output::control::journal::{
    self, Lanes,
    storage::{Entry, Key, Native, Revision, Set, Slot, Status, View},
};
use crate::conn::output::{control, delivery};
use control::{owner, revision};
use o3::depot::arena::slab::key::Parts;

pub(super) struct Insert<'a> {
    pub(super) set: &'a mut Set,
    pub(super) record: delivery::Control,
}

// SAFETY: only successful growth constructs Insert, retaining the original set
// and one concrete record. Its context cannot change storage or consume vacancy.
unsafe impl<'a> demand::raw::Owner<{ owner::MAX }> for Insert<'a> {
    type Value = Slot;
    type Tag = control::Tag;
    type Plane = delivery::Control;
    type Output = (&'a mut Set, ());
    type Context<'b>
        = delivery::Control
    where
        Self: 'b;

    fn parts(
        &mut self,
    ) -> (
        &mut demand::Table<Slot, control::Tag, { owner::MAX }>,
        Self::Context<'_>,
    ) {
        (&mut self.set.slots, self.record)
    }

    fn build<'b>(index: links::Index, record: Self::Context<'b>) -> Slot
    where
        Self: 'b,
    {
        Slot::new(index, record)
    }

    fn finish(self) -> Self::Output {
        (self.set, ())
    }
}

/// One occupied journal slot and the queues counted by that same storage owner.
#[must_use]
pub(in crate::conn::output::control) struct Occupied<'a, P = ()> {
    pub(super) slot: Native<'a, P>,
    pub(super) queues: &'a mut journal::Queues,
}

#[repr(transparent)]
pub(in crate::conn::output::control::journal) struct Projected<S>(
    pub depot::raw::Proof<(S, links::Index), Initialized<()>>,
);

fn project<'a, P>(
    live: depot::raw::Proof<(&'a Native<'_, P>, links::Index), Initialized<()>>,
) -> (Key, &'a Entry) {
    let live = unsafe { live.map(|(slot, index)| (slot.as_table().entries(), index)) };
    let (key, slot) = demand::Entries::project(live);
    (Key::new(key), &slot.value)
}

// SAFETY: the proof selects an initialized slot in the retained native store.
unsafe impl<'a, P> depot::raw::KeyBorrow<'a> for Projected<&'a Native<'_, P>> {
    type Key = Key;

    fn parts(self) -> (Key, &'a keyed::Link<Key>) {
        let (key, entry) = project(self.0);
        (key, &entry.hook)
    }
}

// SAFETY: View projects the selected native slot's generation and hook together.
unsafe impl<'a> depot::raw::KeyBorrow<'a> for Projected<View<'a>> {
    type Key = Key;

    fn parts(self) -> (Key, &'a keyed::Link<Key>) {
        let (key, _, entry) = View::project(self.0);
        (key, &entry.hook)
    }
}

struct Move<'a, 'slot, P> {
    slot: &'a mut Native<'slot, P>,
    source: &'a keyed::Fifo<Key>,
    target: &'a keyed::Fifo<Key>,
}

// SAFETY: only transitions of the fused occupied owner construct this route;
// the original native slot and that same owner's queues remain borrowed together.
unsafe impl<P> depot::raw::KeyOwner for Move<'_, '_, P> {
    type Key = Key;
    type Fifo = keyed::Fifo<Key>;

    fn parts(&self) -> (Key, &keyed::Link<Key>) {
        (Key::new(self.slot.key()), &self.slot.get().value.hook)
    }

    fn fifo(&self) -> &keyed::Fifo<Key> {
        self.source
    }

    fn entry<'a>(
        live: depot::raw::Proof<(&'a Self, links::Index), Initialized<()>>,
    ) -> keyed::Entry<'a, Key> {
        let live = unsafe { live.map(|(owner, index)| (&*owner.slot, index)) };
        keyed::Entry::from_source(Projected(live))
    }
}

// SAFETY: routing consumes the same detached slot and its two original queues.
unsafe impl<P> depot::raw::KeyRoute for Move<'_, '_, P> {
    type Target = Self;

    unsafe fn route(self) -> Self {
        Self {
            slot: self.slot,
            source: self.target,
            target: self.source,
        }
    }
}

impl<'a> Insert<'a> {
    pub(super) fn commit(self) -> Occupied<'a, delivery::Control> {
        let live = demand::raw::Owner::insert(self);
        let (mut occupied, ()) = Set::project(live);
        let Occupied { slot, queues } = &mut occupied;
        let lane = control::kind(slot.get().value.record);
        if let Some(lane) = lane {
            let source = lane.bind(&queues.lanes.ready);
            let owner = Move {
                slot,
                source,
                target: source,
            };
            unsafe { keyed::Slot::from_source(depot::raw::Proof::new(owner)) }.push::<false>();
            queues.lanes.ready_bits |= lane.bit();
        }
        change(&mut queues.lanes, None, lane);
        occupied
    }
}

impl<'a, P> Occupied<'a, P> {
    pub(in crate::conn::output::control) fn entry(&self) -> &Entry {
        &self.slot.get().value
    }

    pub(in crate::conn::output::control) fn revision(&self) -> revision::Key {
        let slot = self.slot.get();
        let parts = Parts::new(self.slot.key().index(), slot.revision);
        revision::Key::new(parts)
    }

    pub(in crate::conn::output::control) fn owner<Kind>(&self) -> owner::Key<Kind> {
        owner::Key::new(self.slot.key().parts())
    }

    pub(in crate::conn::output::control) fn revise(mut self) -> Result<Revision<Self>, Self> {
        let Some(epoch) = self.slot.get().revision.checked_add(1) else {
            return Err(self);
        };
        self.slot.get_mut().revision = epoch;
        Ok(Revision(self))
    }

    pub(in crate::conn::output::control::journal) fn replace(&mut self, record: delivery::Control) {
        let Self { slot, queues } = self;
        let old = control::kind(slot.get().value.record);
        let new = control::kind(record);
        match slot.get().value.status {
            Status::InFlight { epoch, .. } => {
                let key = Key::new(slot.key());
                let source = epoch.bind(&queues.flights.in_flight);
                let target = new.map_or(source, |lane| lane.bind(&queues.lanes.ready));
                let member = unsafe {
                    keyed::Slot::from_source(depot::raw::Proof::new(Move {
                        slot,
                        source,
                        target,
                    }))
                };
                let next = member.successor().map(|live| {
                    let live = unsafe { live.map(|(owner, index)| (&*owner.slot, index)) };
                    project(live).0
                });
                if new.is_some() {
                    member.transfer();
                } else {
                    member.remove();
                }
                let cursor = epoch.bind_mut(&mut queues.flights.probe_cursor);
                if *cursor == Some(key) {
                    *cursor = next;
                }
            }
            Status::Queued => match (old, new) {
                (Some(old), Some(new)) if old != new => {
                    let source = old.bind(&queues.lanes.ready);
                    let target = new.bind(&queues.lanes.ready);
                    unsafe {
                        keyed::Slot::from_source(depot::raw::Proof::new(Move {
                            slot,
                            source,
                            target,
                        }))
                    }
                    .transfer();
                }
                (Some(old), None) => {
                    let source = old.bind(&queues.lanes.ready);
                    unsafe {
                        keyed::Slot::from_source(depot::raw::Proof::new(Move {
                            slot,
                            source,
                            target: source,
                        }))
                    }
                    .remove();
                }
                (None, Some(new)) => {
                    let source = new.bind(&queues.lanes.ready);
                    unsafe {
                        keyed::Slot::from_source(depot::raw::Proof::new(Move {
                            slot,
                            source,
                            target: source,
                        }))
                    }
                    .push::<false>();
                }
                (Some(_), Some(_)) | (None, None) => {}
            },
        }
        if let Some(old) = old
            && old.bind(&queues.lanes.ready).is_empty()
        {
            queues.lanes.ready_bits &= !old.bit();
        }
        if let Some(new) = new {
            queues.lanes.ready_bits |= new.bit();
        }
        change(&mut queues.lanes, old, new);
        let entry = &mut slot.get_mut().value;
        entry.record = record;
        entry.status = Status::Queued;
    }

    pub(in crate::conn::output::control) fn remove(self) -> delivery::Control {
        let Self { mut slot, queues } = self;
        let lane = control::kind(slot.get().value.record);
        match slot.get().value.status {
            Status::Queued => {
                if let Some(lane) = lane {
                    let source = lane.bind(&queues.lanes.ready);
                    unsafe {
                        keyed::Slot::from_source(depot::raw::Proof::new(Move {
                            slot: &mut slot,
                            source,
                            target: source,
                        }))
                    }
                    .remove();
                    if source.is_empty() {
                        queues.lanes.ready_bits &= !lane.bit();
                    }
                }
            }
            Status::InFlight { epoch, .. } => {
                let key = Key::new(slot.key());
                let source = epoch.bind(&queues.flights.in_flight);
                let member = unsafe {
                    keyed::Slot::from_source(depot::raw::Proof::new(Move {
                        slot: &mut slot,
                        source,
                        target: source,
                    }))
                };
                let next = member.successor().map(|live| {
                    let live = unsafe { live.map(|(owner, index)| (&*owner.slot, index)) };
                    project(live).0
                });
                member.remove();
                let cursor = epoch.bind_mut(&mut queues.flights.probe_cursor);
                if *cursor == Some(key) {
                    *cursor = next;
                }
            }
        }
        change(&mut queues.lanes, lane, None);
        slot.remove().value.record
    }

    /// Moves one queued hook to its epoch's in-flight chain.
    pub(in crate::conn::output::control::journal) fn dispatch(&mut self, epoch: conn::Epoch) {
        let Self { slot, queues } = self;
        let record = slot.get().value.record;
        let target = epoch.bind(&queues.flights.in_flight);
        if let Some(lane) = control::kind(record) {
            let bit = lane.bit();
            let source = lane.bind(&queues.lanes.ready);
            let owner = Move {
                slot,
                source,
                target,
            };
            unsafe { keyed::Slot::from_source(depot::raw::Proof::new(owner)) }.transfer();
            if source.is_empty() {
                queues.lanes.ready_bits &= !bit;
            }
        } else {
            let owner = Move {
                slot,
                source: target,
                target,
            };
            unsafe { keyed::Slot::from_source(depot::raw::Proof::new(owner)) }.push::<false>();
        }
        slot.get_mut().value.status = Status::InFlight {
            epoch,
            carriers: NonZero::<u16>::MIN,
            probe_round: queues.flights.probe_round(epoch),
        };
    }

    pub(in crate::conn::output::control::journal) fn probe(
        self,
        epoch: conn::Epoch,
        carriers: NonZero<u16>,
        round: u32,
    ) {
        let Self { mut slot, queues } = self;
        let source = epoch.bind(&queues.flights.in_flight);
        let member = unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(Move {
                slot: &mut slot,
                source,
                target: source,
            }))
        };
        let next = member.successor().map(|live| {
            let live = unsafe { live.map(|(owner, index)| (&*owner.slot, index)) };
            project(live).0
        });
        slot.get_mut().value.status = Status::InFlight {
            epoch,
            carriers,
            probe_round: round,
        };
        *epoch.bind_mut(&mut queues.flights.probe_cursor) = next;
    }

    pub(in crate::conn::output::control) fn lose(mut self) {
        let entry = self.entry();
        let record = entry.record;
        let Status::InFlight {
            epoch,
            carriers: count,
            probe_round: round,
        } = entry.status
        else {
            return;
        };
        if matches!(
            record,
            delivery::Control::PathValidation(_) | delivery::Control::PathResponse(_)
        ) {
            self.remove();
            return;
        }
        if let Some(carriers) = NonZero::new(count.get() - 1) {
            self.slot.get_mut().value.status = Status::InFlight {
                epoch,
                carriers,
                probe_round: round,
            };
            return;
        }
        self.retry(epoch);
        self.slot.get_mut().value.status = Status::Queued;
    }

    /// Moves one final lost carrier back to its ready-kind chain.
    fn retry(&mut self, epoch: conn::Epoch) {
        let Self { slot, queues } = self;
        let record = slot.get().value.record;
        let key = Key::new(slot.key());
        let source = epoch.bind(&queues.flights.in_flight);
        let lane = control::kind(record);
        let target = lane.map_or(source, |lane| lane.bind(&queues.lanes.ready));
        let owner = Move {
            slot,
            source,
            target,
        };
        let member = unsafe { keyed::Slot::from_source(depot::raw::Proof::new(owner)) };
        let next = member.successor().map(|live| {
            let live = unsafe { live.map(|(owner, index)| (&*owner.slot, index)) };
            project(live).0
        });
        match lane {
            Some(lane) => {
                member.transfer();
                queues.lanes.ready_bits |= lane.bit();
            }
            None => {
                member.remove();
            }
        }
        let cursor = epoch.bind_mut(&mut queues.flights.probe_cursor);
        if *cursor == Some(key) {
            *cursor = next;
        }
    }
}

/// Insert publishes a fresh slot; replace and remove retain a counted slot.
/// Exclusive ownership keeps each lane change paired with that same slot.
/// Counts stay within the admitted table's u16::MAX live slots.
fn change(lanes: &mut Lanes, old: Option<control::Lane>, new: Option<control::Lane>) {
    if old == new {
        return;
    }
    if let Some(lane) = old {
        let count = lane.bind(&lanes.kind_counts) - 1;
        *lane.bind_mut(&mut lanes.kind_counts) = count;
        if count == 0 {
            lanes.bits &= !lane.bit();
        }
    }
    if let Some(lane) = new {
        let count = lane.bind(&lanes.kind_counts) + 1;
        *lane.bind_mut(&mut lanes.kind_counts) = count;
        lanes.bits |= lane.bit();
    }
}

const _: () = {
    assert!(std::mem::size_of::<Move<'static, 'static, ()>>() == 3 * std::mem::size_of::<usize>());
    assert!(
        std::mem::size_of::<Option<Move<'static, 'static, ()>>>()
            == 3 * std::mem::size_of::<usize>()
    );
};
