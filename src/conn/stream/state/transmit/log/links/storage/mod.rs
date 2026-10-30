use crate::conn::Selected;
use crate::conn::stream::state::transmit::log::links::topology::Record;
use crate::conn::{
    machine::storage::{self, demand},
    stream::state::transmit::log::{journal, planes},
};
use o3::depot;
use o3::depot::index::Access;
use o3::depot::queue::links::Index;
use o3::depot::{capacity::Reason, queue::indexed::keyed};
pub(in crate::conn::stream::state::transmit::log) use scan::Scan;

mod scan;

pub(in crate::conn::stream::state::transmit::log) enum Account {
    Active,
    Retired,
}

#[repr(transparent)]
pub(in crate::conn::stream::state::transmit::log) struct Records<'a> {
    journal: &'a mut journal::Journal,
}

impl<'a> Records<'a> {
    pub(in crate::conn::stream::state::transmit::log) fn new(
        journal: &'a mut journal::Journal,
    ) -> Self {
        Self { journal }
    }
}

impl Records<'_> {
    pub(in crate::conn::stream::state::transmit::log) fn try_reap(
        &mut self,
        count: usize,
    ) -> Result<(), Reason> {
        while self.journal.storage.groups.remaining().get() < count {
            let first = Record::reclaim(self.journal).ok_or(Reason::Full)?;
            let mut next = first.next(Account::Retired);
            while let Some(record) = next {
                next = record.next(Account::Retired);
            }
        }
        Ok(())
    }

    pub(in crate::conn::stream::state::transmit::log) fn try_prune(
        &mut self,
        count: usize,
    ) -> Result<(), Reason> {
        while self.journal.storage.nodes.remaining().get() < count {
            Record::reclaim(self.journal)
                .ok_or(Reason::Full)?
                .discard(Account::Retired);
        }
        Ok(())
    }
}

pub(in crate::conn::stream::state::transmit::log) struct Walk<'a, P: planes::Plane> {
    pub(in crate::conn::stream::state::transmit::log) entries:
        demand::Entries<'a, P::Value, P::Tag>,
    pub(in crate::conn::stream::state::transmit::log) queue:
        &'a keyed::Fifo<storage::Key<P::Tag>, P>,
}

struct Member<'a, P: planes::Plane> {
    walk: Walk<'a, P>,
    index: Index,
}

#[repr(transparent)]
pub(in crate::conn::stream::state::transmit::log) struct Projected<'a, P: planes::Plane>(
    pub(super) Selected<demand::Entries<'a, P::Value, P::Tag>, Index, P>,
);

// SAFETY: the consumed live source retains the exact table, key, and link plane.
unsafe impl<'a, P: planes::Plane> depot::raw::KeyBorrow<'a, P> for Projected<'a, P> {
    type Key = storage::Key<P::Tag>;

    fn parts(self) -> (Self::Key, &'a keyed::Link<Self::Key, P>) {
        let (key, value) = demand::Entries::project(self.0);
        (storage::Key::new(key), P::link(value))
    }
}

#[repr(transparent)]
pub(in crate::conn::stream::state::transmit::log) struct Borrowed<'b, 'a, P: planes::Plane, Q>(
    pub(super) &'b demand::Occupied<'a, P::Value, P::Tag, { u32::MAX }, Q>,
);

// SAFETY: the native occupied guard keeps its exact key and initialized value stable.
unsafe impl<'b, P: planes::Plane, Q> depot::raw::KeyBorrow<'b, P> for Borrowed<'b, '_, P, Q> {
    type Key = storage::Key<P::Tag>;

    fn parts(self) -> (Self::Key, &'b keyed::Link<Self::Key, P>) {
        (storage::Key::new(self.0.key()), P::link(self.0.get()))
    }
}

// SAFETY: binding checked this slot and link plane in the retained table.
unsafe impl<P: planes::Plane> depot::raw::Source<P> for Member<'_, P> {
    type Key = Index;
    fn key(&self) -> Self::Key {
        self.index
    }
}

impl<'a, P: planes::Plane> Walk<'a, P> {
    pub(in crate::conn::stream::state::transmit::log) fn bind(
        self,
        key: storage::Key<P::Tag>,
    ) -> Option<Selected<Self, Index, P>> {
        let value = self.entries.get(key.handle())?;
        if !P::link(value).is_linked(key) {
            return None;
        }
        let member = Member {
            walk: self,
            index: unsafe { depot::raw::Word::from_offset(key.index() as usize) },
        };
        let live = Access::into_live(member);
        Some(unsafe { live.map(|(member, index)| (member.walk, index)) })
    }

    pub(in crate::conn::stream::state::transmit::log) fn get(
        live: Selected<&Self, Index, P>,
    ) -> (storage::Key<P::Tag>, &'a P::Value) {
        let live = unsafe { live.map(|(walk, index)| (walk.entries, index)) };
        let (key, value) = demand::Entries::project(live);
        (storage::Key::new(key), value)
    }
}

// SAFETY: each journal walk borrows a queue with its original table. Its shared
// borrow prevents membership changes and removal until the last projection.
unsafe impl<P: planes::Plane> depot::raw::KeySource<P> for Walk<'_, P> {
    type Key = storage::Key<P::Tag>;

    fn fifo(&self) -> &keyed::Fifo<Self::Key, P> {
        self.queue
    }
}

unsafe impl<P: planes::Plane> depot::raw::KeyRead<P> for Walk<'_, P> {
    fn entry<'a>(live: Selected<&'a Self, Index, P>) -> keyed::Entry<'a, Self::Key, P> {
        let live = unsafe { live.map(|(walk, index)| (walk.entries, index)) };
        keyed::Entry::from_source(Projected(live))
    }
}

const _: () = assert!(std::mem::size_of::<Walk<'static, planes::All>>() == 16);
