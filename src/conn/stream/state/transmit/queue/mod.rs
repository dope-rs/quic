//! Connection-owned stream send queue.

use o3::depot::index::Initialized;

use crate::{
    conn::{
        self,
        life::options,
        output::control,
        stream::{
            self, resident,
            state::{
                resident::{Table, sides},
                streams,
                transmit::{log::journal, queue},
            },
        },
    },
    stream::outbound::{self, chunk},
    wire::varint,
};
pub(in crate::conn) use credit::Credit;
pub(in crate::conn) use entry::Entry;
pub(in crate::conn) use error::Error;
use o3::depot;
use o3::depot::capacity::Extent as _;
use o3::{
    buffer::{self, storage},
    depot::queue::pool,
};
use resident::slot::{self, plane, store};
use std::mem;
use store::Pool;

mod budget;
mod credit;
mod entry;
mod error;
mod occupied;
mod view;
pub(in crate::conn) use occupied::Occupied;
pub(crate) use occupied::{Publication, Reclaim};
pub(in crate::conn) use view::View;
pub(in crate::conn) mod plan;
pub(in crate::conn) mod recycle;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Phase {
    Open,
    Marked,
    Sent,
    Acked,
    Reset,
}

pub(in crate::conn) struct StopImpact {
    pub(in crate::conn) key: Option<resident::Key>,
    pub(in crate::conn) active: bool,
    pub(in crate::conn) event_slots: usize,
    pub(in crate::conn) stream_slots: usize,
}

impl StopImpact {
    pub(super) const NONE: Self = Self {
        key: None,
        active: false,
        event_slots: 0,
        stream_slots: 0,
    };
}

/// Send-map identity domain.
struct Side;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(in crate::conn) struct Id(slot::Id<Side>);

impl Id {
    pub(in crate::conn) fn new(id: stream::Id) -> Self {
        Self(slot::Id::new(id))
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) struct Handle(slot::Handle<Side>);

impl Handle {
    fn index(self) -> usize {
        self.0.index() as usize
    }

    fn from_storage(handle: slot::Handle<Side>) -> Self {
        Self(handle)
    }
}

pub(in crate::conn) struct Map<D: buffer::raw::Segment> {
    core: Pool<Side, queue::Entry, (), plane::RoundRobin<Side>>,
    data: Data<D>,
}

#[repr(C)]
struct Data<D: buffer::raw::Segment> {
    lanes: pool::Lanes<chunk::Node<D>>,
    pending: usize,
    buffers: outbound::BufferCache,
    budget: budget::Budget,
}

pub(in crate::conn) enum Preparation {
    Create,
    Live,
}

impl Preparation {
    pub(in crate::conn) fn new(stream: streams::Relative) -> Self {
        if stream.is_local() {
            Self::Live
        } else {
            Self::Create
        }
    }
}

#[must_use = "send removal must distinguish an absent resident"]
pub(in crate::conn) enum Removal {
    Absent,
    Removed,
}

impl<D: buffer::raw::Segment> Map<D> {
    pub(in crate::conn) fn try_new(
        limits: &options::Limits,
        capacity: slot::Capacity,
    ) -> Result<Self, queue::Error> {
        let plan = pool::Plan::new(limits.send_parts().get(), capacity.get())
            .map_err(queue::Error::Plan)?;
        let lanes = pool::Lanes::try_new(plan).map_err(queue::Error::Alloc)?;
        Ok(Self {
            core: Pool::try_new(capacity).map_err(queue::Error::Alloc)?,
            data: Data {
                lanes,
                pending: 0,
                buffers: outbound::BufferCache::new(),
                budget: budget::Budget::new(
                    limits.send_bytes(),
                    limits.resident(),
                    limits.send_parts(),
                ),
            },
        })
    }

    pub(in crate::conn) fn find(
        &self,
        id: stream::Id,
        registry: &Table,
    ) -> Option<queue::Resolved<'_>> {
        let (_, slot) = registry.read().find::<true>(id)?;
        self.core.current(slot).map(Resolved)
    }

    pub(in crate::conn) fn find_key(
        &self,
        key: resident::Key,
        registry: &Table,
    ) -> Option<queue::Resolved<'_>> {
        let slot = registry.read().slot::<true>(key)?;
        self.core.current(slot).map(Resolved)
    }

    pub(in crate::conn::stream::state::transmit) fn try_prepared<'a, R>(
        &'a mut self,
        id: Id,
        key: Option<resident::Key>,
        credit: varint::VarInt,
        mode: Preparation,
        table: &mut Table,
        finish: impl FnOnce(resident::Key, Occupied<'a, D>) -> R,
    ) -> Result<Option<R>, stream::Error> {
        let side = match key {
            Some(key) => match table
                .side::<true>()
                .try_exact(resident::Local::new(id.0.id(), key))
            {
                Ok(side) => side,
                Err(_) => return Ok(None),
            },
            None => table.side::<true>().claim(id.0.id()),
        };
        match side {
            sides::Entry::Occupied(resident) => {
                let key = resident.key();
                let entry = self
                    .core
                    .bind_at(resident.slot())
                    .ok_or(stream::Error::Capacity)?;
                Ok(Some(finish(
                    key,
                    Occupied {
                        entry,
                        data: &mut self.data,
                    },
                )))
            }
            sides::Entry::Vacant(vacant) if matches!(mode, Preparation::Create) => {
                self.try_insert(vacant, id, credit, finish).map(Some)
            }
            sides::Entry::Vacant(vacant) => {
                vacant.release();
                Ok(None)
            }
            sides::Entry::Unavailable if matches!(mode, Preparation::Live) => Ok(None),
            sides::Entry::Unavailable => Err(stream::Error::Capacity),
        }
    }

    pub(in crate::conn::stream::state::transmit) fn try_live(
        &mut self,
        local: resident::Local,
        credit: varint::VarInt,
        mode: Preparation,
        table: &mut Table,
    ) -> Result<Option<Occupied<'_, D>>, resident::Error> {
        match table
            .side::<true>()
            .try_exact(local)
            .map_err(resident::Error::Stale)?
        {
            sides::Entry::Occupied(resident) => {
                let entry = self
                    .core
                    .bind_at(resident.slot())
                    .ok_or(resident::Error::Stream(stream::Error::Capacity))?;
                Ok(Some(Occupied {
                    entry,
                    data: &mut self.data,
                }))
            }
            sides::Entry::Vacant(vacant) if matches!(mode, Preparation::Create) => self
                .try_insert(vacant, Id::new(local.id()), credit, |_, slot| Some(slot))
                .map_err(resident::Error::Stream),
            sides::Entry::Vacant(vacant) => {
                vacant.release();
                Ok(None)
            }
            sides::Entry::Unavailable => Err(resident::Error::Stream(stream::Error::Capacity)),
        }
    }

    fn try_insert<'a, R>(
        &'a mut self,
        vacant: sides::Vacant<'_, true>,
        id: Id,
        credit: varint::VarInt,
        finish: impl FnOnce(resident::Key, Occupied<'a, D>) -> R,
    ) -> Result<R, stream::Error> {
        let Some(entry) = self.core.vacant(id.0).insert(credit) else {
            vacant.release();
            return Err(stream::Error::Capacity);
        };
        let key = vacant.key();
        vacant.bind(entry.handle());
        Ok(finish(
            key,
            Occupied {
                entry,
                data: &mut self.data,
            },
        ))
    }

    pub(in crate::conn::stream::state::transmit) fn bind(
        &mut self,
        id: stream::Id,
        registry: &Table,
    ) -> Option<(resident::Key, Occupied<'_, D>)> {
        let (key, slot) = registry.read().find::<true>(id)?;
        let entry = self.core.bind_at(slot)?;
        if entry.id() != id {
            return None;
        }
        Some((
            key,
            Occupied {
                entry,
                data: &mut self.data,
            },
        ))
    }

    pub(in crate::conn) fn read(
        &self,
        handle: Handle,
    ) -> Option<(Resolved<'_>, pool::View<'_, chunk::Node<D>>)> {
        use o3::depot;

        let entry = self.core.resolve(handle.0)?;
        // SAFETY: this owner allocates both domains together and never replaces either.
        // The successful lookup retains the generation until this shared borrow ends.
        let lane = unsafe { depot::raw::Proof::new((&self.data.lanes, handle.index())) }.into();
        Some((Resolved(entry), lane))
    }

    pub(in crate::conn::stream::state::transmit) fn occupied(
        &mut self,
        handle: Handle,
    ) -> Option<Occupied<'_, D>> {
        self.core.occupied(handle.0).map(|entry| Occupied {
            entry,
            data: &mut self.data,
        })
    }

    pub(in crate::conn::stream::state::transmit) fn publish(debit: journal::Debit<'_, D>) {
        let (map, next) = debit.into_parts();
        map.data.pending = next;
    }

    pub(in crate::conn) fn view(&self) -> View<'_, D> {
        View::new(self)
    }

    pub(in crate::conn) fn iter_ready(&self) -> impl Iterator<Item = queue::Resolved<'_>> {
        self.core.iter().map(Resolved)
    }

    /// Visits each live owner in reverse slot order without allocating scratch.
    pub(in crate::conn::stream::state::transmit) fn try_for_each<E>(
        &mut self,
        mut visit: impl FnMut(Occupied<'_, D>) -> Result<(), E>,
    ) -> Result<(), E> {
        for index in (0..self.core.slot_count()).rev() {
            let Some(entry) = self.core.bind_at(index) else {
                continue;
            };
            visit(Occupied {
                entry,
                data: &mut self.data,
            })?;
        }
        Ok(())
    }

    pub(in crate::conn::stream::state::transmit) fn snapshot(
        &mut self,
        out: &mut Vec<Handle>,
        control: &mut control::Pending,
        mut quota: usize,
        admit: impl Fn(stream::Id) -> bool,
    ) -> Result<(), control::Admission> {
        out.clear();
        let work = self.core.length().min(conn::STREAM_SCHEDULE_WORK_LIMIT);
        for _ in 0..work {
            let Some(mut active) = self.core.active() else {
                break;
            };
            let id = active.id();
            if !admit(id) {
                active.advance();
                continue;
            }
            match active.get_mut().deferred() {
                Some((reset, size)) if quota != 0 => {
                    reset.try_queue(control, id, size)?;
                    active.advance();
                    active.deactivate();
                    quota -= 1;
                }
                Some(_) => active.advance(),
                None => {
                    active.advance();
                    out.push(Handle::from_storage(active.handle()));
                }
            }
        }
        Ok(())
    }
}

pub(in crate::conn) struct Resolved<'map>(slot::Resolved<'map, Side, queue::Entry, ()>);

impl Resolved<'_> {
    pub(in crate::conn) fn id(&self) -> stream::Id {
        self.0.id()
    }

    pub(in crate::conn) fn state(&self) -> &queue::Entry {
        self.0.value()
    }
}

// SAFETY: Live retains the original composite owner, generation and operation;
// both disjoint field loans remain in the resulting occupied capability.
unsafe impl<'a, D: buffer::raw::Segment, P> depot::raw::Project<Handle, P> for &'a mut Map<D> {
    type Output = Occupied<'a, D, P>;

    unsafe fn project(self, handle: Handle) -> Self::Output {
        use o3::depot;

        let entry =
            unsafe { depot::raw::Proof::<(_, _), Initialized<P>>::new((&mut self.core, handle.0)) }
                .into();
        Occupied {
            entry,
            data: &mut self.data,
        }
    }
}

const _: () = {
    assert!(mem::size_of::<Occupied<'static, storage::Shared>>() == 4 * mem::size_of::<usize>());
    assert!(mem::size_of::<Id>() == mem::size_of::<u64>());
    assert!(!mem::needs_drop::<Id>());
    assert!(mem::size_of::<Handle>() == mem::size_of::<u64>());
    assert!(mem::size_of::<Option<Handle>>() == mem::size_of::<u64>());
    assert!(!mem::needs_drop::<Handle>());
    assert!(mem::size_of::<Removal>() == 1);
    assert!(!mem::needs_drop::<Removal>());
};
const _: () = assert!(
    mem::size_of::<Map<storage::Shared>>()
        == mem::size_of::<Pool<Side, queue::Entry, (), plane::RoundRobin<Side>>>()
            + mem::size_of::<Data<storage::Shared>>()
);
