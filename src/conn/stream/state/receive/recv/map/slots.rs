use crate::conn::stream::resident::slot::{plane, store};
use crate::conn::stream::state::receive::recv::{
    self,
    map::{self, Id, Occupied, Side, Slot, Vacant},
};
use crate::conn::stream::state::resident::Table;
use crate::conn::stream::{event::queue::readable, resident};
use crate::stream::Recv;
use o3::depot;

pub(in crate::conn) struct Slots<'map, B: Recv> {
    pub(super) core:
        &'map mut store::Pool<Side, recv::Entry<B>, Option<readable::Handle>, plane::HeadOnly>,
    pub(super) arena: &'map depot::raw::Arena<map::Node<B>, map::Tag>,
}

impl<B: Recv> Slots<'_, B> {
    pub(in crate::conn) fn available(&self) -> usize {
        self.core.available()
    }

    pub(in crate::conn) fn entry(&mut self, id: Id, registry: &Table) -> Slot<'_, B> {
        if let Some((_, slot)) = registry.read().find::<false>(id.0.id()) {
            return self.core.bind_at(slot).map_or(Slot::Unavailable, |entry| {
                Slot::Occupied(Occupied {
                    entry,
                    arena: self.arena,
                })
            });
        }
        self.raw_entry(id)
    }

    pub(in crate::conn) fn try_prepared(
        &mut self,
        local: resident::Local,
        table: &Table,
    ) -> Result<Slot<'_, B>, resident::Stale> {
        let Some(slot) = table.read().try_slot(local)? else {
            return Ok(self.raw_entry(Id::new(local.id())));
        };
        Ok(self.core.bind_at(slot).map_or(Slot::Unavailable, |entry| {
            Slot::Occupied(Occupied {
                entry,
                arena: self.arena,
            })
        }))
    }

    pub(in crate::conn) fn prepared(
        &mut self,
        id: Id,
        key: Option<resident::Key>,
        registry: &Table,
    ) -> Slot<'_, B> {
        let Some(key) = key else {
            return self.raw_entry(id);
        };
        let local = resident::Local::new(id.0.id(), key);
        let Some(slot) = registry.read().recv_exact(local) else {
            return self.raw_entry(id);
        };
        self.core.bind_at(slot).map_or(Slot::Unavailable, |entry| {
            Slot::Occupied(Occupied {
                entry,
                arena: self.arena,
            })
        })
    }

    fn raw_entry(&mut self, id: Id) -> Slot<'_, B> {
        Slot::Vacant(Vacant {
            entry: self.core.vacant(id.0),
            arena: self.arena,
        })
    }
}
