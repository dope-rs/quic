use o3::{
    alloc,
    depot::map::resident::{self, Id},
};

use crate::conn::stream::{
    Count,
    resident::{Key, Local, MAX_GENERATION, Stale},
    state,
};

use state::resident::{bindings, events, hash::Hash, node::Node, read, scopes, sides};

#[derive(Clone, Copy)]
pub(in crate::conn) struct Capacity {
    plan: resident::Plan,
}

impl Capacity {
    pub(in crate::conn) const fn new(counts: [Count; 4]) -> Self {
        Self {
            plan: resident::Plan::counts([
                counts[0].bounded(),
                counts[1].bounded(),
                counts[2].bounded(),
                counts[3].bounded(),
            ]),
        }
    }
}

pub(in crate::conn) struct Table {
    pub(super) core: resident::Table<Node, Hash, MAX_GENERATION>,
}

impl Table {
    pub(in crate::conn) fn try_new(capacity: Capacity) -> Result<Self, alloc::Error> {
        Ok(Self {
            core: resident::Table::try_new(capacity.plan, Hash)?,
        })
    }

    pub(in crate::conn) fn scope<R>(
        &mut self,
        run: impl for<'id> FnOnce(scopes::Scope<'_, 'id>) -> R,
    ) -> R {
        self.core.scope(|scope| run(scopes::Scope::new(scope)))
    }

    pub(in crate::conn) const fn read(&self) -> read::Read<'_> {
        read::Read::new(self)
    }

    pub(in crate::conn) fn side<const SEND: bool>(&mut self) -> sides::State<'_, SEND> {
        sides::State::new(self)
    }

    pub(in crate::conn) fn event<const SEND: bool>(&mut self) -> events::State<'_, SEND> {
        events::State::new(self)
    }

    pub(in crate::conn) fn binding(&mut self) -> bindings::State<'_> {
        bindings::State::new(self)
    }

    pub(super) fn exact(
        &mut self,
        local: Local,
    ) -> Result<resident::Occupied<'_, Node, Hash, MAX_GENERATION>, Stale> {
        self.core
            .exact(local.key().0, Id::mask(local.id().get()))
            .map_err(|owner| Stale::new(local, owner.key(Id::mask(local.id().get())).map(Key)))
    }
}

pub(super) fn retire_idle(entry: resident::Occupied<'_, Node, Hash, MAX_GENERATION>) {
    if !entry.get().is_live() {
        entry.remove();
    }
}

const _: () = assert!(std::mem::size_of::<Key>() == std::mem::size_of::<u64>());
