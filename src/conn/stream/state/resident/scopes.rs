use crate::{
    conn::stream::{
        resident::{self, MAX_GENERATION, slot},
        state,
    },
    wire::stream,
};
use o3::depot::{
    map,
    map::resident::{Id, scoped},
};
use state::resident::{
    events,
    hash::Hash,
    node::{self, Node},
    table,
};
use std::mem;

pub(in crate::conn) struct Scope<'a, 'id> {
    core: scoped::Scope<'a, 'id, Node, Hash, MAX_GENERATION>,
}

pub(in crate::conn) struct Committed<'a, 'id>(Scope<'a, 'id>);

pub(in crate::conn) struct Lease<'id> {
    lease: scoped::Lease<'id, MAX_GENERATION>,
    id: stream::Id,
}

pub(in crate::conn) struct Vacant<'a, 'id> {
    entry: scoped::Occupied<'a, 'id, Node, Hash, MAX_GENERATION>,
}

pub(in crate::conn) struct Fresh<'id> {
    lease: Lease<'id>,
    fresh: Option<scoped::Fresh<'id, MAX_GENERATION>>,
}

pub(in crate::conn) struct Canceled<'a, 'id> {
    core: scoped::Retirement<'a, 'id, Node, Hash, MAX_GENERATION>,
}

pub(in crate::conn) enum Entry<'a, 'id> {
    Occupied { lease: Lease<'id>, slot: u32 },
    Vacant(Vacant<'a, 'id>),
    Unavailable,
}

impl<'a, 'id> Scope<'a, 'id> {
    pub(super) fn new(core: scoped::Scope<'a, 'id, Node, Hash, MAX_GENERATION>) -> Self {
        Self { core }
    }

    pub(in crate::conn) fn claim(
        &mut self,
        key: Option<resident::Key>,
        id: stream::Id,
    ) -> Result<Entry<'_, 'id>, resident::Stale> {
        let wire = Id::mask(id.get());
        let mut entry = match key {
            Some(key) => self.core.exact(key.0, wire).map_err(|owner| {
                resident::Stale::new(
                    resident::Local::new(id, key),
                    owner.key(wire).map(resident::Key),
                )
            })?,
            None => match self.core.entry(wire) {
                map::Entry::Occupied(entry) => entry,
                map::Entry::Vacant(Some(entry)) => entry.insert(Node::new()),
                map::Entry::Vacant(None) => return Ok(Entry::Unavailable),
            },
        };
        let word = &mut entry.get_mut().receive;
        Ok(match *word & node::SLOT_MASK {
            node::SLOT_NONE => {
                *word = *word & node::EVENT | node::SLOT_CLAIMED;
                Entry::Vacant(Vacant { entry })
            }
            node::SLOT_CLAIMED => Entry::Unavailable,
            slot => {
                let (lease, _) = entry.publish();
                Entry::Occupied {
                    lease: Lease { lease, id },
                    slot,
                }
            }
        })
    }

    pub(in crate::conn) fn clear(&mut self, fresh: &Fresh<'id>) {
        let word = &mut self.core.get_mut(&fresh.lease.lease).receive;
        *word = *word & node::EVENT | node::SLOT_NONE;
    }

    pub(in crate::conn) fn cancel(self) -> Canceled<'a, 'id> {
        Canceled {
            core: self.core.retire(),
        }
    }

    pub(in crate::conn) fn commit(self) -> Committed<'a, 'id> {
        Committed(self)
    }
}

impl<'id> Committed<'_, 'id> {
    pub(in crate::conn) fn hold(&mut self, lease: &Lease<'id>) -> events::Hold {
        let word = &mut self.0.core.get_mut(&lease.lease).receive;
        if *word & node::EVENT != 0 {
            events::Hold::Pending
        } else {
            *word |= node::EVENT;
            events::Hold::Added
        }
    }

    pub(in crate::conn) fn refund(&mut self, lease: &Lease<'id>) {
        self.0.core.get_mut(&lease.lease).receive &= !node::EVENT;
    }
}

impl<'id> Vacant<'_, 'id> {
    pub(in crate::conn) fn bind<S>(mut self, handle: slot::Handle<S>) -> Fresh<'id> {
        let word = &mut self.entry.get_mut().receive;
        *word = *word & node::EVENT | handle.index();
        let id = stream::Id::from_bounded(self.entry.id());
        let (lease, fresh) = self.entry.publish();
        Fresh {
            lease: Lease { lease, id },
            fresh,
        }
    }

    pub(in crate::conn) fn release(mut self) {
        let word = &mut self.entry.get_mut().receive;
        *word = *word & node::EVENT | node::SLOT_NONE;
        self.entry.release();
    }
}

impl Lease<'_> {
    pub(in crate::conn) fn local(&self) -> resident::Local {
        resident::Local::new(self.id, resident::Key(self.lease.key()))
    }
}

impl<'id> Fresh<'id> {
    pub(in crate::conn) fn commit(self) -> Lease<'id> {
        self.lease
    }
}

impl<'id> Canceled<'_, 'id> {
    pub(in crate::conn) fn remove(&mut self, fresh: Fresh<'id>) {
        if let Some(fresh) = fresh.fresh {
            table::retire_idle(self.core.occupied(fresh));
        }
    }
}

const _: () = {
    assert!(mem::size_of::<Scope<'static, 'static>>() == mem::size_of::<usize>());
    assert!(mem::size_of::<Lease<'static>>() <= 3 * mem::size_of::<usize>());
    assert!(mem::size_of::<Fresh<'static>>() <= 3 * mem::size_of::<usize>());
};
