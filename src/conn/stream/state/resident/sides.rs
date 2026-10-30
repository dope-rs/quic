use crate::{
    conn::stream::{
        resident::{Key, Local, MAX_GENERATION, Stale, slot},
        state,
    },
    wire::stream,
};
use o3::depot::map::{
    self,
    resident::{self, Id},
};
use state::resident::{
    hash::Hash,
    node::{self, Node},
    table,
};

pub(in crate::conn) enum Entry<'a, const SEND: bool> {
    Occupied(Occupied),
    Vacant(Vacant<'a, SEND>),
    Unavailable,
}

pub(in crate::conn) struct Removed;

#[derive(Clone, Copy)]
pub(in crate::conn) struct Occupied {
    key: Key,
    slot: u32,
}

impl Occupied {
    pub(in crate::conn) const fn key(self) -> Key {
        self.key
    }

    pub(in crate::conn) const fn slot(self) -> u32 {
        self.slot
    }
}

pub(in crate::conn) struct Vacant<'a, const SEND: bool> {
    entry: resident::Occupied<'a, Node, Hash, MAX_GENERATION>,
}

impl<const SEND: bool> Vacant<'_, SEND> {
    pub(in crate::conn) fn key(&self) -> Key {
        Key(self.entry.key())
    }

    pub(in crate::conn) fn bind<S>(mut self, slot: slot::Handle<S>) {
        let word = self.entry.get_mut().word_mut::<SEND>();
        *word = *word & node::EVENT | slot.index();
    }

    pub(in crate::conn) fn release(mut self) {
        let word = self.entry.get_mut().word_mut::<SEND>();
        *word = *word & node::EVENT | node::SLOT_NONE;
        table::retire_idle(self.entry);
    }
}

#[repr(transparent)]
pub(in crate::conn) struct State<'a, const SEND: bool> {
    table: &'a mut table::Table,
}

impl<'a, const SEND: bool> State<'a, SEND> {
    pub(in crate::conn::stream::state::resident) fn new(table: &'a mut table::Table) -> Self {
        Self { table }
    }

    pub(in crate::conn) fn try_exact(self, local: Local) -> Result<Entry<'a, SEND>, Stale> {
        Ok(Self::claim_node(self.table.exact(local)?))
    }

    pub(in crate::conn) fn claim(self, id: stream::Id) -> Entry<'a, SEND> {
        let entry = match self.table.core.entry(Id::mask(id.get())) {
            map::Entry::Occupied(entry) => entry,
            map::Entry::Vacant(Some(entry)) => entry.insert(node::Node::new()),
            map::Entry::Vacant(None) => return Entry::Unavailable,
        };
        Self::claim_node(entry)
    }

    fn claim_node(
        mut entry: resident::Occupied<'a, Node, Hash, MAX_GENERATION>,
    ) -> Entry<'a, SEND> {
        let word = entry.get_mut().word_mut::<SEND>();
        match *word & node::SLOT_MASK {
            node::SLOT_NONE => {
                *word = *word & node::EVENT | node::SLOT_CLAIMED;
                Entry::Vacant(Vacant { entry })
            }
            node::SLOT_CLAIMED => Entry::Unavailable,
            slot => Entry::Occupied(Occupied {
                key: Key(entry.key()),
                slot,
            }),
        }
    }

    pub(in crate::conn) fn remove(self, key: Key, id: stream::Id, slot: u32) -> Option<Removed> {
        let mut entry = self.table.core.exact(key.0, Id::mask(id.get())).ok()?;
        let word = entry.get_mut().word_mut::<SEND>();
        if *word & node::SLOT_MASK != slot {
            return None;
        }
        *word = *word & node::EVENT | node::SLOT_NONE;
        table::retire_idle(entry);
        Some(Removed)
    }
}

const _: () = assert!(std::mem::size_of::<State<'static, true>>() == std::mem::size_of::<usize>());

const _: () = {
    assert!(std::mem::size_of::<Occupied>() == 2 * std::mem::size_of::<usize>());
    assert!(std::mem::size_of::<Vacant<'static, false>>() <= 3 * std::mem::size_of::<usize>());
};
