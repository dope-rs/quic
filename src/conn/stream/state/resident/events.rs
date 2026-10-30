use crate::conn::stream::{
    resident::{Key, MAX_GENERATION},
    state,
};
use crate::wire::stream;
use o3::depot::map::resident::{self, Id};

use state::resident::{hash::Hash, node, table};

pub(in crate::conn) enum Hold {
    Added,
    Pending,
}

pub(in crate::conn) struct Held<'a, const SEND: bool> {
    entry: resident::Occupied<'a, node::Node, Hash, MAX_GENERATION>,
}

#[repr(transparent)]
pub(in crate::conn) struct State<'a, const SEND: bool> {
    table: &'a mut table::Table,
}

impl<'a, const SEND: bool> State<'a, SEND> {
    pub(super) fn new(table: &'a mut table::Table) -> Self {
        Self { table }
    }

    pub(in crate::conn) fn hold(self, key: Key, id: stream::Id) -> Option<(Hold, Held<'a, SEND>)> {
        let mut entry = self.table.core.exact(key.0, Id::mask(id.get())).ok()?;
        let word = entry.get_mut().word_mut::<SEND>();
        if *word & node::SLOT_MASK >= node::SLOT_CLAIMED {
            return None;
        }
        let hold = if *word & node::EVENT != 0 {
            Hold::Pending
        } else {
            *word |= node::EVENT;
            Hold::Added
        };
        Some((hold, Held { entry }))
    }

    pub(in crate::conn) fn held(self, key: Key, id: stream::Id) -> Option<Held<'a, SEND>> {
        let mut entry = self.table.core.exact(key.0, Id::mask(id.get())).ok()?;
        if *entry.get_mut().word_mut::<SEND>() & node::EVENT == 0 {
            return None;
        }
        Some(Held { entry })
    }
}

impl<const SEND: bool> Held<'_, SEND> {
    pub(in crate::conn) fn release(mut self) {
        *self.entry.get_mut().word_mut::<SEND>() &= !node::EVENT;
        table::retire_idle(self.entry);
    }
}

const _: () = assert!(std::mem::size_of::<State<'static, true>>() == std::mem::size_of::<usize>());
