use crate::conn::stream::{
    resident::{Local, MAX_GENERATION, Stale},
    state,
};
use o3::depot::map::resident;

use state::resident::{
    hash::Hash,
    node::{self, Node},
    table,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Status {
    Vacant,
    Unbound,
    Bound(u32),
}

pub(in crate::conn) enum Entry<'a> {
    Vacant(Vacant<'a>),
    Unbound(Unbound<'a>),
    Bound(Bound<'a>),
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn) struct Slot(u32);

struct Resident<'a> {
    entry: resident::Occupied<'a, Node, Hash, MAX_GENERATION>,
}

pub(in crate::conn) struct Vacant<'a> {
    resident: Resident<'a>,
}

pub(in crate::conn) struct Unbound<'a> {
    resident: Resident<'a>,
}

pub(in crate::conn) struct Bound<'a> {
    resident: Resident<'a>,
    slot: Slot,
}

#[repr(transparent)]
pub(in crate::conn) struct State<'a> {
    table: &'a mut table::Table,
}

impl Slot {
    pub(in crate::conn) fn new(slot: u32) -> Option<Self> {
        (slot < node::BINDING_UNBOUND).then_some(Self(slot))
    }

    pub(in crate::conn) const fn get(self) -> u32 {
        self.0
    }
}

impl<'a> State<'a> {
    pub(super) fn new(table: &'a mut table::Table) -> Self {
        Self { table }
    }

    pub(in crate::conn) fn entry(self, local: Local) -> Result<Entry<'a>, Stale> {
        let entry = self.table.exact(local)?;
        let status = entry.get().binding;
        let resident = Resident { entry };
        Ok(match status {
            node::BINDING_NONE => Entry::Vacant(Vacant { resident }),
            node::BINDING_UNBOUND => Entry::Unbound(Unbound { resident }),
            slot => Entry::Bound(Bound {
                resident,
                slot: Slot(slot),
            }),
        })
    }
}

impl Resident<'_> {
    fn set(&mut self, binding: u32) {
        self.entry.get_mut().binding = binding;
    }

    fn free(mut self) {
        self.set(node::BINDING_NONE);
        table::retire_idle(self.entry);
    }
}

impl Vacant<'_> {
    pub(in crate::conn) fn attach(mut self) {
        self.resident.set(node::BINDING_UNBOUND);
    }

    pub(in crate::conn) fn bind(mut self, slot: Slot) {
        self.resident.set(slot.get());
    }
}

impl Unbound<'_> {
    pub(in crate::conn) fn bind(mut self, slot: Slot) {
        self.resident.set(slot.get());
    }

    pub(in crate::conn) fn free(self) {
        self.resident.free();
    }
}

impl Bound<'_> {
    pub(in crate::conn) const fn slot(&self) -> u32 {
        self.slot.get()
    }

    pub(in crate::conn) fn unbind(mut self) {
        self.resident.set(node::BINDING_UNBOUND);
    }

    pub(in crate::conn) fn free(self) -> u32 {
        let slot = self.slot();
        self.resident.free();
        slot
    }
}

const _: () = assert!(std::mem::size_of::<Slot>() == std::mem::size_of::<u32>());
