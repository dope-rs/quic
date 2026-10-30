use std::mem;

use o3::buffer::{self, resident::Shared};

use crate::conn;
use crate::conn::stream::state::resident::bindings;
use crate::conn::stream::{resident, state::transmit};
use crate::runtime::brand;
use crate::stream;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    Added,
    Present,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Bind {
    Added,
    Present,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Release {
    Vacant,
    Unbound,
    Bound(u32),
}

impl Release {
    pub const fn slot(self) -> Option<u32> {
        match self {
            Self::Vacant | Self::Unbound => None,
            Self::Bound(slot) => Some(slot),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Stale(resident::Stale),
    Vacant(resident::Local),
    Unbound(resident::Local),
    Bound {
        local: resident::Local,
        expected: u32,
        actual: u32,
    },
    Slot {
        slot: u32,
    },
}

#[repr(transparent)]
pub struct Scope<
    'access,
    'conn,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
> {
    connection: &'access mut conn::Machine<DOMAIN, B, D>,
    brand: brand::Token<'conn>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Scope<'_, 'conn, DOMAIN, B, RECONCILE, D>
{
    pub(super) fn new<'access>(
        machine: &'access mut conn::Machine<DOMAIN, B, D>,
        brand: brand::Token<'conn>,
    ) -> Scope<'access, 'conn, DOMAIN, B, RECONCILE, D> {
        Scope {
            connection: machine,
            brand,
        }
    }

    pub fn try_attach(
        &mut self,
        handle: resident::Handle<'conn>,
    ) -> Result<Attach, resident::Stale> {
        let local = handle.local();
        let state = self.connection.streams.state.resident.binding();
        match state.entry(local)? {
            bindings::Entry::Vacant(vacant) => {
                vacant.attach();
                Ok(Attach::Added)
            }
            bindings::Entry::Unbound(_) | bindings::Entry::Bound(_) => Ok(Attach::Present),
        }
    }

    pub fn try_slot(
        &self,
        handle: resident::Handle<'conn>,
    ) -> Result<Option<u32>, resident::Stale> {
        Ok(
            match self
                .connection
                .streams
                .state
                .resident
                .read()
                .binding(handle.local())?
            {
                bindings::Status::Vacant | bindings::Status::Unbound => None,
                bindings::Status::Bound(slot) => Some(slot),
            },
        )
    }

    pub fn try_bind(&mut self, handle: resident::Handle<'conn>, slot: u32) -> Result<Bind, Fault> {
        let local = handle.local();
        let Some(slot) = bindings::Slot::new(slot) else {
            return Err(Fault::Slot { slot });
        };
        let state = self.connection.streams.state.resident.binding();
        match state.entry(local).map_err(Fault::Stale)? {
            bindings::Entry::Vacant(vacant) => {
                vacant.bind(slot);
                Ok(Bind::Added)
            }
            bindings::Entry::Unbound(unbound) => {
                unbound.bind(slot);
                Ok(Bind::Added)
            }
            bindings::Entry::Bound(bound) if bound.slot() == slot.get() => Ok(Bind::Present),
            bindings::Entry::Bound(bound) => Err(Fault::Bound {
                local,
                expected: slot.get(),
                actual: bound.slot(),
            }),
        }
    }

    pub fn try_unbind(&mut self, handle: resident::Handle<'conn>, slot: u32) -> Result<(), Fault> {
        self.bound(handle, slot)?.unbind();
        Ok(())
    }

    pub fn try_retire(&mut self, handle: resident::Handle<'conn>, slot: u32) -> Result<(), Fault> {
        self.bound(handle, slot)?.free();
        Ok(())
    }

    fn bound(
        &mut self,
        handle: resident::Handle<'conn>,
        slot: u32,
    ) -> Result<bindings::Bound<'_>, Fault> {
        let local = handle.local();
        let state = self.connection.streams.state.resident.binding();
        match state.entry(local).map_err(Fault::Stale)? {
            bindings::Entry::Vacant(_) => Err(Fault::Vacant(local)),
            bindings::Entry::Unbound(_) => Err(Fault::Unbound(local)),
            bindings::Entry::Bound(bound) if bound.slot() == slot => Ok(bound),
            bindings::Entry::Bound(bound) => Err(Fault::Bound {
                local,
                expected: slot,
                actual: bound.slot(),
            }),
        }
    }

    pub fn try_release(
        &mut self,
        handle: resident::Handle<'conn>,
    ) -> Result<Release, resident::Stale> {
        let local = handle.local();
        let state = self.connection.streams.state.resident.binding();
        Ok(match state.entry(local)? {
            bindings::Entry::Vacant(_) => Release::Vacant,
            bindings::Entry::Unbound(unbound) => {
                unbound.free();
                Release::Unbound
            }
            bindings::Entry::Bound(bound) => Release::Bound(bound.free()),
        })
    }

    pub fn try_prepare(&mut self, handle: resident::Handle<'conn>) -> Result<(), resident::Error> {
        let result = transmit::Writer::new(self.connection).try_prepare(handle.local());
        if result.is_ok() {
            self.track();
        }
        result
    }

    fn track(&mut self) {
        self.connection.record::<RECONCILE>(conn::Effects::STREAMS);
    }
}

const _: () = assert!(
    mem::size_of::<Scope<'_, '_, 0, Vec<u8>, false, Shared<'_>>>()
        == mem::size_of::<&mut conn::Machine<0, Vec<u8>, Shared<'_>>>()
);
