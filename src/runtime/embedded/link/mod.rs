use crate::runtime::Transit;
use crate::runtime::mux::output;
use dope::core::driver;
use dope::core::driver::route;
use dope::core::driver::route::indices;
use dope::core::driver::schedule::ready;
use dope::core::driver::settings;
use dope::core::driver::settings::claim;
use dope::core::driver::settings::errors::Claim;
use dope::manifold::app::dispatch;
use dope::manifold::network::datagram::packet;
use o3::alloc;
use o3::buffer::Residency as _;
use o3::buffer::resident;
use o3::buffer::storage::provided;
use settings::demands;
use std::cell;
use std::marker;
use std::net;
use std::num::NonZero;

pub mod bind;
pub(super) mod limits;

/// Validated allocation and route plan for one owner-preserving link.
#[derive(Clone, Copy)]
pub struct Plan<const ROUTE: u8, const FROM: u8, const TO: u8> {
    limits: limits::Limits,
    local: net::SocketAddr,
    peer: net::SocketAddr,
}

/// Fixed owner table joining socket-free output directly to retained input.
/// Route and endpoint direction are part of the type and cannot be reversed.
pub struct Link<'d, const ROUTE: u8, const FROM: u8, const TO: u8> {
    arena: provided::Root<'d, output::Flight, Plan<ROUTE, FROM, TO>>,
    receive: resident::Budget<'d>,
    ready: ready::Slot<'d, route::KeyTag<FROM>>,
    waiting: cell::Cell<bool>,
}

/// Exclusive coordination access to one installed owner-preserving link.
#[repr(transparent)]
pub struct Control<'step, 'd, const ROUTE: u8, const FROM: u8, const TO: u8> {
    pub(super) owner: dispatch::raw::Installed<'step, 'd, Link<'d, ROUTE, FROM, TO>>,
}

pub(in crate::runtime::embedded) enum AdoptError<'link> {
    WrongPeer {
        actual: net::SocketAddr,
        expected: &'link net::SocketAddr,
    },
    TooLarge {
        resident_bytes: usize,
        limit: usize,
    },
    Projection {
        projected: usize,
        resident: u32,
    },
}

pub(in crate::runtime::embedded) struct Vacancy<
    'link,
    'd,
    const ROUTE: u8,
    const FROM: u8,
    const TO: u8,
> {
    vacant: provided::Vacant<'d, output::Flight>,
    local: &'link net::SocketAddr,
    peer: &'link net::SocketAddr,
    max_flight_resident_bytes: usize,
    retainer: packet::Retainer<'d>,
    direction: marker::PhantomData<fn() -> Link<'d, ROUTE, FROM, TO>>,
}

struct Transfer<'d> {
    owner: provided::Unique<'d>,
    segment: NonZero<usize>,
}

impl<const ROUTE: u8, const FROM: u8, const TO: u8> Plan<ROUTE, FROM, TO> {
    pub(in crate::runtime::embedded) const fn new(
        limits: limits::Limits,
        local: net::SocketAddr,
        peer: net::SocketAddr,
    ) -> Self {
        Self {
            limits,
            local,
            peer,
        }
    }

    pub fn try_arena(self) -> Result<provided::Arena<output::Flight, Self>, alloc::Error> {
        provided::Arena::<output::Flight, Self>::try_with(self.limits.entries, || Ok(self))
    }

    pub const fn capacity(self) -> NonZero<u32> {
        self.limits.capacity()
    }

    pub const fn flight_limit(self) -> usize {
        self.limits.flight()
    }

    pub const fn local(self) -> net::SocketAddr {
        self.local
    }

    pub const fn peer(self) -> net::SocketAddr {
        self.peer
    }
}

impl<'d, const ROUTE: u8, const FROM: u8, const TO: u8> Link<'d, ROUTE, FROM, TO> {
    pub fn try_new(
        arena: provided::Root<'d, output::Flight, Plan<ROUTE, FROM, TO>>,
        driver: &mut driver::Context<'_, 'd>,
    ) -> Result<Self, bind::Error> {
        let handle = driver.driver_ref();
        let target = handle
            .targets::<route::KeyTag<FROM>>()
            .bind(indices::SlotIndex::ZERO, route::Epoch::INITIAL);
        let ready = handle.ready().make_slot(target.dispatch())?;
        let receive = driver
            .storage
            .allocator()
            .try_budget(arena.context().limits.retained())?;
        Ok(Self {
            arena,
            receive,
            ready,
            waiting: cell::Cell::new(false),
        })
    }

    pub fn capacity(&self) -> NonZero<u32> {
        self.arena.capacity()
    }

    pub fn flight_limit(&self) -> usize {
        self.arena.context().limits.flight()
    }

    pub fn local(&self) -> net::SocketAddr {
        self.arena.context().local
    }

    pub fn peer(&self) -> net::SocketAddr {
        self.arena.context().peer
    }

    fn reclaim(&self) -> Option<output::Flight> {
        let flight = self.arena.pop_returned()?;
        self.waiting.set(false);
        Some(flight)
    }

    pub(super) fn wake(&self) {
        if self.waiting.get() && self.arena.has_returned() {
            self.ready.activate();
        }
    }

    fn vacancy(&self) -> Option<Vacancy<'_, 'd, ROUTE, FROM, TO>> {
        let Some(vacant) = self.arena.vacant() else {
            self.waiting.set(true);
            return None;
        };
        Some(Vacancy {
            vacant,
            local: &self.arena.context().local,
            peer: &self.arena.context().peer,
            max_flight_resident_bytes: self.arena.context().limits.flight(),
            retainer: packet::Retainer::from_budget(self.receive),
            direction: marker::PhantomData,
        })
    }
}

impl<'link, 'd, const ROUTE: u8, const FROM: u8, const TO: u8> Vacancy<'link, 'd, ROUTE, FROM, TO> {
    fn try_adopt<'op>(
        self,
        flight: Transit<'op>,
    ) -> Result<Transfer<'d>, (Transit<'op>, AdoptError<'link>)> {
        let actual = flight.flight().addr();
        if actual != *self.peer {
            return Err((
                flight,
                AdoptError::WrongPeer {
                    actual,
                    expected: self.peer,
                },
            ));
        }
        let resident = flight.resident();
        if resident > self.max_flight_resident_bytes {
            return Err((
                flight,
                AdoptError::TooLarge {
                    resident_bytes: resident,
                    limit: self.max_flight_resident_bytes,
                },
            ));
        }
        let segment = flight
            .flight()
            .segment_size()
            .map_or(NonZero::<usize>::MAX, NonZero::<usize>::from);
        let resident = resident as u32;
        let rest = self
            .vacant
            .try_adopt(flight, resident)
            .map_err(|rejected| {
                let (flight, error) = rejected.into_parts();
                (
                    flight,
                    AdoptError::Projection {
                        projected: error.projected(),
                        resident: error.resident(),
                    },
                )
            })?;
        Ok(Transfer {
            owner: rest,
            segment,
        })
    }

    pub(in crate::runtime::embedded) fn try_for_each<'op, E>(
        self,
        flight: Transit<'op>,
        mut receive: impl for<'turn> FnMut(
            net::SocketAddr,
            packet::Packet<'turn, 'd, provided::Prefix<'turn, 'd>>,
            packet::Retainer<'d>,
        ) -> Result<(), E>,
    ) -> Result<Result<(), E>, (Transit<'op>, AdoptError<'link>)> {
        let local = *self.local;
        let retainer = self.retainer;
        let mut transfer = self.try_adopt(flight)?;
        for prefix in provided::Chunks::new(&mut transfer.owner, transfer.segment) {
            if let Err(error) = receive(local, packet::Packet::from_prefix(prefix), retainer) {
                return Ok(Err(error));
            }
        }
        Ok(Ok(()))
    }
}

impl<'step, 'd, const ROUTE: u8, const FROM: u8, const TO: u8> Control<'step, 'd, ROUTE, FROM, TO> {
    pub(in crate::runtime::embedded) fn reclaim(&mut self) -> Option<output::Flight> {
        self.owner.as_ref().get_ref().reclaim()
    }

    pub(in crate::runtime::embedded) fn vacancy(
        &mut self,
    ) -> Option<Vacancy<'_, 'd, ROUTE, FROM, TO>> {
        self.owner.as_ref().get_ref().vacancy()
    }
}

impl<const ROUTE: u8, const FROM: u8, const TO: u8> settings::Resource for Plan<ROUTE, FROM, TO> {
    fn include_in(&self, needs: claim::Needs) -> Result<claim::Needs, Claim> {
        needs.include(
            claim::Claim::new(settings::Routes::singleton::<route::KeyTag<ROUTE>>())
                .domains(settings::Domain::ONE)
                .schedule(demands::Schedule::fixed::<1, 0>()),
        )
    }
}

const _: () = {
    assert!(size_of::<Link<'static, 0, 0, 1>>() == 5 * size_of::<usize>());
    assert!(size_of::<Control<'static, 'static, 0, 0, 1>>() == size_of::<usize>());
};
