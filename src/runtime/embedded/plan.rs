use std::{net, num};

use dope::core::driver::schedule::ready::task::owner;
use dope::core::driver::settings;
use settings::demands;

use crate::runtime::embedded::{Config, link};
use crate::runtime::mux::builder;
use link::limits;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Mux(builder::Error),
    LinkCapacity {
        actual: usize,
        maximum: usize,
    },
    Flight {
        actual: u32,
    },
    Retained {
        capacity: usize,
        flight: u32,
    },
    LinkRange {
        actual: num::NonZero<u32>,
        minimum: usize,
        maximum: usize,
    },
}

/// Validated capacities shared by socket-free clients, servers, and links.
#[derive(Clone, Copy)]
pub struct Plan {
    mux: builder::Plan,
    link: limits::Limits,
}

impl Plan {
    pub fn try_new(config: Config) -> Result<Self, Error> {
        let mux = builder::Plan::try_new(
            config.max_connections,
            config.outgoing_capacity,
            config.outgoing_bytes_capacity,
        )
        .map_err(Error::Mux)?;
        let link = limits::Limits::try_new(config.link_capacity, config.max_flight_resident_bytes)?;
        if link.capacity().get() < 2 || link.capacity().get() as usize > mux.outgoing() {
            return Err(Error::LinkRange {
                actual: link.capacity(),
                minimum: 2,
                maximum: mux.outgoing(),
            });
        }
        Ok(Self { mux, link })
    }

    pub(super) const fn capacity(self) -> owner::Capacity {
        self.mux.owners()
    }

    pub(super) const fn limits(self) -> builder::Plan {
        self.mux
    }

    pub(super) fn schedule(self) -> demands::Schedule {
        let conns = self.mux.owners();
        let tasks = owner::Capacity::new(conns.count().saturating_add(1));
        demands::Schedule::new(tasks.into(), conns.into())
    }

    pub fn link<const ROUTE: u8, const FROM: u8, const TO: u8>(
        self,
        local: net::SocketAddr,
        peer: net::SocketAddr,
    ) -> link::Plan<ROUTE, FROM, TO> {
        link::Plan::new(self.link, local, peer)
    }
}
