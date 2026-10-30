use crate::proto::datagram;
use std::net;

use o3::{buffer::resident, depot::capacity};

use dope::core::driver;

use crate::conn::id;
use crate::runtime::endpoint::{self, config, owner, reactor};
use crate::runtime::mux::{self, app, auth, builder, handler};
use crate::runtime::receive;
use crate::runtime::routing;
use handler::hook::{
    set::Dispatch,
    wire::{cert, packet},
};

/// Single-use client socket and resource plan.
#[must_use = "a client plan must be consumed by one endpoint binding"]
pub struct Plan<const ID: u8, R: receive::Policy = receive::Copied> {
    bind: net::SocketAddr,
    endpoint: endpoint::Plan<ID, R>,
}

impl<const ID: u8, R: receive::Policy> Plan<ID, R> {
    pub fn new(bind: net::SocketAddr, config: config::Config) -> Result<Self, config::Error> {
        Ok(Self {
            bind,
            endpoint: endpoint::Plan::new(config)?,
        })
    }

    pub(crate) const fn capacity(&self) -> capacity::Limit<{ mux::MAX_CONNECTIONS }> {
        self.endpoint.mux().conns()
    }
}

impl<const ID: u8, R: receive::Policy> AsRef<endpoint::Plan<ID, R>> for Plan<ID, R> {
    fn as_ref(&self) -> &endpoint::Plan<ID, R> {
        &self.endpoint
    }
}

impl<const ID: u8, R: receive::Policy> Plan<ID, R> {
    pub fn bind<'pool, 'd, H, M>(
        self,
        events: H,
        driver: &mut driver::Context<'_, 'd>,
    ) -> endpoint::Bound<'d, ID, H, R, endpoint::Idle, M, datagram::Sealed<'pool>>
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
        M: owner::Binding<'d, ID>,
        M::Mode: auth::Mode<
                ID,
                LocalRoute = routing::Plain,
                Random = <auth::Owned<routing::Plain, id::Driver<'d>> as auth::Mode<ID>>::Random,
            >,
    {
        let mux = builder::Builder::<M::Mode, _, ID, _>::client_in(
            events,
            routing::Plain,
            self.endpoint.mux(),
        )
        .bind(driver)
        .map_err(endpoint::BindError::Mux)?;
        let ep = self.endpoint.prepare(driver)?;
        ep.bind(
            self.bind,
            reactor::Engine::new(mux, endpoint::Idle::new()),
            driver,
        )
    }

    pub fn bind_app<'pool, 'd, H, A>(
        self,
        events: H,
        app: A,
        driver: &mut driver::Context<'_, 'd>,
    ) -> endpoint::Bound<'d, ID, H, R, endpoint::Run<A>, owner::Owned, datagram::Sealed<'pool>>
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
        A: app::Driver<'d, H, ID, R::Buffer<'d>, resident::Shared<'d>>,
    {
        let mux = builder::Builder::<auth::Owned<_, _>, _, ID, _>::client_in(
            events,
            routing::Plain,
            self.endpoint.mux(),
        )
        .bind(driver)
        .map_err(endpoint::BindError::Mux)?;
        let ep = self.endpoint.prepare(driver)?;
        ep.bind(
            self.bind,
            reactor::Engine::new(mux, endpoint::Run::<_, app::Silent>::new(app)),
            driver,
        )
    }
}

const _: () = {
    assert!(
        std::mem::size_of::<Plan<0, receive::Copied>>()
            == std::mem::size_of::<Plan<0, receive::Retained>>()
    );
};
