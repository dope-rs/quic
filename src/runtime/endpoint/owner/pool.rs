use std::net;

use o3::buffer::resident;

use dope::core::driver;

use crate::conn::id;
use crate::conn::life::tls::servers;
use crate::proto::datagram;
use crate::runtime::endpoint::{self, owner, reactor};
use crate::runtime::mux::{builder, handler};
use crate::runtime::receive;
use crate::runtime::routing;
use handler::hook::{
    set::Dispatch,
    wire::{cert, packet},
};

pub struct Binding<'tls, const ID: u8> {
    pool: &'tls servers::Pool<ID>,
}

impl<'tls, const ID: u8> Binding<'tls, ID> {
    pub fn new(pool: &'tls servers::Pool<ID>) -> Self {
        Self { pool }
    }

    pub fn bind<'pool, 'd, H, R>(
        self,
        bind: net::SocketAddr,
        events: H,
        plan: endpoint::Plan<ID, R>,
        driver: &mut driver::Context<'_, 'd>,
    ) -> endpoint::Bound<
        'd,
        ID,
        H,
        R,
        endpoint::Idle,
        owner::Pooled<'tls, routing::Plain>,
        datagram::Sealed<'pool>,
    >
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
        R: receive::Policy,
    {
        let mut opts = self.pool.authority().options().copy();
        opts.cap_udp(plan.packet());
        let mux = builder::Builder::from_pool(events, opts, self.pool, routing::Plain, plan.mux())
            .bind(driver)
            .map_err(endpoint::BindError::Mux)?;
        let ep = plan.prepare(driver)?;
        ep.bind(
            bind,
            reactor::Engine::new(mux, endpoint::Idle::new()),
            driver,
        )
    }

    pub fn bind_routed<'pool, 'd, H, R>(
        self,
        bind: routing::Binding,
        events: H,
        plan: endpoint::Plan<ID, R>,
        driver: &mut driver::Context<'_, 'd>,
    ) -> endpoint::Bound<
        'd,
        ID,
        H,
        R,
        endpoint::Idle,
        owner::Pooled<'tls, routing::Routed>,
        datagram::Sealed<'pool>,
    >
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
        R: receive::Policy,
    {
        let mut opts = self.pool.authority().options().copy();
        opts.cap_udp(plan.packet());
        let (lease, route) = bind.into_parts();
        let mux = builder::Builder::from_pool(events, opts, self.pool, route, plan.mux())
            .bind(driver)
            .map_err(endpoint::BindError::Mux)?;
        let ep = plan.prepare(driver)?;
        ep.adopt(
            lease,
            reactor::Engine::new(mux, endpoint::Idle::new()),
            driver,
        )
    }
}
