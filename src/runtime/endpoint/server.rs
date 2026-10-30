use crate::proto::datagram;
use crate::runtime::endpoint::owner;
use std::net;

use o3::buffer::resident;

use dope::core::driver;

use crate::conn::id;
use crate::conn::life::{accept, options};
use crate::errors;
use crate::runtime::endpoint::{self, config, reactor};
use crate::runtime::mux::{app, builder, handler};
use crate::runtime::receive;
use crate::{
    proto::{early, param},
    runtime::routing,
};
use handler::hook::{
    set::Dispatch,
    wire::{cert, packet},
};

/// Single-use server auth and receive resource plan.
#[must_use = "a server plan must be consumed by one endpoint binding"]
pub struct Plan<const ID: u8, R: receive::Policy = receive::Retained> {
    bind: net::SocketAddr,
    source: rustls::ServerConfig,
    connection: options::Options,
    early: Option<early::ReplayCap>,
    endpoint: endpoint::Plan<ID, R>,
}

impl<const ID: u8, R: receive::Policy> Plan<ID, R> {
    pub fn new(
        bind: net::SocketAddr,
        source: rustls::ServerConfig,
        opts: options::Options,
        config: config::Config,
    ) -> Result<Self, endpoint::PlanError> {
        Self::prepare(bind, source, opts, None, config)
    }

    pub fn from_params(
        bind: net::SocketAddr,
        source: rustls::ServerConfig,
        params: param::Set,
        config: config::Config,
    ) -> Result<Self, endpoint::PlanError> {
        let opts = options::Options::try_from(params)
            .map_err(errors::Connect::Options)
            .map_err(endpoint::PlanError::Connection)?;
        Self::new(bind, source, opts, config)
    }

    pub fn with_early(
        bind: net::SocketAddr,
        source: rustls::ServerConfig,
        opts: options::Options,
        cap: early::ReplayCap,
        config: config::Config,
    ) -> Result<Self, endpoint::PlanError> {
        Self::prepare(bind, source, opts, Some(cap), config)
    }

    fn prepare(
        bind: net::SocketAddr,
        source: rustls::ServerConfig,
        mut opts: options::Options,
        early: Option<early::ReplayCap>,
        config: config::Config,
    ) -> Result<Self, endpoint::PlanError> {
        let ep = endpoint::Plan::new(config).map_err(endpoint::PlanError::Config)?;
        opts.cap_udp(ep.packet());
        Ok(Self {
            bind,
            source,
            connection: opts,
            early,
            endpoint: ep,
        })
    }

    pub const fn capacity(&self) -> usize {
        self.endpoint.len()
    }
}

impl<const ID: u8, R: receive::Policy> AsRef<endpoint::Plan<ID, R>> for Plan<ID, R> {
    fn as_ref(&self) -> &endpoint::Plan<ID, R> {
        &self.endpoint
    }
}

impl<const ID: u8, R: receive::Policy> Plan<ID, R> {
    pub fn bind<'pool, 'd, H>(
        self,
        events: H,
        driver: &mut driver::Context<'_, 'd>,
    ) -> endpoint::Bound<'d, ID, H, R, endpoint::Idle, owner::Owned, datagram::Sealed<'pool>>
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
    {
        let auth = accept::Authority::from_parts(self.source, self.connection, self.early)
            .map_err(endpoint::BindError::Connection)?;
        let mux = builder::Builder::server_in(events, auth, routing::Plain, self.endpoint.mux())
            .bind(driver)
            .map_err(endpoint::BindError::Mux)?;
        let ep = self.endpoint.prepare(driver)?;
        ep.bind(
            self.bind,
            reactor::Engine::new(mux, endpoint::Idle::new()),
            driver,
        )
    }

    fn bind_app<'pool, 'd, Q, H, A>(
        self,
        events: H,
        app: A,
        driver: &mut driver::Context<'_, 'd>,
    ) -> endpoint::Bound<'d, ID, H, R, endpoint::Run<A, Q>, owner::Owned, datagram::Sealed<'pool>>
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
        A: app::Driver<'d, H, ID, R::Buffer<'d>, resident::Shared<'d>>,
        Q: app::Receipt<'d, H, ID, R::Buffer<'d>, resident::Shared<'d>, A>,
    {
        let auth = accept::Authority::from_parts(self.source, self.connection, self.early)
            .map_err(endpoint::BindError::Connection)?;
        let mux = builder::Builder::server_in(events, auth, routing::Plain, self.endpoint.mux())
            .bind(driver)
            .map_err(endpoint::BindError::Mux)?;
        let ep = self.endpoint.prepare(driver)?;
        ep.bind(
            self.bind,
            reactor::Engine::new(mux, endpoint::Run::<A, Q>::new(app)),
            driver,
        )
    }

    pub fn bind_with<'pool, 'd, Q, H, A, F, E>(
        self,
        driver: &mut driver::Context<'_, 'd>,
        bind: F,
    ) -> endpoint::Bound<
        'd,
        ID,
        H,
        R,
        endpoint::Run<A, Q>,
        owner::Owned,
        datagram::Sealed<'pool>,
        endpoint::BindFailure<E>,
    >
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
        A: app::Driver<'d, H, ID, R::Buffer<'d>, resident::Shared<'d>>,
        Q: app::Receipt<'d, H, ID, R::Buffer<'d>, resident::Shared<'d>, A>,
        F: FnOnce(driver::Binding<'d>) -> Result<(H, A), E>,
    {
        let binding = driver::Binding::new(driver.driver_ref().timer(), self.endpoint.owners());
        let (events, app) = bind(binding).map_err(endpoint::BindFailure::Application)?;
        self.bind_app::<Q, _, _>(events, app, driver)
            .map_err(endpoint::BindFailure::Endpoint)
    }
}

const _: () = {
    assert!(
        std::mem::size_of::<Plan<0, receive::Copied>>()
            == std::mem::size_of::<Plan<0, receive::Retained>>()
    );
};
