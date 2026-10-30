use std::marker;

use core::driver;
use dope::core;
use dope::core::driver::schedule::ready::task::owner;
use o3::alloc;
use o3::depot::capacity;

use crate::conn::id;
use crate::conn::life::{accept, options, tls};
use crate::wire::packet::long::retry;
use crate::{errors, runtime::mux, runtime::routing, stream};
use mux::{auth, handler, router};
use router::routing::issuer;
use tls::servers;

/// Invalid mux capacity relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Connections { got: usize, max: usize },
    Packets { got: usize, max: usize },
    Bytes { got: usize, max: usize },
}

/// Exact failure while allocating and binding a complete mux.
#[derive(Debug)]
pub enum Failure {
    Connection(errors::Connect),
    Retry(retry::Crypto),
    Storage(router::Error),
    Workspace(alloc::Error),
    Output {
        packets: capacity::Count,
        bytes: usize,
        error: alloc::Error,
    },
}

/// Validated scalar capacity plan shared by mux construction and driver claims.
#[derive(Clone, Copy)]
pub struct Plan {
    conns: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
    queue: capacity::Limit<{ mux::MAX_OUTGOING_CAPACITY }>,
    bytes: capacity::Limit<{ mux::MAX_OUTGOING_BYTES }>,
}

impl Plan {
    pub fn standard() -> Self {
        let conns = capacity::Limit::fixed::<{ mux::DEFAULT_MAX_CONNS }>();
        let queue = capacity::Limit::fixed::<{ mux::DEFAULT_OUTGOING_CAP }>();
        let bytes = capacity::Limit::fixed::<{ mux::DEFAULT_OUTGOING_BYTES_CAP }>();
        Self {
            conns,
            queue,
            bytes,
        }
    }

    pub fn try_new(conns: usize, queue: usize, bytes: usize) -> Result<Self, Error> {
        let Some(conns) = capacity::Limit::new(conns) else {
            return Err(Error::Connections {
                got: conns,
                max: mux::MAX_CONNECTIONS,
            });
        };
        let Some(queue) = capacity::Limit::new(queue) else {
            return Err(Error::Packets {
                got: queue,
                max: mux::MAX_OUTGOING_CAPACITY,
            });
        };
        let Some(bytes) = capacity::Limit::new(bytes) else {
            return Err(Error::Bytes {
                got: bytes,
                max: mux::MAX_OUTGOING_BYTES,
            });
        };
        Ok(Self {
            conns,
            queue,
            bytes,
        })
    }

    pub const fn connections(self) -> usize {
        self.conns.get()
    }

    pub(crate) const fn conns(self) -> capacity::Limit<{ mux::MAX_CONNECTIONS }> {
        self.conns
    }

    pub(crate) const fn owners(self) -> owner::Capacity {
        owner::Capacity::new(self.conns.count())
    }

    pub const fn outgoing(self) -> usize {
        self.queue.get()
    }

    pub const fn bytes(self) -> usize {
        self.bytes.get()
    }
}

const _: () = {
    assert!(mux::MAX_CONNECTIONS < usize::MAX);
    assert!(std::mem::size_of::<Plan>() == 3 * std::mem::size_of::<u32>());
};

pub struct Builder<A, H, const DOMAIN: u8, B>
where
    A: auth::Mode<DOMAIN>,
    B: stream::Recv,
{
    events: H,
    server: Option<A::Server>,
    route: A::LocalRoute,
    limits: Plan,
    buffer: marker::PhantomData<fn() -> B>,
}

impl<A, H, const DOMAIN: u8, B> Builder<A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    B: stream::Recv,
{
    pub fn limits(mut self, limits: Plan) -> Self {
        self.limits = limits;
        self
    }

    fn from_parts(
        events: H,
        server: Option<A::Server>,
        route: A::LocalRoute,
        limits: Plan,
    ) -> Self {
        Self {
            events,
            server,
            route,
            limits,
            buffer: marker::PhantomData,
        }
    }
}

impl<H, const DOMAIN: u8, B> Builder<auth::Owned<routing::Plain, id::Static>, H, DOMAIN, B>
where
    B: stream::Recv,
{
    pub fn client(events: H) -> Self {
        Self::from_parts(events, None, routing::Plain, Plan::standard())
    }
}

impl<'tls, H, const DOMAIN: u8, B>
    Builder<auth::Pooled<'tls, routing::Plain, id::Static>, H, DOMAIN, B>
where
    B: stream::Recv,
{
    pub fn client_pool(events: H) -> Self {
        Self::from_parts(events, None, routing::Plain, Plan::standard())
    }
}

impl<H, const DOMAIN: u8, B> Builder<auth::Owned<routing::Plain, id::Static>, H, DOMAIN, B>
where
    B: stream::Recv,
{
    pub fn server(events: H, auth: accept::Authority<DOMAIN>) -> Self {
        Self::server_in(events, auth, routing::Plain, Plan::standard())
    }
}

impl<'tls, H, const DOMAIN: u8, B>
    Builder<auth::Pooled<'tls, routing::Plain, id::Static>, H, DOMAIN, B>
where
    B: stream::Recv,
{
    pub fn server_pool(events: H, pool: &'tls servers::Pool<DOMAIN>) -> Self {
        Self::from_pool(
            events,
            pool.authority().options().copy(),
            pool,
            routing::Plain,
            Plan::standard(),
        )
    }
}

impl<R, G, H, const DOMAIN: u8, B> Builder<auth::Owned<R, G>, H, DOMAIN, B>
where
    R: routing::LocalRoute,
    G: issuer::Binding,
    B: stream::Recv,
{
    pub(crate) fn server_in(
        events: H,
        auth: accept::Authority<DOMAIN>,
        route: R,
        limits: Plan,
    ) -> Self {
        Self::from_parts(events, Some(auth), route, limits)
    }
}

impl<A, H, const DOMAIN: u8, B> Builder<A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    B: stream::Recv,
{
    pub(crate) fn client_in(events: H, route: A::LocalRoute, limits: Plan) -> Self {
        Self::from_parts(events, None, route, limits)
    }
}

impl<'tls, R, G, H, const DOMAIN: u8, B> Builder<auth::Pooled<'tls, R, G>, H, DOMAIN, B>
where
    R: routing::LocalRoute,
    G: issuer::Binding,
    B: stream::Recv,
{
    pub(crate) fn from_pool(
        events: H,
        cfg: options::Options,
        pool: &'tls servers::Pool<DOMAIN>,
        route: R,
        limits: Plan,
    ) -> Self {
        let server = auth::PooledServer { config: cfg, pool };
        Self::from_parts(events, Some(server), route, limits)
    }
}

impl<A, H, const DOMAIN: u8, B> Builder<A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    pub fn build(self) -> Result<router::Router<H, DOMAIN, B, A>, Failure>
    where
        A: auth::Mode<
                DOMAIN,
                Identity = id::Static,
                Random = <id::Static as issuer::Binding>::Authority,
                Send = <id::Static as issuer::Binding>::Send,
            >,
    {
        let id = id::Domain::new().ok_or(Failure::Connection(
            errors::Connect::IdentifierSpaceExhausted,
        ))?;
        let rng = issuer::Issuer::random()
            .map_err(errors::Connect::Entropy)
            .map_err(Failure::Connection)?;
        self.finish(id, rng)
    }

    /// Binds mux identity, randomness, and send owner to one driver domain.
    pub fn bind<'d>(
        self,
        driver: &driver::Context<'_, 'd>,
    ) -> Result<router::Router<H, DOMAIN, B, A>, Failure>
    where
        A: auth::Mode<
                DOMAIN,
                Identity = id::Driver<'d>,
                Random = <id::Driver<'d> as issuer::Binding>::Authority,
                Send = <id::Driver<'d> as issuer::Binding>::Send,
            >,
    {
        let id = id::Domain::for_driver(driver).ok_or(Failure::Connection(
            errors::Connect::IdentifierSpaceExhausted,
        ))?;
        let issuer = issuer::Issuer::for_driver(driver)
            .map_err(errors::Connect::RandomSpaceExhausted)
            .map_err(Failure::Connection)?;
        self.finish(id, issuer)
    }

    fn finish(
        self,
        id: id::Domain<A::Identity, DOMAIN>,
        rng: A::Random,
    ) -> Result<router::Router<H, DOMAIN, B, A>, Failure> {
        let plan = self.limits;
        Ok(router::Router {
            state: router::State::try_new(
                router::Binding {
                    domain: id,
                    route: self.route,
                    issuer: rng,
                },
                plan.conns(),
                capacity::Count::new(plan.queue.count().get()),
                plan.bytes(),
                self.server,
            )?,
            handler: self.events,
        })
    }
}
