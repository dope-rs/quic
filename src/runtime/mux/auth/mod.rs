use crate::{
    conn, errors,
    runtime::{mux, routing},
    stream,
};
use conn::{id, life};
use life::{accept, initial, options, tls};
use mux::router;
use o3::buffer;
use router::routing::issuer;
use std::{convert::Infallible, marker, mem};
use tls::servers;

mod boundary;

pub(crate) use boundary::Boundary;

/// Admission creates the transport and its capacity lease as one transition.
type Accepted<const DOMAIN: u8, B, D, T> =
    Result<(conn::Connection<DOMAIN, B, D>, Option<T>), errors::Connect>;

/// Connection-owned TLS selected statically by [`router::Router`].
#[doc(hidden)]
pub struct Owned<R = routing::Plain, E = id::Static>(marker::PhantomData<fn() -> (R, E)>);

/// External handshake admission preserving the exact pool lifetime.
#[doc(hidden)]
pub struct Pooled<'tls, R = routing::Plain, E = id::Static> {
    lifetime: marker::PhantomData<&'tls ()>,
    route: marker::PhantomData<fn() -> R>,
    identity: marker::PhantomData<fn() -> E>,
}

/// Server settings borrowed for exactly the admission pool's lifetime.
#[doc(hidden)]
pub struct PooledServer<'tls, const DOMAIN: u8> {
    pub(super) config: options::Options,
    pub(super) pool: &'tls servers::Pool<DOMAIN>,
}

#[doc(hidden)]
pub struct ConfigRef<'a>(pub(super) &'a options::Options);

#[doc(hidden)]
pub struct ServerConfig(pub(super) options::Options);

/// Compile-time coupling of identity, routing, admission, and send ownership.
#[doc(hidden)]
pub trait Mode<const DOMAIN: u8>: Boundary {
    type Identity: id::Temporal;
    type Session;
    type Server;
    type LocalRoute: routing::LocalRoute;
    type Random: issuer::Source;
    type Send: buffer::raw::Segment;

    fn config(server: &Self::Server) -> ConfigRef<'_>;
    fn reconfigure(
        server: &Self::Server,
        config: rustls::ServerConfig,
    ) -> Result<(), errors::Connect>;

    fn reject_early(server: &Self::Server);

    fn accept<B: stream::Recv>(
        server: &Self::Server,
        ids: accept::Ids,
        config: ServerConfig,
    ) -> Accepted<DOMAIN, B, Self::Send, Self::Session>;
}

impl<R, G, const DOMAIN: u8> Mode<DOMAIN> for Owned<R, G>
where
    R: routing::LocalRoute,
    G: issuer::Binding,
{
    type Identity = G::Identity;
    type Session = Infallible;
    type Server = accept::Authority<DOMAIN>;
    type LocalRoute = R;
    type Random = G::Authority;
    type Send = G::Send;

    fn config(server: &Self::Server) -> ConfigRef<'_> {
        ConfigRef(server.options())
    }

    fn reconfigure(
        server: &Self::Server,
        config: rustls::ServerConfig,
    ) -> Result<(), errors::Connect> {
        server.reconfigure(config)
    }

    fn reject_early(server: &Self::Server) {
        server.reject_early();
    }

    fn accept<B: stream::Recv>(
        server: &Self::Server,
        ids: accept::Ids,
        config: ServerConfig,
    ) -> Accepted<DOMAIN, B, Self::Send, Self::Session> {
        let init = initial::Acceptor::new(ids, config.0);
        let conn = init.try_owned(server.config())?;
        Ok((conn, None))
    }
}

impl<'tls, R, G, const DOMAIN: u8> Mode<DOMAIN> for Pooled<'tls, R, G>
where
    R: routing::LocalRoute,
    G: issuer::Binding,
{
    type Identity = G::Identity;
    type Session = tls::Permit<'tls>;
    type Server = PooledServer<'tls, DOMAIN>;
    type LocalRoute = R;
    type Random = G::Authority;
    type Send = G::Send;

    fn config(server: &Self::Server) -> ConfigRef<'_> {
        ConfigRef(&server.config)
    }

    fn reconfigure(
        server: &Self::Server,
        config: rustls::ServerConfig,
    ) -> Result<(), errors::Connect> {
        server.pool.reconfigure(config)
    }

    fn reject_early(server: &Self::Server) {
        server.pool.authority().reject_early();
    }

    fn accept<B: stream::Recv>(
        server: &Self::Server,
        ids: accept::Ids,
        config: ServerConfig,
    ) -> Accepted<DOMAIN, B, Self::Send, Self::Session> {
        let init = initial::Acceptor::new(ids, config.0);
        let (conn, permit) = init.try_pooled(server.pool)?;
        Ok((conn, Some(permit)))
    }
}

const _: () = assert!(mem::size_of::<Pooled<'static>>() == 0);
