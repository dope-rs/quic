use crate::runtime::brand;

use std::net;
use std::pin;
use std::time;

use o3::{buffer::resident, mem::rc};

use crate::conn::id;
use crate::conn::life;
use crate::conn::life::options;
use crate::conn::life::tls::clients;
use crate::errors;
use crate::proto::datagram;
use crate::runtime::endpoint::{self, control::conn, owner};
use crate::runtime::mux::handler;
use crate::runtime::receive::Storage;
use crate::runtime::routing;

/// One client endpoint retains its driver, packet pool, and selected TLS binding.
type Bound<'pool, 'd, const ID: u8, H, B, M> =
    endpoint::Endpoint<'d, ID, H, B, endpoint::Idle, M, datagram::Sealed<'pool>>;

fn prepare<'pool, 'd, const ID: u8, H, B, M>(
    ep: pin::Pin<&mut Bound<'pool, 'd, ID, H, B, M>>,
    mut config: options::Options,
) -> options::Options
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
{
    config.cap_udp(ep.as_ref().get_ref().packet());
    config
}

/// TLS auth retained by one client endpoint.
#[doc(hidden)]
pub trait Mode: Sized {
    type Binding;

    fn try_clone(&self) -> Result<Self, rc::Error>;

    fn connect<'pool, 'd, const ID: u8, H, B, R>(
        &self,
        scope: brand::Token<'_>,
        ep: pin::Pin<&mut Bound<'pool, 'd, ID, H, B, Self::Binding>>,
        addr: net::SocketAddr,
        config: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: Storage<'d, resident::Shared<'d>>,
        R: routing::PeerRoute,
        Self::Binding: owner::Binding<'d, ID>;

    fn reconnect<'pool, 'd, const ID: u8, H, B, R>(
        &self,
        scope: brand::Token<'_>,
        ep: pin::Pin<&mut Bound<'pool, 'd, ID, H, B, Self::Binding>>,
        config: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Reconnect>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: Storage<'d, resident::Shared<'d>>,
        R: routing::PeerRoute,
        Self::Binding: owner::Binding<'d, ID>;
}

/// Native TLS auth retained by one configured endpoint.
#[repr(transparent)]
pub struct Owned(clients::Authority);

impl Owned {
    pub(super) fn new(auth: clients::Authority) -> Self {
        Self(auth)
    }
}

impl Mode for Owned {
    type Binding = owner::Owned;

    fn try_clone(&self) -> Result<Self, rc::Error> {
        Ok(Self(self.0.try_clone()?))
    }

    fn connect<'pool, 'd, const ID: u8, H, B, R>(
        &self,
        scope: brand::Token<'_>,
        mut ep: pin::Pin<&mut Bound<'pool, 'd, ID, H, B, Self::Binding>>,
        addr: net::SocketAddr,
        config: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: Storage<'d, resident::Shared<'d>>,
        R: routing::PeerRoute,
        Self::Binding: owner::Binding<'d, ID>,
    {
        let config = prepare(ep.as_mut(), config);
        conn::connect_prepared(ep, scope, addr, &self.0, config, route, now)
    }

    fn reconnect<'pool, 'd, const ID: u8, H, B, R>(
        &self,
        scope: brand::Token<'_>,
        mut ep: pin::Pin<&mut Bound<'pool, 'd, ID, H, B, Self::Binding>>,
        config: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Reconnect>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: Storage<'d, resident::Shared<'d>>,
        R: routing::PeerRoute,
        Self::Binding: owner::Binding<'d, ID>,
    {
        if !self.0.matches(again.auth()) {
            return Err(errors::Reconnect::retained(
                errors::Preflight::AuthorityMismatch,
                again,
            ));
        }
        let config = prepare(ep.as_mut(), config);
        conn::reconnect_prepared(ep, scope, config, again, route, now)
    }
}

/// Borrow of external TLS auth and handshake admission.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Pooled<'tls>(&'tls clients::Pool);

impl<'tls> Pooled<'tls> {
    pub(super) fn new(pool: &'tls clients::Pool) -> Self {
        Self(pool)
    }
}

impl<'tls> Mode for Pooled<'tls> {
    type Binding = owner::Pooled<'tls>;

    fn try_clone(&self) -> Result<Self, rc::Error> {
        Ok(*self)
    }

    fn connect<'pool, 'd, const ID: u8, H, B, R>(
        &self,
        scope: brand::Token<'_>,
        mut ep: pin::Pin<&mut Bound<'pool, 'd, ID, H, B, Self::Binding>>,
        addr: net::SocketAddr,
        config: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: Storage<'d, resident::Shared<'d>>,
        R: routing::PeerRoute,
        Self::Binding: owner::Binding<'d, ID>,
    {
        let config = prepare(ep.as_mut(), config);
        conn::pool_route(ep, scope, addr, self.0, config, route, now)
    }

    fn reconnect<'pool, 'd, const ID: u8, H, B, R>(
        &self,
        scope: brand::Token<'_>,
        mut ep: pin::Pin<&mut Bound<'pool, 'd, ID, H, B, Self::Binding>>,
        config: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Reconnect>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: Storage<'d, resident::Shared<'d>>,
        R: routing::PeerRoute,
        Self::Binding: owner::Binding<'d, ID>,
    {
        let config = prepare(ep.as_mut(), config);
        conn::pool_again(ep, scope, self.0, config, again, route, now)
    }
}
