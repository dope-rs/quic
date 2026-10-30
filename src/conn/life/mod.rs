use std::{net, ops, time};

use o3::buffer::{self, storage};

use crate::{conn, runtime::routing, stream, wire::packet::cid};
use conn::scope;
use tls::{Permit, clients};

pub mod accept;
pub mod datagram;
pub(crate) mod initial;
pub mod options;
pub mod status;
pub mod tls;

mod token;
pub(crate) use token::Token;

/// An owned engine retaining the exact admission owner's lifetime.
pub struct Connection<
    'pool,
    const DOMAIN: u8 = 0,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = storage::Shared,
> {
    core: conn::Connection<DOMAIN, B, D>,
    permit: Option<Permit<'pool>>,
}

impl<'pool, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Connection<'pool, DOMAIN, B, D>
{
    pub(in crate::conn) fn new(
        core: conn::Connection<DOMAIN, B, D>,
        permit: Permit<'pool>,
    ) -> Self {
        Self {
            core,
            permit: Some(permit),
        }
    }

    /// All engine mutations finish before this owner's admission is settled.
    pub fn with_scope<R>(
        &mut self,
        run: impl for<'a> FnOnce(scope::Access<'a, DOMAIN, B, false, D>) -> R,
    ) -> R {
        let result = self.core.with_scope(run);
        let core = self.core.machine();
        if core.is_closing()
            || core.egress.lifecycle.state != conn::State::Handshaking
            || !core.handshake.is_pending()
        {
            self.permit.take();
        }
        result
    }

    pub fn recv_packet(
        &mut self,
        work: &mut conn::Workspace,
        wire: &mut [u8],
        now: time::Instant,
        failure: impl FnMut(&rustls::Error),
    ) -> Result<(), conn::Error> {
        self.with_scope(|mut scope| scope.input(work).recv_packet(wire, now, failure))
    }
}

impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> ops::Deref
    for Connection<'_, DOMAIN, B, D>
{
    type Target = conn::Connection<DOMAIN, B, D>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

/// Address-validation state bound to an authentication policy and peer route.
#[must_use = "a saved address token belongs to its matching client endpoint"]
pub struct Reconnect {
    token: Token,
    auth: clients::Authority,
    peer: net::SocketAddr,
    route: cid::Id,
}

impl Reconnect {
    pub(crate) fn new(
        token: Token,
        auth: clients::Authority,
        peer: net::SocketAddr,
        route: cid::Id,
    ) -> Self {
        Self {
            token,
            auth,
            peer,
            route,
        }
    }

    pub const fn peer(&self) -> net::SocketAddr {
        self.peer
    }

    pub const fn auth(&self) -> &clients::Authority {
        &self.auth
    }

    pub(crate) fn matches_path(&self, route: impl routing::PeerRoute) -> bool {
        routing::matches_peer(route.shard(), self.route.as_ref_id())
    }

    pub(crate) fn into_parts(self) -> (Token, clients::Authority) {
        (self.token, self.auth)
    }
}
