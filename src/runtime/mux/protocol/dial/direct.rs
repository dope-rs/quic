use crate::runtime::brand;

use std::{net, time};

use crate::{
    conn, errors,
    runtime::{mux, routing},
    stream,
    wire::packet::cid,
};
use conn::{id, life};
use life::{options, tls::clients};
use mux::{auth, handler, protocol};
use protocol::dial::{self, setup};

pub(crate) trait Direct<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>
{
    fn connect(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        dcid: Vec<u8>,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect>;

    fn connect_id(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        dcid: cid::Id,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect>;

    fn connect_in(
        &mut self,
        scope: brand::Token<'_>,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        dcid: cid::Id,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect>;

    fn connect_with<R: routing::PeerRoute>(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect>;

    fn route_in<R: routing::PeerRoute>(
        &mut self,
        scope: brand::Token<'_>,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect>;

    fn reconnect<R: routing::PeerRoute>(
        &mut self,
        options: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Reconnect>;

    fn reconnect_in<R: routing::PeerRoute>(
        &mut self,
        scope: brand::Token<'_>,
        options: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Reconnect>;
}

impl<'a, 'tls, H, const DOMAIN: u8, B, A> Direct<A, H, DOMAIN, B>
    for protocol::Io<'a, 'tls, H, DOMAIN, B, A>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    fn connect(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        dcid: Vec<u8>,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect> {
        let dcid = cid::Id::try_from(dcid)?;
        self.connect_id(peer, auth, options, dcid, now)
    }

    fn connect_id(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        dcid: cid::Id,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect> {
        brand::Token::with(|scope| self.connect_in(scope, peer, auth, options, dcid, now))
    }

    fn connect_in(
        &mut self,
        scope: brand::Token<'_>,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        dcid: cid::Id,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect> {
        setup::Setup::with(self, |setup| {
            let ready = setup.reserve(&options)?;
            if !routing::PeerRoute::matches(routing::Plain, &dcid) {
                drop(options);
                return Err(errors::Connect::InvalidConfig);
            }
            ready.finish(
                scope,
                auth.try_clone()?,
                options,
                dial::Prepared {
                    route: routing::Plain,
                    initial_dcid: dcid,
                    peer_addr: peer,
                    now,
                    token: None,
                },
                None,
            )
        })
    }

    fn connect_with<R: routing::PeerRoute>(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect> {
        brand::Token::with(|scope| self.route_in(scope, peer, auth, options, route, now))
    }

    fn route_in<R: routing::PeerRoute>(
        &mut self,
        scope: brand::Token<'_>,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        options: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect> {
        setup::Setup::with(self, |setup| {
            let (dcid, ready) = setup.issue(&options, route)?;
            ready.finish(
                scope,
                auth.try_clone()?,
                options,
                dial::Prepared {
                    route,
                    initial_dcid: dcid,
                    peer_addr: peer,
                    now,
                    token: None,
                },
                None,
            )
        })
    }

    fn reconnect<R: routing::PeerRoute>(
        &mut self,
        options: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Reconnect> {
        brand::Token::with(|scope| self.reconnect_in(scope, options, again, route, now))
    }

    fn reconnect_in<R: routing::PeerRoute>(
        &mut self,
        scope: brand::Token<'_>,
        options: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Reconnect> {
        setup::Setup::with(self, |setup| {
            if !again.matches_path(route) {
                return Err(errors::Reconnect::retained(
                    errors::Preflight::InvalidConfig,
                    again,
                ));
            }
            let (dcid, ready) = match setup.issue(&options, route) {
                Ok(plan) => plan,
                Err(error) => return Err(errors::Reconnect::retained(error, again)),
            };
            let peer = again.peer();
            let (token, auth) = again.into_parts();
            ready
                .finish(
                    scope,
                    auth,
                    options,
                    dial::Prepared {
                        route,
                        initial_dcid: dcid,
                        peer_addr: peer,
                        now,
                        token: Some(token),
                    },
                    None,
                )
                .map_err(errors::Reconnect::consumed)
        })
    }
}
