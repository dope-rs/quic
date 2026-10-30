use crate::runtime::brand;

use std::{net, time};

use crate::{
    conn, errors,
    runtime::{mux, routing},
    stream,
    wire::packet::cid,
};
use conn::{id, life};
use life::{options, tls};
use mux::{auth, handler, protocol, router};
use protocol::dial::{self, setup};
use router::routing::issuer;
use tls::clients;

pub(crate) trait Pooled<'tls, H, const DOMAIN: u8, B, Route, E>
where
    H: handler::Handler<DOMAIN, B, E::Send, E::Identity>,
    B: stream::Recv,
    Route: routing::LocalRoute,
    E: issuer::Binding,
{
    fn connect_in(
        &mut self,
        scope: brand::Token<'_>,
        peer: net::SocketAddr,
        pool: &'tls clients::Pool,
        opts: options::Options,
        dcid: cid::Id,
        now: time::Instant,
    ) -> Result<id::Handle<E::Identity, DOMAIN>, errors::Connect>;

    fn route_in<R: routing::PeerRoute>(
        &mut self,
        scope: brand::Token<'_>,
        peer: net::SocketAddr,
        pool: &'tls clients::Pool,
        opts: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<E::Identity, DOMAIN>, errors::Connect>;

    fn reconnect_in<R: routing::PeerRoute>(
        &mut self,
        scope: brand::Token<'_>,
        pool: &'tls clients::Pool,
        opts: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<E::Identity, DOMAIN>, errors::Reconnect>;
}

impl<'a, 'brand, 'tls, H, const DOMAIN: u8, B, Route, E> Pooled<'tls, H, DOMAIN, B, Route, E>
    for protocol::Io<'a, 'brand, H, DOMAIN, B, auth::Pooled<'tls, Route, E>>
where
    H: handler::Handler<DOMAIN, B, E::Send, E::Identity>,
    B: stream::Recv,
    Route: routing::LocalRoute,
    E: issuer::Binding,
{
    fn connect_in(
        &mut self,
        scope: brand::Token<'_>,
        peer: net::SocketAddr,
        pool: &'tls clients::Pool,
        opts: options::Options,
        dcid: cid::Id,
        now: time::Instant,
    ) -> Result<id::Handle<E::Identity, DOMAIN>, errors::Connect> {
        setup::Setup::with(self, |setup| {
            let ready = setup.reserve(&opts)?;
            let permit = pool.reserve()?;
            if !routing::PeerRoute::matches(routing::Plain, &dcid) {
                drop(opts);
                return Err(errors::Connect::InvalidConfig);
            }
            ready.finish(
                scope,
                pool.authority().try_clone()?,
                opts,
                dial::Prepared {
                    route: routing::Plain,
                    initial_dcid: dcid,
                    peer_addr: peer,
                    now,
                    token: None,
                },
                Some(permit),
            )
        })
    }

    fn route_in<R: routing::PeerRoute>(
        &mut self,
        scope: brand::Token<'_>,
        peer: net::SocketAddr,
        pool: &'tls clients::Pool,
        opts: options::Options,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<E::Identity, DOMAIN>, errors::Connect> {
        setup::Setup::with(self, |setup| {
            let (dcid, ready) = setup.issue(&opts, route)?;
            let permit = pool.reserve()?;
            ready.finish(
                scope,
                pool.authority().try_clone()?,
                opts,
                dial::Prepared {
                    route,
                    initial_dcid: dcid,
                    peer_addr: peer,
                    now,
                    token: None,
                },
                Some(permit),
            )
        })
    }

    fn reconnect_in<R: routing::PeerRoute>(
        &mut self,
        scope: brand::Token<'_>,
        pool: &'tls clients::Pool,
        opts: options::Options,
        again: life::Reconnect,
        route: R,
        now: time::Instant,
    ) -> Result<id::Handle<E::Identity, DOMAIN>, errors::Reconnect> {
        setup::Setup::with(self, |setup| {
            let peer = again.peer();
            if !pool.authority().matches(again.auth()) {
                return Err(errors::Reconnect::retained(
                    errors::Preflight::AuthorityMismatch,
                    again,
                ));
            }
            if !again.matches_path(route) {
                return Err(errors::Reconnect::retained(
                    errors::Preflight::InvalidConfig,
                    again,
                ));
            }
            let permit = match pool.reserve() {
                Ok(permit) => permit,
                Err(error) => return Err(errors::Reconnect::retained(error, again)),
            };
            let (dcid, ready) = match setup.issue(&opts, route) {
                Ok(plan) => plan,
                Err(error) => return Err(errors::Reconnect::retained(error, again)),
            };
            let (token, auth) = again.into_parts();
            ready
                .finish(
                    scope,
                    auth,
                    opts,
                    dial::Prepared {
                        route,
                        initial_dcid: dcid,
                        peer_addr: peer,
                        now,
                        token: Some(token),
                    },
                    Some(permit),
                )
                .map_err(errors::Reconnect::consumed)
        })
    }
}
