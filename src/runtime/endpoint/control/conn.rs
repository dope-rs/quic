use crate::runtime::brand;

use std::{net, pin, time};

use o3::buffer::{self, resident};

use dope::core::driver::schedule::clock;

use crate::conn::id;
use crate::conn::life;
use crate::conn::life::tls::clients;
use crate::runtime::endpoint::{self, owner};
use crate::runtime::receive::Storage;
use crate::{
    errors,
    proto::param,
    runtime::{mux, routing},
    wire::packet::cid,
};
use dial::{direct, pooled};
use direct::Direct as _;
use life::options;
use mux::{handler, protocol};
use protocol::dial;

pub(super) fn connect_with_config<
    'd,
    const ID: u8,
    H,
    B,
    A,
    M,
    Q: buffer::Residency + buffer::raw::Source,
>(
    ep: pin::Pin<&mut endpoint::Endpoint<'d, ID, H, B, A, M, Q>>,
    peer: net::SocketAddr,
    auth: &clients::Authority,
    config: options::Options,
    dcid: Vec<u8>,
    now: clock::Moment<'d>,
) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
{
    let dcid = cid::Id::try_from(dcid)?;
    now.at(ep).apply(|ep, raw| {
        brand::Token::with(|scope| {
            let mut config = config;
            config.cap_udp(ep.packet);
            protocol::Io::new(ep.project().udp.handler_mut().mux_mut())
                .connect_in(scope, peer, auth, config, dcid, raw)
        })
    })
}

pub(crate) fn connect_prepared<
    'd,
    const ID: u8,
    H,
    B,
    R,
    M,
    Q: buffer::Residency + buffer::raw::Source,
>(
    ep: pin::Pin<&mut endpoint::Endpoint<'d, ID, H, B, endpoint::Idle, M, Q>>,
    scope: brand::Token<'_>,
    peer: net::SocketAddr,
    auth: &clients::Authority,
    config: options::Options,
    route: R,
    now: time::Instant,
) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    R: routing::PeerRoute,
    M: owner::Binding<'d, ID>,
{
    protocol::Io::new(ep.project().udp.handler_mut().mux_mut())
        .route_in(scope, peer, auth, config, route, now)
}

pub(super) fn reconnect<
    'd,
    const ID: u8,
    H,
    B,
    A,
    M,
    R,
    Q: buffer::Residency + buffer::raw::Source,
>(
    ep: pin::Pin<&mut endpoint::Endpoint<'d, ID, H, B, A, M, Q>>,
    config: options::Options,
    again: life::Reconnect,
    route: R,
    now: clock::Moment<'d>,
) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Reconnect>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
    R: routing::PeerRoute,
{
    now.at(ep).apply(|ep, raw| {
        brand::Token::with(|scope| {
            let mut config = config;
            config.cap_udp(ep.packet);
            reconnect_prepared(ep, scope, config, again, route, raw)
        })
    })
}

pub(crate) fn reconnect_prepared<
    'd,
    const ID: u8,
    H,
    B,
    A,
    M,
    R,
    Q: buffer::Residency + buffer::raw::Source,
>(
    ep: pin::Pin<&mut endpoint::Endpoint<'d, ID, H, B, A, M, Q>>,
    scope: brand::Token<'_>,
    config: options::Options,
    again: life::Reconnect,
    route: R,
    now: time::Instant,
) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Reconnect>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
    R: routing::PeerRoute,
{
    protocol::Io::new(ep.project().udp.handler_mut().mux_mut())
        .reconnect_in(scope, config, again, route, now)
}

pub(super) fn connect_pooled<
    'd,
    'tls,
    const ID: u8,
    H,
    B,
    R,
    Q: buffer::Residency + buffer::raw::Source,
>(
    ep: pin::Pin<&mut Leased<'tls, 'd, ID, H, B, endpoint::Idle, R, Q>>,
    peer: net::SocketAddr,
    pool: &'tls clients::Pool,
    params: param::Set,
    dcid: Vec<u8>,
    now: clock::Moment<'d>,
) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    R: routing::LocalRoute,
{
    let config = options::Options::try_from(params)?;
    let dcid = cid::Id::try_from(dcid)?;
    now.at(ep).apply(|ep, raw| {
        brand::Token::with(|scope| {
            let mut config = config;
            config.cap_udp(ep.packet);
            let mut protocol = protocol::Io::new(ep.project().udp.handler_mut().mux_mut());
            pooled::Pooled::connect_in(&mut protocol, scope, peer, pool, config, dcid, raw)
        })
    })
}

pub(crate) fn pool_route<
    'd,
    'tls,
    const ID: u8,
    H,
    B,
    R,
    Q: buffer::Residency + buffer::raw::Source,
>(
    ep: pin::Pin<&mut endpoint::Endpoint<'d, ID, H, B, endpoint::Idle, owner::Pooled<'tls>, Q>>,
    scope: brand::Token<'_>,
    peer: net::SocketAddr,
    pool: &'tls clients::Pool,
    config: options::Options,
    route: R,
    now: time::Instant,
) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    R: routing::PeerRoute,
{
    let mut protocol = protocol::Io::new(ep.project().udp.handler_mut().mux_mut());
    pooled::Pooled::route_in(&mut protocol, scope, peer, pool, config, route, now)
}

pub(crate) fn pool_again<
    'd,
    'tls,
    const ID: u8,
    H,
    B,
    A,
    L,
    R,
    Q: buffer::Residency + buffer::raw::Source,
>(
    ep: pin::Pin<&mut Leased<'tls, 'd, ID, H, B, A, L, Q>>,
    scope: brand::Token<'_>,
    pool: &'tls clients::Pool,
    config: options::Options,
    again: life::Reconnect,
    route: R,
    now: time::Instant,
) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Reconnect>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    L: routing::LocalRoute,
    R: routing::PeerRoute,
{
    let mut protocol = protocol::Io::new(ep.project().udp.handler_mut().mux_mut());
    pooled::Pooled::reconnect_in(&mut protocol, scope, pool, config, again, route, now)
}

/// Pooled connection operations preserve the endpoint's exact TLS loan and routing policy.
type Leased<'tls, 'd, const ID: u8, H, B, A, R, Q> =
    endpoint::Endpoint<'d, ID, H, B, A, owner::Pooled<'tls, R>, Q>;
