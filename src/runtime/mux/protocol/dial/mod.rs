pub(crate) mod direct;
pub(crate) mod pooled;
pub(super) mod setup;

use std::{net, time};

use crate::{conn::life, wire::packet::cid};

pub(crate) struct Prepared<R> {
    pub(super) route: R,
    pub(super) initial_dcid: cid::Id,
    pub(super) peer_addr: net::SocketAddr,
    pub(super) now: time::Instant,
    pub(super) token: Option<life::Token>,
}
