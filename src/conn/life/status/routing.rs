use std::{mem, net, time};

use o3::buffer::{self, resident};

use crate::conn::wire::path;
use crate::stream;
use crate::wire::stream::Initiator;
use crate::wire::varint;
use crate::{conn, proto::param};
use path::reset;

/// Borrowed view of the bounded local connection-ID set.
#[derive(Clone, Copy)]
pub struct LocalCids<'conn> {
    path: &'conn path::State,
}

impl<'conn> LocalCids<'conn> {
    pub fn values(self) -> impl Iterator<Item = &'conn [u8]> {
        self.path.local.cids().map(|entry| entry.1)
    }

    pub fn entries(self) -> impl Iterator<Item = (varint::VarInt, &'conn [u8])> {
        self.path.local.cids()
    }
}

#[repr(transparent)]
pub struct Path<
    'conn,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    connection: &'conn conn::Machine<DOMAIN, B, D>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Path<'conn, DOMAIN, B, D> {
    pub(crate) fn new(conn: &'conn conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    pub fn is_reset(&self) -> bool {
        self.connection.control.probe().is_reset()
    }

    pub fn has_token(&self, token: &[u8; 8]) -> bool {
        self.connection.control.probe().has_token(token)
    }

    pub fn mtu(&self) -> u64 {
        self.connection.egress.cc.metrics().current_mtu()
    }

    pub fn local_cids(&self) -> LocalCids<'conn> {
        LocalCids {
            path: &self.connection.path,
        }
    }

    /// Address currently authorized for app output.
    pub fn peer_address(&self) -> Option<net::SocketAddr> {
        self.connection.path.ingress().peer()
    }

    pub fn is_valid(&self) -> bool {
        self.connection.egress.activity.peer_address_validated
    }

    pub fn received(&self) -> u64 {
        self.connection.egress.activity.amplification_received
    }

    pub(crate) fn has_output(&self) -> bool {
        self.connection
            .path
            .output()
            .has_output(&self.connection.control)
    }

    pub(crate) fn is_retry_due(&self, now: time::Instant) -> bool {
        self.connection.path.output().is_retry_due(now)
    }

    pub(crate) fn reset_tokens(&self) -> impl Iterator<Item = reset::Token> + '_ {
        self.connection.path.peer.reset_tokens()
    }

    pub(crate) fn is_dirty(&self) -> bool {
        self.connection.path.peer.is_dirty()
    }
}

#[repr(transparent)]
pub struct Peer<
    'conn,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    connection: &'conn conn::Machine<DOMAIN, B, D>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Peer<'conn, DOMAIN, B, D> {
    pub(crate) fn new(conn: &'conn conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    pub fn local(&self) -> Initiator {
        self.connection.peer.local
    }

    pub fn params(&self) -> Option<&'conn param::Set> {
        self.connection.peer.transport_params.as_ref()
    }
}

const _: () = {
    assert!(mem::size_of::<Path<'static, 0>>() == mem::size_of::<&conn::Machine<0, Vec<u8>>>());
    assert!(mem::size_of::<Peer<'static, 0>>() == mem::size_of::<&conn::Machine<0, Vec<u8>>>());
};
