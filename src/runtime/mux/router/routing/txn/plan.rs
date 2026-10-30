use o3::buffer;
use std::{net, time};

use crate::{conn, proto::datagram::Size, runtime::mux::router::routing::state::cids, stream};

/// Complete owned input and the original directory loan for one installation.
pub(in crate::runtime::mux) struct Plan<
    'storage,
    'id,
    C,
    T,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
> {
    pub(super) connection: conn::Connection<DOMAIN, B, D>,
    pub(super) tls: Option<T>,
    pub(super) peer_addr: net::SocketAddr,
    pub(super) max_packet_bytes: Size,
    pub(super) now: time::Instant,
    pub(super) routes: cids::Prepared<'storage, 'id, C, DOMAIN, B, D, T>,
}

impl<'storage, 'id, C, T, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Plan<'storage, 'id, C, T, DOMAIN, B, D>
{
    pub(in crate::runtime::mux) fn new(
        conn: conn::Connection<DOMAIN, B, D>,
        tls: Option<T>,
        peer: net::SocketAddr,
        limit: Size,
        now: time::Instant,
        routes: cids::Prepared<'storage, 'id, C, DOMAIN, B, D, T>,
    ) -> Self {
        Self {
            connection: conn,
            tls,
            peer_addr: peer,
            max_packet_bytes: limit,
            now,
            routes,
        }
    }
}
