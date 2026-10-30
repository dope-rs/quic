use std::mem;

use o3::buffer::{self, resident};

use crate::conn;
use crate::stream;

#[repr(transparent)]
pub struct State<
    'conn,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    conn: &'conn conn::Machine<DOMAIN, B, D>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> State<'conn, DOMAIN, B, D> {
    pub(crate) fn new(conn: &'conn conn::Machine<DOMAIN, B, D>) -> Self {
        Self { conn }
    }

    pub fn state(&self) -> conn::State {
        self.conn.egress.lifecycle.state
    }

    pub fn is_opening(&self) -> bool {
        self.state() == conn::State::Handshaking
    }

    pub fn is_ready(&self) -> bool {
        self.state() == conn::State::Established
    }

    pub fn is_closed(&self) -> bool {
        self.state() == conn::State::Closed
    }

    pub fn is_closing(&self) -> bool {
        self.conn.is_closing()
    }

    pub fn is_confirmed(&self) -> bool {
        self.conn.egress.lifecycle.handshake_confirmed
    }

    /// Whether TLS has accepted early data.
    pub fn is_early(&self) -> bool {
        self.conn.handshake.peer.is_early()
    }
}

const _: () = {
    assert!(mem::size_of::<State<'static, 0>>() == mem::size_of::<&conn::Machine<0, Vec<u8>>>());
};
