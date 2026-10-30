use crate::runtime::brand;

use o3::buffer::{self, resident::Shared};

use crate::conn;
use crate::conn::stream::access::{Usage, query::Query};
use crate::conn::stream::{Access, Error, id, resident};
use crate::stream;
use crate::wire::stream::{Direction, Id};
use std::mem;

/// Scoped immutable stream state.
#[repr(transparent)]
pub struct View<'access, 'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    connection: &'access conn::Machine<DOMAIN, B, D>,
    brand: brand::Token<'conn>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    View<'_, 'conn, DOMAIN, B, D>
{
    pub(in crate::conn) fn new<'access>(
        conn: &'access conn::Machine<DOMAIN, B, D>,
        brand: brand::Token<'conn>,
    ) -> View<'access, 'conn, DOMAIN, B, D> {
        View {
            connection: conn,
            brand,
        }
    }

    fn kernel(&self) -> Query<'_, DOMAIN, B, D> {
        Query::new(self.connection)
    }

    pub fn resolve_send(&self, id: Id) -> Result<id::Send<'conn>, Error> {
        if !self.kernel().permits(id, Access::Send) {
            return Err(Error::InvalidDirection);
        }
        Ok(id::Send::new(self.brand, id))
    }

    pub fn resolve_recv(&self, id: Id) -> Result<id::Receive<'conn>, Error> {
        if !self.kernel().permits(id, Access::Receive) {
            return Err(Error::InvalidDirection);
        }
        Ok(id::Receive::new(self.brand, id))
    }

    pub fn resolve_bidi(&self, id: Id) -> Result<id::Bidi<'conn>, Error> {
        if matches!(id.direction(), Direction::Uni) {
            return Err(Error::InvalidDirection);
        }
        Ok(id::Bidi::new(self.brand, id))
    }

    pub fn is_recv_eof(&self, id: id::Receive<'conn>) -> bool {
        self.kernel().is_recv_eof(id.id())
    }

    pub(super) fn try_recv_eof(
        &self,
        handle: resident::Handle<'conn>,
    ) -> Result<bool, resident::Stale> {
        self.kernel().try_recv_eof(handle.local())
    }

    pub fn has_recv_fin(&self, id: id::Receive<'conn>) -> bool {
        self.kernel().has_recv_fin(id.id())
    }

    /// Whether this stream's send half still accepts new bytes.
    /// Excludes finished, reset, and retired halves, independently of
    /// connection readiness, flow credit, and buffer capacity.
    pub fn is_send_open(&self, id: id::Send<'conn>) -> bool {
        self.kernel().is_send_open(id.id())
    }

    pub fn stopped(&self, id: id::Send<'conn>) -> Option<crate::errors::Code> {
        self.kernel().stopped(id.id())
    }

    pub fn has_events(&self) -> bool {
        self.kernel().has_events()
    }

    pub fn buffered(&self, id: id::Send<'conn>) -> usize {
        let streams = &self.connection.streams;
        streams
            .transmit
            .map()
            .find(id.id(), &streams.resident)
            .map_or(0, |resolved| resolved.state().buffered_len())
    }

    pub fn usage(&self) -> Usage<'_, D> {
        Usage::new(&self.connection.streams.transmit)
    }
}

const _: () = {
    assert!(
        mem::size_of::<View<'_, '_, 0, Vec<u8>, Shared<'_>>>()
            == mem::size_of::<&conn::Machine<0, Vec<u8>, Shared<'_>>>()
    );
};
