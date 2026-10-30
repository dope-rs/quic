use o3::buffer;

use crate::conn;
use crate::conn::stream::{
    Access, resident,
    state::{receive::recv, transmit::queue},
};
use crate::stream;
use crate::wire::stream::{Direction, Id};
use recv::map;

/// The single unbranded read kernel used by the branded public API.
#[repr(transparent)]
pub(super) struct Query<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    connection: &'conn conn::Machine<DOMAIN, B, D>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Query<'conn, DOMAIN, B, D> {
    pub(in crate::conn) fn new(conn: &'conn conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    pub(in crate::conn) fn permits(&self, id: Id, access: Access) -> bool {
        if matches!(id.direction(), Direction::Bidi) {
            return true;
        }
        match access {
            Access::Send => id.initiator() == self.connection.peer.local,
            Access::Receive => id.initiator() != self.connection.peer.local,
        }
    }

    pub(in crate::conn) fn is_recv_eof(&self, id: Id) -> bool {
        let streams = &self.connection.streams;
        streams
            .receive
            .map
            .find(map::Id::new(id), &streams.resident)
            .is_some_and(|resolved| resolved.state().is_eof())
            || streams.is_recv_done(id)
    }

    pub(in crate::conn) fn try_recv_eof(
        &self,
        local: resident::Local,
    ) -> Result<bool, resident::Stale> {
        let streams = &self.connection.streams;
        Ok(streams
            .receive
            .map
            .try_find(local, &streams.resident)?
            .is_some_and(|resolved| resolved.state().is_eof())
            || streams.is_recv_done(local.id()))
    }

    pub(in crate::conn) fn has_recv_fin(&self, id: Id) -> bool {
        let streams = &self.connection.streams;
        streams
            .receive
            .map
            .find(map::Id::new(id), &streams.resident)
            .and_then(|resolved| resolved.state().final_size())
            .is_some()
            || streams.is_recv_done(id)
    }

    pub(in crate::conn) fn is_send_open(&self, id: Id) -> bool {
        let streams = &self.connection.streams;
        if !streams.can_access(id, Access::Send) {
            return false;
        }
        streams
            .transmit
            .map()
            .find(id, &streams.resident)
            .map_or_else(
                || id.initiator() != self.connection.peer.local && !streams.is_send_done(id),
                |resolved| matches!(resolved.state().phase(), queue::Phase::Open),
            )
    }

    pub(in crate::conn) fn stopped(&self, id: Id) -> Option<crate::errors::Code> {
        self.connection
            .streams
            .transmit
            .map()
            .find(id, &self.connection.streams.resident)
            .and_then(|resolved| resolved.state().stop_error())
    }

    pub(super) fn has_events(&self) -> bool {
        !self.connection.streams.events.is_empty()
    }
}
