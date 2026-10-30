use o3::buffer;

use crate::wire::stream::Direction;

pub(in crate::conn) mod control;
pub(in crate::conn) mod credits;
pub(in crate::conn) mod input;
pub(in crate::conn) mod planner;
pub(crate) mod recv;
mod state;
mod update;

pub(in crate::conn) use state::{State, Status};
pub(in crate::conn) use update::Update;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn) struct Limits([varint::VarInt; 3]);

impl Limits {
    pub(in crate::conn) const fn new(values: [varint::VarInt; 3]) -> Self {
        Self(values)
    }

    pub(in crate::conn) const fn credit(self, stream: streams::Relative) -> varint::VarInt {
        match (stream.direction(), stream.is_local()) {
            (Direction::Uni, true) => varint::VarInt::ZERO,
            (Direction::Uni, false) => self.0[2],
            (Direction::Bidi, true) => self.0[0],
            (Direction::Bidi, false) => self.0[1],
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<Limits>() == 3 * core::mem::size_of::<varint::VarInt>());
    assert!(core::mem::align_of::<Limits>() == core::mem::align_of::<varint::VarInt>());
};

use std::mem;

use crate::conn;
use crate::conn::stream;
use crate::errors;
use crate::stream::{Capacity, Recv};
use crate::wire::stream::Id;
use crate::wire::varint;
use conn::stream::{
    Error, Streams, resident,
    state::{streams, transmit},
};
use recv::map;
use transmit::Writer;

/// The single unbranded receive kernel used by the branded public API.
#[repr(transparent)]
pub(in crate::conn) struct Receive<'conn, const DOMAIN: u8, B: Recv, D: buffer::raw::Segment> {
    connection: &'conn mut conn::Machine<DOMAIN, B, D>,
}

struct Consumed<R> {
    value: R,
    id: Id,
    free: u64,
    retire: bool,
}

impl<'conn, const DOMAIN: u8, B: Recv, D: buffer::raw::Segment> Receive<'conn, DOMAIN, B, D> {
    pub(in crate::conn) fn new(conn: &'conn mut conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    fn finish<R, const CONNECTION: bool>(&mut self, done: Consumed<R>) -> R {
        let Consumed {
            value,
            id,
            free,
            retire,
        } = done;
        let ctrl = &mut self.connection.control;
        let state = &mut self.connection.streams.state;
        if CONNECTION && free != 0 {
            Update::new(state).release_conn(free, ctrl);
        }
        if retire {
            Update::new(state).close_recv(id, ctrl);
        }
        value
    }

    fn consume<R, const CONNECTION: bool>(
        &mut self,
        id: Id,
        absent: R,
        read: impl for<'map> FnOnce(map::Occupied<'map, B>) -> map::DeliveryRead<'map, B, R>,
    ) -> R {
        let done = {
            let ctrl = &mut self.connection.control;
            let Streams { state, events } = &mut self.connection.streams;
            let local = state.local();
            let stream::State {
                resident: table,
                receive: recv,
                ..
            } = state;
            let stream = streams::Relative::new(id, local);
            let base = recv.initial_stream_data.credit(stream);
            let mut slots = recv.map.parts();
            let map::Slot::Occupied(slot) = slots.entry(map::Id::new(id), table) else {
                return absent;
            };
            read(slot).finish(base, ctrl, table, events)
        };
        self.finish::<_, CONNECTION>(done)
    }

    pub(in crate::conn) fn recv(&mut self, id: Id, dst: &mut Vec<u8>) -> Result<usize, Capacity> {
        self.consume::<_, true>(id, Ok(0), |stream| stream.read(dst))
    }

    pub(in crate::conn) fn recv_owned(&mut self, id: Id) -> Result<Option<Vec<u8>>, Capacity> {
        self.consume::<_, true>(id, Ok(None), |stream| stream.read_owned())
    }

    pub(in crate::conn) fn recv_buffer(&mut self, id: Id) -> Option<B> {
        self.consume::<_, true>(id, None, |stream| stream.read_buffer())
    }

    #[inline]
    fn hold_slot(
        slot: map::Slot<'_, B>,
        ctrl: &mut conn::output::control::Pending,
        table: &mut stream::state::resident::Table,
        events: &mut stream::event::queue::Pending,
    ) -> Option<Consumed<(Option<map::Held<B>>, bool)>> {
        let map::Slot::Occupied(mut item) = slot else {
            return None;
        };
        let value = item.hold();
        Some(if value.0.is_none() && value.1 {
            map::DeliveryRead {
                slot: item,
                value,
                free: 0,
            }
            .finish(varint::VarInt::ZERO, ctrl, table, events)
        } else {
            Consumed {
                value,
                id: item.id(),
                free: 0,
                retire: false,
            }
        })
    }

    pub(in crate::conn) fn hold_parts(&mut self, id: Id) -> (Option<map::Held<B>>, bool) {
        let done = {
            let ctrl = &mut self.connection.control;
            let Streams { state, events } = &mut self.connection.streams;
            let stream::State {
                resident: table,
                receive: recv,
                ..
            } = state;
            let mut slots = recv.map.parts();
            let slot = slots.entry(map::Id::new(id), table);
            Self::hold_slot(slot, ctrl, table, events)
        };
        done.map_or((None, false), |done| self.finish::<_, false>(done))
    }

    pub(in crate::conn) fn try_hold(
        &mut self,
        local: resident::Local,
    ) -> Result<(Option<map::Held<B>>, bool), resident::Stale> {
        let done = {
            let ctrl = &mut self.connection.control;
            let Streams { state, events } = &mut self.connection.streams;
            let stream::State {
                resident: table,
                receive: recv,
                ..
            } = state;
            let mut slots = recv.map.parts();
            let slot = slots.try_prepared(local, table)?;
            Self::hold_slot(slot, ctrl, table, events)
        };
        Ok(done.map_or((None, false), |done| self.finish::<_, false>(done)))
    }

    pub(in crate::conn) fn stop(&mut self, id: Id, code: errors::Code) -> Result<(), Error> {
        let avail = Writer::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).stop_sending(
            id,
            code,
            avail,
            &mut self.connection.control,
        )
    }

    pub(in crate::conn) fn try_stop(
        &mut self,
        local: resident::Local,
        code: errors::Code,
    ) -> Result<(), resident::Error> {
        let id = self
            .connection
            .streams
            .state
            .resident
            .read()
            .try_id(local)
            .map_err(resident::Error::Stale)?;
        self.stop(id, code).map_err(resident::Error::Stream)
    }
}

const _: () = {
    use o3::buffer::resident::Shared;

    assert!(mem::size_of::<Receive<'_, 0, Vec<u8>, Shared<'_>>>() == mem::size_of::<usize>());
    assert!(mem::align_of::<Receive<'_, 0, Vec<u8>, Shared<'_>>>() == mem::align_of::<usize>());
    assert!(usize::BITS <= u64::BITS);
};
