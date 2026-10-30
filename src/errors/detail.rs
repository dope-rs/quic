use dope::manifold::network::datagram::packet;
use o3::{
    alloc,
    base::num::bounded,
    buffer::{
        storage,
        write::{consume, spans},
    },
    depot::capacity,
    mem::rc,
};
use std::collections::TryReserveError;
use storage::range;

use crate::{
    conn::{
        self,
        stream::{Error, resident},
    },
    stream,
    wire::{
        frame, ranges,
        stream::{Direction, Id},
        varint,
    },
};

#[derive(Clone, Debug)]
pub enum Receive {
    Access(conn::Error),
    Peer {
        number: u64,
        limit: bounded::U64<0, { conn::MAX_STREAM_COUNT }>,
        direction: Direction,
    },
    Flow {
        end: u64,
        limit: varint::VarInt,
    },
    Final {
        end: u64,
        high: u64,
        known: Option<u64>,
        cause: Final,
    },
    Range(Ranges),
    Payload(Payload),
    Bytes {
        current: usize,
        additional: usize,
    },
}

#[derive(Clone, Debug)]
pub enum Final {
    Stream(frame::Boundary),
    Reset,
}

#[derive(Clone, Copy, Debug)]
pub enum Slot {
    Receive,
    Send,
    Resident,
}

#[derive(Clone, Debug)]
pub enum Plan {
    Access(conn::Error),
    Payload(Payload),
    Receive(Receive),
    Bytes {
        current: usize,
        additional: usize,
        limit: usize,
    },
    Capacity {
        slot: Slot,
        needed: usize,
        available: usize,
    },
    Credit {
        current: u64,
        additional: u64,
    },
    Datagram {
        len: usize,
        length: frame::Length,
        maximum: Option<u64>,
    },
    Flow(Flow),
}

impl From<conn::Error> for Plan {
    fn from(error: conn::Error) -> Self {
        Self::Access(error)
    }
}

impl From<Payload> for Plan {
    fn from(error: Payload) -> Self {
        Self::Payload(error)
    }
}

impl From<Receive> for Plan {
    fn from(error: Receive) -> Self {
        Self::Receive(error)
    }
}

impl From<Flow> for Plan {
    fn from(error: Flow) -> Self {
        Self::Flow(error)
    }
}

impl Plan {
    pub(crate) fn close_code(&self) -> Option<conn::Error> {
        match self {
            Self::Payload(_)
            | Self::Bytes { .. }
            | Self::Capacity { .. }
            | Self::Receive(Receive::Range(_) | Receive::Payload(_) | Receive::Bytes { .. }) => {
                None
            }
            Self::Datagram { .. } => Some(conn::Error::ProtocolViolation),
            Self::Receive(Receive::Peer { .. }) => Some(conn::Error::StreamLimit),
            Self::Credit { .. } | Self::Flow(_) | Self::Receive(Receive::Flow { .. }) => {
                Some(conn::Error::FlowControl)
            }
            Self::Receive(Receive::Final { .. }) => Some(conn::Error::FinalSize),
            Self::Access(error) | Self::Receive(Receive::Access(error)) => Some(error.clone()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Diagnostic {
    Plan(Plan),
    Preparation(Preparation),
    Datagram(Unavailable),
    Streams(Streams),
    Send { id: Id, error: Error },
    Peer(capacity::Reason),
}

#[derive(Clone, Debug)]
pub struct Payload {
    pub actual: usize,
}

impl Payload {
    pub(crate) const fn new(actual: usize) -> Self {
        Self { actual }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub current: u64,
    pub count: u64,
    pub limit: varint::VarInt,
}

#[derive(Clone, Debug)]
pub enum Ranges {
    Ranges {
        current: usize,
        additional: usize,
        capacity: usize,
    },
}

#[derive(Clone, Debug)]
pub enum Preparation {
    Retention(packet::Cause),
    Storage(storage::AllocError),
    Copy(Copying),
    Incomplete(spans::Gap),
}

#[derive(Clone, Debug)]
pub enum Copying {
    Projection(frame::Projection),
    Capacity(consume::Error),
    Range(stream::Capacity),
}

impl From<frame::Projection> for Copying {
    fn from(error: frame::Projection) -> Self {
        Self::Projection(error)
    }
}

impl From<consume::Error> for Copying {
    fn from(error: consume::Error) -> Self {
        Self::Capacity(error)
    }
}

#[derive(Clone, Debug)]
pub enum Unavailable {
    Allocation {
        error: alloc::Error,
        requested: usize,
    },
    Queue {
        error: TryReserveError,
        requested: usize,
    },
    Backing(Backing),
}

#[derive(Clone, Debug)]
pub enum Backing {
    Capacity(stream::Capacity),
    Body(frame::Projection),
    Payload(Projection),
}

#[derive(Clone, Debug)]
pub enum Projection {
    Start { base: usize, offset: usize },
    End { base: usize, offset: usize },
    Driver(Retention),
    Compact(range::Error),
    CompactRetain(rc::Error),
}

#[derive(Clone, Debug)]
pub enum Scope<E> {
    Stale(resident::Stale),
    Slot {
        id: Id,
    },
    Full {
        id: Id,
    },
    Identity {
        expected: Id,
        actual: Id,
    },
    Prepare {
        id: Id,
        error: E,
    },
    Slots {
        current: capacity::Count,
        additional: capacity::Count,
    },
}

#[derive(Clone, Debug)]
pub enum Streams {
    Receiver(Scope<Stream>),
    Slots(capacity::Shortage),
}

#[derive(Clone, Debug)]
pub enum Stream {
    Backing { frame: usize, error: Backing },
    Range(ranges::Error),
}

impl From<ranges::Error> for Stream {
    fn from(error: ranges::Error) -> Self {
        Self::Range(error)
    }
}

#[derive(Clone, Debug)]
pub enum Retention {
    Range(range::Error),
    Retain(rc::Error),
}
