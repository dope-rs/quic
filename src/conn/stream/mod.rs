pub mod access;
mod build;
pub mod event;
pub mod id;
pub mod recv;
pub mod resident;
pub mod send;
pub(crate) mod state;

use std::{marker, mem, ops};

pub use build::Build;
use control::owner;
use event::queue::{Lease, Pending, Popped, Record};
use o3::alloc::VecExt as _;
use o3::{alloc, base::num::bounded, buffer, depot::capacity::Shortage};
use resident::slot;
use state::{
    receive,
    receive::recv::map,
    resident::{Capacity, Table},
    streams, transmit,
};

use crate::{
    conn,
    conn::{
        life::options,
        machine::storage::capacity,
        output::{control, control::kind},
        stream::state::{receive::credits, streams::closed},
    },
    stream,
    stream::send::Overflow,
    wire::stream::{Direction, Id, Initiator},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    NotEstablished,
    PeerLimit,
    Allocation {
        error: alloc::Error,
        requested: usize,
    },
    Capacity,
    Chunks(Shortage),
    Demand(Overflow),
    IdOverflow,
    InvalidDirection,
    InvalidStream,
    ValueOutOfRange,
}

#[derive(Clone, PartialEq, Eq)]
pub enum SendOutcome<T> {
    Accepted,
    Blocked(T),
    Failed { owner: T, error: Error },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Writable,
    Readable {
        id: Id,
    },
    Reset {
        id: Id,
        error_code: crate::errors::Code,
    },
    Stopped {
        id: Id,
        error_code: crate::errors::Code,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoundEvent<'conn> {
    event: Event,
    key: Option<resident::Key>,
    invariant: marker::PhantomData<fn(&'conn mut ()) -> &'conn mut ()>,
}

impl<'conn> BoundEvent<'conn> {
    pub(in crate::conn) const fn new(event: Event, key: Option<resident::Key>) -> Self {
        Self {
            event,
            key,
            invariant: marker::PhantomData,
        }
    }

    pub const fn event(self) -> Event {
        self.event
    }

    pub const fn key(self) -> Option<resident::Key> {
        self.key
    }

    pub const fn handle(self) -> Option<resident::Handle<'conn>> {
        let id = match self.event {
            Event::Writable => return None,
            Event::Readable { id } | Event::Reset { id, .. } | Event::Stopped { id, .. } => id,
        };
        let Some(key) = self.key else {
            return None;
        };
        Some(resident::Handle::new(resident::Local::new(id, key)))
    }
}

#[derive(Clone, Copy)]
pub(super) enum Access {
    Receive,
    Send,
}

#[derive(Clone, Copy)]
pub(in crate::conn) struct Count(bounded::U32<0, { conn::MAX_STREAMS as u32 }>);

impl Count {
    pub(in crate::conn) const fn from_u64(value: u64) -> Option<Self> {
        Self::from_usize(value as usize)
    }

    pub(in crate::conn) const fn from_usize(value: usize) -> Option<Self> {
        const { assert!(conn::MAX_STREAMS <= u32::MAX as u64) };
        match bounded::U32::from_usize(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(in crate::conn) const fn get(self) -> usize {
        self.0.into_usize()
    }

    pub(in crate::conn) const fn bounded(self) -> bounded::U32<0, { conn::MAX_STREAMS as u32 }> {
        self.0
    }
}

#[derive(Clone, Copy)]
pub(in crate::conn) struct Capacities {
    resident: Capacity,
    send: slot::Capacity,
    receive: map::Limit,
    closed: closed::Plan,
}

impl Capacities {
    pub(in crate::conn) const fn new(local: [Count; 2], initial: [Count; 2]) -> Self {
        let closed = closed::Plan::new([local[0], initial[0], initial[1], initial[0]]);
        let send = slot::Capacity::new([local[0], local[1], initial[0]]);
        let receive = map::Limit::new([local[0], initial[0], initial[1]]);
        let resident = Capacity::new([local[0], local[1], initial[0], initial[1]]);
        Self {
            resident,
            send,
            receive,
            closed,
        }
    }
}

pub(super) struct Streams<B: stream::Recv, D: buffer::raw::Segment> {
    pub(super) state: State<B, D>,
    pub(super) events: Pending,
}

pub(super) struct State<B: stream::Recv, D: buffer::raw::Segment> {
    pub(super) resident: Table,
    pub(super) transmit: transmit::State<D>,
    pub(super) receive: receive::State<B>,
    pub(super) closed: closed::Set,
    pub(super) peer_initiated: Peer,
    pub(super) local_initiated: Local,
}

impl<B: stream::Recv, D: buffer::raw::Segment> ops::Deref for Streams<B, D> {
    type Target = State<B, D>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> ops::DerefMut for Streams<B, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

pub(super) struct Peer {
    opened_count: [u64; 2],
    pub(super) max: [bounded::U64<0, { conn::MAX_STREAM_COUNT }>; 2],
    pub(super) initial_max: [bounded::U64<0, { conn::MAX_STREAM_COUNT }>; 2],
    pub(super) closed: [u64; 2],
    pub(super) max_streams: [Option<owner::Key<kind::MaxStreams>>; 2],
}

impl Peer {
    fn new(initial: [Count; 2]) -> Self {
        let initial = initial.map(|value| bounded::U64::clamp(value.get() as u64));
        Self {
            opened_count: [0; 2],
            max: initial,
            initial_max: initial,
            closed: [0; 2],
            max_streams: [None; 2],
        }
    }

    fn is_open(&self, stream: streams::Relative) -> bool {
        stream.number() < *stream.direction().bind(&self.opened_count)
    }

    fn open_through(&mut self, stream: streams::Relative) {
        let dir = stream.direction();
        let count = stream.number().saturating_add(1);
        let opened = dir.bind_mut(&mut self.opened_count);
        *opened = (*opened).max(count);
    }
}

pub(super) struct Local {
    pub(super) next: [Id; 2],
    pub(super) peer_max: [u64; 2],
    pub(super) opened: [u64; 2],
    pub(super) active: [u64; 2],
    pub(super) capacity: [u64; 2],
}

impl Local {
    pub(in crate::conn) fn all_allowed(&self) -> bool {
        self.opened
            .iter()
            .zip(self.peer_max)
            .all(|(&opened, limit)| opened <= limit)
    }

    pub(in crate::conn) fn allows(&self, stream: streams::Relative) -> bool {
        !stream.is_local() || stream.number() < *stream.direction().bind(&self.peer_max)
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> Streams<B, D> {
    pub(super) fn try_new(
        local: Initiator,
        journal: capacity::Capacity<capacity::Stream>,
        flow: options::Flow<'_>,
        limits: options::Limits,
    ) -> Result<Self, Build> {
        use crate::conn::stream::state::transmit::queue;

        let meta = credits::Meta::try_new().map_err(Build::Origin)?;
        let Capacities {
            resident,
            send,
            receive,
            closed,
        } = limits.capacities();
        let [bidi_cap, uni_cap] = limits.local();
        let send_map = queue::Map::try_new(&limits, send)?;
        let recv_map =
            map::Map::try_new(receive, limits.recv_parts(), meta).map_err(Build::Receive)?;
        let closed = closed::Set::try_new(closed).map_err(Build::Closed)?;
        let events = Pending::try_new(limits.events()).map_err(Build::Events)?;
        let capacity = [bidi_cap.get() as u64, uni_cap.get() as u64];
        Ok(Self {
            state: State {
                resident: Table::try_new(resident).map_err(Build::Resident)?,
                transmit: transmit::State::new(
                    Vec::try_new(conn::STREAM_SCHEDULE_CAPACITY).map_err(Build::Schedule)?,
                    send_map,
                    journal,
                ),
                receive: receive::State {
                    map: recv_map,
                    connection_window: credits::Flow::new(flow.initial_data()),
                    initial_stream_data: receive::Limits::new([
                        flow.local_bidi(),
                        flow.remote_bidi(),
                        flow.stream_uni(),
                    ]),
                    max_data: None,
                },
                closed,
                peer_initiated: Peer::new(limits.peer()),
                local_initiated: Local {
                    next: match local {
                        Initiator::Client => [Id::from_u8(0), Id::from_u8(2)],
                        Initiator::Server => [Id::from_u8(1), Id::from_u8(3)],
                    },
                    peer_max: [0; 2],
                    opened: [0; 2],
                    active: [0; 2],
                    capacity,
                },
            },
            events,
        })
    }

    pub(in crate::conn) fn poll_event(&mut self) -> Option<Record> {
        loop {
            let popped = self.events.pop()?;
            if self.retire(popped) {
                return Some(popped.event());
            }
        }
    }

    pub(in crate::conn) fn finish_mux(&mut self, lease: Lease, accept: bool) {
        if let Some(popped) = self.events.finish(lease, accept) {
            self.retire(popped);
        }
    }

    fn retire(&mut self, popped: Popped) -> bool {
        let State {
            resident, receive, ..
        } = &mut self.state;
        match popped {
            Popped::Writable => {}
            Popped::Reset { key, id, .. } => {
                if let Some(key) = key {
                    let Some(event) = resident.event::<false>().held(key, id) else {
                        return false;
                    };
                    event.release();
                }
            }
            Popped::Readable { key, id, index } => {
                if !matches!(
                    receive.map.deliver(resident, key, index, id),
                    map::Delivery::Applied
                ) {
                    return false;
                }
            }
            Popped::Stopped { key, id, .. } => {
                let Some(event) = resident.event::<true>().held(key, id) else {
                    return false;
                };
                event.release();
            }
        }
        true
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> State<B, D> {
    pub(in crate::conn) const fn local(&self) -> Initiator {
        self.local_initiated.next[0].initiator()
    }

    pub(in crate::conn) fn validate(&self, id: Id, access: Access) -> Result<(), conn::Error> {
        if !self.can_access(id, access) {
            return Err(conn::Error::StreamState);
        }
        Ok(())
    }

    pub(in crate::conn) fn try_peer(&self, id: Id, access: Access) -> Result<(), conn::Error> {
        let stream = streams::Relative::new(id, self.local());
        if stream.is_local() {
            return self.validate(id, access);
        }
        let dir = stream.direction();
        if matches!(dir, Direction::Uni) && matches!(access, Access::Send) {
            return Err(conn::Error::StreamState);
        }
        if stream.number() >= dir.bind(&self.peer_initiated.max).get() {
            return Err(conn::Error::StreamLimit);
        }
        Ok(())
    }

    pub(in crate::conn) fn can_access(&self, id: Id, access: Access) -> bool {
        let stream = streams::Relative::new(id, self.local());
        let dir = stream.direction();
        if stream.is_local() {
            let opened = stream.number() < *dir.bind(&self.local_initiated.opened);
            if !opened || matches!(dir, Direction::Uni) && matches!(access, Access::Receive) {
                return false;
            }
        } else if !self.peer_initiated.is_open(stream)
            || matches!(dir, Direction::Uni) && matches!(access, Access::Send)
        {
            return false;
        }
        true
    }

    pub(in crate::conn) fn is_recv_done(&self, id: Id) -> bool {
        closed::Half::try_receive(id, self.local()).is_some_and(|half| self.closed.contains(half))
    }

    pub(in crate::conn) fn is_send_done(&self, id: Id) -> bool {
        closed::Half::try_send(id, self.local()).is_some_and(|half| self.closed.contains(half))
    }
}

const _: () = assert!(mem::size_of::<Event>() == 3 * mem::size_of::<u64>());
const _: () = assert!(mem::size_of::<BoundEvent<'static>>() == 4 * mem::size_of::<u64>());
const _: () = assert!(mem::size_of::<Capacities>() == 5 * mem::size_of::<u32>());
const _: () = assert!(mem::size_of::<Peer>() == 10 * mem::size_of::<u64>());
const _: () = {
    use o3::buffer::resident::Shared;

    assert!(mem::size_of::<Streams<Vec<u8>, Shared<'static>>>() == 109 * mem::size_of::<usize>());
    assert!(mem::size_of::<State<Vec<u8>, Shared<'static>>>() == 103 * mem::size_of::<usize>());
};
