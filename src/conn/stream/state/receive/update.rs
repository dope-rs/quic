use std::{mem, ops};

use o3::{base::num::bounded, buffer};
use recv::map;

use crate::{
    conn::{
        self,
        output::{
            control,
            control::journal::{self, records},
            delivery,
        },
        stream,
        stream::{
            event::queue,
            state::{
                receive::{input, recv},
                streams,
                streams::closed,
                transmit::log::Ack,
            },
        },
        wire::ingress::frames::CommitPermit,
    },
    stream::release,
    wire::{
        frame,
        stream::{Direction, Id},
    },
};

pub(in crate::conn) struct Update<'state, B: crate::stream::Recv, D: buffer::raw::Segment> {
    state: &'state mut stream::State<B, D>,
}

impl<'state, B: crate::stream::Recv, D: buffer::raw::Segment> Update<'state, B, D> {
    pub(in crate::conn) fn new(state: &'state mut stream::State<B, D>) -> Self {
        Self { state }
    }
}

impl<B: crate::stream::Recv, D: buffer::raw::Segment> ops::Deref for Update<'_, B, D> {
    type Target = stream::State<B, D>;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl<B: crate::stream::Recv, D: buffer::raw::Segment> ops::DerefMut for Update<'_, B, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state
    }
}

fn try_close(
    id: Id,
    local: &stream::Local,
    closed: &closed::Set,
) -> Option<(streams::Relative, Direction, Option<u64>)> {
    let role = local.next[0].initiator();
    let stream = streams::Relative::new(id, role);
    let dir = stream.direction();
    let done = stream.is_local()
        && (matches!(dir, Direction::Uni)
            || closed::Half::try_receive(id, role).is_some_and(|half| closed.contains(half)));
    let count = if done {
        Some(dir.bind(&local.active).checked_sub(1)?)
    } else {
        None
    };
    Some((stream, dir, count))
}

impl<'state, B: crate::stream::Recv, D: buffer::raw::Segment> Update<'state, B, D> {
    pub(in crate::conn) fn release_conn(&mut self, count: u64, ctrl: &mut control::Pending) {
        let Some(max) = self.receive.connection_window.release(count) else {
            return;
        };
        match records::Records::new(ctrl).set_data(&mut self.receive.max_data, max) {
            Ok(()) => self.receive.map.clear_data(),
            Err(journal::Error::Vacant | journal::Error::Revision(_)) => {
                self.receive.map.mark_data();
            }
        }
    }

    pub(in crate::conn) fn open_peer(&mut self, id: Id) {
        let stream = streams::Relative::new(id, self.local());
        if !stream.is_local() {
            self.peer_initiated.open_through(stream);
        }
    }

    fn is_send_done(&self, id: Id, stream: streams::Relative) -> bool {
        if stream.is_local() {
            let opened = stream.number() < *stream.direction().bind(&self.local_initiated.opened);
            opened && self.transmit.map().find(id, &self.resident).is_none()
        } else {
            self.state.is_send_done(id)
        }
    }

    fn release_peer(&mut self, dir: Direction, ctrl: &mut control::Pending) {
        let Some(closed) = dir.bind(&self.peer_initiated.closed).checked_add(1) else {
            return;
        };
        let gate = (dir.bind(&self.peer_initiated.initial_max).get() / 2).max(1);
        if closed < gate {
            *dir.bind_mut(&mut self.peer_initiated.closed) = closed;
            return;
        }
        let current = *dir.bind(&self.peer_initiated.max);
        let Some(next) = current.get().checked_add(closed) else {
            return;
        };
        let next = bounded::U64::clamp(next);
        *dir.bind_mut(&mut self.peer_initiated.closed) = 0;
        if next > current {
            *dir.bind_mut(&mut self.peer_initiated.max) = next;
            let owner = dir.bind_mut(&mut self.peer_initiated.max_streams);
            match records::Records::new(ctrl).set_streams(owner, dir, next) {
                Ok(()) => self.receive.map.clear_stream(dir),
                Err(journal::Error::Vacant | journal::Error::Revision(_)) => {
                    self.receive.map.mark_streams(dir);
                }
            }
        }
    }

    pub(in crate::conn) fn close_recv(&mut self, id: Id, ctrl: &mut control::Pending) {
        let stream = streams::Relative::new(id, self.local());
        let dir = stream.direction();
        let local =
            stream.is_local() && matches!(dir, Direction::Bidi) && self.is_send_done(id, stream);
        let count = if local {
            let Some(count) = self.local_initiated.active[0].checked_sub(1) else {
                return;
            };
            Some(count)
        } else {
            None
        };
        let Some(half) = closed::Half::try_receive(id, self.local()) else {
            return;
        };
        if self.closed.insert(half) != closed::Insertion::Inserted {
            return;
        }
        if !stream.is_local() && (matches!(dir, Direction::Uni) || self.is_send_done(id, stream)) {
            self.release_peer(dir, ctrl);
        } else if let Some(count) = count {
            self.local_initiated.active[0] = count;
        }
    }

    pub(in crate::conn) fn commit_seen(
        &mut self,
        permit: &CommitPermit<'_>,
        frame: input::Input,
        events: &mut queue::Permit<'_>,
    ) {
        let input::Input {
            key,
            id,
            offset,
            plan,
            boundary,
        } = frame;
        if self.is_recv_done(id) {
            return;
        }
        let stream::State {
            resident: table,
            receive: recv,
            ..
        } = self.state;
        let mut slots = recv.map.parts();
        let Some(mut slot) = slots.prepared(map::Id::new(id), key, table).insert(table) else {
            return;
        };
        slot.observe(*permit, offset, plan, boundary);
        if plan.len() != 0 || matches!(boundary, frame::Boundary::End) {
            slot.push_read(events, table);
        }
    }

    pub(in crate::conn) fn commit_reset(
        &mut self,
        reset: input::Reset,
        ctrl: &mut control::Pending,
        events: &mut queue::Permit<'_>,
    ) {
        let input::Reset {
            key,
            id,
            code,
            end,
            free,
        } = reset;
        if self.is_recv_done(id) {
            return;
        }
        let stream::State {
            resident: table,
            receive: recv,
            ..
        } = self.state;
        let mut slots = recv.map.parts();
        let retire = match slots.prepared(map::Id::new(id), key, table) {
            map::Slot::Occupied(mut slot) => {
                slot.reset(code, end);
                slot.push_reset(events, table, code);
                match slot.try_reclaim() {
                    Ok(reclaim) => {
                        reclaim.remove(table, ctrl);
                        true
                    }
                    Err(slot) => {
                        slot.retain(ctrl);
                        false
                    }
                }
            }
            map::Slot::Vacant(_) => {
                events.reset_orphan(id, code);
                true
            }
            map::Slot::Unavailable => return,
        };
        self.release_conn(free, ctrl);
        if retire {
            self.close_recv(id, ctrl);
        }
    }

    pub(in crate::conn) fn retire_recv(
        &mut self,
        events: &mut queue::Pending,
        id: Id,
        ctrl: &mut control::Pending,
    ) {
        if self.is_recv_done(id) {
            return;
        }
        let stream::State {
            resident: table,
            receive: recv,
            ..
        } = self.state;
        let mut slots = recv.map.parts();
        let mut retire = true;
        if let map::Slot::Occupied(slot) = slots.entry(map::Id::new(id), table) {
            match slot.try_reclaim() {
                Ok(mut reclaim) => {
                    reclaim.cancel_read(events, table);
                    reclaim.remove(table, ctrl);
                }
                Err(slot) => {
                    slot.retain(ctrl);
                    retire = false;
                }
            }
        }
        if retire {
            self.close_recv(id, ctrl);
        }
    }

    pub(in crate::conn) fn acknowledge<E: release::Sink>(
        &mut self,
        events: &mut queue::Pending,
        handle: delivery::Handle<delivery::Stream>,
        ctrl: &mut control::Pending,
        evidence: &mut E,
    ) {
        let done = {
            let stream::State {
                resident: table,
                transmit: tx,
                local_initiated: local,
                closed,
                ..
            } = self.state;
            Ack::acknowledge(tx, handle, table, ctrl, events, evidence, |id| {
                try_close(id, local, closed)
            })
        };
        if let Some((id, close)) = done {
            self.retire_send(events, id, close, ctrl);
        }
    }

    pub(in crate::conn) fn retire_reset(
        &mut self,
        events: &mut queue::Pending,
        id: Id,
        ctrl: &mut control::Pending,
    ) -> Result<(), conn::Error> {
        let done = {
            let stream::State {
                resident: table,
                transmit: tx,
                local_initiated: local,
                closed,
                ..
            } = self.state;
            Ack::retire_reset(tx, id, table, ctrl, |id| try_close(id, local, closed))?
        };
        if let Some((id, close)) = done {
            self.retire_send(events, id, close, ctrl);
        }
        Ok(())
    }

    fn retire_send(
        &mut self,
        events: &mut queue::Pending,
        id: Id,
        close: (streams::Relative, Direction, Option<u64>),
        ctrl: &mut control::Pending,
    ) {
        let (stream, dir, count) = close;
        if stream.is_local() {
            if let Some(count) = count {
                *dir.bind_mut(&mut self.local_initiated.active) = count;
            }
        } else if matches!(dir, Direction::Bidi) {
            let closed = self.is_recv_done(id);
            let half = closed::Half::peer_send(id);
            if self.closed.insert(half) == closed::Insertion::Inserted && closed {
                self.release_peer(Direction::Bidi, ctrl);
            }
        }
        if self
            .receive
            .map
            .find(map::Id::new(id), &self.resident)
            .is_some_and(|item| item.state().is_eof() && item.state().reset_error().is_none())
        {
            self.retire_recv(events, id, ctrl);
        }
    }
}

const _: () = assert!(
    mem::size_of::<Update<'_, Vec<u8>, o3::buffer::resident::Shared<'_>>>()
        == mem::size_of::<usize>()
);
