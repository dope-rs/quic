use o3::buffer;

use crate::errors::detail;
use crate::errors::detail::{Final, Receive};
use std::ops::ControlFlow;
use std::{convert::Infallible, mem, ops};

use o3::buffer::write::{self, Sink as _};

use crate::conn::stream::{
    Access, State,
    state::{receive::recv, streams},
};
use crate::conn::wire::ingress::frames::{self, record};
use crate::stream;
use crate::wire::frame;
use crate::wire::ranges::{inserts, plan};
use recv::map;

pub(in crate::conn) struct Planner<'a, B: stream::Recv, D: buffer::raw::Segment> {
    state: &'a State<B, D>,
}

impl<'a, B: stream::Recv, D: buffer::raw::Segment> Planner<'a, B, D> {
    pub(in crate::conn) fn new(state: &'a State<B, D>) -> Self {
        Self { state }
    }
}
impl<B: stream::Recv, D: buffer::raw::Segment> ops::Deref for Planner<'_, B, D> {
    type Target = State<B, D>;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}
pub(in crate::conn) struct Impact {
    pub(in crate::conn) accepted_bytes: usize,
    pub(in crate::conn) stream_slots: usize,
    pub(in crate::conn) event_slots: usize,
    pub(in crate::conn) flow_control_bytes: u64,
}

impl Impact {
    const fn none() -> Self {
        Self {
            accepted_bytes: 0,
            stream_slots: 0,
            event_slots: 0,
            flow_control_bytes: 0,
        }
    }
}

pub(in crate::conn) struct Plan<'a> {
    segments: &'a mut Vec<ops::Range<u64>>,
    parts: &'a mut Vec<inserts::Part>,
}

impl<'a> Plan<'a> {
    pub(in crate::conn) fn new(
        segs: &'a mut Vec<ops::Range<u64>>,
        parts: &'a mut Vec<inserts::Part>,
    ) -> Self {
        Self {
            segments: segs,
            parts,
        }
    }
}

pub(in crate::conn) struct Commit<'a, 'wire, 'body, 'target, 'commit> {
    segments: &'a mut Vec<ops::Range<u64>>,
    parts: &'a mut Vec<inserts::Part>,
    body: frame::Body<'wire, 'body>,
    output: &'a mut write::Spare<'target>,
    permit: frames::CommitPermit<'commit>,
}

impl<'a, 'wire, 'body, 'target, 'commit> Commit<'a, 'wire, 'body, 'target, 'commit> {
    pub(in crate::conn) fn new(
        segs: &'a mut Vec<ops::Range<u64>>,
        parts: &'a mut Vec<inserts::Part>,
        body: frame::Body<'wire, 'body>,
        out: &'a mut write::Spare<'target>,
        permit: frames::CommitPermit<'commit>,
    ) -> Self {
        Self {
            segments: segs,
            parts,
            body,
            output: out,
            permit,
        }
    }
}
impl<B: stream::Recv, D: buffer::raw::Segment> Planner<'_, B, D> {
    pub(in crate::conn) fn try_plan(
        &self,
        mut frames: record::Group<'_, '_, '_, '_>,
        ctx: Plan<'_>,
    ) -> Result<Impact, Receive> {
        let id = frames.id();
        let Plan {
            segments: segs,
            parts,
        } = ctx;
        let will = frames
            .records()
            .any(|rec| matches!(rec.view(), frame::View::ResetStream { .. }));
        let stream = streams::Relative::new(id, self.local());
        if stream.is_local() {
            self.validate(id, Access::Receive)
                .map_err(Receive::Access)?;
        } else {
            let number = stream.number();
            let dir = stream.direction();
            let limit = *dir.bind(&self.peer_initiated.max);
            if number >= limit.get() {
                return Err(Receive::Peer {
                    number,
                    limit,
                    direction: dir,
                });
            }
        }
        if self.is_recv_done(id) {
            return Ok(Impact::none());
        }
        let recv = &self.receive;
        let found = self.resident.read().key(id).and_then(|key| {
            recv.map
                .find_key(key, &self.resident)
                .map(|stream| (key, stream))
        });
        if found
            .as_ref()
            .is_some_and(|entry| entry.1.state().reset_error().is_some())
        {
            return Ok(Impact::none());
        }

        let base = self.receive.initial_stream_data.credit(stream);
        let seen = found
            .as_ref()
            .map_or(0, |entry| entry.1.state().delivered_to());
        let (key, limit, mut high, mut size, mut queued, mut exists, mut plan) = match found {
            Some((key, slot)) => (
                Some(key),
                slot.state().credit.limit(base),
                slot.state().high(),
                slot.state().final_size(),
                slot.has_event(),
                true,
                (!will)
                    .then(|| slot.try_plan(segs, parts))
                    .transpose()
                    .map_err(Receive::Range)?,
            ),
            None => (
                None,
                base,
                0,
                None,
                false,
                false,
                (!will).then(|| plan::Plan::empty(segs, parts)),
            ),
        };
        let prior = high;
        let mut bytes = 0usize;
        let mut slots = 0;
        let mut events = 0;
        let flow = frames.try_for_each(|_, entry| {
            match entry {
                Some(record::Receive::Stream(mut rec)) => {
                    let offset = rec.offset();
                    let len = rec.len();
                    let boundary = rec.boundary();
                    let Some(payload) = plan::Record::full(len) else {
                        return Err(Receive::Payload(detail::Payload::new(len)));
                    };
                    let end = payload.end(offset);
                    if end > limit.get() {
                        return Err(Receive::Flow { end, limit });
                    }
                    if size.is_some_and(|known| {
                        end > known || matches!(boundary, frame::Boundary::End) && end != known
                    }) || matches!(boundary, frame::Boundary::End) && end < high
                    {
                        return Err(Receive::Final {
                            end,
                            high,
                            known: size,
                            cause: Final::Stream(boundary),
                        });
                    }
                    let added = match &mut plan {
                        Some(plan) => {
                            let add = plan.try_insert(offset, payload).map_err(Receive::Range)?;
                            Some(add)
                        }
                        None => None,
                    };
                    let used = added.as_ref().map_or(0, |add| add.bytes());
                    bytes = bytes.checked_add(used).ok_or(Receive::Bytes {
                        current: bytes,
                        additional: used,
                    })?;
                    high = high.max(end);
                    if matches!(boundary, frame::Boundary::End) {
                        size = Some(end);
                    }
                    if !exists {
                        exists = true;
                        slots = 1;
                    }
                    if (len != 0 || matches!(boundary, frame::Boundary::End)) && !queued {
                        queued = true;
                        events = 1;
                    }
                    if let Some(added) = added.as_ref() {
                        rec.admit(key, added);
                    } else {
                        rec.seen(key, payload);
                    }
                }
                Some(record::Receive::Reset(mut rec)) => {
                    let reset = rec.final_size().get();
                    if reset > limit.get() {
                        return Err(Receive::Flow { end: reset, limit });
                    }
                    if reset < high || size.is_some_and(|known| known != reset) {
                        return Err(Receive::Final {
                            end: reset,
                            high,
                            known: size,
                            cause: Final::Reset,
                        });
                    }
                    high = reset;
                    if !queued {
                        events = 1;
                    }
                    rec.admit(key, reset - seen);
                    return Ok(ControlFlow::Break(None));
                }
                None => return Ok(ControlFlow::Break(Some(Impact::none()))),
            }
            Ok(ControlFlow::Continue(()))
        })?;
        if let ControlFlow::Break(Some(impact)) = flow {
            return Ok(impact);
        }
        Ok(Impact {
            accepted_bytes: bytes,
            stream_slots: slots,
            event_slots: events,
            flow_control_bytes: high - prior,
        })
    }

    pub(in crate::conn) fn commit(
        &self,
        mut frames: record::Group<'_, '_, '_, '_>,
        ctx: Commit<'_, '_, '_, '_, '_>,
    ) -> Result<(), detail::Copying> {
        let id = frames.id();
        let Commit {
            segments: segs,
            parts,
            body,
            output: out,
            permit,
        } = ctx;
        if !frames
            .records()
            .any(|rec| matches!(rec.operation(), record::Operation::Stream { .. }))
        {
            return Ok(());
        }
        let recv = &self.receive;
        let mut plan = match recv.map.find(map::Id::new(id), &self.resident) {
            Some(slot) => slot
                .try_plan(segs, parts)
                .map_err(|error| detail::Copying::Range(error.into()))?,
            None => plan::Plan::empty(segs, parts),
        };

        match frames.try_for_each::<Infallible, detail::Copying>(|_, entry| {
            let Some(record::Receive::Stream(mut rec)) = entry else {
                return Ok(ControlFlow::Continue(()));
            };
            let Some(mut stored) = rec.stored_mut() else {
                return Ok(ControlFlow::Continue(()));
            };
            let offset = stored.offset();
            let data = stored.data().clone();
            let record = stored.record();
            let base = out.len();
            stored.set_start(permit, base);
            let mut copy: Result<(), detail::Copying> = Ok(());
            let result = record.try_copy(&mut plan, offset, |range| {
                copy = mem::replace(&mut copy, Ok(())).and_then(|()| {
                    out.write_slice(body.part(&data, range)?)?;
                    Ok(())
                });
            });
            copy?;
            result.map_err(detail::Copying::Range)?;
            Ok(ControlFlow::Continue(()))
        })? {
            ControlFlow::Continue(()) => (),
            ControlFlow::Break(never) => match never {},
        }
        Ok(())
    }
}

const _: () = assert!(
    mem::size_of::<Planner<'_, Vec<u8>, o3::buffer::resident::Shared<'_>>>()
        == mem::size_of::<usize>()
);
const _: () = assert!(usize::BITS <= u64::BITS);
const _: () = assert!(mem::size_of::<Commit<'_, '_, '_, '_, '_>>() == 5 * mem::size_of::<usize>());
