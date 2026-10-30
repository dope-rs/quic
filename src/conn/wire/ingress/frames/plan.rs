use crate::errors::detail;
use o3::buffer::{self, resident};
use std::{marker, mem, num::NonZero, ops};

use crate::conn;
use crate::conn::stream::{
    State,
    state::{receive, transmit},
};
use crate::conn::wire::{crypto::chunks, ingress, scratch};
use crate::stream;
use crate::wire::frame::{self, ack::ranges};
use crate::wire::stream::Initiator;
use frames::{record, sources};
use ingress::frames;
use receive::{credits, planner};

/// Packet-wide receive preflight bound to the borrowed stream state.
#[derive(Clone, Copy)]
pub struct CommitPermit<'commit> {
    brand: marker::PhantomData<fn(&'commit mut ()) -> &'commit mut ()>,
}

/// Parsing accounts for payloads while the initialized record owner admits rows.
pub(super) struct Build {
    bytes: usize,
    dgrams: usize,
    max: Option<u64>,
}

impl Build {
    fn try_bytes(current: usize, add: usize) -> Result<usize, detail::Plan> {
        let limit = u16::MAX as usize;
        let Some(total) = current.checked_add(add) else {
            return Err(detail::Plan::Bytes {
                current,
                additional: add,
                limit,
            });
        };
        if total > limit {
            return Err(detail::Plan::Bytes {
                current,
                additional: add,
                limit,
            });
        }
        Ok(total)
    }

    pub(super) fn new(dgrams: usize, max: Option<u64>) -> Self {
        Self {
            bytes: 0,
            dgrams,
            max,
        }
    }

    pub(super) fn try_record<'id>(
        &mut self,
        slot: record::Vacant<'_, '_, '_, 'id, '_, '_, '_, '_>,
        body: &frame::Body<'_, 'id>,
        kind: frames::PacketKind,
        local: Initiator,
        frame: frame::Frame<ops::Range<usize>, ranges::Proof<'id>>,
        used: NonZero<usize>,
    ) -> Result<(), detail::Plan> {
        let admitted = record::Admitted::new(kind, local, frame)?;
        if let frame::View::Datagram { length, data } = admitted.frame().view()
            && self.max.is_none_or(|max| used.get() as u64 > max)
        {
            return Err(detail::Plan::Datagram {
                len: data.len(),
                length,
                maximum: self.max,
            });
        }
        let mut record = record::FrameRecord::new(admitted, body);
        if kind.is_app()
            && self.dgrams != 0
            && let Some(datagram) = record.datagram_mut()
        {
            let accepted = datagram.len();
            let dgrams = self.dgrams.checked_sub(1).ok_or(detail::Plan::Datagram {
                len: accepted,
                length: datagram.length(),
                maximum: self.max,
            })?;
            datagram.admit()?;
            self.bytes = Self::try_bytes(self.bytes, accepted)?;
            self.dgrams = dgrams;
        }
        slot.insert(record, kind.is_app())
    }
}

/// One body, its initialized records, and the remaining disjoint scratch fields.
pub(super) struct Plan<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send> {
    work: &'a mut scratch::Buffers,
    body: frame::Body<'wire, 'id>,
    records: record::Records<'a, 'f, 'slots, 'id, 'r, 'recv, 's, 'send>,
    bytes: usize,
}

pub(super) struct Reserved<
    'a,
    'wire,
    'f,
    'slots,
    'id,
    'r,
    'recv,
    's,
    'send,
    'state,
    B: stream::Recv,
    D: buffer::raw::Segment,
> {
    plan: Plan<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send>,
    streams: receive::Update<'state, B, D>,
    events: usize,
    credit: credits::Recorded,
}

pub(super) struct Prepared<
    'a,
    'wire,
    'f,
    'slots,
    'id,
    'r,
    'recv,
    's,
    'send,
    'state,
    'crypto,
    B: stream::Recv,
    D: buffer::raw::Segment,
> {
    work: &'a mut scratch::Buffers,
    input: sources::Preparation<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto>,
    streams: receive::Update<'state, B, D>,
    credit: credits::Recorded,
}

impl<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send>
    Plan<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send>
{
    pub(super) fn new(
        work: &'a mut scratch::Buffers,
        body: frame::Body<'wire, 'id>,
        records: record::Records<'a, 'f, 'slots, 'id, 'r, 'recv, 's, 'send>,
        build: Build,
    ) -> Self {
        Self {
            work,
            body,
            records,
            bytes: build.bytes,
        }
    }

    pub(super) fn try_reserve<'state, B: stream::Recv, D: buffer::raw::Segment>(
        mut self,
        streams: &'state mut State<B, D>,
    ) -> Result<
        Reserved<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'state, B, D>,
        detail::Plan,
    > {
        let mut streams = receive::Update::new(streams);
        self.records.sort();
        let segments = &mut self.work.segments;
        let parts = &mut self.work.parts;
        let mut bytes = self.bytes;
        let mut recv_n = 0usize;
        let mut send_n = 0usize;
        let mut resident = 0usize;
        let mut events = 0usize;
        let mut credit = 0u64;

        self.records.try_receives(|group| {
            let id = group.id();
            let impact = planner::Planner::new(&streams)
                .try_plan(group, planner::Plan::new(segments, parts))?;
            bytes = Build::try_bytes(bytes, impact.accepted_bytes)?;
            recv_n += impact.stream_slots;
            resident +=
                usize::from(impact.stream_slots != 0 && streams.resident.read().key(id).is_none());
            events += impact.event_slots;
            credit = credit
                .checked_add(impact.flow_control_bytes)
                .ok_or(detail::Plan::Credit {
                    current: credit,
                    additional: impact.flow_control_bytes,
                })?;
            Ok::<_, detail::Plan>(())
        })?;

        self.records.try_sends(|mut group| {
            let id = group.id();
            let slots = if group.has_stop() {
                let impact = transmit::Commit::new(&mut streams).plan_stop(id)?;
                if impact.active {
                    group.admit_stops(impact.key);
                }
                events += impact.event_slots;
                impact.stream_slots
            } else {
                transmit::Commit::new(&mut streams).plan_credit(id)?
            };
            send_n += slots;
            if slots != 0 && streams.resident.read().key(id).is_none() {
                resident += usize::from(group.receive().is_none());
            }
            Ok::<_, detail::Plan>(())
        })?;

        let cap = streams.receive.map.parts().available();
        if recv_n > cap {
            return Err(detail::Plan::Capacity {
                slot: detail::Slot::Receive,
                needed: recv_n,
                available: cap,
            });
        }
        let cap = streams.transmit.map().view().vacancy();
        if send_n > cap {
            return Err(detail::Plan::Capacity {
                slot: detail::Slot::Send,
                needed: send_n,
                available: cap,
            });
        }
        let cap = streams.resident.read().available();
        if resident > cap {
            return Err(detail::Plan::Capacity {
                slot: detail::Slot::Resident,
                needed: resident,
                available: cap,
            });
        }
        let mut flow = streams.receive.connection_window;
        let credit = flow.try_record(credit)?;
        self.bytes = bytes;

        Ok(Reserved {
            plan: self,
            streams,
            events,
            credit,
        })
    }
}

impl<
    'a,
    'wire,
    'f,
    'slots,
    'id,
    'r,
    'recv,
    's,
    'send,
    'state,
    B: stream::Recv,
    D: buffer::raw::Segment,
> Reserved<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'state, B, D>
{
    pub(super) const fn bytes(&self) -> usize {
        self.plan.bytes
    }
    pub(super) const fn events(&self) -> usize {
        self.events
    }

    pub(super) fn prepare<'crypto>(
        self,
        spaces: &'crypto mut chunks::Spaces,
        epoch: conn::Epoch,
    ) -> Result<
        Prepared<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'state, 'crypto, B, D>,
        chunks::Failure,
    > {
        let input = sources::Preparation::try_new(
            self.plan.records,
            self.plan.body,
            spaces,
            epoch,
            &mut self.plan.work.crypto,
        )?;
        Ok(Prepared {
            work: self.plan.work,
            input,
            streams: self.streams,
            credit: self.credit,
        })
    }
}

impl<
    'a,
    'wire,
    'f,
    'slots,
    'id,
    'r,
    'recv,
    's,
    'send,
    'state,
    'crypto,
    B: stream::Recv,
    D: buffer::raw::Segment,
> Prepared<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'state, 'crypto, B, D>
{
    pub(super) fn commit<R>(
        mut self,
        apply: impl for<'commit> FnOnce(
            &'commit mut scratch::Buffers,
            sources::Preparation<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto>,
            &'commit mut receive::Update<'state, B, D>,
            credits::Recorded,
            CommitPermit<'commit>,
        ) -> R,
    ) -> R {
        apply(
            self.work,
            self.input,
            &mut self.streams,
            self.credit,
            CommitPermit {
                brand: marker::PhantomData,
            },
        )
    }
}

const _: () = assert!(
    mem::size_of::<Reserved<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, Vec<u8>, resident::Shared<'_>>>(
    ) == mem::size_of::<Plan<'_, '_, '_, '_, '_, '_, '_, '_, '_>>() + 3 * mem::size_of::<usize>()
);
const _: () = assert!(
    mem::size_of::<
        Prepared<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, Vec<u8>, resident::Shared<'_>>,
    >() == mem::size_of::<sources::Preparation<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_>>()
        + 3 * mem::size_of::<usize>()
);
const _: () = assert!(mem::size_of::<CommitPermit<'_>>() == 0);
const _: () = assert!(!mem::needs_drop::<CommitPermit<'_>>());
const _: () = assert!(conn::MAX_FRAMES_PER_PACKET <= usize::MAX / crate::wire::ranges::MAX);
const _: () = assert!(usize::BITS <= u64::BITS);
