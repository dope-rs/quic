use crate::stream::ReceiveBuffer;
use crate::varint::VarInt;

use crate::conn::receive_workspace::{
    ParsedFrame, ReceiveAdmission, ReceiveAdmissions, ReceivePayloadPlans, StreamFrameIndex,
};
use crate::conn::{Error, MAX_STREAM_COUNT, control, event_queue, recv, send, stream};
use crate::frame::Frame;
use crate::range_buffer::{MAX_RANGES, Plan};

use super::transmit::Transmit;
use super::{Access, State, Streams, table};
use crate::conn::control::Write as _;

const MAX_DATA_DIRTY: u8 = 1 << 0;
const MAX_STREAMS_BIDI_DIRTY: u8 = 1 << 1;
const MAX_STREAMS_UNI_DIRTY: u8 = 1 << 2;

const fn max_streams_dirty(kind: usize) -> u8 {
    [MAX_STREAMS_BIDI_DIRTY, MAX_STREAMS_UNI_DIRTY][kind]
}

impl super::ReceiveCredits {
    const fn any(&self) -> bool {
        self.0 != 0
    }

    const fn contains(&self, credit: u8) -> bool {
        self.0 & credit != 0
    }

    fn mark(&mut self, credit: u8) {
        self.0 |= credit;
    }

    fn clear(&mut self, credit: u8) {
        self.0 &= !credit;
    }
}

pub(in crate::conn) trait Incoming<B: ReceiveBuffer> {
    fn len(&self) -> usize;
    fn insert(
        self,
        stream: &mut crate::stream::RecvStream<B>,
        ranges: &mut crate::range_buffer::Arena<B>,
        parts: &mut Vec<(u64, std::ops::Range<usize>)>,
        offset: u64,
        fin: bool,
    ) -> Result<(), crate::stream::RecvError>;
}

pub(in crate::conn) struct Copied<'a>(pub(in crate::conn) &'a [u8]);

pub(in crate::conn) enum RetainedIncoming<'d> {
    Driver(crate::stream::RecvBuffer<'d>),
    Compact {
        bytes: o3::buffer::storage::Shared,
        original_len: usize,
    },
}

pub(in crate::conn) struct AdmissionImpact {
    pub(in crate::conn) accepted_bytes: usize,
    pub(in crate::conn) stream_slots: usize,
    pub(in crate::conn) range_slots: usize,
    pub(in crate::conn) event_slots: usize,
    pub(in crate::conn) flow_control_bytes: u64,
}

pub(in crate::conn) struct IncomingStream {
    stream_id: u64,
    offset: u64,
    fin: bool,
    is_client: bool,
}

impl IncomingStream {
    pub(in crate::conn) const fn new(
        stream_id: u64,
        offset: u64,
        fin: bool,
        is_client: bool,
    ) -> Self {
        Self {
            stream_id,
            offset,
            fin,
            is_client,
        }
    }
}

pub(in crate::conn) struct FrameGroup<'a> {
    frame_indices: &'a [StreamFrameIndex],
    parsed_frames: &'a [ParsedFrame],
}

impl<'a> FrameGroup<'a> {
    pub(in crate::conn) const fn new(
        frame_indices: &'a [StreamFrameIndex],
        parsed_frames: &'a [ParsedFrame],
    ) -> Self {
        Self {
            frame_indices,
            parsed_frames,
        }
    }
}

pub(in crate::conn) struct PlanContext<'a> {
    admissions: &'a mut ReceiveAdmissions,
    payloads: &'a mut ReceivePayloadPlans,
    segments: &'a mut Vec<std::ops::Range<u64>>,
    parts: &'a mut Vec<(u64, std::ops::Range<usize>)>,
    is_client: bool,
}

impl<'a> PlanContext<'a> {
    pub(in crate::conn) fn new(
        admissions: &'a mut ReceiveAdmissions,
        payloads: &'a mut ReceivePayloadPlans,
        segments: &'a mut Vec<std::ops::Range<u64>>,
        parts: &'a mut Vec<(u64, std::ops::Range<usize>)>,
        is_client: bool,
    ) -> Self {
        Self {
            admissions,
            payloads,
            segments,
            parts,
            is_client,
        }
    }
}

pub(in crate::conn) struct MaterializeContext<'a> {
    admissions: &'a ReceiveAdmissions,
    payloads: &'a mut ReceivePayloadPlans,
    segments: &'a mut Vec<std::ops::Range<u64>>,
    parts: &'a mut Vec<(u64, std::ops::Range<usize>)>,
    body: &'a [u8],
    output: &'a mut o3::buffer::storage::Owned,
}

impl<'a> MaterializeContext<'a> {
    pub(in crate::conn) fn new(
        admissions: &'a ReceiveAdmissions,
        payloads: &'a mut ReceivePayloadPlans,
        segments: &'a mut Vec<std::ops::Range<u64>>,
        parts: &'a mut Vec<(u64, std::ops::Range<usize>)>,
        body: &'a [u8],
        output: &'a mut o3::buffer::storage::Owned,
    ) -> Self {
        Self {
            admissions,
            payloads,
            segments,
            parts,
            body,
            output,
        }
    }
}

struct ReceiveControlDrain<'a, B: ReceiveBuffer> {
    streams: &'a mut State<B>,
    control: &'a mut control::Pending,
    remaining: usize,
}

impl<'a, B: ReceiveBuffer> ReceiveControlDrain<'a, B> {
    fn new(streams: &'a mut State<B>, control: &'a mut control::Pending, remaining: usize) -> Self {
        Self {
            streams,
            control,
            remaining,
        }
    }

    fn drain(self) {
        let Self {
            streams,
            control,
            mut remaining,
        } = self;
        if streams.receive_credits.contains(MAX_DATA_DIRTY) {
            if remaining == 0 {
                return;
            }
            let owner_live = control.owner_is_live(streams.receive.max_data);
            debug_assert!(!owner_live, "dirty MAX_DATA has no live control owner");
            let Some(mut permit) = control.try_reserve(1) else {
                return;
            };
            permit.queue_max_data(
                &mut streams.receive.max_data,
                streams.receive.local_max_data,
            );
            drop(permit);
            streams.receive_credits.clear(MAX_DATA_DIRTY);
            remaining -= 1;
        }

        for kind in 0..2 {
            let dirty = max_streams_dirty(kind);
            if !streams.receive_credits.contains(dirty) {
                continue;
            }
            if remaining == 0 {
                return;
            }
            let owner_live = control.owner_is_live(streams.peer_initiated.max_streams[kind]);
            debug_assert!(!owner_live, "dirty MAX_STREAMS has no live control owner");
            let Some(mut permit) = control.try_reserve(1) else {
                return;
            };
            permit.queue_max_streams(
                &mut streams.peer_initiated.max_streams[kind],
                kind != 0,
                streams.peer_initiated.max[kind],
            );
            drop(permit);
            streams.receive_credits.clear(dirty);
            remaining -= 1;
        }

        while remaining != 0 {
            let receive = &mut streams.receive;
            let Some(handle) = receive.control_schedule.front() else {
                break;
            };
            let (stream_id, max_stream_data_dirty) = receive
                .map
                .resolve(handle)
                .map(|(stream_id, stream)| (stream_id, stream.max_stream_data_dirty()))
                .expect("scheduled receive control retains a live stream owner");
            if max_stream_data_dirty {
                debug_assert!(
                    !control.owner_is_live(
                        receive
                            .map
                            .resolve(handle)
                            .expect("scheduled receive control retains its generation")
                            .1
                            .max_stream_data
                    ),
                    "dirty MAX_STREAM_DATA has no live control owner"
                );
                let Some(mut permit) = control.try_reserve(1) else {
                    break;
                };
                let (_, stream) = receive
                    .map
                    .resolve_mut(handle)
                    .expect("scheduled receive credit retains its generation");
                let stream_limit = stream.limit();
                permit.queue_max_stream_data(&mut stream.max_stream_data, stream_id, stream_limit);
                stream.clear_max_stream_data_dirty();
                drop(permit);
                remaining -= 1;
            }

            if remaining != 0 {
                let stop_error = receive
                    .map
                    .resolve(handle)
                    .expect("scheduled receive control retains its generation")
                    .1
                    .stop_sending
                    .deferred();
                if let Some(error) = stop_error {
                    let Some(mut permit) = control.try_reserve(1) else {
                        break;
                    };
                    let (_, stream) = receive
                        .map
                        .resolve_mut(handle)
                        .expect("scheduled STOP_SENDING retains its generation");
                    permit.queue_stop_sending(&mut stream.stop_sending, stream_id, error);
                    drop(permit);
                    remaining -= 1;
                }
            }

            let still_deferred = receive
                .map
                .resolve(handle)
                .expect("scheduled receive control retains its generation")
                .1
                .has_deferred_control();
            if still_deferred {
                break;
            }
            receive
                .control_schedule
                .deactivate(&mut receive.map, handle);
        }
    }
}

impl<B: ReceiveBuffer> Incoming<B> for Copied<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn insert(
        self,
        stream: &mut crate::stream::RecvStream<B>,
        ranges: &mut crate::range_buffer::Arena<B>,
        parts: &mut Vec<(u64, std::ops::Range<usize>)>,
        offset: u64,
        fin: bool,
    ) -> Result<(), crate::stream::RecvError> {
        B::insert_copied(stream, ranges, parts, offset, self.0, fin)
    }
}

impl<'d> Incoming<crate::stream::RecvBuffer<'d>> for RetainedIncoming<'d> {
    fn len(&self) -> usize {
        match self {
            Self::Driver(bytes) => bytes.len(),
            Self::Compact { original_len, .. } => *original_len,
        }
    }

    fn insert(
        self,
        stream: &mut crate::stream::RecvStream<crate::stream::RecvBuffer<'d>>,
        ranges: &mut crate::range_buffer::Arena<crate::stream::RecvBuffer<'d>>,
        parts: &mut Vec<(u64, std::ops::Range<usize>)>,
        offset: u64,
        fin: bool,
    ) -> Result<(), crate::stream::RecvError> {
        match self {
            Self::Driver(bytes) => stream.insert_retained(ranges, parts, offset, bytes, fin),
            Self::Compact {
                bytes,
                original_len,
            } => stream.insert_compact(ranges, parts, offset, original_len, bytes, fin),
        }
    }
}

impl<B: ReceiveBuffer> Incoming<B> for B {
    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn insert(
        self,
        stream: &mut crate::stream::RecvStream<B>,
        ranges: &mut crate::range_buffer::Arena<B>,
        parts: &mut Vec<(u64, std::ops::Range<usize>)>,
        offset: u64,
        fin: bool,
    ) -> Result<(), crate::stream::RecvError> {
        stream.insert(ranges, parts, offset, self, fin)
    }
}

impl<B: ReceiveBuffer> State<B> {
    pub(in crate::conn) fn receive_controls_pending(&self) -> bool {
        self.receive_credits.any() || !self.receive.control_schedule.is_empty()
    }

    pub(in crate::conn) fn receive_controls_sendable(&self, control: &control::Pending) -> bool {
        self.receive_controls_pending() && control.remaining_capacity() != 0
    }

    pub(in crate::conn) fn reconcile_receive_controls(
        &mut self,
        control: &mut control::Pending,
        work: usize,
    ) {
        ReceiveControlDrain::new(self, control, work).drain();
    }

    fn release_connection_receive_credit<C: control::Write>(
        &mut self,
        count: u64,
        control: &mut C,
    ) {
        self.receive.local_max_data = self.receive.local_max_data.saturating_add(count);
        if control.owner_is_live(self.receive.max_data) {
            control.queue_max_data(&mut self.receive.max_data, self.receive.local_max_data);
            self.receive_credits.clear(MAX_DATA_DIRTY);
        } else {
            self.receive_credits.mark(MAX_DATA_DIRTY);
        }
    }

    pub(in crate::conn) fn validate_or_open_peer_reserved(
        &mut self,
        stream_id: u64,
        access: Access,
        is_client: bool,
    ) -> Result<(), Error> {
        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == is_client;
        if we_initiated {
            return self.validate_access_reserved(stream_id, access, is_client);
        }
        if is_uni && matches!(access, Access::Send)
            || stream_id >> 2 >= self.peer_initiated.max[usize::from(is_uni)]
        {
            return Err(Error::ProtocolViolation);
        }
        self.peer_initiated.opened.open(stream_id);
        Ok(())
    }

    pub(in crate::conn) fn validate_access_reserved(
        &self,
        stream_id: u64,
        access: Access,
        is_client: bool,
    ) -> Result<(), Error> {
        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == is_client;
        if we_initiated {
            let opened = stream_id < self.local_initiated.next[usize::from(is_uni)];
            if !opened || is_uni && matches!(access, Access::Receive) {
                return Err(Error::ProtocolViolation);
            }
        } else if !self.peer_initiated.opened.contains(stream_id)
            || is_uni && matches!(access, Access::Send)
        {
            return Err(Error::ProtocolViolation);
        }
        Ok(())
    }

    fn receive_side_closed(&self, stream_id: u64, is_client: bool) -> bool {
        self.receive.retired.recv_contains(stream_id, is_client)
    }

    fn send_side_is_closed(&self, stream_id: u64, is_client: bool) -> bool {
        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == is_client;
        if we_initiated {
            let opened = stream_id < self.local_initiated.next[usize::from(is_uni)];
            opened && self.transmit.map.get(send::Id::new(stream_id)).is_none()
        } else {
            !is_uni && self.receive.retired.peer_bidi_send_contains(stream_id)
        }
    }

    fn initial_receive_credit(&self, stream_id: u64, is_client: bool) -> u64 {
        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == is_client;
        if is_uni {
            if we_initiated {
                0
            } else {
                self.receive.initial_stream_data[2]
            }
        } else if we_initiated {
            self.receive.initial_stream_data[0]
        } else {
            self.receive.initial_stream_data[1]
        }
    }

    fn release_peer_receive_credit<C: control::Write>(&mut self, is_uni: bool, control: &mut C) {
        let kind = usize::from(is_uni);
        self.peer_initiated.closed[kind] = self.peer_initiated.closed[kind].saturating_add(1);
        let threshold = (self.peer_initiated.initial_max[kind] / 2).max(1);
        if self.peer_initiated.closed[kind] < threshold {
            return;
        }
        let next = self.peer_initiated.max[kind]
            .saturating_add(self.peer_initiated.closed[kind])
            .min(MAX_STREAM_COUNT);
        self.peer_initiated.closed[kind] = 0;
        if next > self.peer_initiated.max[kind] {
            self.peer_initiated.max[kind] = next;
            if control.owner_is_live(self.peer_initiated.max_streams[kind]) {
                control.queue_max_streams(&mut self.peer_initiated.max_streams[kind], is_uni, next);
                self.receive_credits.clear(max_streams_dirty(kind));
            } else {
                self.receive_credits.mark(max_streams_dirty(kind));
            }
        }
    }

    fn finish_reserved_reset<C: control::Write>(
        &mut self,
        stream_id: u64,
        is_client: bool,
        control: &mut C,
    ) {
        let newly_closed = self
            .receive
            .retired
            .retire_recv(stream_id, is_client)
            .expect("retired receive ranges are bounded by live stream capacity");
        if !newly_closed {
            return;
        }
        let is_uni = stream_id & 0x2 != 0;
        let peer_initiated = (stream_id & 0x1 == 0) != is_client;
        if peer_initiated && (is_uni || self.send_side_is_closed(stream_id, is_client)) {
            self.release_peer_receive_credit(is_uni, control);
        } else if !peer_initiated && !is_uni && self.send_side_is_closed(stream_id, is_client) {
            let active = &mut self.local_initiated.active[0];
            debug_assert_ne!(*active, 0);
            *active = active.saturating_sub(1);
        }
    }

    pub(in crate::conn) fn ingest_stream_reserved<D: Incoming<B>>(
        &mut self,
        incoming: IncomingStream,
        data: D,
        parts: &mut Vec<(u64, std::ops::Range<usize>)>,
        events: &mut event_queue::Permit<'_>,
    ) -> Result<(), Error> {
        let IncomingStream {
            stream_id,
            offset,
            fin,
            is_client,
        } = incoming;
        if self.receive_side_closed(stream_id, is_client) {
            return Ok(());
        }
        let initial_limit = self.initial_receive_credit(stream_id, is_client);
        let data_len = data.len();
        let new_end = offset
            .checked_add(u64::try_from(data_len).map_err(|_| Error::StreamBufferExceeded)?)
            .ok_or(Error::StreamBufferExceeded)?;
        let receive = &mut self.receive;
        let (limit, previous_high, final_size, new_entry) = receive
            .map
            .get(recv::Id::new(stream_id))
            .map_or((initial_limit, 0, None, true), |stream| {
                (
                    stream.limit(),
                    stream.highest_offset(),
                    stream.final_size(),
                    false,
                )
            });
        if new_end > limit {
            return Err(Error::FlowControl);
        }
        if final_size.is_some_and(|final_size| new_end > final_size || fin && new_end != final_size)
            || fin && new_end < previous_high
        {
            return Err(Error::FinalSize);
        }
        let projected_total = receive
            .total
            .checked_add(new_end.saturating_sub(previous_high))
            .filter(|&total| total <= receive.local_max_data)
            .ok_or(Error::FlowControl)?;

        let (handle, stream, event_position) = receive
            .map
            .entry(recv::Id::new(stream_id))
            .or_insert_with_position(initial_limit)
            .expect("advertised active receive streams fit the fixed state index");
        if data
            .insert(stream, &mut receive.ranges, parts, offset, fin)
            .is_err()
        {
            if new_entry {
                stream.release_ranges(&mut receive.ranges);
                receive.map.remove(recv::Id::new(stream_id));
            }
            return Err(Error::StreamBufferExceeded);
        }
        receive.total = projected_total;
        if data_len != 0 || fin {
            events.push_readable(handle, event_position, stream_id);
        }
        Ok(())
    }

    pub(in crate::conn) fn ingest_stream_transient_reserved(
        &mut self,
        stream_id: u64,
        offset: u64,
        data_len: usize,
        fin: bool,
        is_client: bool,
        events: &mut event_queue::Permit<'_>,
    ) -> Result<(), Error> {
        if self.receive_side_closed(stream_id, is_client) {
            return Ok(());
        }
        let initial_limit = self.initial_receive_credit(stream_id, is_client);
        let new_end = offset
            .checked_add(u64::try_from(data_len).map_err(|_| Error::StreamBufferExceeded)?)
            .ok_or(Error::StreamBufferExceeded)?;
        let receive = &mut self.receive;
        let (limit, previous_high, final_size, new_entry) = receive
            .map
            .get(recv::Id::new(stream_id))
            .map_or((initial_limit, 0, None, true), |stream| {
                (
                    stream.limit(),
                    stream.highest_offset(),
                    stream.final_size(),
                    false,
                )
            });
        if new_end > limit {
            return Err(Error::FlowControl);
        }
        if final_size.is_some_and(|final_size| new_end > final_size || fin && new_end != final_size)
            || fin && new_end < previous_high
        {
            return Err(Error::FinalSize);
        }
        let projected_total = receive
            .total
            .checked_add(new_end.saturating_sub(previous_high))
            .filter(|&total| total <= receive.local_max_data)
            .ok_or(Error::FlowControl)?;

        let (handle, stream, event_position) = receive
            .map
            .entry(recv::Id::new(stream_id))
            .or_insert_with_position(initial_limit)
            .expect("advertised active receive streams fit the fixed state index");
        if stream.observe_transient(offset, data_len, fin).is_err() {
            if new_entry {
                stream.release_ranges(&mut receive.ranges);
                receive.map.remove(recv::Id::new(stream_id));
            }
            return Err(Error::StreamBufferExceeded);
        }
        receive.total = projected_total;
        if data_len != 0 || fin {
            events.push_readable(handle, event_position, stream_id);
        }
        Ok(())
    }

    pub(in crate::conn) fn ingest_reset_reserved<C: control::Write>(
        &mut self,
        stream_id: u64,
        error_code: u64,
        final_size: u64,
        is_client: bool,
        control: &mut C,
        events: &mut event_queue::Permit<'_>,
    ) -> Result<(), Error> {
        if self.receive_side_closed(stream_id, is_client) {
            return Ok(());
        }
        let initial_limit = self.initial_receive_credit(stream_id, is_client);
        let receive = &mut self.receive;
        let projected_total = match receive.map.get(recv::Id::new(stream_id)) {
            Some(stream) => {
                if final_size > stream.limit() {
                    return Err(Error::FlowControl);
                }
                let previous_high = stream.highest_offset();
                if final_size < previous_high
                    || stream.final_size().is_some_and(|known| known != final_size)
                {
                    return Err(Error::FinalSize);
                }
                receive
                    .total
                    .checked_add(final_size - previous_high)
                    .filter(|&total| total <= receive.local_max_data)
                    .ok_or(Error::FlowControl)?
            }
            None => {
                if final_size > initial_limit {
                    return Err(Error::FlowControl);
                }
                receive
                    .total
                    .checked_add(final_size)
                    .filter(|&total| total <= receive.local_max_data)
                    .ok_or(Error::FlowControl)?
            }
        };
        let (map, control_schedule, ranges) = (
            &mut receive.map,
            &mut receive.control_schedule,
            &mut receive.ranges,
        );
        match map.entry(recv::Id::new(stream_id)) {
            table::Entry::Occupied(mut occupied) => {
                let (stream, event_position) = occupied.get_with_position_mut();
                stream.reset(error_code, final_size);
                events.push_reset(event_position, stream_id, error_code);
                control.remove_control(&mut stream.max_stream_data);
                control.remove_signal(&mut stream.stop_sending);
                stream.release_ranges(ranges);
                occupied.remove_with(|map, handle| control_schedule.deactivate(map, handle));
            }
            table::Entry::Vacant(_) => {
                let mut readable = table::Position::none();
                events.push_reset(&mut readable, stream_id, error_code);
            }
        }
        receive.total = projected_total;
        self.finish_reserved_reset(stream_id, is_client, control);
        Ok(())
    }

    pub(in crate::conn) fn retire_recv_reserved<C: control::Write>(
        &mut self,
        events: &mut event_queue::Events,
        stream_id: u64,
        is_client: bool,
        control: &mut C,
    ) {
        if self.receive_side_closed(stream_id, is_client) {
            return;
        }
        let receive = &mut self.receive;
        let (map, control_schedule, ranges) = (
            &mut receive.map,
            &mut receive.control_schedule,
            &mut receive.ranges,
        );
        if let table::Entry::Occupied(mut occupied) = map.entry(recv::Id::new(stream_id)) {
            let (stream, event_position) = occupied.get_with_position_mut();
            control.remove_control(&mut stream.max_stream_data);
            control.remove_signal(&mut stream.stop_sending);
            events.cancel(event_position);
            stream.release_ranges(ranges);
            occupied.remove_with(|map, handle| control_schedule.deactivate(map, handle));
        }
        self.finish_reserved_reset(stream_id, is_client, control);
    }

    pub(in crate::conn) fn retire_send_reserved<C: control::Write>(
        &mut self,
        events: &mut event_queue::Events,
        stream_id: u64,
        is_client: bool,
        control: &mut C,
    ) {
        let super::TransmitState {
            map,
            schedule,
            deliveries,
            ..
        } = &mut self.transmit;
        let table::Entry::Occupied(mut occupied) = map.entry(send::Id::new(stream_id)) else {
            return;
        };
        let entry = occupied.get_mut();
        control.remove_signal(&mut entry.reset_stream);
        entry.credit.clear_blocked(control);
        if let Some(group) = entry.delivery_group.take() {
            deliveries.cancel(group);
        }
        occupied.remove_with(|map, handle| schedule.deactivate(map, handle));
        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == is_client;
        if we_initiated {
            if is_uni || self.receive_side_closed(stream_id, is_client) {
                let active = &mut self.local_initiated.active[usize::from(is_uni)];
                debug_assert_ne!(*active, 0);
                *active = active.saturating_sub(1);
            }
        } else if !is_uni {
            let recv_closed = self.receive_side_closed(stream_id, is_client);
            self.receive
                .retired
                .retire_peer_bidi_send(stream_id)
                .expect("retired send ranges are bounded by live stream capacity");
            if recv_closed {
                self.release_peer_receive_credit(false, control);
            }
        }
        if self
            .receive
            .map
            .get(recv::Id::new(stream_id))
            .is_some_and(|stream| stream.is_eof() && stream.reset_error().is_none())
        {
            self.retire_recv_reserved(events, stream_id, is_client, control);
        }
    }
}

impl<B: ReceiveBuffer> Streams<B> {
    fn consume_receive<R>(
        &mut self,
        stream_id: u64,
        is_client: bool,
        control: &mut control::Pending,
        absent: R,
        consume: impl FnOnce(&mut recv::State<B>, &mut crate::range_buffer::Arena<B>) -> (R, u64),
    ) -> R {
        let receive = &mut self.state.receive;
        let (map, control_schedule, ranges) = (
            &mut receive.map,
            &mut receive.control_schedule,
            &mut receive.ranges,
        );
        let (value, released, retire, schedule_credit, handle) = {
            let table::Entry::Occupied(mut occupied) = map.entry(recv::Id::new(stream_id)) else {
                return absent;
            };
            let handle = occupied.handle();
            let (value, released, retire, schedule_credit) = {
                let (stream, event_position) = occupied.get_with_position_mut();
                let (value, released) = consume(stream, ranges);
                let retire = stream.is_eof() && stream.reset_error().is_none();
                let schedule_credit = if released == 0 || retire {
                    false
                } else {
                    let stream_limit = stream.release_credit(released);
                    if control.owner_is_live(stream.max_stream_data) {
                        control.queue_max_stream_data(
                            &mut stream.max_stream_data,
                            stream_id,
                            stream_limit,
                        );
                        false
                    } else {
                        stream.mark_max_stream_data_dirty();
                        true
                    }
                };
                if retire {
                    control.remove_control(&mut stream.max_stream_data);
                    control.remove_signal(&mut stream.stop_sending);
                    self.events.cancel(event_position);
                }
                (value, released, retire, schedule_credit)
            };

            if retire {
                occupied.get_mut().release_ranges(ranges);
                occupied.remove_with(|map, handle| control_schedule.deactivate(map, handle));
            }
            (value, released, retire, schedule_credit, handle)
        };

        if !retire && schedule_credit {
            control_schedule.activate(map, handle);
        }

        if released != 0 {
            self.state
                .release_connection_receive_credit(released, control);
        }
        if retire {
            self.finish_recv_retirement(stream_id, is_client, control);
        }
        value
    }

    pub(in crate::conn) fn finish_recv_retirement(
        &mut self,
        stream_id: u64,
        is_client: bool,
        control: &mut control::Pending,
    ) {
        let newly_closed = self
            .receive
            .retired
            .retire_recv(stream_id, is_client)
            .expect("retired receive ranges are bounded by live stream capacity");
        if !newly_closed {
            return;
        }
        let is_uni = stream_id & 0x2 != 0;
        let peer_initiated = (stream_id & 0x1 == 0) != is_client;
        if peer_initiated && (is_uni || self.send_side_closed(stream_id, is_client)) {
            self.state.release_peer_receive_credit(is_uni, control);
        } else if !peer_initiated && !is_uni && self.send_side_closed(stream_id, is_client) {
            self.release_local_capacity(false);
        }
    }
}

pub(in crate::conn) trait Receive<B: ReceiveBuffer> {
    fn read(
        &mut self,
        stream_id: u64,
        destination: &mut Vec<u8>,
        is_client: bool,
        control: &mut control::Pending,
    ) -> usize;
    fn read_owned(
        &mut self,
        stream_id: u64,
        is_client: bool,
        control: &mut control::Pending,
    ) -> Option<Vec<u8>>;
    fn read_buffer(
        &mut self,
        stream_id: u64,
        is_client: bool,
        control: &mut control::Pending,
    ) -> Option<B>;
    fn release_local_capacity(&mut self, is_uni: bool);
    fn validate_access(&self, stream_id: u64, access: Access, is_client: bool)
    -> Result<(), Error>;
    fn validate_operation(
        &self,
        stream_id: u64,
        access: Access,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error>;
    fn local_initial_credit(&self, stream_id: u64, is_client: bool) -> u64;
    fn recv_eof(&self, stream_id: u64, is_client: bool) -> bool;
    fn recv_fin_received(&self, stream_id: u64, is_client: bool) -> bool;
}

impl<B: ReceiveBuffer> State<B> {
    pub(in crate::conn) fn plan_stream_frames(
        &self,
        frames: FrameGroup<'_>,
        context: PlanContext<'_>,
    ) -> Result<AdmissionImpact, Error> {
        let FrameGroup {
            frame_indices,
            parsed_frames,
        } = frames;
        let PlanContext {
            admissions,
            payloads,
            segments,
            parts,
            is_client,
        } = context;
        let stream_id = frame_indices
            .first()
            .and_then(|&frame_index| parsed_frames.get(frame_index.get()))
            .and_then(|frame| match frame {
                Frame::Stream { stream_id, .. } | Frame::ResetStream { stream_id, .. } => {
                    Some(stream_id.get())
                }
                _ => None,
            })
            .ok_or(Error::FrameDecode)?;

        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == is_client;
        if we_initiated {
            self.validate_access_reserved(stream_id, Access::Receive, is_client)?;
        } else if stream_id >> 2 >= self.peer_initiated.max[usize::from(is_uni)] {
            return Err(Error::ProtocolViolation);
        }
        if self.receive_side_closed(stream_id, is_client) {
            return Ok(AdmissionImpact {
                accepted_bytes: 0,
                stream_slots: 0,
                range_slots: 0,
                event_slots: 0,
                flow_control_bytes: 0,
            });
        }

        let will_reset = frame_indices.iter().any(|&frame_index| {
            matches!(
                parsed_frames.get(frame_index.get()),
                Some(Frame::ResetStream { .. })
            )
        });
        let initial_limit = self.initial_receive_credit(stream_id, is_client);
        let receive = &self.receive;
        let (
            limit,
            mut highest,
            mut final_size,
            mut event_pending,
            mut stream_present,
            mut range_plan,
            original_ranges,
        ) = match receive.map.get_with_position(recv::Id::new(stream_id)) {
            Some((stream, event_position)) => (
                stream.limit(),
                stream.highest_offset(),
                stream.final_size(),
                !event_position.is_none(),
                true,
                (!will_reset).then(|| stream.receive_plan(&receive.ranges, segments, parts)),
                stream.receive_range_count(),
            ),
            None => (
                initial_limit,
                0,
                None,
                false,
                false,
                (!will_reset).then(|| Plan::empty(segments, parts)),
                0,
            ),
        };
        let previous_highest = highest;
        let mut accepted_bytes = 0usize;
        let mut accepted_segments = 0usize;
        let mut stream_slots = 0;
        let mut event_slots = 0;
        let mut peak_ranges = original_ranges;
        let mut closed = false;
        for &frame_index in frame_indices {
            if closed {
                continue;
            }
            match &parsed_frames[frame_index.get()] {
                Frame::Stream {
                    offset, data, fin, ..
                } => {
                    let offset = offset.get();
                    let len = data.len();
                    let end = offset
                        .checked_add(u64::try_from(len).map_err(|_| Error::StreamBufferExceeded)?)
                        .ok_or(Error::StreamBufferExceeded)?;
                    if end > limit {
                        return Err(Error::FlowControl);
                    }
                    if final_size.is_some_and(|known| end > known || *fin && end != known)
                        || *fin && end < highest
                    {
                        return Err(Error::FinalSize);
                    }
                    let accepted = match &mut range_plan {
                        Some(range_plan) => range_plan
                            .insert_observed::<crate::range_buffer::InsertError>(
                                offset,
                                len,
                                MAX_RANGES,
                                |_| {
                                    accepted_segments = accepted_segments
                                        .checked_add(1)
                                        .ok_or(crate::range_buffer::InsertError::BufferFull)?;
                                    Ok(())
                                },
                            )
                            .map_err(|_| Error::StreamBufferExceeded)?,
                        None => 0,
                    };
                    payloads
                        .set_accepted(frame_index.get(), accepted)
                        .ok_or(Error::StreamBufferExceeded)?;
                    accepted_bytes = accepted_bytes
                        .checked_add(accepted)
                        .ok_or(Error::StreamBufferExceeded)?;
                    if let Some(range_plan) = &range_plan {
                        peak_ranges = peak_ranges.max(range_plan.range_count());
                    }
                    highest = highest.max(end);
                    if *fin {
                        final_size = Some(end);
                    }
                    if !stream_present {
                        stream_present = true;
                        stream_slots = 1;
                    }
                    if (len != 0 || *fin) && !event_pending {
                        event_pending = true;
                        event_slots = 1;
                    }
                    admissions.mark(
                        frame_index.get(),
                        if will_reset {
                            ReceiveAdmission::StreamTransient
                        } else {
                            ReceiveAdmission::Stream
                        },
                    );
                }
                Frame::ResetStream {
                    final_size: reset, ..
                } => {
                    let reset = reset.get();
                    if reset > limit {
                        return Err(Error::FlowControl);
                    }
                    if reset < highest || final_size.is_some_and(|known| known != reset) {
                        return Err(Error::FinalSize);
                    }
                    highest = highest.max(reset);
                    if !event_pending {
                        event_slots = 1;
                    }
                    // Earlier STREAM frames still apply their observable metadata
                    // in wire order, but their payload and gap topology can never
                    // escape the later RESET_STREAM.
                    admissions.mark(frame_index.get(), ReceiveAdmission::Reset);
                    closed = true;
                }
                _ => return Err(Error::FrameDecode),
            }
        }
        Ok(AdmissionImpact {
            accepted_bytes,
            stream_slots,
            range_slots: if B::SEGMENTED_READY {
                accepted_segments
            } else {
                peak_ranges - original_ranges
            },
            event_slots,
            flow_control_bytes: highest - previous_highest,
        })
    }

    pub(in crate::conn) fn materialize_stream_frames(
        &self,
        frames: FrameGroup<'_>,
        context: MaterializeContext<'_>,
    ) -> Result<(), Error> {
        let FrameGroup {
            frame_indices,
            parsed_frames,
        } = frames;
        let MaterializeContext {
            admissions,
            payloads,
            segments,
            parts,
            body,
            output,
        } = context;
        if !frame_indices
            .iter()
            .any(|&index| admissions.get(index.get()) == ReceiveAdmission::Stream)
        {
            return Ok(());
        }
        let stream_id = frame_indices
            .first()
            .and_then(|&index| parsed_frames.get(index.get()))
            .and_then(|frame| match frame {
                Frame::Stream { stream_id, .. } | Frame::ResetStream { stream_id, .. } => {
                    Some(stream_id.get())
                }
                _ => None,
            })
            .ok_or(Error::FrameDecode)?;
        let receive = &self.receive;
        let mut range_plan = match receive.map.get(recv::Id::new(stream_id)) {
            Some(stream) => stream.receive_plan(&receive.ranges, segments, parts),
            None => Plan::empty(segments, parts),
        };

        for &frame_index in frame_indices {
            if admissions.get(frame_index.get()) != ReceiveAdmission::Stream {
                continue;
            }
            let Frame::Stream { offset, data, .. } = &parsed_frames[frame_index.get()] else {
                return Err(Error::FrameDecode);
            };
            let compact_start = output.len();
            payloads
                .set_start(frame_index.get(), compact_start)
                .ok_or(Error::StreamBufferExceeded)?;
            let accepted = range_plan
                .insert_observed::<crate::range_buffer::InsertError>(
                    offset.get(),
                    data.len(),
                    MAX_RANGES,
                    |range| {
                        let start = data
                            .start
                            .checked_add(range.start)
                            .ok_or(crate::range_buffer::InsertError::OffsetOverflow)?;
                        let end = data
                            .start
                            .checked_add(range.end)
                            .ok_or(crate::range_buffer::InsertError::OffsetOverflow)?;
                        let bytes = body
                            .get(start..end)
                            .ok_or(crate::range_buffer::InsertError::OffsetOverflow)?;
                        output
                            .try_extend(bytes)
                            .map_err(|_| crate::range_buffer::InsertError::BufferFull)
                    },
                )
                .map_err(|_| Error::StreamBufferExceeded)?;
            if accepted != payloads.get(frame_index.get()).accepted() {
                return Err(Error::StreamBufferExceeded);
            }
        }
        Ok(())
    }
}

impl<B: ReceiveBuffer> Receive<B> for Streams<B> {
    fn read(
        &mut self,
        stream_id: u64,
        destination: &mut Vec<u8>,
        is_client: bool,
        control: &mut control::Pending,
    ) -> usize {
        self.consume_receive(stream_id, is_client, control, 0, |stream, ranges| {
            let count = stream.read(ranges, destination);
            (count, count as u64)
        })
    }

    fn read_owned(
        &mut self,
        stream_id: u64,
        is_client: bool,
        control: &mut control::Pending,
    ) -> Option<Vec<u8>> {
        self.consume_receive(stream_id, is_client, control, None, |stream, ranges| {
            let bytes = stream.read_owned(ranges);
            let released = bytes.as_ref().map_or(0, |bytes| bytes.len() as u64);
            (bytes, released)
        })
    }

    fn read_buffer(
        &mut self,
        stream_id: u64,
        is_client: bool,
        control: &mut control::Pending,
    ) -> Option<B> {
        self.consume_receive(stream_id, is_client, control, None, |stream, ranges| {
            let buffer = stream.read_buffer(ranges);
            let released = buffer
                .as_ref()
                .map_or(0, |buffer| buffer.as_ref().len() as u64);
            (buffer, released)
        })
    }

    fn release_local_capacity(&mut self, is_uni: bool) {
        let active = &mut self.local_initiated.active[usize::from(is_uni)];
        debug_assert_ne!(*active, 0);
        *active = active.saturating_sub(1);
    }

    fn validate_access(
        &self,
        stream_id: u64,
        access: Access,
        is_client: bool,
    ) -> Result<(), Error> {
        let is_uni = stream_id & 0x2 != 0;
        let initiator_is_client = stream_id & 0x1 == 0;
        let we_initiated = initiator_is_client == is_client;
        if we_initiated {
            let opened = stream_id < self.local_initiated.next[usize::from(is_uni)];
            if !opened || is_uni && matches!(access, Access::Receive) {
                return Err(Error::ProtocolViolation);
            }
        } else if !self.peer_initiated.opened.contains(stream_id)
            || is_uni && matches!(access, Access::Send)
        {
            return Err(Error::ProtocolViolation);
        }
        Ok(())
    }

    fn validate_operation(
        &self,
        stream_id: u64,
        access: Access,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error> {
        if stream_id > VarInt::MAX {
            return Err(stream::Error::IdOverflow);
        }
        if !available {
            return Err(stream::Error::NotEstablished);
        }
        self.validate_access(stream_id, access, is_client)
            .map_err(|_| stream::Error::InvalidStream)
    }

    fn local_initial_credit(&self, stream_id: u64, is_client: bool) -> u64 {
        let is_uni = stream_id & 0x2 != 0;
        let initiator_is_client = stream_id & 0x1 == 0;
        let we_initiated = initiator_is_client == is_client;
        if is_uni {
            if we_initiated {
                0
            } else {
                self.receive.initial_stream_data[2]
            }
        } else if we_initiated {
            self.receive.initial_stream_data[0]
        } else {
            self.receive.initial_stream_data[1]
        }
    }

    fn recv_eof(&self, stream_id: u64, is_client: bool) -> bool {
        self.receive
            .map
            .get(recv::Id::new(stream_id))
            .is_some_and(|stream| stream.is_eof())
            || self.recv_side_closed(stream_id, is_client)
    }

    fn recv_fin_received(&self, stream_id: u64, is_client: bool) -> bool {
        self.receive
            .map
            .get(recv::Id::new(stream_id))
            .and_then(|stream| stream.final_size())
            .is_some()
            || self.recv_side_closed(stream_id, is_client)
    }
}
