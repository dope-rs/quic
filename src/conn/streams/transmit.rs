use crate::stream::SendBuffer;
use crate::transport_params::Params;
use crate::varint::VarInt;

use crate::conn::{Error, control, event_queue, send, stream};

use super::receive::Receive;
use super::{Access, State, Streams, table};
use crate::stream::ReceiveBuffer;

pub(in crate::conn) struct SendParts {
    first: SendBuffer,
    second: Option<SendBuffer>,
    fin: bool,
}

impl SendParts {
    pub(in crate::conn) const fn new(
        first: SendBuffer,
        second: Option<SendBuffer>,
        fin: bool,
    ) -> Self {
        Self { first, second, fin }
    }
}

pub(in crate::conn) trait Transmit {
    fn send_bytes(
        &mut self,
        stream_id: u64,
        data: &[u8],
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error>;
    fn send_buffer(
        &mut self,
        stream_id: u64,
        data: SendBuffer,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error>;
    fn send_parts(
        &mut self,
        stream_id: u64,
        parts: SendParts,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error>;
    fn recv_side_closed(&self, stream_id: u64, is_client: bool) -> bool;
    fn send_side_closed(&self, stream_id: u64, is_client: bool) -> bool;
    fn send_fin(
        &mut self,
        stream_id: u64,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error>;
    fn reset(
        &mut self,
        stream_id: u64,
        error_code: u64,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
        control: &mut control::Pending,
    ) -> Result<(), stream::Error>;
    fn stop_sending(
        &mut self,
        stream_id: u64,
        error_code: u64,
        is_client: bool,
        available: bool,
        control: &mut control::Pending,
    ) -> Result<(), stream::Error>;
    fn send_stopped(&self, stream_id: u64) -> Option<u64>;
    fn open_local(
        &mut self,
        is_uni: bool,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<u64, stream::Error>;
    fn peer_initial_credit(
        peer_transport_params: Option<&Params>,
        is_client: bool,
        stream_id: u64,
    ) -> u64;
}

impl<B: ReceiveBuffer> Streams<B> {
    /// Resolves a wire stream ID once, retains the lifetime-bound entry for the
    /// whole mutation, and schedules through its typed slot handle.
    fn with_send_entry<R>(
        &mut self,
        stream_id: u64,
        initial_credit: u64,
        create: bool,
        mutate: impl FnOnce(&mut send::Entry) -> R,
    ) -> Option<R> {
        let transmit = &mut self.transmit;
        let (handle, entry) = match transmit.map.entry(send::Id::new(stream_id)) {
            table::Entry::Occupied(occupied) => (occupied.handle(), occupied.into_mut()),
            table::Entry::Vacant(vacant) if create => vacant.insert(initial_credit)?,
            table::Entry::Vacant(_) => return None,
        };
        let result = mutate(entry);
        let active = entry.has_deferred_reset() || entry.has_pending() && !entry.blocked();
        transmit.schedule.update(&mut transmit.map, handle, active);
        Some(result)
    }

    fn send_entry_can_be_created(stream_id: u64, is_client: bool) -> bool {
        (stream_id & 0x1 == 0) != is_client
    }

    fn peer_send_retired(&self, stream_id: u64, is_client: bool) -> bool {
        let peer_initiated = (stream_id & 0x1 == 0) != is_client;
        peer_initiated
            && stream_id & 0x2 == 0
            && self.receive.retired.peer_bidi_send_contains(stream_id)
    }
}

impl<B: ReceiveBuffer> State<B> {
    pub(in crate::conn) fn raise_stream_credit_reserved<C: control::Write>(
        &mut self,
        stream_id: u64,
        maximum: u64,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        control: &mut C,
    ) {
        let peer_initiated = (stream_id & 0x1 == 0) != is_client;
        if peer_initiated
            && stream_id & 0x2 == 0
            && self.receive.retired.peer_bidi_send_contains(stream_id)
        {
            return;
        }
        let credit = <Streams<B> as Transmit>::peer_initial_credit(
            peer_transport_params,
            is_client,
            stream_id,
        );
        let create = (stream_id & 0x1 == 0) != is_client;
        let transmit = &mut self.transmit;
        let (handle, entry) = match transmit.map.entry(send::Id::new(stream_id)) {
            table::Entry::Occupied(occupied) => (occupied.handle(), occupied.into_mut()),
            table::Entry::Vacant(vacant) if create => match vacant.insert(credit) {
                Some(inserted) => inserted,
                None => return,
            },
            table::Entry::Vacant(_) => return,
        };
        entry.credit.raise(maximum, control);
        let active = entry.has_deferred_reset() || entry.has_pending() && !entry.blocked();
        transmit.schedule.update(&mut transmit.map, handle, active);
    }

    pub(in crate::conn) fn plan_stop(
        &self,
        stream_id: u64,
        is_client: bool,
    ) -> Result<StopImpact, Error> {
        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == is_client;
        if we_initiated {
            self.validate_access_reserved(stream_id, Access::Send, is_client)?;
        } else if is_uni || stream_id >> 2 >= self.peer_initiated.max[usize::from(is_uni)] {
            return Err(Error::ProtocolViolation);
        }
        let peer_send_retired = (stream_id & 0x1 == 0) != is_client
            && stream_id & 0x2 == 0
            && self.receive.retired.peer_bidi_send_contains(stream_id);
        if peer_send_retired {
            return Ok(StopImpact::NONE);
        }
        let create = (stream_id & 0x1 == 0) != is_client;
        Ok(match self.transmit.map.get(send::Id::new(stream_id)) {
            Some(entry) => StopImpact {
                active: true,
                event_slots: usize::from(!entry.stop_event_pending()),
                stream_slots: 0,
            },
            None if create => StopImpact {
                active: true,
                event_slots: 1,
                stream_slots: 1,
            },
            None => StopImpact::NONE,
        })
    }

    pub(in crate::conn) fn ingest_stop_reserved(
        &mut self,
        stream_id: u64,
        error_code: u64,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        control: &mut control::Pending,
        events: &mut event_queue::Permit<'_>,
    ) {
        let peer_initiated = (stream_id & 0x1 == 0) != is_client;
        if peer_initiated
            && stream_id & 0x2 == 0
            && self.receive.retired.peer_bidi_send_contains(stream_id)
        {
            return;
        }
        let credit = <Streams<B> as Transmit>::peer_initial_credit(
            peer_transport_params,
            is_client,
            stream_id,
        );
        let create = (stream_id & 0x1 == 0) != is_client;
        let transmit = &mut self.transmit;
        let (handle, group, reset_deferred) = {
            let (handle, entry) = match transmit.map.entry(send::Id::new(stream_id)) {
                table::Entry::Occupied(occupied) => (occupied.handle(), occupied.into_mut()),
                table::Entry::Vacant(vacant) if create => vacant
                    .insert(credit)
                    .expect("active send streams fit the fixed state index"),
                table::Entry::Vacant(_) => return,
            };
            let final_size = entry.next_offset();
            let deferred_reset = entry.reset_stream.deferred();
            let group = entry.delivery_group.take();
            entry.stop(error_code);
            entry.credit.clear_blocked(control);
            if let Some(reset_error) = deferred_reset {
                control.queue_reset_stream(
                    &mut entry.reset_stream,
                    stream_id,
                    reset_error,
                    final_size,
                );
            } else if !entry.reset_sent() {
                entry.mark_reset_sent();
                control.queue_reset_stream(
                    &mut entry.reset_stream,
                    stream_id,
                    error_code,
                    final_size,
                );
            }
            events.push_stopped(handle, &mut entry.stream, stream_id, error_code);
            (handle, group, entry.has_deferred_reset())
        };
        transmit
            .schedule
            .update(&mut transmit.map, handle, reset_deferred);
        if let Some(group) = group {
            transmit.deliveries.cancel(group);
        }
    }
}

pub(in crate::conn) struct StopImpact {
    pub(in crate::conn) active: bool,
    pub(in crate::conn) event_slots: usize,
    pub(in crate::conn) stream_slots: usize,
}

impl StopImpact {
    const NONE: Self = Self {
        active: false,
        event_slots: 0,
        stream_slots: 0,
    };
}

impl<B: ReceiveBuffer> Transmit for Streams<B> {
    fn send_bytes(
        &mut self,
        stream_id: u64,
        data: &[u8],
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error> {
        self.validate_operation(stream_id, Access::Send, is_client, available)?;
        if self.peer_send_retired(stream_id, is_client) {
            return Ok(());
        }
        let credit = Self::peer_initial_credit(peer_transport_params, is_client, stream_id);
        let create = Self::send_entry_can_be_created(stream_id, is_client);
        self.with_send_entry(stream_id, credit, create, |entry| {
            entry.blocked() || entry.write(data)
        })
        .unwrap_or(true)
        .then_some(())
        .ok_or(stream::Error::ValueOutOfRange)
    }

    fn send_buffer(
        &mut self,
        stream_id: u64,
        data: SendBuffer,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error> {
        self.validate_operation(stream_id, Access::Send, is_client, available)?;
        if self.peer_send_retired(stream_id, is_client) {
            return Ok(());
        }
        let credit = Self::peer_initial_credit(peer_transport_params, is_client, stream_id);
        let create = Self::send_entry_can_be_created(stream_id, is_client);
        self.with_send_entry(stream_id, credit, create, |entry| {
            entry.blocked() || entry.write_buffer(data)
        })
        .unwrap_or(true)
        .then_some(())
        .ok_or(stream::Error::ValueOutOfRange)
    }

    fn send_parts(
        &mut self,
        stream_id: u64,
        parts: SendParts,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error> {
        let SendParts { first, second, fin } = parts;
        self.validate_operation(stream_id, Access::Send, is_client, available)?;
        if self.peer_send_retired(stream_id, is_client) {
            return Ok(());
        }
        let credit = Self::peer_initial_credit(peer_transport_params, is_client, stream_id);
        let create = Self::send_entry_can_be_created(stream_id, is_client);
        let written = self.with_send_entry(stream_id, credit, create, |entry| {
            if entry.blocked() {
                return true;
            }
            let written =
                entry.write_buffer(first) && second.is_none_or(|buffer| entry.write_buffer(buffer));
            if written && fin {
                entry.mark_fin();
            }
            written
        });
        if written == Some(false) {
            return Err(stream::Error::ValueOutOfRange);
        }
        Ok(())
    }

    fn recv_side_closed(&self, stream_id: u64, is_client: bool) -> bool {
        self.receive.retired.recv_contains(stream_id, is_client)
    }

    fn send_side_closed(&self, stream_id: u64, is_client: bool) -> bool {
        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == is_client;
        if we_initiated {
            let opened = stream_id < self.local_initiated.next[usize::from(is_uni)];
            opened && self.transmit.map.get(send::Id::new(stream_id)).is_none()
        } else {
            !is_uni && self.receive.retired.peer_bidi_send_contains(stream_id)
        }
    }

    fn send_fin(
        &mut self,
        stream_id: u64,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<(), stream::Error> {
        self.validate_operation(stream_id, Access::Send, is_client, available)?;
        if self.peer_send_retired(stream_id, is_client) {
            return Ok(());
        }
        let credit = Self::peer_initial_credit(peer_transport_params, is_client, stream_id);
        let create = Self::send_entry_can_be_created(stream_id, is_client);
        self.with_send_entry(stream_id, credit, create, |entry| {
            if !entry.blocked() {
                entry.mark_fin();
            }
        });
        Ok(())
    }

    fn reset(
        &mut self,
        stream_id: u64,
        error_code: u64,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
        control: &mut control::Pending,
    ) -> Result<(), stream::Error> {
        self.validate_operation(stream_id, Access::Send, is_client, available)?;
        if error_code > VarInt::MAX {
            return Err(stream::Error::ValueOutOfRange);
        }
        if self.peer_send_retired(stream_id, is_client) {
            return Ok(());
        }
        let credit = Self::peer_initial_credit(peer_transport_params, is_client, stream_id);
        let create = Self::send_entry_can_be_created(stream_id, is_client);
        let group = self.with_send_entry(stream_id, credit, create, |entry| {
            if entry.reset_sent() {
                return None;
            }
            let final_size = entry.next_offset();
            let group = entry.delivery_group.take();
            entry.mark_reset_sent();
            entry.credit.clear_blocked(control);
            control.queue_reset_stream(&mut entry.reset_stream, stream_id, error_code, final_size);
            group
        });
        if let Some(Some(group)) = group {
            self.transmit.deliveries.cancel(group);
        }
        Ok(())
    }

    fn stop_sending(
        &mut self,
        stream_id: u64,
        error_code: u64,
        is_client: bool,
        available: bool,
        control: &mut control::Pending,
    ) -> Result<(), stream::Error> {
        self.validate_operation(stream_id, Access::Receive, is_client, available)?;
        if error_code > VarInt::MAX {
            return Err(stream::Error::ValueOutOfRange);
        }
        if !self.recv_side_closed(stream_id, is_client) {
            let limit = self.local_initial_credit(stream_id, is_client);
            let receive = &mut self.receive;
            let (map, schedule) = (&mut receive.map, &mut receive.control_schedule);
            let (handle, entry) = map
                .entry(crate::conn::recv::Id::new(stream_id))
                .or_insert(limit)
                .expect("advertised active receive streams fit the fixed state index");
            control.queue_stop_sending(&mut entry.stop_sending, stream_id, error_code);
            schedule.activate(map, handle);
        }
        Ok(())
    }

    fn send_stopped(&self, stream_id: u64) -> Option<u64> {
        self.transmit
            .map
            .get(send::Id::new(stream_id))
            .and_then(|stream| stream.stop_sending_error())
    }

    fn open_local(
        &mut self,
        is_uni: bool,
        peer_transport_params: Option<&Params>,
        is_client: bool,
        available: bool,
    ) -> Result<u64, stream::Error> {
        if !available || peer_transport_params.is_none() {
            return Err(stream::Error::NotEstablished);
        }
        let kind = usize::from(is_uni);
        let local = &mut self.state.local_initiated;
        let next = &mut local.next[kind];
        let opened = &mut local.opened[kind];
        if *opened >= local.peer_max[kind] {
            return Err(stream::Error::PeerLimit);
        }
        if local.active[kind] >= local.capacity[kind] {
            return Err(stream::Error::Capacity);
        }
        let stream_id = *next;
        *next = next.checked_add(4).ok_or(stream::Error::IdOverflow)?;
        *opened = opened.saturating_add(1);
        local.active[kind] += 1;
        let credit = Self::peer_initial_credit(peer_transport_params, is_client, stream_id);
        self.with_send_entry(stream_id, credit, true, |_| ())
            .expect("new local stream fits the fixed state index");
        Ok(stream_id)
    }

    fn peer_initial_credit(
        peer_transport_params: Option<&Params>,
        is_client: bool,
        stream_id: u64,
    ) -> u64 {
        let Some(params) = peer_transport_params else {
            return 0;
        };
        let is_uni = stream_id & 0x2 != 0;
        let initiator_is_client = stream_id & 0x1 == 0;
        let we_initiated = initiator_is_client == is_client;
        if is_uni {
            if we_initiated {
                params.initial_max_stream_data_uni
            } else {
                0
            }
        } else if we_initiated {
            params.initial_max_stream_data_bidi_remote
        } else {
            params.initial_max_stream_data_bidi_local
        }
    }
}
