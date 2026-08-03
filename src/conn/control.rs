use std::collections::BTreeMap;
use std::ops::DerefMut;

use crate::frame::Frame;
use crate::varint::VarInt;

use super::delivery::{Control, Handle, Tracker};

const HANDSHAKE_DONE: u16 = 1 << 0;
const NEW_CONNECTION_ID: u16 = 1 << 1;
const RETIRE_CONNECTION_ID: u16 = 1 << 2;
const STOP_SENDING: u16 = 1 << 3;
const RESET_STREAM: u16 = 1 << 4;
const MAX_DATA: u16 = 1 << 5;
const MAX_STREAM_DATA: u16 = 1 << 6;
const MAX_STREAMS_BIDI: u16 = 1 << 7;
const MAX_STREAMS_UNI: u16 = 1 << 8;
const PATH_RESPONSE: u16 = 1 << 9;
const PATH_CHALLENGE: u16 = 1 << 10;

pub(super) const PREFIX: u16 = HANDSHAKE_DONE | NEW_CONNECTION_ID | RETIRE_CONNECTION_ID;
pub(super) const SUFFIX: u16 = STOP_SENDING
    | RESET_STREAM
    | MAX_DATA
    | MAX_STREAM_DATA
    | MAX_STREAMS_BIDI
    | MAX_STREAMS_UNI
    | PATH_RESPONSE
    | PATH_CHALLENGE;

pub(super) enum Effect {
    None,
    RetireStream(u64),
}

// A pending value owns its current delivery generation. Replacing the value
// detaches the old handle before the new generation becomes selectable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Queued,
    InFlight(Handle<Control>),
    Acknowledged,
}

impl Status {
    fn is_queued(self) -> bool {
        self == Self::Queued
    }

    fn sent(&mut self, handle: Handle<Control>) -> bool {
        if !self.is_queued() {
            return false;
        }
        *self = Self::InFlight(handle);
        true
    }

    fn lost(&mut self, handle: Handle<Control>) -> bool {
        if *self != Self::InFlight(handle) {
            return false;
        }
        *self = Self::Queued;
        true
    }

    fn acknowledges(self, handle: Handle<Control>) -> bool {
        self == Self::InFlight(handle)
    }

    fn handle(self) -> Option<Handle<Control>> {
        match self {
            Self::InFlight(handle) => Some(handle),
            Self::Queued | Self::Acknowledged => None,
        }
    }
}

struct PendingValue<T> {
    value: T,
    status: Status,
}

impl<T> PendingValue<T> {
    fn queued(value: T) -> Self {
        Self {
            value,
            status: Status::Queued,
        }
    }
}

struct NewConnectionId {
    sequence: u64,
    connection_id: Vec<u8>,
    reset_token: [u8; 16],
    status: Status,
}

struct PathToken {
    data: [u8; 8],
    status: Status,
}

pub(super) struct Cursor<const MASK: u16> {
    remaining: u16,
    response: usize,
    challenge: usize,
}

impl<const MASK: u16> Cursor<MASK> {
    fn new(pending: &Pending) -> Self {
        Self {
            remaining: pending.bits & MASK,
            response: pending.path_responses.len(),
            challenge: pending.path_challenges.len(),
        }
    }

    pub(super) fn next(&mut self, pending: &Pending) -> Option<Control> {
        if MASK == PREFIX {
            self.next_prefix(pending)
        } else {
            debug_assert_eq!(MASK, SUFFIX);
            self.next_suffix(pending)
        }
    }

    fn next_prefix(&mut self, pending: &Pending) -> Option<Control> {
        while self.remaining != 0 {
            let bit = 1 << self.remaining.trailing_zeros();
            self.remaining &= !bit;
            let record = match bit {
                HANDSHAKE_DONE => pending
                    .handshake_done
                    .filter(|status| status.is_queued())
                    .map(|_| Control::HandshakeDone),
                NEW_CONNECTION_ID => pending
                    .new_connection_ids
                    .iter()
                    .rev()
                    .find(|item| item.status.is_queued())
                    .map(|item| Control::NewConnectionId(item.sequence)),
                RETIRE_CONNECTION_ID => pending
                    .retire_connection_ids
                    .iter()
                    .rev()
                    .find(|(_, status)| status.is_queued())
                    .map(|(sequence, _)| Control::RetireConnectionId(*sequence)),
                _ => unreachable!("prefix cursor contains only prefix bits"),
            };
            if record.is_some() {
                return record;
            }
        }
        None
    }

    fn next_suffix(&mut self, pending: &Pending) -> Option<Control> {
        if self.remaining == PATH_RESPONSE {
            while let Some(index) = self.response.checked_sub(1) {
                self.response = index;
                let token = &pending.path_responses[index];
                if token.status.is_queued() {
                    return Some(Control::PathResponse(token.data));
                }
            }
            self.remaining = 0;
            return None;
        }
        if self.remaining == PATH_CHALLENGE {
            while let Some(index) = self.challenge.checked_sub(1) {
                self.challenge = index;
                let token = &pending.path_challenges[index];
                if token.status.is_queued() {
                    return Some(Control::PathChallenge(token.data));
                }
            }
            self.remaining = 0;
            return None;
        }
        while self.remaining != 0 {
            let bit = 1 << self.remaining.trailing_zeros();
            let record = match bit {
                STOP_SENDING => {
                    self.remaining &= !bit;
                    pending
                        .stop_sending
                        .iter()
                        .find(|(_, pending)| pending.status.is_queued())
                        .map(|(stream_id, pending)| Control::StopSending(*stream_id, pending.value))
                }
                RESET_STREAM => {
                    self.remaining &= !bit;
                    pending
                        .reset_streams
                        .iter()
                        .find(|(_, pending)| pending.status.is_queued())
                        .map(|(stream_id, pending)| {
                            Control::ResetStream(*stream_id, pending.value.0, pending.value.1)
                        })
                }
                MAX_DATA => {
                    self.remaining &= !bit;
                    pending
                        .max_data
                        .as_ref()
                        .filter(|pending| pending.status.is_queued())
                        .map(|pending| Control::MaxData(pending.value))
                }
                MAX_STREAM_DATA => {
                    self.remaining &= !bit;
                    pending
                        .max_stream_data
                        .iter()
                        .find(|(_, pending)| pending.status.is_queued())
                        .map(|(stream_id, pending)| {
                            Control::MaxStreamData(*stream_id, pending.value)
                        })
                }
                MAX_STREAMS_BIDI | MAX_STREAMS_UNI => {
                    self.remaining &= !bit;
                    let uni = bit == MAX_STREAMS_UNI;
                    pending.max_streams[usize::from(uni)]
                        .as_ref()
                        .filter(|pending| pending.status.is_queued())
                        .map(|pending| Control::MaxStreams(uni, pending.value))
                }
                PATH_RESPONSE => loop {
                    let Some(index) = self.response.checked_sub(1) else {
                        self.remaining &= !bit;
                        break None;
                    };
                    self.response = index;
                    let token = &pending.path_responses[index];
                    if token.status.is_queued() {
                        break Some(Control::PathResponse(token.data));
                    }
                },
                PATH_CHALLENGE => loop {
                    let Some(index) = self.challenge.checked_sub(1) else {
                        self.remaining &= !bit;
                        break None;
                    };
                    self.challenge = index;
                    let token = &pending.path_challenges[index];
                    if token.status.is_queued() {
                        break Some(Control::PathChallenge(token.data));
                    }
                },
                _ => unreachable!("suffix cursor contains only suffix bits"),
            };
            if record.is_some() {
                return record;
            }
        }
        None
    }
}

pub(super) struct Pending {
    bits: u16,
    limit: usize,
    overflowed: bool,
    handshake_done: Option<Status>,
    max_data: Option<PendingValue<u64>>,
    max_streams: [Option<PendingValue<u64>>; 2],
    max_stream_data: BTreeMap<u64, PendingValue<u64>>,
    reset_streams: BTreeMap<u64, PendingValue<(u64, u64)>>,
    stop_sending: BTreeMap<u64, PendingValue<u64>>,
    path_responses: Vec<PathToken>,
    path_challenges: Vec<PathToken>,
    new_connection_ids: Vec<NewConnectionId>,
    retire_connection_ids: BTreeMap<u64, Status>,
    data_blocked: Option<PendingValue<u64>>,
    stream_data_blocked: BTreeMap<u64, PendingValue<u64>>,
    deliveries: Tracker<Control>,
}

impl Pending {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            bits: 0,
            limit,
            overflowed: false,
            handshake_done: None,
            max_data: None,
            max_streams: [None, None],
            max_stream_data: BTreeMap::new(),
            reset_streams: BTreeMap::new(),
            stop_sending: BTreeMap::new(),
            path_responses: Vec::new(),
            path_challenges: Vec::new(),
            new_connection_ids: Vec::new(),
            retire_connection_ids: BTreeMap::new(),
            data_blocked: None,
            stream_data_blocked: BTreeMap::new(),
            deliveries: Tracker::new(limit),
        }
    }

    fn len(&self) -> usize {
        usize::from(self.handshake_done.is_some())
            + usize::from(self.max_data.is_some())
            + self.max_streams.iter().flatten().count()
            + self.max_stream_data.len()
            + self.reset_streams.len()
            + self.stop_sending.len()
            + self.path_responses.len()
            + self.path_challenges.len()
            + self.new_connection_ids.len()
            + self.retire_connection_ids.len()
            + usize::from(self.data_blocked.is_some())
            + self.stream_data_blocked.len()
    }

    fn reserve_new(&mut self) -> bool {
        if self.len() < self.limit {
            true
        } else {
            self.overflowed = true;
            false
        }
    }

    pub(super) fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub(super) fn take_overflowed(&mut self) -> bool {
        std::mem::take(&mut self.overflowed)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.bits == 0
    }

    pub(super) fn only_path_responses(&self) -> Option<impl Iterator<Item = Control> + '_> {
        (self.bits == PATH_RESPONSE).then(|| {
            self.path_responses
                .iter()
                .rev()
                .filter(|token| token.status.is_queued())
                .map(|token| Control::PathResponse(token.data))
        })
    }

    pub(super) fn only_path_challenges(&self) -> Option<impl Iterator<Item = Control> + '_> {
        (self.bits == PATH_CHALLENGE).then(|| {
            self.path_challenges
                .iter()
                .rev()
                .filter(|token| token.status.is_queued())
                .map(|token| Control::PathChallenge(token.data))
        })
    }

    pub(super) fn prefix(&self) -> Option<Cursor<PREFIX>> {
        (self.bits & PREFIX != 0).then(|| Cursor::new(self))
    }

    pub(super) fn suffix(&self) -> Option<Cursor<SUFFIX>> {
        (self.bits & SUFFIX != 0).then(|| Cursor::new(self))
    }

    pub(super) fn has_sendable(&self) -> bool {
        self.prefix()
            .is_some_and(|mut cursor| cursor.next(self).is_some())
            || self
                .suffix()
                .is_some_and(|mut cursor| cursor.next(self).is_some())
    }

    pub(super) fn handshake_done(&mut self) {
        if self.handshake_done.is_none() && !self.reserve_new() {
            return;
        }
        self.handshake_done.get_or_insert(Status::Queued);
        self.bits |= HANDSHAKE_DONE;
    }

    pub(super) fn queue_new_connection_id(
        &mut self,
        sequence: u64,
        connection_id: Vec<u8>,
        reset_token: [u8; 16],
    ) {
        if let Some(pending) = self
            .new_connection_ids
            .iter_mut()
            .find(|pending| pending.sequence == sequence)
        {
            if pending.connection_id != connection_id || pending.reset_token != reset_token {
                let stale = pending.status.handle();
                *pending = NewConnectionId {
                    sequence,
                    connection_id,
                    reset_token,
                    status: Status::Queued,
                };
                self.cancel(stale);
            }
        } else if self.reserve_new() {
            self.new_connection_ids.push(NewConnectionId {
                sequence,
                connection_id,
                reset_token,
                status: Status::Queued,
            });
        }
        self.bits |= NEW_CONNECTION_ID;
    }

    pub(super) fn retirement_count(&self) -> usize {
        self.retire_connection_ids.len()
    }

    pub(super) fn contains_retirement(&self, sequence: u64) -> bool {
        self.retire_connection_ids.contains_key(&sequence)
    }

    pub(super) fn retire_connection_id(&mut self, sequence: u64) {
        if self.retire_connection_ids.contains_key(&sequence) {
            return;
        }
        if !self.reserve_new() {
            return;
        }
        self.retire_connection_ids.insert(sequence, Status::Queued);
        self.bits |= RETIRE_CONNECTION_ID;
    }

    pub(super) fn queue_stop_sending(&mut self, stream_id: u64, error: u64) {
        if !self.stop_sending.contains_key(&stream_id) && !self.reserve_new() {
            return;
        }
        let stale = Self::queue_map(&mut self.stop_sending, stream_id, error);
        self.cancel(stale);
        self.bits |= STOP_SENDING;
    }

    pub(super) fn queue_reset_stream(&mut self, stream_id: u64, error: u64, final_size: u64) {
        if !self.reset_streams.contains_key(&stream_id) && !self.reserve_new() {
            return;
        }
        let stale = Self::queue_map(&mut self.reset_streams, stream_id, (error, final_size));
        self.cancel(stale);
        self.bits |= RESET_STREAM;
    }

    pub(super) fn queue_max_data(&mut self, maximum: u64) {
        if self.max_data.is_none() && !self.reserve_new() {
            return;
        }
        let stale = Self::queue_slot(&mut self.max_data, maximum);
        self.cancel(stale);
        self.bits |= MAX_DATA;
    }

    pub(super) fn queue_max_stream_data(&mut self, stream_id: u64, maximum: u64) {
        if !self.max_stream_data.contains_key(&stream_id) && !self.reserve_new() {
            return;
        }
        let stale = Self::queue_map(&mut self.max_stream_data, stream_id, maximum);
        self.cancel(stale);
        self.bits |= MAX_STREAM_DATA;
    }

    pub(super) fn remove_max_stream_data(&mut self, stream_id: u64) {
        let stale = self
            .max_stream_data
            .remove(&stream_id)
            .and_then(|pending| pending.status.handle());
        self.cancel(stale);
        if self.max_stream_data.is_empty() {
            self.bits &= !MAX_STREAM_DATA;
        }
    }

    pub(super) fn queue_max_streams(&mut self, uni: bool, maximum: u64) {
        let index = usize::from(uni);
        if self.max_streams[index].is_none() && !self.reserve_new() {
            return;
        }
        let stale = Self::queue_slot(&mut self.max_streams[index], maximum);
        self.cancel(stale);
        self.bits |= if uni {
            MAX_STREAMS_UNI
        } else {
            MAX_STREAMS_BIDI
        };
    }

    pub(super) fn queue_path_response(&mut self, data: [u8; 8], limit: usize) {
        if self.path_responses.len() < limit
            && !self.path_responses.iter().any(|token| token.data == data)
            && self.reserve_new()
        {
            self.path_responses.push(PathToken {
                data,
                status: Status::Queued,
            });
            self.bits |= PATH_RESPONSE;
        }
    }

    pub(super) fn queue_path_challenge(
        &mut self,
        data: [u8; 8],
        outstanding: &[[u8; 8]],
        limit: usize,
    ) {
        if self.path_challenges.len() < limit
            && !self.path_challenges.iter().any(|token| token.data == data)
            && !outstanding.contains(&data)
            && self.reserve_new()
        {
            self.path_challenges.push(PathToken {
                data,
                status: Status::Queued,
            });
            self.bits |= PATH_CHALLENGE;
        }
    }

    fn queue_slot<T: PartialEq>(
        slot: &mut Option<PendingValue<T>>,
        value: T,
    ) -> Option<Handle<Control>> {
        if slot.as_ref().is_none_or(|pending| pending.value != value) {
            let stale = slot
                .replace(PendingValue::queued(value))
                .and_then(|pending| pending.status.handle());
            return stale;
        }
        None
    }

    fn queue_map<K: Ord, T: PartialEq>(
        pending: &mut BTreeMap<K, PendingValue<T>>,
        key: K,
        value: T,
    ) -> Option<Handle<Control>> {
        if let Some(entry) = pending.get_mut(&key) {
            if entry.value != value {
                let stale = entry.status.handle();
                *entry = PendingValue::queued(value);
                return stale;
            }
        } else {
            pending.insert(key, PendingValue::queued(value));
        }
        None
    }

    pub(super) fn data_blocked_sendable(&self, maximum: u64) -> bool {
        self.data_blocked
            .as_ref()
            .is_none_or(|pending| pending.value != maximum || pending.status.is_queued())
    }

    pub(super) fn queue_data_blocked(&mut self, maximum: u64) {
        if self.data_blocked.is_none() && !self.reserve_new() {
            return;
        }
        let stale = Self::queue_slot(&mut self.data_blocked, maximum);
        self.cancel(stale);
    }

    pub(super) fn data_credit_raised(&mut self) {
        let stale = self
            .data_blocked
            .take()
            .and_then(|pending| pending.status.handle());
        self.cancel(stale);
    }

    pub(super) fn stream_data_blocked_sendable(&self, stream_id: u64, maximum: u64) -> bool {
        self.stream_data_blocked
            .get(&stream_id)
            .is_none_or(|pending| pending.value != maximum || pending.status.is_queued())
    }

    pub(super) fn queue_stream_data_blocked(&mut self, stream_id: u64, maximum: u64) {
        if !self.stream_data_blocked.contains_key(&stream_id) && !self.reserve_new() {
            return;
        }
        let stale = Self::queue_map(&mut self.stream_data_blocked, stream_id, maximum);
        self.cancel(stale);
    }

    pub(super) fn stream_credit_raised(&mut self, stream_id: u64) {
        self.retire_send_stream(stream_id);
    }

    pub(super) fn retire_send_stream(&mut self, stream_id: u64) {
        let stale = self
            .stream_data_blocked
            .remove(&stream_id)
            .and_then(|pending| pending.status.handle());
        self.cancel(stale);
    }

    fn cancel(&mut self, handle: Option<Handle<Control>>) {
        if let Some(handle) = handle {
            self.deliveries.remove(handle);
        }
    }

    pub(super) fn has_delivery_room(&self, needed: usize) -> bool {
        self.deliveries.has_room(needed)
    }

    pub(super) fn arm_probes(&mut self, epoch: super::Epoch) {
        self.deliveries.arm_probes(epoch);
    }

    pub(super) fn next_probe(
        &self,
        epoch: super::Epoch,
        excluded: impl FnMut(Handle<Control>) -> bool,
    ) -> Option<(Handle<Control>, Control)> {
        self.deliveries.next_probe(epoch, excluded)
    }

    pub(super) fn commit(
        &mut self,
        epoch: super::Epoch,
        record: Control,
        probe: Option<Handle<Control>>,
    ) -> Option<Handle<Control>> {
        if let Some(handle) = probe {
            return self.deliveries.add_probe_carrier(handle).then_some(handle);
        }
        let handle = self.deliveries.insert(epoch, record)?;
        if self
            .status_mut(record)
            .is_some_and(|status| status.sent(handle))
        {
            Some(handle)
        } else {
            self.deliveries.remove(handle);
            None
        }
    }

    pub(super) fn acknowledge(&mut self, handle: Handle<Control>) -> Effect {
        let Some(delivery) = self.deliveries.remove(handle) else {
            return Effect::None;
        };
        let record = delivery.record;
        if !self
            .status_mut(record)
            .is_some_and(|status| status.acknowledges(handle))
        {
            return Effect::None;
        }
        match record {
            Control::HandshakeDone => {
                self.handshake_done = None;
                self.bits &= !HANDSHAKE_DONE;
            }
            Control::NewConnectionId(sequence) => {
                if let Some(index) = self
                    .new_connection_ids
                    .iter()
                    .position(|pending| pending.sequence == sequence)
                {
                    self.new_connection_ids.swap_remove(index);
                }
                if self.new_connection_ids.is_empty() {
                    self.bits &= !NEW_CONNECTION_ID;
                }
            }
            Control::RetireConnectionId(sequence) => {
                self.retire_connection_ids.remove(&sequence);
                if self.retire_connection_ids.is_empty() {
                    self.bits &= !RETIRE_CONNECTION_ID;
                }
            }
            Control::StopSending(stream_id, _) => {
                self.stop_sending.remove(&stream_id);
                if self.stop_sending.is_empty() {
                    self.bits &= !STOP_SENDING;
                }
            }
            Control::ResetStream(stream_id, _, _) => {
                self.reset_streams.remove(&stream_id);
                if self.reset_streams.is_empty() {
                    self.bits &= !RESET_STREAM;
                }
                return Effect::RetireStream(stream_id);
            }
            Control::MaxData(_) => {
                self.max_data = None;
                self.bits &= !MAX_DATA;
            }
            Control::MaxStreamData(stream_id, _) => self.remove_max_stream_data(stream_id),
            Control::MaxStreams(uni, _) => {
                self.max_streams[usize::from(uni)] = None;
                self.bits &= if uni {
                    !MAX_STREAMS_UNI
                } else {
                    !MAX_STREAMS_BIDI
                };
            }
            Control::PathResponse(data) => {
                if let Some(index) = self
                    .path_responses
                    .iter()
                    .position(|token| token.data == data)
                {
                    self.path_responses.swap_remove(index);
                }
                if self.path_responses.is_empty() {
                    self.bits &= !PATH_RESPONSE;
                }
            }
            Control::PathChallenge(data) => {
                if let Some(index) = self
                    .path_challenges
                    .iter()
                    .position(|token| token.data == data)
                {
                    self.path_challenges.swap_remove(index);
                }
                if self.path_challenges.is_empty() {
                    self.bits &= !PATH_CHALLENGE;
                }
            }
            Control::DataBlocked(_) => {
                if let Some(pending) = &mut self.data_blocked {
                    pending.status = Status::Acknowledged;
                }
            }
            Control::StreamDataBlocked(stream_id, _) => {
                if let Some(pending) = self.stream_data_blocked.get_mut(&stream_id) {
                    pending.status = Status::Acknowledged;
                }
            }
        }
        Effect::None
    }

    pub(super) fn lose(&mut self, handle: Handle<Control>) {
        if let Some(delivery) = self.deliveries.release(handle) {
            let _ = self
                .status_mut(delivery.record)
                .is_some_and(|status| status.lost(handle));
        }
    }

    fn status_mut(&mut self, record: Control) -> Option<&mut Status> {
        match record {
            Control::HandshakeDone => self.handshake_done.as_mut(),
            Control::NewConnectionId(sequence) => self
                .new_connection_ids
                .iter_mut()
                .find(|pending| pending.sequence == sequence)
                .map(|pending| &mut pending.status),
            Control::RetireConnectionId(sequence) => self.retire_connection_ids.get_mut(&sequence),
            Control::StopSending(stream_id, error) => self
                .stop_sending
                .get_mut(&stream_id)
                .filter(|pending| pending.value == error)
                .map(|pending| &mut pending.status),
            Control::ResetStream(stream_id, error, final_size) => self
                .reset_streams
                .get_mut(&stream_id)
                .filter(|pending| pending.value == (error, final_size))
                .map(|pending| &mut pending.status),
            Control::MaxData(maximum) => self
                .max_data
                .as_mut()
                .filter(|pending| pending.value == maximum)
                .map(|pending| &mut pending.status),
            Control::MaxStreamData(stream_id, maximum) => self
                .max_stream_data
                .get_mut(&stream_id)
                .filter(|pending| pending.value == maximum)
                .map(|pending| &mut pending.status),
            Control::MaxStreams(uni, maximum) => self.max_streams[usize::from(uni)]
                .as_mut()
                .filter(|pending| pending.value == maximum)
                .map(|pending| &mut pending.status),
            Control::PathResponse(data) => self
                .path_responses
                .iter_mut()
                .find(|token| token.data == data)
                .map(|token| &mut token.status),
            Control::PathChallenge(data) => self
                .path_challenges
                .iter_mut()
                .find(|token| token.data == data)
                .map(|token| &mut token.status),
            Control::DataBlocked(maximum) => self
                .data_blocked
                .as_mut()
                .filter(|pending| pending.value == maximum)
                .map(|pending| &mut pending.status),
            Control::StreamDataBlocked(stream_id, maximum) => self
                .stream_data_blocked
                .get_mut(&stream_id)
                .filter(|pending| pending.value == maximum)
                .map(|pending| &mut pending.status),
        }
    }

    pub(super) fn encode_pending<const MASK: u16, Out>(
        &self,
        out: &mut Out,
        limit: usize,
        record: Control,
    ) -> bool
    where
        Out: DerefMut<Target = Vec<u8>>,
    {
        if MASK == PREFIX {
            match record {
                Control::HandshakeDone => Self::append(out, limit, &Frame::HandshakeDone),
                Control::NewConnectionId(sequence_number) => {
                    let Some(pending) = self
                        .new_connection_ids
                        .iter()
                        .find(|item| item.sequence == sequence_number)
                    else {
                        return false;
                    };
                    let start = out.len();
                    out.push(0x18);
                    let Some(sequence_number) = VarInt::new(sequence_number) else {
                        out.truncate(start);
                        return false;
                    };
                    sequence_number.encode(&mut **out);
                    VarInt::ZERO.encode(&mut **out);
                    out.push(pending.connection_id.len() as u8);
                    out.extend_from_slice(&pending.connection_id);
                    out.extend_from_slice(&pending.reset_token);
                    if out.len() <= limit {
                        true
                    } else {
                        out.truncate(start);
                        false
                    }
                }
                Control::RetireConnectionId(sequence_number) => {
                    let Some(sequence_number) = VarInt::new(sequence_number) else {
                        return false;
                    };
                    Self::append(out, limit, &Frame::RetireConnectionId { sequence_number })
                }
                _ => unreachable!("prefix cursor emitted a suffix control"),
            }
        } else {
            debug_assert_eq!(MASK, SUFFIX);
            match record {
                Control::StopSending(stream_id, error_code) => {
                    let (Some(stream_id), Some(error_code)) =
                        (VarInt::new(stream_id), VarInt::new(error_code))
                    else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &Frame::StopSending {
                            stream_id,
                            error_code,
                        },
                    )
                }
                Control::ResetStream(stream_id, error_code, final_size) => {
                    let (Some(stream_id), Some(error_code), Some(final_size)) = (
                        VarInt::new(stream_id),
                        VarInt::new(error_code),
                        VarInt::new(final_size),
                    ) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &Frame::ResetStream {
                            stream_id,
                            error_code,
                            final_size,
                        },
                    )
                }
                Control::MaxData(maximum_data) => {
                    let Some(maximum_data) = VarInt::new(maximum_data) else {
                        return false;
                    };
                    Self::append(out, limit, &Frame::MaxData { maximum_data })
                }
                Control::MaxStreamData(stream_id, maximum_stream_data) => {
                    let (Some(stream_id), Some(maximum_stream_data)) =
                        (VarInt::new(stream_id), VarInt::new(maximum_stream_data))
                    else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &Frame::MaxStreamData {
                            stream_id,
                            maximum_stream_data,
                        },
                    )
                }
                Control::MaxStreams(is_uni, max_streams) => {
                    let Some(max_streams) = VarInt::new(max_streams) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &Frame::MaxStreams {
                            is_uni,
                            max_streams,
                        },
                    )
                }
                Control::PathResponse(data) => {
                    Self::append(out, limit, &Frame::PathResponse { data })
                }
                Control::PathChallenge(data) => {
                    Self::append(out, limit, &Frame::PathChallenge { data })
                }
                _ => unreachable!("suffix cursor emitted a non-suffix control"),
            }
        }
    }

    pub(super) fn encode_probe<Out>(&self, out: &mut Out, limit: usize, record: Control) -> bool
    where
        Out: DerefMut<Target = Vec<u8>>,
    {
        match record {
            Control::HandshakeDone
            | Control::NewConnectionId(_)
            | Control::RetireConnectionId(_) => {
                self.encode_pending::<PREFIX, _>(out, limit, record)
            }
            Control::StopSending(_, _)
            | Control::ResetStream(_, _, _)
            | Control::MaxData(_)
            | Control::MaxStreamData(_, _)
            | Control::MaxStreams(_, _)
            | Control::PathResponse(_)
            | Control::PathChallenge(_) => self.encode_pending::<SUFFIX, _>(out, limit, record),
            Control::DataBlocked(_) | Control::StreamDataBlocked(_, _) => {
                self.encode_blocked(out, limit, record)
            }
        }
    }

    pub(super) fn encode_blocked<Out>(&self, out: &mut Out, limit: usize, record: Control) -> bool
    where
        Out: DerefMut<Target = Vec<u8>>,
    {
        match record {
            Control::DataBlocked(maximum_data) => {
                let Some(maximum_data) = VarInt::new(maximum_data) else {
                    return false;
                };
                Self::append(out, limit, &Frame::DataBlocked { maximum_data })
            }
            Control::StreamDataBlocked(stream_id, maximum_stream_data) => {
                let (Some(stream_id), Some(maximum_stream_data)) =
                    (VarInt::new(stream_id), VarInt::new(maximum_stream_data))
                else {
                    return false;
                };
                Self::append(
                    out,
                    limit,
                    &Frame::StreamDataBlocked {
                        stream_id,
                        maximum_stream_data,
                    },
                )
            }
            _ => unreachable!("blocked encoder received a regular control"),
        }
    }

    fn append<Out>(out: &mut Out, limit: usize, frame: &Frame) -> bool
    where
        Out: DerefMut<Target = Vec<u8>>,
    {
        let start = out.len();
        if frame.encode(out).is_ok() && out.len() <= limit {
            true
        } else {
            out.truncate(start);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Epoch;

    fn next_suffix(pending: &Pending) -> Control {
        pending
            .suffix()
            .and_then(|mut cursor| cursor.next(pending))
            .expect("queued suffix control")
    }

    #[test]
    fn stale_ack_does_not_clear_a_newer_generation() {
        let mut pending = Pending::new(8);
        pending.queue_max_data(10);
        let old = next_suffix(&pending);
        let old_handle = pending
            .commit(Epoch::Application, old, None)
            .expect("first delivery");

        pending.queue_max_data(20);
        assert_eq!(next_suffix(&pending), Control::MaxData(20));
        pending.arm_probes(Epoch::Application);
        assert!(pending.next_probe(Epoch::Application, |_| false).is_none());
        assert!(matches!(pending.acknowledge(old_handle), Effect::None));
        assert_eq!(next_suffix(&pending), Control::MaxData(20));
    }

    #[test]
    fn final_carrier_loss_requeues_the_current_generation() {
        let mut pending = Pending::new(8);
        pending.queue_path_challenge([7; 8], &[], 8);
        let record = next_suffix(&pending);
        let handle = pending
            .commit(Epoch::Application, record, None)
            .expect("first delivery");

        pending.arm_probes(Epoch::Application);
        let (probe, probe_record) = pending
            .next_probe(Epoch::Application, |_| false)
            .expect("probe delivery");
        assert_eq!(probe, handle);
        assert_eq!(probe_record, record);
        assert_eq!(
            pending.commit(Epoch::Application, record, Some(probe)),
            Some(handle)
        );

        pending.lose(handle);
        assert!(!pending.has_sendable());
        pending.lose(handle);
        assert_eq!(next_suffix(&pending), record);
    }

    #[test]
    fn logical_controls_cannot_exceed_the_delivery_limit() {
        let mut pending = Pending::new(2);
        pending.queue_max_data(10);
        pending.queue_stop_sending(1, 2);

        pending.queue_reset_stream(5, 6, 7);
        assert_eq!(pending.len(), 2);
        assert!(!pending.reset_streams.contains_key(&5));
        assert!(pending.overflowed());
        assert!(pending.take_overflowed());
        assert!(!pending.take_overflowed());

        pending.queue_max_data(20);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending.max_data.as_ref().map(|value| value.value), Some(20));
        assert!(!pending.overflowed());
    }

    #[test]
    fn removing_a_control_releases_logical_capacity() {
        let mut pending = Pending::new(1);
        pending.queue_max_stream_data(1, 10);
        pending.remove_max_stream_data(1);
        pending.queue_reset_stream(2, 3, 4);

        assert_eq!(pending.len(), 1);
        assert!(pending.reset_streams.contains_key(&2));
        assert!(!pending.overflowed());
    }
}
