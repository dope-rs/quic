use std::{marker, num::NonZeroU64};

use super::{
    Epoch,
    delivery::{Control, Handle},
    send,
};

pub(super) mod cursor;
pub(super) mod delivery;
pub(super) mod encode;
mod linkage;
mod records;

use records::Records;

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
const LANE_COUNT: usize = 11;

pub(super) const PREFIX: u16 = HANDSHAKE_DONE | NEW_CONNECTION_ID | RETIRE_CONNECTION_ID;
pub(super) const SUFFIX: u16 = STOP_SENDING
    | RESET_STREAM
    | MAX_DATA
    | MAX_STREAM_DATA
    | MAX_STREAMS_BIDI
    | MAX_STREAMS_UNI
    | PATH_RESPONSE
    | PATH_CHALLENGE;

const NONE: u32 = u32::MAX;
const SIGNAL_LIVE: u64 = 1 << 63;
const SIGNAL_VALUE_MAX: u64 = (1 << 62) - 1;

pub(super) mod kind {
    pub(in crate::conn) struct HandshakeDone;
    pub(in crate::conn) struct NewConnectionId;
    pub(in crate::conn) struct RetireConnectionId;
    pub(in crate::conn) struct StopSending;
    pub(in crate::conn) struct ResetStream;
    pub(in crate::conn) struct MaxData;
    pub(in crate::conn) struct MaxStreamData;
    pub(in crate::conn) struct MaxStreams;
    pub(in crate::conn) struct PathResponse;
    pub(in crate::conn) struct PathChallenge;
    pub(in crate::conn) struct DataBlocked;
    pub(in crate::conn) struct StreamDataBlocked;
}

/// Stable typed identity held by the control's natural owner.
///
/// Its generation changes only when a slot is removed and reused. Packet
/// delivery handles use a separate generation, so loss and replacement can
/// invalidate stale packets without invalidating the owner's identity.
#[repr(transparent)]
pub(super) struct OwnerKey<Kind>(NonZeroU64, marker::PhantomData<fn() -> Kind>);

impl<Kind> OwnerKey<Kind> {
    fn new(index: usize, generation: u32) -> Option<Self> {
        let encoded_index = u32::try_from(index).ok()?.checked_add(1)?;
        let raw = (u64::from(generation) << 32) | u64::from(encoded_index);
        Some(Self(NonZeroU64::new(raw)?, marker::PhantomData))
    }

    fn index(self) -> usize {
        ((self.0.get() as u32) - 1) as usize
    }

    fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }

    fn from_raw(raw: u64) -> Option<Self> {
        Some(Self(NonZeroU64::new(raw)?, marker::PhantomData))
    }
}

impl<Kind> Clone for OwnerKey<Kind> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Kind> Copy for OwnerKey<Kind> {}

impl<Kind> PartialEq for OwnerKey<Kind> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<Kind> Eq for OwnerKey<Kind> {}

/// One word owned by the state that requires a reliable control record.
///
/// Zero is idle, a low nonzero value retains a deferred QUIC varint, and the
/// high-bit form retains a live or acknowledged generation-checked owner. The
/// queue therefore owns delivery only; desired state never depends on space in
/// the bounded journal.
#[repr(transparent)]
pub(super) struct Signal<Kind>(u64, marker::PhantomData<fn() -> Kind>);

impl<Kind> Signal<Kind> {
    pub(super) const fn new() -> Self {
        Self(0, marker::PhantomData)
    }

    pub(super) const fn is_deferred(&self) -> bool {
        self.0 != 0 && self.0 & SIGNAL_LIVE == 0
    }

    pub(super) const fn deferred(&self) -> Option<u64> {
        if self.is_deferred() {
            Some(self.0 - 1)
        } else {
            None
        }
    }

    fn defer(&mut self, value: u64) {
        debug_assert!(value <= SIGNAL_VALUE_MAX);
        self.0 = value.saturating_add(1);
    }

    fn owner(&self) -> Option<OwnerKey<Kind>> {
        (self.0 & SIGNAL_LIVE != 0)
            .then(|| OwnerKey::from_raw(self.0 & !SIGNAL_LIVE))
            .flatten()
    }

    fn set_owner(&mut self, owner: Option<OwnerKey<Kind>>) {
        self.0 = owner.map_or(0, |owner| SIGNAL_LIVE | owner.0.get());
    }

    fn clear(&mut self) {
        self.0 = 0;
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

pub(super) enum Effect {
    None,
    RetireStream(u64),
}

#[derive(Clone, Copy)]
enum Status {
    Queued,
    InFlight {
        epoch: Epoch,
        carriers: u16,
        probe_round: u32,
    },
}

#[derive(Clone, Copy)]
struct Links {
    prev: u32,
    next: u32,
}

impl Links {
    const EMPTY: Self = Self {
        prev: NONE,
        next: NONE,
    };
}

#[derive(Clone, Copy)]
struct Chain {
    head: u32,
    tail: u32,
}

impl Chain {
    const EMPTY: Self = Self {
        head: NONE,
        tail: NONE,
    };
}

struct NewConnectionId {
    key: super::path::LocalCidKey,
}

struct Entry {
    record: Control,
    new_connection_id: Option<NewConnectionId>,
    status: Status,
    ready: Links,
    flight: Links,
}

struct Slot {
    delivery_generation: u32,
    owner_generation: u32,
    next_free: u32,
    entry: Option<Entry>,
}

/// One bounded owner for a control's value, delivery generation and queue links.
///
/// Queueing resolves a typed key supplied by the record's natural owner in one
/// slot access. Selection, commit, ACK, loss and probe scheduling then need no
/// allocation, hashing or delivery-table lookup. A cursor borrows this owner,
/// so selected records cannot outlive or race mutation of their generation.
pub(super) struct Pending {
    slots: Vec<Slot>,
    free_head: u32,
    len: usize,
    limit: usize,
    overflowed: bool,
    bits: u16,
    ready_bits: u16,
    kind_counts: [usize; LANE_COUNT],
    ready: [Chain; LANE_COUNT],
    in_flight: [Chain; 3],
    probe_cursor: [u32; 3],
    probe_round: [u32; 3],
    handshake_done: Option<OwnerKey<kind::HandshakeDone>>,
}

/// Linear budget for new records. Reserving temporarily lowers the ordinary
/// queue ceiling; consuming or releasing the permit restores it exactly.
pub(super) struct Permit<'pending> {
    pending: &'pending mut Pending,
    remaining: usize,
}

impl Permit<'_> {
    fn take(&mut self) {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .expect("control commit consumes only its proven capacity");
        self.pending.limit = self
            .pending
            .limit
            .checked_add(1)
            .expect("released control reservation fits its original limit");
    }

    fn credit(&mut self) {
        self.pending.limit = self
            .pending
            .limit
            .checked_sub(1)
            .expect("a removed control leaves one reusable reserved slot");
        self.remaining = self
            .remaining
            .checked_add(1)
            .expect("a bounded control queue has a bounded reservation");
    }

    fn queue<Kind>(
        &mut self,
        owner: &mut Option<OwnerKey<Kind>>,
        record: Control,
        new_connection_id: Option<NewConnectionId>,
    ) {
        if self.pending.resolve_owner(*owner).is_none() {
            self.take();
        }
        self.pending
            .queue(owner, record, new_connection_id)
            .unwrap_or_else(|| unreachable!("control capacity was reserved"));
    }

    fn queue_signal<Kind>(
        &mut self,
        signal: &mut Signal<Kind>,
        record: Control,
        new_connection_id: Option<NewConnectionId>,
    ) {
        let mut owner = signal.owner();
        self.queue(&mut owner, record, new_connection_id);
        signal.set_owner(owner);
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.pending.limit = self
            .pending
            .limit
            .checked_add(self.remaining)
            .expect("released control reservations fit the original limit");
    }
}

/// Typed mutations available to natural owners and derived-control drains.
/// `Pending` retains defer-capable required values in their typed signal, while
/// `Permit` materializes them under a linear journal reservation. Neither
/// exposes queue storage or lets a borrowed record escape the mutation.
pub(in crate::conn) trait Write {
    fn owner_is_live<Kind>(&self, owner: Option<OwnerKey<Kind>>) -> bool;
    fn remove_control<Kind>(&mut self, owner: &mut Option<OwnerKey<Kind>>);
    fn remove_signal<Kind>(&mut self, signal: &mut Signal<Kind>);
    fn handshake_done(&mut self);
    fn queue_new_connection_id(
        &mut self,
        owner: &mut Option<OwnerKey<kind::NewConnectionId>>,
        sequence: u64,
        key: super::path::LocalCidKey,
    );
    fn retire_connection_id(
        &mut self,
        owner: &mut Option<OwnerKey<kind::RetireConnectionId>>,
        sequence: u64,
    );
    fn queue_reset_stream(
        &mut self,
        signal: &mut Signal<kind::ResetStream>,
        stream_id: u64,
        error: u64,
        final_size: u64,
    );
    fn queue_stop_sending(
        &mut self,
        signal: &mut Signal<kind::StopSending>,
        stream_id: u64,
        error: u64,
    );
    fn queue_max_data(&mut self, owner: &mut Option<OwnerKey<kind::MaxData>>, maximum: u64);
    fn queue_max_stream_data(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxStreamData>>,
        stream_id: u64,
        maximum: u64,
    );
    fn queue_max_streams(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxStreams>>,
        uni: bool,
        maximum: u64,
    );
    fn queue_path_response(
        &mut self,
        owner: &mut Option<OwnerKey<kind::PathResponse>>,
        data: [u8; 8],
    );
    fn queue_path_challenge(
        &mut self,
        owner: &mut Option<OwnerKey<kind::PathChallenge>>,
        data: [u8; 8],
    );
    fn acknowledge_control(&mut self, handle: Handle<Control>) -> Effect;
    fn lose_control(&mut self, handle: Handle<Control>);
}

impl Write for Pending {
    fn owner_is_live<Kind>(&self, owner: Option<OwnerKey<Kind>>) -> bool {
        Pending::owner_is_live(self, owner)
    }

    fn remove_control<Kind>(&mut self, owner: &mut Option<OwnerKey<Kind>>) {
        Pending::remove_control(self, owner);
    }

    fn remove_signal<Kind>(&mut self, signal: &mut Signal<Kind>) {
        Pending::remove_signal(self, signal);
    }

    fn handshake_done(&mut self) {
        Pending::handshake_done(self);
    }

    fn queue_new_connection_id(
        &mut self,
        owner: &mut Option<OwnerKey<kind::NewConnectionId>>,
        sequence: u64,
        key: super::path::LocalCidKey,
    ) {
        Pending::queue_new_connection_id(self, owner, sequence, key);
    }

    fn retire_connection_id(
        &mut self,
        owner: &mut Option<OwnerKey<kind::RetireConnectionId>>,
        sequence: u64,
    ) {
        Pending::retire_connection_id(self, owner, sequence);
    }

    fn queue_reset_stream(
        &mut self,
        signal: &mut Signal<kind::ResetStream>,
        stream_id: u64,
        error: u64,
        final_size: u64,
    ) {
        Pending::queue_reset_stream(self, signal, stream_id, error, final_size);
    }

    fn queue_stop_sending(
        &mut self,
        signal: &mut Signal<kind::StopSending>,
        stream_id: u64,
        error: u64,
    ) {
        Pending::queue_stop_sending(self, signal, stream_id, error);
    }

    fn queue_max_data(&mut self, owner: &mut Option<OwnerKey<kind::MaxData>>, maximum: u64) {
        Pending::queue_max_data(self, owner, maximum);
    }

    fn queue_max_stream_data(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxStreamData>>,
        stream_id: u64,
        maximum: u64,
    ) {
        Pending::queue_max_stream_data(self, owner, stream_id, maximum);
    }

    fn queue_max_streams(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxStreams>>,
        uni: bool,
        maximum: u64,
    ) {
        Pending::queue_max_streams(self, owner, uni, maximum);
    }

    fn queue_path_response(
        &mut self,
        owner: &mut Option<OwnerKey<kind::PathResponse>>,
        data: [u8; 8],
    ) {
        Pending::queue_path_response(self, owner, data);
    }

    fn queue_path_challenge(
        &mut self,
        owner: &mut Option<OwnerKey<kind::PathChallenge>>,
        data: [u8; 8],
    ) {
        Pending::queue_path_challenge(self, owner, data);
    }

    fn acknowledge_control(&mut self, handle: Handle<Control>) -> Effect {
        delivery::Delivery::new(self).acknowledge(handle)
    }

    fn lose_control(&mut self, handle: Handle<Control>) {
        delivery::Delivery::new(self).lose(handle);
    }
}

impl Write for Permit<'_> {
    fn owner_is_live<Kind>(&self, owner: Option<OwnerKey<Kind>>) -> bool {
        self.pending.owner_is_live(owner)
    }

    fn remove_control<Kind>(&mut self, owner: &mut Option<OwnerKey<Kind>>) {
        if self.pending.remove_owner(owner) {
            self.credit();
        }
    }

    fn remove_signal<Kind>(&mut self, signal: &mut Signal<Kind>) {
        let mut owner = signal.owner();
        if self.pending.remove_owner(&mut owner) {
            self.credit();
        }
        signal.clear();
    }

    fn handshake_done(&mut self) {
        let mut owner = self.pending.handshake_done.take();
        self.queue(&mut owner, Control::HandshakeDone, None);
        self.pending.handshake_done = owner;
    }

    fn queue_new_connection_id(
        &mut self,
        owner: &mut Option<OwnerKey<kind::NewConnectionId>>,
        sequence: u64,
        key: super::path::LocalCidKey,
    ) {
        self.queue(
            owner,
            Control::NewConnectionId(sequence),
            Some(NewConnectionId { key }),
        );
    }

    fn retire_connection_id(
        &mut self,
        owner: &mut Option<OwnerKey<kind::RetireConnectionId>>,
        sequence: u64,
    ) {
        self.queue(owner, Control::RetireConnectionId(sequence), None);
    }

    fn queue_reset_stream(
        &mut self,
        signal: &mut Signal<kind::ResetStream>,
        stream_id: u64,
        error: u64,
        final_size: u64,
    ) {
        self.queue_signal(
            signal,
            Control::ResetStream(stream_id, error, final_size),
            None,
        );
    }

    fn queue_stop_sending(
        &mut self,
        signal: &mut Signal<kind::StopSending>,
        stream_id: u64,
        error: u64,
    ) {
        self.queue_signal(signal, Control::StopSending(stream_id, error), None);
    }

    fn queue_max_data(&mut self, owner: &mut Option<OwnerKey<kind::MaxData>>, maximum: u64) {
        self.queue(owner, Control::MaxData(maximum), None);
    }

    fn queue_max_stream_data(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxStreamData>>,
        stream_id: u64,
        maximum: u64,
    ) {
        self.queue(owner, Control::MaxStreamData(stream_id, maximum), None);
    }

    fn queue_max_streams(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxStreams>>,
        uni: bool,
        maximum: u64,
    ) {
        self.queue(owner, Control::MaxStreams(uni, maximum), None);
    }

    fn queue_path_response(
        &mut self,
        owner: &mut Option<OwnerKey<kind::PathResponse>>,
        data: [u8; 8],
    ) {
        self.queue(owner, Control::PathResponse(data), None);
    }

    fn queue_path_challenge(
        &mut self,
        owner: &mut Option<OwnerKey<kind::PathChallenge>>,
        data: [u8; 8],
    ) {
        self.queue(owner, Control::PathChallenge(data), None);
    }

    fn acknowledge_control(&mut self, handle: Handle<Control>) -> Effect {
        let previous_len = self.pending.len;
        let effect = delivery::Delivery::new(self.pending).acknowledge(handle);
        if self.pending.len != previous_len && self.pending.free_head == handle.index() as u32 {
            self.credit();
        }
        effect
    }

    fn lose_control(&mut self, handle: Handle<Control>) {
        delivery::Delivery::new(self.pending).lose(handle);
    }
}

impl Pending {
    pub(super) fn new(limit: usize) -> Self {
        let limit = limit.min((u32::MAX - 1) as usize);
        Self {
            slots: Vec::with_capacity(limit),
            free_head: NONE,
            len: 0,
            limit,
            overflowed: false,
            bits: 0,
            ready_bits: 0,
            kind_counts: [0; LANE_COUNT],
            ready: [Chain::EMPTY; LANE_COUNT],
            in_flight: [Chain::EMPTY; 3],
            probe_cursor: [NONE; 3],
            probe_round: [0; 3],
            handshake_done: None,
        }
    }

    pub(super) fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub(super) fn take_overflowed(&mut self) -> bool {
        let overflowed = self.overflowed;
        self.overflowed = false;
        overflowed
    }

    pub(super) fn is_empty(&self) -> bool {
        self.bits == 0
    }

    pub(super) fn remaining_capacity(&self) -> usize {
        self.limit - self.len
    }

    pub(super) fn handshake_done_control_slots(&self) -> usize {
        usize::from(!self.owner_is_live(self.handshake_done))
    }

    pub(super) fn try_reserve(&mut self, additional: usize) -> Option<Permit<'_>> {
        if additional > self.limit - self.len {
            return None;
        }
        self.limit -= additional;
        Some(Permit {
            pending: self,
            remaining: additional,
        })
    }

    pub(super) fn only_path_responses(&self) -> Option<cursor::Cursor<'_, PATH_RESPONSE>> {
        (self.bits == PATH_RESPONSE).then(|| cursor::Cursor::new(self))
    }

    pub(super) fn only_path_challenges(&self) -> Option<cursor::Cursor<'_, PATH_CHALLENGE>> {
        (self.bits == PATH_CHALLENGE).then(|| cursor::Cursor::new(self))
    }

    pub(super) fn prefix(&self) -> Option<cursor::Cursor<'_, PREFIX>> {
        (self.ready_bits & PREFIX != 0).then(|| cursor::Cursor::new(self))
    }

    pub(super) fn suffix(&self) -> Option<cursor::Cursor<'_, SUFFIX>> {
        (self.ready_bits & SUFFIX != 0).then(|| cursor::Cursor::new(self))
    }

    pub(super) fn has_sendable(&self) -> bool {
        self.ready_bits & (PREFIX | SUFFIX) != 0
    }

    pub(super) fn handshake_done(&mut self) {
        let mut owner = self.handshake_done.take();
        self.queue(&mut owner, Control::HandshakeDone, None);
        self.handshake_done = owner;
    }

    pub(super) fn queue_new_connection_id(
        &mut self,
        owner: &mut Option<OwnerKey<kind::NewConnectionId>>,
        sequence: u64,
        key: super::path::LocalCidKey,
    ) {
        self.queue(
            owner,
            Control::NewConnectionId(sequence),
            Some(NewConnectionId { key }),
        );
    }

    pub(super) fn retire_connection_id(
        &mut self,
        owner: &mut Option<OwnerKey<kind::RetireConnectionId>>,
        sequence: u64,
    ) {
        self.queue(owner, Control::RetireConnectionId(sequence), None);
    }

    pub(super) fn queue_stop_sending(
        &mut self,
        signal: &mut Signal<kind::StopSending>,
        _stream_id: u64,
        error: u64,
    ) {
        self.defer_signal(signal, error);
    }

    pub(super) fn queue_reset_stream(
        &mut self,
        signal: &mut Signal<kind::ResetStream>,
        _stream_id: u64,
        error: u64,
        _final_size: u64,
    ) {
        self.defer_signal(signal, error);
    }

    pub(super) fn queue_max_data(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxData>>,
        maximum: u64,
    ) {
        self.queue(owner, Control::MaxData(maximum), None);
    }

    pub(super) fn queue_max_stream_data(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxStreamData>>,
        stream_id: u64,
        maximum: u64,
    ) {
        self.queue(owner, Control::MaxStreamData(stream_id, maximum), None);
    }

    pub(super) fn queue_max_streams(
        &mut self,
        owner: &mut Option<OwnerKey<kind::MaxStreams>>,
        uni: bool,
        maximum: u64,
    ) {
        self.queue(owner, Control::MaxStreams(uni, maximum), None);
    }

    pub(super) fn queue_path_response(
        &mut self,
        owner: &mut Option<OwnerKey<kind::PathResponse>>,
        data: [u8; 8],
    ) {
        self.queue(owner, Control::PathResponse(data), None);
    }

    pub(super) fn queue_path_challenge(
        &mut self,
        owner: &mut Option<OwnerKey<kind::PathChallenge>>,
        data: [u8; 8],
    ) {
        self.queue(owner, Control::PathChallenge(data), None);
    }

    pub(super) fn data_blocked_sendable(&self, credit: &send::Credit<kind::DataBlocked>) -> bool {
        self.blocked_sendable(credit.blocked(), Control::DataBlocked(credit.limit()))
    }

    pub(super) fn queue_data_blocked(
        &mut self,
        credit: &mut send::Credit<kind::DataBlocked>,
    ) -> Option<Handle<Control>> {
        let record = Control::DataBlocked(credit.limit());
        self.queue_blocked(credit.blocked_mut(), record)
    }

    pub(super) fn stream_data_blocked_sendable(
        &self,
        credit: &send::Credit<kind::StreamDataBlocked>,
        stream_id: u64,
    ) -> bool {
        self.blocked_sendable(
            credit.blocked(),
            Control::StreamDataBlocked(stream_id, credit.limit()),
        )
    }

    pub(super) fn queue_stream_data_blocked(
        &mut self,
        credit: &mut send::Credit<kind::StreamDataBlocked>,
        stream_id: u64,
    ) -> Option<Handle<Control>> {
        let record = Control::StreamDataBlocked(stream_id, credit.limit());
        self.queue_blocked(credit.blocked_mut(), record)
    }

    fn blocked_sendable<Kind>(&self, owner: Option<OwnerKey<Kind>>, record: Control) -> bool {
        // A stale typed key is the natural owner's ACK tombstone. Only an
        // absent key may allocate for this limit; a queued live key may retry.
        match owner {
            None => self.remaining_capacity() != 0,
            Some(owner) => self.resolve_owner(Some(owner)).is_some_and(|entry| {
                debug_assert_eq!(entry.record, record);
                matches!(entry.status, Status::Queued)
            }),
        }
    }

    fn queue_blocked<Kind>(
        &mut self,
        owner: &mut Option<OwnerKey<Kind>>,
        record: Control,
    ) -> Option<Handle<Control>> {
        // BLOCKED frames are advisory. Capacity pressure defers a first
        // emission, while a stale ACK tombstone suppresses the same limit.
        match *owner {
            None if self.remaining_capacity() == 0 => return None,
            Some(owner) if self.resolve_owner(Some(owner)).is_none() => return None,
            None | Some(_) => {}
        }
        self.queue(owner, record, None)
    }

    pub(super) fn arm_probes(&mut self, epoch: Epoch) {
        let epoch_index = epoch as usize;
        let next = self.probe_round[epoch_index].wrapping_add(1);
        if next == 0 {
            for slot in &mut self.slots {
                if let Some(Entry {
                    status: Status::InFlight { probe_round, .. },
                    ..
                }) = &mut slot.entry
                {
                    *probe_round = 0;
                }
            }
            self.probe_round[epoch_index] = 1;
        } else {
            self.probe_round[epoch_index] = next;
        }
        self.probe_cursor[epoch_index] = self.in_flight[epoch_index].head;
    }

    pub(super) fn next_probe(
        &self,
        epoch: Epoch,
        mut excluded: impl FnMut(Handle<Control>) -> bool,
    ) -> Option<(Handle<Control>, Control)> {
        let epoch_index = epoch as usize;
        let round = self.probe_round[epoch_index];
        let mut current = self.probe_cursor[epoch_index];
        while current != NONE {
            let index = current as usize;
            let slot = &self.slots[index];
            let entry = slot.entry.as_ref().unwrap();
            current = entry.flight.next;
            if let Status::InFlight {
                epoch: entry_epoch,
                probe_round,
                ..
            } = entry.status
                && entry_epoch == epoch
                && probe_round != round
            {
                let handle = Handle::new(index, slot.delivery_generation)?;
                if !excluded(handle) {
                    return Some((handle, entry.record));
                }
            }
        }
        None
    }

    pub(super) fn local_cid_key(
        &self,
        handle: Handle<Control>,
    ) -> Option<super::path::LocalCidKey> {
        Some(self.resolve(handle)?.new_connection_id.as_ref()?.key)
    }

    pub(super) fn owner_is_live<Kind>(&self, owner: Option<OwnerKey<Kind>>) -> bool {
        self.resolve_owner(owner).is_some()
    }

    pub(super) fn remove_control<Kind>(&mut self, owner: &mut Option<OwnerKey<Kind>>) {
        self.remove_owner(owner);
    }

    pub(super) fn remove_signal<Kind>(&mut self, signal: &mut Signal<Kind>) {
        let mut owner = signal.owner();
        self.remove_owner(&mut owner);
        signal.clear();
    }

    fn defer_signal<Kind>(&mut self, signal: &mut Signal<Kind>, value: u64) {
        let mut owner = signal.owner();
        self.remove_owner(&mut owner);
        signal.defer(value);
    }
}

fn lane(bit: u16) -> usize {
    bit.trailing_zeros() as usize
}

fn kind_bit(record: Control) -> u16 {
    match record {
        Control::HandshakeDone => HANDSHAKE_DONE,
        Control::NewConnectionId(_) => NEW_CONNECTION_ID,
        Control::RetireConnectionId(_) => RETIRE_CONNECTION_ID,
        Control::StopSending(_, _) => STOP_SENDING,
        Control::ResetStream(_, _, _) => RESET_STREAM,
        Control::MaxData(_) => MAX_DATA,
        Control::MaxStreamData(_, _) => MAX_STREAM_DATA,
        Control::MaxStreams(false, _) => MAX_STREAMS_BIDI,
        Control::MaxStreams(true, _) => MAX_STREAMS_UNI,
        Control::PathResponse(_) => PATH_RESPONSE,
        Control::PathChallenge(_) => PATH_CHALLENGE,
        Control::DataBlocked(_) | Control::StreamDataBlocked(_, _) => 0,
    }
}

const _: () = assert!(std::mem::size_of::<Option<OwnerKey<kind::MaxData>>>() == 8);
const _: () = assert!(std::mem::size_of::<Signal<kind::ResetStream>>() == 8);
