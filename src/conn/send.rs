use std::mem;
use std::ops;

use crate::stream;
use crate::varint;

use super::streams::table;
use crate::conn::control;
use crate::conn::control::Write as _;
use crate::conn::stream_journal;

pub(super) struct Side;

pub(super) type Id = table::Id<Side>;
pub(super) type Handle = table::Handle<Side>;
pub(super) type Map = table::Map<Side, Entry>;

const READY_NONE: u32 = u32::MAX;
const READY_END: u32 = u32::MAX - 1;

/// Peer-owned flow-control credit and the advisory derived from its limit.
///
/// `blocked == None` means the current limit has not been reported, a live key
/// means queued or in flight, and a stale key is the zero-allocation ACK
/// tombstone. Raising the limit clears all three states through the queue owner.
pub(super) struct Credit<Kind> {
    limit: u64,
    blocked: Option<control::OwnerKey<Kind>>,
}

impl<Kind> Credit<Kind> {
    pub(super) fn new(limit: u64) -> Self {
        debug_assert!(limit <= varint::VarInt::MAX);
        Self {
            limit,
            blocked: None,
        }
    }

    pub(super) fn limit(&self) -> u64 {
        self.limit
    }

    pub(super) fn initialize(&mut self, limit: u64) {
        debug_assert!(self.blocked.is_none());
        debug_assert!(limit <= varint::VarInt::MAX);
        self.limit = limit;
    }

    pub(super) fn raise<C: control::Write>(&mut self, limit: u64, control: &mut C) {
        debug_assert!(limit <= varint::VarInt::MAX);
        if limit <= self.limit() {
            return;
        }
        self.limit = limit;
        control.remove_control(&mut self.blocked);
    }

    pub(super) fn clear_blocked<C: control::Write>(&mut self, control: &mut C) {
        control.remove_control(&mut self.blocked);
    }

    pub(in crate::conn) fn blocked(&self) -> Option<control::OwnerKey<Kind>> {
        self.blocked
    }

    pub(in crate::conn) fn blocked_mut(&mut self) -> &mut Option<control::OwnerKey<Kind>> {
        &mut self.blocked
    }
}

pub(super) struct Entry {
    pub(super) stream: stream::Sender,
    pub(super) credit: Credit<control::kind::StreamDataBlocked>,
    pub(super) delivery_group: Option<stream_journal::GroupId>,
    pub(super) reset_stream: control::Signal<control::kind::ResetStream>,
}

impl Entry {
    fn new(credit: u64) -> Self {
        Self {
            stream: stream::Sender::default(),
            credit: Credit::new(credit),
            delivery_group: None,
            reset_stream: control::Signal::new(),
        }
    }

    fn reuse(&mut self, credit: u64) {
        debug_assert!(self.delivery_group.is_none());
        debug_assert!(self.reset_stream.is_empty());
        debug_assert!(self.credit.blocked().is_none());
        debug_assert!(self.stream.ready_previous().is_none());
        self.credit = Credit::new(credit);
    }

    fn retire(&mut self) {
        debug_assert!(self.delivery_group.is_none());
        debug_assert!(self.reset_stream.is_empty());
        debug_assert!(self.credit.blocked().is_none());
        debug_assert!(self.stream.ready_previous().is_none());
        self.delivery_group = None;
        self.reset_stream = control::Signal::new();
        self.stream.recycle();
        self.credit = Credit::new(0);
    }

    pub(super) fn has_deferred_reset(&self) -> bool {
        self.reset_stream.is_deferred()
    }
}

impl table::Reusable for Entry {
    type Init = u64;

    fn new(init: Self::Init) -> Self {
        Self::new(init)
    }

    fn reuse(&mut self, init: Self::Init) {
        self.reuse(init);
    }

    fn retire(&mut self) {
        self.retire();
    }
}

impl ops::Deref for Entry {
    type Target = stream::Sender;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl ops::DerefMut for Entry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

pub(super) struct Schedule {
    head: Option<Handle>,
    tail: Option<Handle>,
    cursor: Option<Handle>,
    len: usize,
}

impl Schedule {
    pub(super) fn new() -> Self {
        Self {
            head: None,
            tail: None,
            cursor: None,
            len: 0,
        }
    }

    pub(super) fn update(&mut self, streams: &mut Map, handle: Handle, active: bool) {
        if active {
            self.activate(streams, handle);
        } else {
            self.deactivate(streams, handle);
        }
    }

    fn activate(&mut self, streams: &mut Map, handle: Handle) {
        debug_assert!(handle.index() < READY_END);
        let previous = self.tail.map_or(READY_END, Handle::index);
        let Some((_, entry, next)) = streams.resolve_with_position_mut(handle) else {
            return;
        };
        if entry.stream.ready_previous().is_some() {
            return;
        }
        debug_assert!(
            next.is_none(),
            "ready link cannot overlap an owned stream event"
        );
        if !next.is_none() {
            return;
        }
        entry.stream.set_ready_previous(Some(previous));
        next.set(READY_END);

        if let Some(tail) = self.tail {
            let tail_next = streams
                .position_mut(tail)
                .expect("ready tail retains a live generation-checked handle");
            debug_assert_eq!(tail_next.get(), READY_END);
            tail_next.set(handle.index());
        } else {
            self.head = Some(handle);
            self.cursor = Some(handle);
        }
        self.tail = Some(handle);
        self.len += 1;
    }

    pub(super) fn deactivate(&mut self, streams: &mut Map, handle: Handle) {
        let Some((_, entry, next_position)) = streams.resolve_with_position_mut(handle) else {
            return;
        };
        let Some(previous) = entry.stream.ready_previous() else {
            return;
        };
        let next = next_position.get();
        debug_assert_ne!(next, READY_NONE);
        entry.stream.set_ready_previous(None);
        next_position.clear();

        let previous_handle = Self::linked_handle(streams, previous);
        let next_handle = Self::linked_handle(streams, next);
        if let Some(previous_handle) = previous_handle {
            streams
                .position_mut(previous_handle)
                .expect("ready predecessor retains a live handle")
                .set(next);
        } else {
            self.head = next_handle;
        }
        if let Some(next_handle) = next_handle {
            streams
                .resolve_mut(next_handle)
                .expect("ready successor retains a live handle")
                .1
                .stream
                .set_ready_previous(Some(previous));
        } else {
            self.tail = previous_handle;
        }

        debug_assert_ne!(self.len, 0);
        self.len -= 1;
        if self.len == 0 {
            self.head = None;
            self.tail = None;
            self.cursor = None;
        } else if self.cursor == Some(handle) {
            self.cursor = next_handle.or(self.head);
        }
    }

    fn linked_handle(streams: &Map, index: u32) -> Option<Handle> {
        if index == READY_END {
            return None;
        }
        debug_assert_ne!(index, READY_NONE);
        Some(
            streams
                .handle_at(index)
                .expect("ready link targets a live stream slot"),
        )
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn iter<'a>(&self, streams: &'a Map) -> Iter<'a> {
        Iter {
            streams,
            current: self.head,
            remaining: self.len,
        }
    }

    pub(super) fn snapshot(
        &mut self,
        streams: &mut Map,
        out: &mut Vec<Handle>,
        control: &mut control::Pending,
        mut control_work: usize,
    ) {
        out.clear();
        let work = self.len.min(crate::conn::STREAM_SCHEDULE_WORK_LIMIT);
        let mut current = self.cursor.or(self.head);
        for _ in 0..work {
            let handle = current.expect("nonempty ready schedule retains its cursor");
            let (next, deferred_reset, reset_materialized) = {
                let (stream_id, entry, next) = streams
                    .resolve_with_position_mut(handle)
                    .expect("scheduled stream retains a live handle");
                let deferred_reset = entry.reset_stream.deferred();
                let reset_materialized = if control_work != 0
                    && let Some(error) = deferred_reset
                    && let Some(mut permit) = control.try_reserve(1)
                {
                    let final_size = entry.reset_final_size();
                    permit.queue_reset_stream(
                        &mut entry.reset_stream,
                        stream_id,
                        error,
                        final_size,
                    );
                    true
                } else {
                    false
                };
                (next.get(), deferred_reset, reset_materialized)
            };
            current = Self::linked_handle(streams, next).or(self.head);

            if reset_materialized {
                self.deactivate(streams, handle);
                if self.len == 0 {
                    current = None;
                } else if current == Some(handle) {
                    current = self.head;
                }
                control_work -= 1;
                continue;
            }

            if deferred_reset.is_none() {
                out.push(handle);
            }
        }
        self.cursor = (self.len != 0).then_some(current.or(self.head)).flatten();
    }
}

pub(super) struct Iter<'a> {
    streams: &'a Map,
    current: Option<Handle>,
    remaining: usize,
}

impl Iterator for Iter<'_> {
    type Item = Handle;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let handle = self.current?;
        let next = self.streams.position(handle)?.get();
        self.current = Schedule::linked_handle(self.streams, next);
        self.remaining -= 1;
        Some(handle)
    }
}

const _: () = assert!(
    mem::size_of::<Credit<control::kind::StreamDataBlocked>>() == 2 * mem::size_of::<u64>()
);
const _: () = assert!(
    mem::size_of::<Entry>() == mem::size_of::<stream::Sender>() + 4 * mem::size_of::<u64>()
);
const _: () = assert!(mem::size_of::<Handle>() == mem::size_of::<u64>());
const _: () = assert!(mem::size_of::<Option<Handle>>() == mem::size_of::<u64>());
