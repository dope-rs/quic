use std::mem;
use std::ops;

use crate::stream;

use crate::conn::control;
use crate::conn::streams::table;

pub(super) struct Side;

pub(super) type Id = table::Id<Side>;
pub(super) type Handle = table::Handle<Side>;
pub(super) type Map<B> = table::Map<Side, State<B>>;

const CONTROL_INDEX_MASK: u32 = (1 << 30) - 1;
const CONTROL_FLAGS_MASK: u32 = !CONTROL_INDEX_MASK;
const CONTROL_NONE: u32 = CONTROL_INDEX_MASK;
const CONTROL_END: u32 = CONTROL_INDEX_MASK - 1;
const MAX_STREAM_DATA_DIRTY: u32 = 1 << 31;

#[repr(C)]
struct ControlLink {
    previous: u32,
    next: u32,
}

impl ControlLink {
    const fn none() -> Self {
        Self {
            previous: CONTROL_NONE,
            next: CONTROL_NONE,
        }
    }

    const fn is_active(&self) -> bool {
        self.previous & CONTROL_INDEX_MASK != CONTROL_NONE
    }

    const fn max_stream_data_dirty(&self) -> bool {
        self.previous & MAX_STREAM_DATA_DIRTY != 0
    }

    fn mark_max_stream_data_dirty(&mut self) {
        self.previous |= MAX_STREAM_DATA_DIRTY;
    }

    fn clear_max_stream_data_dirty(&mut self) {
        self.previous &= !MAX_STREAM_DATA_DIRTY;
    }

    fn previous(&self) -> u32 {
        self.previous & CONTROL_INDEX_MASK
    }

    fn set_previous(&mut self, previous: u32) {
        self.previous = self.previous & CONTROL_FLAGS_MASK | previous;
    }

    fn clear(&mut self) {
        *self = Self::none();
    }
}

/// Allocation-free workset for receive streams whose derived controls have
/// not yet acquired bounded journal owners.
pub(super) struct ControlSchedule {
    head: Option<Handle>,
    tail: Option<Handle>,
    len: usize,
}

impl ControlSchedule {
    pub(super) const fn new() -> Self {
        Self {
            head: None,
            tail: None,
            len: 0,
        }
    }

    pub(super) fn activate<B: stream::ReceiveBuffer>(
        &mut self,
        streams: &mut Map<B>,
        handle: Handle,
    ) {
        debug_assert!(handle.index() < CONTROL_END);
        let previous = self.tail.map_or(CONTROL_END, Handle::index);
        let Some((_, stream)) = streams.resolve_mut(handle) else {
            return;
        };
        if stream.control_link.is_active() {
            return;
        }
        stream.control_link.set_previous(previous);
        stream.control_link.next = CONTROL_END;

        if let Some(tail) = self.tail {
            streams
                .resolve_mut(tail)
                .expect("control tail retains a live generation-checked handle")
                .1
                .control_link
                .next = handle.index();
        } else {
            self.head = Some(handle);
        }
        self.tail = Some(handle);
        self.len += 1;
    }

    pub(super) fn deactivate<B: stream::ReceiveBuffer>(
        &mut self,
        streams: &mut Map<B>,
        handle: Handle,
    ) {
        let Some((_, stream)) = streams.resolve_mut(handle) else {
            return;
        };
        if !stream.control_link.is_active() {
            return;
        }
        let previous = stream.control_link.previous();
        let next = stream.control_link.next;
        stream.control_link.clear();

        let previous_handle = Self::linked_handle(streams, previous);
        let next_handle = Self::linked_handle(streams, next);
        if let Some(previous) = previous_handle {
            streams
                .resolve_mut(previous)
                .expect("control predecessor retains a live handle")
                .1
                .control_link
                .next = next;
        } else {
            self.head = next_handle;
        }
        if let Some(next) = next_handle {
            streams
                .resolve_mut(next)
                .expect("control successor retains a live handle")
                .1
                .control_link
                .set_previous(previous);
        } else {
            self.tail = previous_handle;
        }

        debug_assert_ne!(self.len, 0);
        self.len -= 1;
        if self.len == 0 {
            self.head = None;
            self.tail = None;
        }
    }

    pub(super) const fn front(&self) -> Option<Handle> {
        self.head
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn linked_handle<B: stream::ReceiveBuffer>(streams: &Map<B>, index: u32) -> Option<Handle> {
        if index == CONTROL_END {
            return None;
        }
        debug_assert_ne!(index, CONTROL_NONE);
        Some(
            streams
                .handle_at(index)
                .expect("control link targets a live receive-stream slot"),
        )
    }
}

pub(super) struct State<B: stream::ReceiveBuffer> {
    stream: stream::Receiver<B>,
    limit: u64,
    control_link: ControlLink,
    pub(super) max_stream_data: Option<control::OwnerKey<control::kind::MaxStreamData>>,
    pub(super) stop_sending: control::Signal<control::kind::StopSending>,
}

impl<B: stream::ReceiveBuffer> table::Reusable for State<B> {
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

impl<B: stream::ReceiveBuffer> State<B> {
    fn new(limit: u64) -> Self {
        Self {
            stream: stream::Receiver::default(),
            limit,
            control_link: ControlLink::none(),
            max_stream_data: None,
            stop_sending: control::Signal::new(),
        }
    }

    fn reuse(&mut self, limit: u64) {
        debug_assert!(self.max_stream_data.is_none());
        debug_assert!(self.stop_sending.is_empty());
        debug_assert!(!self.control_link.is_active());
        self.limit = limit;
    }

    fn retire(&mut self) {
        self.stream.recycle();
        debug_assert!(!self.control_link.is_active());
        self.limit = 0;
        self.control_link.clear();
        self.max_stream_data = None;
        self.stop_sending = control::Signal::new();
    }

    pub(super) fn limit(&self) -> u64 {
        self.limit
    }

    pub(super) fn release_credit(&mut self, count: u64) -> u64 {
        self.limit = self.limit.saturating_add(count);
        self.limit
    }

    pub(super) fn mark_max_stream_data_dirty(&mut self) {
        self.control_link.mark_max_stream_data_dirty();
    }

    pub(super) fn clear_max_stream_data_dirty(&mut self) {
        self.control_link.clear_max_stream_data_dirty();
    }

    pub(super) fn max_stream_data_dirty(&self) -> bool {
        self.control_link.max_stream_data_dirty()
    }

    pub(super) fn has_deferred_control(&self) -> bool {
        self.max_stream_data_dirty() || self.stop_sending.is_deferred()
    }
}

impl<B: stream::ReceiveBuffer> ops::Deref for State<B> {
    type Target = stream::Receiver<B>;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<B: stream::ReceiveBuffer> ops::DerefMut for State<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

const _: () = assert!(
    mem::size_of::<State<Vec<u8>>>()
        == mem::size_of::<stream::Receiver>() + 4 * mem::size_of::<u64>()
);
const _: () = assert!(mem::size_of::<ControlLink>() == mem::size_of::<u64>());
