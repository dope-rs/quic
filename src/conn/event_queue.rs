use crate::conn::streams::table::Position;
use crate::conn::{recv, send, stream};

const NONE: u32 = u32::MAX;
const SEND_OWNER: u64 = 1 << 63;

#[derive(Clone, Copy)]
struct Owner(u64);

impl Owner {
    const NONE: Self = Self(0);

    fn receive(handle: recv::Handle) -> Self {
        debug_assert_eq!(handle.raw().get() & SEND_OWNER, 0);
        Self(handle.raw().get())
    }

    fn send(handle: send::Handle) -> Self {
        debug_assert_eq!(handle.raw().get() & SEND_OWNER, 0);
        Self(handle.raw().get() | SEND_OWNER)
    }

    fn receive_handle(self) -> Option<recv::Handle> {
        (self.0 != 0 && self.0 & SEND_OWNER == 0).then(|| {
            recv::Handle::from_raw(
                std::num::NonZeroU64::new(self.0).expect("receive event owner is nonzero"),
            )
        })
    }

    fn send_handle(self) -> Option<send::Handle> {
        (self.0 & SEND_OWNER != 0).then(|| {
            send::Handle::from_raw(
                std::num::NonZeroU64::new(self.0 & !SEND_OWNER)
                    .expect("send event owner is nonzero"),
            )
        })
    }
}

struct Node {
    event: Option<stream::Event>,
    owner: Owner,
    previous: u32,
    next: u32,
}

/// Bounded FIFO whose natural stream owner retains pending state.
///
/// Enqueue, duplicate suppression, cancellation and polling use no hash or
/// search. The node carries the existing typed stream handle so polling can
/// clear its owner's inline pending bit by one generation-checked slot access.
/// If the stream retired first, the stale handle simply fails to resolve.
pub(super) struct Events {
    nodes: Vec<Node>,
    free: u32,
    head: u32,
    tail: u32,
    len: usize,
    capacity: usize,
}

/// Proof that a commit may append at most `remaining` event nodes.
pub(super) struct Permit<'events> {
    events: &'events mut Events,
    remaining: usize,
}

impl Permit<'_> {
    pub(super) fn events(&mut self) -> &mut Events {
        self.events
    }

    fn take(&mut self) {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .expect("event commit consumes only its proven capacity");
    }

    pub(super) fn push_readable(
        &mut self,
        handle: recv::Handle,
        position: &mut Position<recv::Side>,
        stream_id: u64,
    ) {
        if !position.is_none() {
            return;
        }
        self.take();
        let event = stream::Event::Readable { stream_id };
        position.set(self.events.push_reserved(Owner::receive(handle), event));
    }

    pub(super) fn push_stopped(
        &mut self,
        handle: send::Handle,
        stream: &mut crate::stream::Sender,
        stream_id: u64,
        error_code: u64,
    ) {
        if stream.stop_event_pending() {
            return;
        }
        self.take();
        let event = stream::Event::Stopped {
            stream_id,
            error_code,
        };
        stream.mark_stop_event_pending();
        self.events.push_reserved(Owner::send(handle), event);
    }

    pub(super) fn push_reset(
        &mut self,
        readable: &mut Position<recv::Side>,
        stream_id: u64,
        error_code: u64,
    ) {
        if readable.is_none() {
            self.take();
        } else {
            self.events.remove(readable.get());
            readable.clear();
        }
        let event = stream::Event::Reset {
            stream_id,
            error_code,
        };
        self.events.push_reserved(Owner::NONE, event);
    }
}

pub(super) struct Popped {
    pub(super) event: stream::Event,
    owner: Owner,
}

impl Popped {
    pub(super) fn receive_owner(&self) -> Option<recv::Handle> {
        self.owner.receive_handle()
    }

    pub(super) fn send_owner(&self) -> Option<send::Handle> {
        self.owner.send_handle()
    }
}

impl Events {
    pub(super) fn new(capacity: usize) -> Self {
        debug_assert!(capacity != 0);
        debug_assert!(u32::try_from(capacity).is_ok());
        Self {
            nodes: Vec::with_capacity(capacity),
            free: NONE,
            head: NONE,
            tail: NONE,
            len: 0,
            capacity,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn remaining_capacity(&self) -> usize {
        self.capacity - self.len
    }

    pub(super) fn reserve(&mut self, additional: usize) -> Option<Permit<'_>> {
        (additional <= self.remaining_capacity()).then_some(Permit {
            events: self,
            remaining: additional,
        })
    }

    pub(super) fn cancel<Side>(&mut self, position: &mut Position<Side>) {
        if !position.is_none() {
            self.remove(position.get());
            position.clear();
        }
    }

    pub(super) fn pop(&mut self) -> Option<Popped> {
        let index = self.head;
        if index == NONE {
            return None;
        }
        let event = self.nodes[index as usize]
            .event
            .take()
            .expect("linked event node is occupied");
        let owner = self.nodes[index as usize].owner;
        self.unlink(index);
        self.release(index);
        Some(Popped { event, owner })
    }

    fn push_reserved(&mut self, owner: Owner, event: stream::Event) -> u32 {
        let index = if self.free == NONE {
            debug_assert!(self.nodes.len() < self.capacity);
            let index = self.nodes.len() as u32;
            self.nodes.push(Node {
                event: Some(event),
                owner,
                previous: self.tail,
                next: NONE,
            });
            index
        } else {
            let index = self.free;
            let node = &mut self.nodes[index as usize];
            self.free = node.next;
            node.event = Some(event);
            node.owner = owner;
            node.previous = self.tail;
            node.next = NONE;
            index
        };
        if self.tail == NONE {
            self.head = index;
        } else {
            self.nodes[self.tail as usize].next = index;
        }
        self.tail = index;
        self.len += 1;
        index
    }

    fn remove(&mut self, index: u32) {
        let Some(node) = self.nodes.get(index as usize) else {
            return;
        };
        if node.event.is_none() {
            return;
        }
        self.nodes[index as usize].event = None;
        self.unlink(index);
        self.release(index);
    }

    fn unlink(&mut self, index: u32) {
        let previous = self.nodes[index as usize].previous;
        let next = self.nodes[index as usize].next;
        if previous == NONE {
            self.head = next;
        } else {
            self.nodes[previous as usize].next = next;
        }
        if next == NONE {
            self.tail = previous;
        } else {
            self.nodes[next as usize].previous = previous;
        }
        self.len -= 1;
    }

    fn release(&mut self, index: u32) {
        let node = &mut self.nodes[index as usize];
        node.owner = Owner::NONE;
        node.previous = NONE;
        node.next = self.free;
        self.free = index;
    }
}

const _: () = assert!(std::mem::size_of::<Owner>() == std::mem::size_of::<u64>());
const _: () = assert!(std::mem::size_of::<Node>() == 40);
