use std::marker;
use std::num::NonZeroU64;
use std::ops::{Index, IndexMut};

use crate::stream::SendStream;

use super::{delivery, send};

pub(super) mod journal;
mod links;
use journal::Journal;
use links::storage::StorageOps as _;

const NONE: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Links {
    previous: u32,
    next: u32,
}

impl Links {
    const DETACHED: Self = Self {
        previous: NONE,
        next: NONE,
    };
}

#[derive(Clone, Copy)]
struct Membership {
    links: Links,
    linked: bool,
}

impl Membership {
    const DETACHED: Self = Self {
        links: Links::DETACHED,
        linked: false,
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

struct GroupNodes {
    all: Chain,
    retry: Chain,
    inflight: Chain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub(super) struct GroupId(NonZeroU64);

impl GroupId {
    fn new(index: u32, generation: u32) -> Self {
        let raw = (u64::from(generation) << 32) | u64::from(index + 1);
        Self(NonZeroU64::new(raw).expect("group index is encoded as nonzero"))
    }

    fn index(self) -> u32 {
        (self.0.get() as u32) - 1
    }

    fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }
}

/// A retry traversal capability tied to one packet-building turn.
///
/// Every candidate, including one rejected for size or duplication, consumes
/// one unit. Code cannot retain this capability beyond the counter it borrows.
pub(super) struct RetryWork<'turn> {
    remaining: &'turn mut usize,
    _exclusive: marker::PhantomData<&'turn mut ()>,
}

impl<'turn> RetryWork<'turn> {
    pub(super) fn new(remaining: &'turn mut usize) -> Self {
        Self {
            remaining,
            _exclusive: marker::PhantomData,
        }
    }

    fn spend(&mut self) -> bool {
        let Some(next) = self.remaining.checked_sub(1) else {
            return false;
        };
        *self.remaining = next;
        true
    }
}

#[derive(Clone, Copy)]
struct Node {
    group: GroupId,
    record: delivery::Stream,
    carriers: u16,
    all: Links,
    retry: Membership,
    inflight: Membership,
}

impl Node {
    /// An acknowledged node remains in its stream-order list until every
    /// preceding node is acknowledged. Its existing link state is the tag, so
    /// retaining an ACK hole costs no extra storage in the fixed node pool.
    fn acknowledged(self) -> bool {
        self.carriers == 0 && !self.retry.linked && !self.inflight.linked
    }
}

struct Slot<T> {
    generation: u32,
    next_free: u32,
    value: Option<T>,
}

/// A fixed-address, fixed-capacity slot arena with a lazily materialized
/// virgin tail.
///
/// `Vec::with_capacity` reserves the complete address range at construction,
/// so the first use of a virgin slot cannot allocate or move existing slots.
/// Unlike a boxed `[Slot; capacity]`, however, no slot page is initialized
/// until a record actually reaches it. Released slots are recycled through an
/// intrusive free list and retain their generation counter.
struct Arena<T> {
    slots: Vec<Slot<T>>,
    free: u32,
    limit: usize,
}

impl<T> Arena<T> {
    fn new(limit: usize) -> Self {
        debug_assert!(u32::try_from(limit).is_ok());
        Self {
            slots: Vec::with_capacity(limit),
            free: NONE,
            limit,
        }
    }

    fn take(&mut self) -> Option<(u32, u32)> {
        if self.free != NONE {
            let index = self.free;
            let slot = &mut self.slots[index as usize];
            self.free = slot.next_free;
            slot.next_free = NONE;
            return Some((index, slot.generation));
        }
        if self.slots.len() == self.limit {
            return None;
        }
        let index = u32::try_from(self.slots.len()).ok()?;
        self.slots.push(Slot {
            generation: 0,
            next_free: NONE,
            value: None,
        });
        Some((index, 0))
    }

    fn release(&mut self, index: u32) {
        let slot = &mut self.slots[index as usize];
        if slot.generation == u32::MAX {
            slot.next_free = NONE;
            return;
        }
        slot.generation += 1;
        slot.next_free = self.free;
        self.free = index;
    }

    fn get(&self, index: usize) -> Option<&Slot<T>> {
        self.slots.get(index)
    }
}

impl<T> Index<usize> for Arena<T> {
    type Output = Slot<T>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.slots[index]
    }
}

impl<T> IndexMut<usize> for Arena<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.slots[index]
    }
}

struct Group {
    owner: send::Handle,
    active: bool,
    len: usize,
    nodes: GroupNodes,
    retry: Membership,
    reclaim: Membership,
    probe: Membership,
}

#[derive(Debug)]
pub(super) struct InvalidPrefix;

/// A contiguous acknowledged prefix tied to an exclusive journal borrow.
///
/// The borrow prevents node reuse until the corresponding stream buffer has
/// advanced. Out-of-order ACKs never produce this capability and therefore
/// remain charged to the journal's fixed capacity.
#[must_use]
pub(super) struct Acknowledged<'journal> {
    journal: &'journal mut Journal,
    group: GroupId,
}

impl Acknowledged<'_> {
    pub(super) fn send_handle(&self) -> send::Handle {
        self.journal
            .group(self.group)
            .expect("acknowledged prefix retains its group")
            .owner
    }

    /// Advances the byte owner before returning any journal node to the pool.
    pub(super) fn commit(self, stream: &mut SendStream) -> Result<bool, InvalidPrefix> {
        let Some((offset, bytes, fin, nodes)) = self.span() else {
            self.journal.cancel(self.group);
            return Err(InvalidPrefix);
        };
        if !stream.acknowledge_prefix(offset, bytes, fin) {
            self.journal.cancel(self.group);
            return Err(InvalidPrefix);
        }
        for _ in 0..nodes {
            let head = self
                .journal
                .group(self.group)
                .expect("committed prefix retains remaining nodes")
                .nodes
                .all
                .head;
            self.journal.discard_node(head, true);
        }
        Ok(stream.is_fully_acked())
    }

    /// Cancels an internally orphaned group without walking its nodes.
    pub(super) fn cancel(self) {
        self.journal.cancel(self.group);
    }

    fn span(&self) -> Option<(u64, usize, bool, usize)> {
        let mut index = self.journal.group(self.group)?.nodes.all.head;
        let first = self.journal.storage.nodes.get(index as usize)?.value?;
        first.acknowledged().then_some(())?;
        let offset = first.record.offset;
        let mut expected = offset;
        let mut bytes = 0usize;
        let mut fin = false;
        let mut nodes = 0usize;

        while index != NONE {
            let node = self.journal.storage.nodes.get(index as usize)?.value?;
            if !node.acknowledged() {
                break;
            }
            if fin || node.record.offset != expected {
                return None;
            }
            let len = usize::try_from(node.record.len).ok()?;
            bytes = bytes.checked_add(len)?;
            expected = expected.checked_add(node.record.len)?;
            fin = node.record.fin;
            nodes += 1;
            if fin && node.all.next != NONE {
                return None;
            }
            index = node.all.next;
        }
        Some((offset, bytes, fin, nodes))
    }
}

const _: () = assert!(std::mem::size_of::<Node>() <= 80);
