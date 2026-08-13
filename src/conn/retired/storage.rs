use std::marker;

use super::{MAX_CHILDREN, MAX_KEYS, NONE};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Interval {
    pub(super) start: u64,
    pub(super) end: u64,
}

pub(super) struct Index<Tag> {
    raw: u32,
    tag: marker::PhantomData<fn(Tag) -> Tag>,
}

impl<Tag> Index<Tag> {
    pub(super) const NONE: Self = Self::new(NONE);

    const fn new(raw: u32) -> Self {
        Self {
            raw,
            tag: marker::PhantomData,
        }
    }

    pub(super) const fn is_none(self) -> bool {
        self.raw == NONE
    }

    pub(super) fn usize(self) -> usize {
        self.raw as usize
    }
}

impl<Tag> Clone for Index<Tag> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Tag> Copy for Index<Tag> {}

pub(super) struct Node<Tag> {
    pub(super) keys: [Interval; MAX_KEYS],
    pub(super) children: [Index<Tag>; MAX_CHILDREN],
    pub(super) len: u8,
    pub(super) leaf: bool,
    pub(super) next_free: Index<Tag>,
}

impl<Tag> Node<Tag> {
    fn new(leaf: bool) -> Self {
        Self {
            keys: [Interval::default(); MAX_KEYS],
            children: [Index::NONE; MAX_CHILDREN],
            len: 0,
            leaf,
            next_free: Index::NONE,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len as usize
    }
}

const _: () = assert!(std::mem::size_of::<Index<()>>() == 4);
const _: () = assert!(std::mem::size_of::<Interval>() == 16);
const _: () = assert!(std::mem::size_of::<Node<()>>() <= 320);

pub(super) struct Storage<Tag> {
    pub(super) nodes: Vec<Node<Tag>>,
    free: Index<Tag>,
    live: usize,
    pub(super) capacity: usize,
}

impl<Tag> Storage<Tag> {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(capacity),
            free: Index::NONE,
            live: 0,
            capacity,
        }
    }

    pub(super) fn allocate(&mut self, leaf: bool) -> Option<Index<Tag>> {
        let index = if self.free.is_none() {
            if self.nodes.len() == self.capacity {
                return None;
            }
            let raw = u32::try_from(self.nodes.len()).ok()?;
            self.nodes.push(Node::new(leaf));
            Index::new(raw)
        } else {
            let index = self.free;
            self.free = self.get(index).next_free;
            self.nodes[index.usize()] = Node::new(leaf);
            index
        };
        self.live += 1;
        Some(index)
    }

    pub(super) fn release(&mut self, index: Index<Tag>) {
        let free = self.free;
        self.nodes[index.usize()].next_free = free;
        self.free = index;
        self.live -= 1;
    }

    pub(super) fn get(&self, index: Index<Tag>) -> &Node<Tag> {
        debug_assert!(!index.is_none());
        &self.nodes[index.usize()]
    }

    pub(super) fn get_mut(&mut self, index: Index<Tag>) -> &mut Node<Tag> {
        debug_assert!(!index.is_none());
        &mut self.nodes[index.usize()]
    }
}
