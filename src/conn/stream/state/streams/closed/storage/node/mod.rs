use crate::conn::stream::state::streams::closed;
use crate::conn::stream::state::streams::closed::storage::index::RawIndex;
use o3::depot::array;
use std::ptr;

mod raw;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::conn::stream::state::streams::closed) struct Interval {
    pub(in crate::conn::stream::state::streams::closed) start: u64,
    pub(in crate::conn::stream::state::streams::closed) end: u64,
}

pub(in crate::conn::stream::state::streams::closed) type Gap =
    array::Index<{ closed::MAX_CHILDREN }>;

pub(in crate::conn::stream::state::streams::closed) type Key = array::Index<{ closed::MAX_KEYS }>;

#[derive(Clone, Copy)]
pub(in crate::conn::stream::state::streams::closed) struct Search {
    gap: Gap,
    left: Option<Key>,
    right: Option<Key>,
}

type Len = Gap;

pub(in crate::conn::stream::state::streams::closed) struct Set;

impl Search {
    pub(in crate::conn::stream::state::streams::closed) const fn gap(self) -> Gap {
        self.gap
    }

    pub(in crate::conn::stream::state::streams::closed) const fn left(self) -> Option<Key> {
        self.left
    }

    pub(in crate::conn::stream::state::streams::closed) const fn right(self) -> Option<Key> {
        self.right
    }
}

pub(in crate::conn::stream::state::streams::closed) struct Node {
    pub(in crate::conn::stream::state::streams::closed) keys: [Interval; closed::MAX_KEYS],
    pub(in crate::conn::stream::state::streams::closed) children: [RawIndex; closed::MAX_CHILDREN],
    len: Len,
    pub(in crate::conn::stream::state::streams::closed) leaf: bool,
    pub(super) link: RawIndex,
}

/// A detached payload snapshot retaining its initialized key and child extents.
pub(in crate::conn::stream::state::streams::closed) struct Snapshot {
    keys: [Interval; closed::MAX_KEYS],
    children: [RawIndex; closed::MAX_CHILDREN],
    len: Len,
    leaf: bool,
}

impl Node {
    pub(super) fn new(leaf: bool) -> Self {
        Self {
            keys: [Interval::default(); closed::MAX_KEYS],
            children: [RawIndex::NONE; closed::MAX_CHILDREN],
            len: Len::at::<0>(),
            leaf,
            link: RawIndex::NONE,
        }
    }

    pub(in crate::conn::stream::state::streams::closed) fn len(&self) -> usize {
        self.len.index()
    }

    pub(in crate::conn::stream::state::streams::closed) fn set_len(
        &mut self,
        len: usize,
    ) -> Option<Set> {
        self.len = Len::new(len)?;
        Some(Set)
    }

    pub(in crate::conn::stream::state::streams::closed) const fn is_leaf(&self) -> bool {
        self.leaf
    }

    pub(in crate::conn::stream::state::streams::closed) fn search(&self, start: u64) -> Search {
        let gap = self.len.partition(&self.keys, |range| range.start <= start);
        let at = gap.index();
        Search {
            gap,
            left: gap.previous(),
            right: Key::new(at).filter(|_| at != self.len()),
        }
    }

    pub(in crate::conn::stream::state::streams::closed) fn last(&self) -> Option<Key> {
        self.len.previous()
    }

    pub(in crate::conn::stream::state::streams::closed) const fn end(&self) -> Gap {
        self.len
    }

    pub(in crate::conn::stream::state::streams::closed) fn left(
        &self,
        gap: Gap,
    ) -> Option<(RawIndex, Key)> {
        let key = gap.previous()?;
        Some((self.child(key.widen()), key))
    }

    pub(in crate::conn::stream::state::streams::closed) fn right(
        &self,
        gap: Gap,
    ) -> Option<(RawIndex, Key)> {
        let at = gap.index();
        if at >= self.len() {
            return None;
        }
        let key = Key::new(at)?;
        Some((self.child(key.next()), key))
    }

    pub(in crate::conn::stream::state::streams::closed) fn key(&self, key: Key) -> Interval {
        *key.get(&self.keys)
    }

    pub(in crate::conn::stream::state::streams::closed) fn key_mut(
        &mut self,
        key: Key,
    ) -> Option<&mut Interval> {
        if key.index() >= self.len() {
            return None;
        }
        Some(key.get_mut(&mut self.keys))
    }

    pub(in crate::conn::stream::state::streams::closed) fn child(&self, gap: Gap) -> RawIndex {
        *gap.get(&self.children)
    }

    pub(in crate::conn::stream::state::streams::closed) fn snapshot(&self) -> Snapshot {
        Snapshot {
            keys: self.keys,
            children: self.children,
            len: self.len,
            leaf: self.leaf,
        }
    }

    /// Admits the gap and growth once while retaining this exact mutable node.
    pub(in crate::conn::stream::state::streams::closed) fn insert<const RIGHT: bool>(
        &mut self,
        gap: Gap,
        interval: Interval,
        child: Option<RawIndex>,
    ) -> Option<Set> {
        let at = gap.index();
        let len = self.len();
        if at > len || self.leaf == child.is_some() {
            return None;
        }
        let next = Len::new(len + 1)?;
        // SAFETY: at <= len < MAX_KEYS admits the key and shifted suffix.
        // The matching child gap is at or at + 1; MAX_CHILDREN adds the end
        // child, so its shifted suffix also fits this exclusively held node.
        unsafe {
            let keys = self.keys.as_mut_ptr().add(at);
            ptr::copy(keys, keys.add(1), len - at);
            keys.write(interval);
            if let Some(child) = child {
                let at = at + usize::from(RIGHT);
                let children = self.children.as_mut_ptr().add(at);
                ptr::copy(children, children.add(1), len + 1 - at);
                children.write(child);
            }
        }
        self.len = next;
        Some(Set)
    }

    /// Removes one admitted key and its matching child from this same owner.
    pub(in crate::conn::stream::state::streams::closed) fn remove<const RIGHT: bool>(
        &mut self,
        key: Key,
    ) -> Option<Set> {
        let at = key.index();
        let len = self.len();
        if at >= len {
            return None;
        }
        let next = Len::new(len - 1)?;
        // SAFETY: at < len <= MAX_KEYS proves a nonempty key prefix. Each
        // suffix moves left inside that prefix; the child prefix has len + 1
        // elements and loses the child immediately before or after this key.
        unsafe {
            let keys = self.keys.as_mut_ptr().add(at);
            ptr::copy(keys.add(1), keys, len - at - 1);
            if !self.leaf {
                let at = at + usize::from(RIGHT);
                let children = self.children.as_mut_ptr().add(at);
                ptr::copy(children.add(1), children, len - at);
            }
        }
        self.len = next;
        Some(Set)
    }

    /// Admits both retained extents before appending the detached sibling.
    pub(in crate::conn::stream::state::streams::closed) fn append(
        &mut self,
        pivot: Interval,
        peer: Snapshot,
    ) -> Option<Set> {
        let len = self.len();
        let count = peer.len.index();
        let total = len + count + 1;
        if self.leaf != peer.leaf {
            return None;
        }
        let next = Len::new(total)?;
        // SAFETY: the admitted sum bounds the pivot and complete source key
        // prefix by MAX_KEYS. Both child arrays add exactly one position.
        // The by-value snapshot and this exclusive node are disjoint owners.
        unsafe {
            let keys = self.keys.as_mut_ptr().add(len);
            keys.write(pivot);
            ptr::copy_nonoverlapping(peer.keys.as_ptr(), keys.add(1), count);
            if !self.leaf {
                ptr::copy_nonoverlapping(
                    peer.children.as_ptr(),
                    self.children.as_mut_ptr().add(len + 1),
                    count + 1,
                );
            }
        }
        self.len = next;
        Some(Set)
    }
}

const _: () = {
    assert!(std::mem::size_of::<Interval>() == 2 * std::mem::size_of::<u64>());
    assert!(std::mem::size_of::<Gap>() == std::mem::size_of::<u8>());
    assert!(std::mem::size_of::<Key>() == std::mem::size_of::<u8>());
    assert!(std::mem::size_of::<Len>() == std::mem::size_of::<u8>());
    assert!(std::mem::size_of::<Node>() == 312);
    assert!(closed::MAX_KEYS <= u8::MAX as usize);
};
