mod remove;
mod storage;
pub(super) mod streams;

use remove::Remove as _;

// With at most 65,536 intervals, a degree-8 B-tree has at most six levels.
// Each level searches at most 15 packed keys and every mutation touches only
// that path plus the two adjacent intervals; connection age is irrelevant.
const MIN_DEGREE: usize = 8;
const MAX_KEYS: usize = MIN_DEGREE * 2 - 1;
const MAX_CHILDREN: usize = MIN_DEGREE * 2;
const MAX_INTERVALS: usize = 65_536;
const MAX_LEVELS: usize = 6;
const NONE: u32 = u32::MAX;

const _: () = assert!(2 * MIN_DEGREE.pow(MAX_LEVELS as u32) - 1 > MAX_INTERVALS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Full;

/// A fixed-allocation B-tree. Node indices never escape an exclusive borrow,
/// so reuse needs neither pointer identity nor runtime generation checks.
struct Tree<Tag> {
    pool: storage::Storage<Tag>,
    root: storage::Index<Tag>,
    len: usize,
    capacity: usize,
}

struct Location<Tag> {
    node: storage::Index<Tag>,
    slot: usize,
    value: storage::Interval,
}

impl<Tag> Clone for Location<Tag> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Tag> Copy for Location<Tag> {}

/// Both ordered neighbors found by one descent. The exclusive tree lifetime
/// prevents either internal index from surviving a structural edit.
struct Neighbors<'tree, Tag> {
    tree: &'tree mut Tree<Tag>,
    left: Option<Location<Tag>>,
    right: Option<Location<Tag>>,
}

impl<Tag> Neighbors<'_, Tag> {
    fn left(&self) -> Option<storage::Interval> {
        self.left.map(|location| location.value)
    }

    fn right(&self) -> Option<storage::Interval> {
        self.right.map(|location| location.value)
    }

    fn extend_left(&mut self, end: u64) {
        let location = self.left.expect("left retired interval exists");
        self.tree.pool.get_mut(location.node).keys[location.slot].end = end;
    }

    fn extend_right(&mut self, start: u64) {
        let location = self.right.expect("right retired interval exists");
        self.tree.pool.get_mut(location.node).keys[location.slot].start = start;
    }

    fn remove_right(&mut self) {
        let location = self.right.expect("right retired interval exists");
        assert!(self.tree.remove(location.value.start));
    }

    fn insert(self, range: storage::Interval) -> Result<(), Full> {
        self.tree.insert(range)
    }
}

impl<Tag> Tree<Tag> {
    fn new(capacity: usize) -> Self {
        assert!(
            capacity <= MAX_INTERVALS,
            "retired interval capacity overflow"
        );
        let node_capacity = if capacity == 0 {
            0
        } else {
            1 + capacity.saturating_sub(1) / (MIN_DEGREE - 1)
        };
        let mut pool = storage::Storage::with_capacity(node_capacity);
        let root = if capacity == 0 {
            storage::Index::NONE
        } else {
            pool.allocate(true)
                .expect("non-empty B-tree plan has a root")
        };
        Self {
            pool,
            root,
            len: 0,
            capacity,
        }
    }

    fn contains(&self, index: u64) -> bool {
        self.predecessor(index)
            .is_some_and(|range| range.start <= index && index < range.end)
    }

    fn first(&self) -> Option<storage::Interval> {
        if self.len == 0 {
            return None;
        }
        let mut index = self.root;
        loop {
            let node = self.pool.get(index);
            if node.leaf {
                return Some(node.keys[0]);
            }
            index = node.children[0];
        }
    }

    fn predecessor(&self, start: u64) -> Option<storage::Interval> {
        if self.root.is_none() {
            return None;
        }
        let mut best = None;
        let mut index = self.root;
        loop {
            let node = self.pool.get(index);
            let at = node.keys[..node.len()].partition_point(|range| range.start <= start);
            if at != 0 {
                best = Some(node.keys[at - 1]);
            }
            if node.leaf {
                return best;
            }
            index = node.children[at];
        }
    }

    fn neighbors(&mut self, start: u64) -> Neighbors<'_, Tag> {
        let mut left = None;
        let mut right = None;
        if !self.root.is_none() {
            let mut index = self.root;
            loop {
                let node = self.pool.get(index);
                let at = node.keys[..node.len()].partition_point(|range| range.start <= start);
                if at != 0 {
                    left = Some(Location {
                        node: index,
                        slot: at - 1,
                        value: node.keys[at - 1],
                    });
                }
                if at != node.len() {
                    right = Some(Location {
                        node: index,
                        slot: at,
                        value: node.keys[at],
                    });
                }
                if node.leaf {
                    break;
                }
                index = node.children[at];
            }
        }
        Neighbors {
            tree: self,
            left,
            right,
        }
    }

    fn position(&self, start: u64) -> Option<(storage::Index<Tag>, usize)> {
        if self.root.is_none() {
            return None;
        }
        let mut index = self.root;
        loop {
            let node = self.pool.get(index);
            let at = node.keys[..node.len()].partition_point(|range| range.start < start);
            if at != node.len() && node.keys[at].start == start {
                return Some((index, at));
            }
            if node.leaf {
                return None;
            }
            index = node.children[at];
        }
    }

    fn insert(&mut self, range: storage::Interval) -> Result<(), Full> {
        if self.len == self.capacity || self.root.is_none() {
            return Err(Full);
        }
        debug_assert!(self.position(range.start).is_none());
        if self.pool.get(self.root).len() == MAX_KEYS {
            let old_root = self.root;
            let new_root = self.pool.allocate(false).ok_or(Full)?;
            self.pool.get_mut(new_root).children[0] = old_root;
            if self.split_child(new_root, 0).is_err() {
                self.pool.release(new_root);
                return Err(Full);
            }
            self.root = new_root;
        }
        self.insert_non_full(self.root, range)?;
        self.len += 1;
        Ok(())
    }

    fn insert_non_full(
        &mut self,
        index: storage::Index<Tag>,
        range: storage::Interval,
    ) -> Result<(), Full> {
        let len = self.pool.get(index).len();
        if self.pool.get(index).leaf {
            let at = self.pool.get(index).keys[..len]
                .partition_point(|existing| existing.start < range.start);
            let node = self.pool.get_mut(index);
            node.keys.copy_within(at..len, at + 1);
            node.keys[at] = range;
            node.len += 1;
            return Ok(());
        }

        let mut at = self.pool.get(index).keys[..len]
            .partition_point(|existing| existing.start < range.start);
        let child = self.pool.get(index).children[at];
        if self.pool.get(child).len() == MAX_KEYS {
            self.split_child(index, at)?;
            if range.start > self.pool.get(index).keys[at].start {
                at += 1;
            }
        }
        let child = self.pool.get(index).children[at];
        self.insert_non_full(child, range)
    }

    fn split_child(&mut self, parent: storage::Index<Tag>, at: usize) -> Result<(), Full> {
        let child = self.pool.get(parent).children[at];
        let leaf = self.pool.get(child).leaf;
        let sibling = self.pool.allocate(leaf).ok_or(Full)?;
        let median = self.pool.get(child).keys[MIN_DEGREE - 1];

        for offset in 0..MIN_DEGREE - 1 {
            let key = self.pool.get(child).keys[offset + MIN_DEGREE];
            self.pool.get_mut(sibling).keys[offset] = key;
        }
        if !leaf {
            for offset in 0..MIN_DEGREE {
                let descendant = self.pool.get(child).children[offset + MIN_DEGREE];
                self.pool.get_mut(sibling).children[offset] = descendant;
            }
        }
        self.pool.get_mut(sibling).len = (MIN_DEGREE - 1) as u8;
        self.pool.get_mut(child).len = (MIN_DEGREE - 1) as u8;

        let parent_len = self.pool.get(parent).len();
        {
            let node = self.pool.get_mut(parent);
            node.children.copy_within(at + 1..=parent_len, at + 2);
            node.keys.copy_within(at..parent_len, at + 1);
            node.children[at + 1] = sibling;
            node.keys[at] = median;
            node.len += 1;
        }
        Ok(())
    }
}
