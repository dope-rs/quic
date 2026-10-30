use crate::conn::stream::state::streams::closed;
use crate::conn::stream::state::streams::closed::storage;
use crate::conn::stream::state::streams::closed::storage::index::{Index, RawIndex};
use crate::conn::stream::state::streams::closed::storage::node::{Gap, Interval};
use crate::conn::stream::state::streams::closed::tree::edit::Edit;
use crate::conn::stream::state::streams::closed::tree::path::Path;
use o3::depot::array::copy;
use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
struct Split<'owner, L> {
    interval: Interval,
    right: Index<'owner, L>,
}

enum Place<'owner, L> {
    Complete,
    Split(Split<'owner, L>),
}

pub(super) struct Applied;

pub(super) struct Insert<'edit, 'owner, L> {
    edit: &'edit mut Edit<'owner, L>,
    path: Path<'owner, L>,
    interval: Interval,
}

impl<'edit, 'owner, L> Insert<'edit, 'owner, L> {
    pub(super) const fn new(
        edit: &'edit mut Edit<'owner, L>,
        path: Path<'owner, L>,
        interval: Interval,
    ) -> Self {
        Self {
            edit,
            path,
            interval,
        }
    }

    pub(super) fn commit(self) -> Option<Applied> {
        let leaves = self.leaves()?;
        let mut held = self.edit.storage.reserve(&leaves)?;
        Self::apply(self.edit.root, self.path, self.interval, &mut held)
    }

    fn apply(
        root: &mut RawIndex,
        path: Path<'owner, L>,
        interval: Interval,
        held: &mut storage::Reserved<'_>,
    ) -> Option<Applied> {
        if path.is_empty() {
            let index: Index<'owner, L> = held.take()?;
            let node = held.node_mut(index)?;
            node.keys[0] = interval;
            node.set_len(1)?;
            *root = index.raw();
            return Some(Applied);
        }

        let mut path = path.steps().rev();
        let leaf = path.next()?;
        let mut split = match Self::place(held, leaf.node(), leaf.gap(), interval, None)? {
            Place::Complete => return Some(Applied),
            Place::Split(split) => split,
        };
        for step in path {
            match Self::place(
                held,
                step.node(),
                step.gap(),
                split.interval,
                Some(split.right),
            )? {
                Place::Complete => return Some(Applied),
                Place::Split(next) => split = next,
            }
        }
        Self::grow(root, held, split)?;
        Some(Applied)
    }

    fn leaves(&self) -> Option<copy::Vec<bool, { closed::MAX_LEVELS + 1 }>> {
        if self.path.is_empty() {
            return Some(copy::Vec::from_one(true));
        }
        let mut leaves = copy::Vec::new();
        let mut carry = true;
        for step in self.path.steps().rev() {
            if !carry {
                break;
            }
            let node = self.edit.storage.get(step.node().raw())?;
            let len = node.len();
            if step.gap().index() > len {
                return None;
            }
            if leaves.is_empty() != node.is_leaf() {
                return None;
            }
            carry = len == closed::MAX_KEYS;
            if carry {
                leaves.vacancy()?.insert(node.is_leaf());
            }
        }
        if carry {
            leaves.vacancy()?.insert(false);
        }
        Some(leaves)
    }

    fn place(
        held: &mut storage::Reserved<'_>,
        index: Index<'owner, L>,
        gap: Gap,
        interval: Interval,
        right: Option<Index<'owner, L>>,
    ) -> Option<Place<'owner, L>> {
        let node = held.node_mut(index)?;
        let len = node.len();
        if node.is_leaf() == right.is_some() {
            return None;
        }
        if len >= closed::MAX_KEYS {
            return Some(Place::Split(Self::split(
                held, index, gap, interval, right,
            )?));
        }
        node.insert::<true>(gap, interval, right.map(Index::raw))?;
        Some(Place::Complete)
    }

    fn split(
        held: &mut storage::Reserved<'_>,
        index: Index<'owner, L>,
        gap: Gap,
        interval: Interval,
        right: Option<Index<'owner, L>>,
    ) -> Option<Split<'owner, L>> {
        let node = held.node(index)?;
        let leaf = node.is_leaf();
        let mut keys = MaybeUninit::uninit();
        let keys = gap.insert(&node.keys, interval, &mut keys);
        let mut children = MaybeUninit::uninit();
        let children = match right {
            Some(right) => gap.next::<{ closed::MAX_CHILDREN + 1 }>().insert(
                &node.children,
                right.raw(),
                &mut children,
            ),
            None => children.write([RawIndex::NONE; closed::MAX_CHILDREN + 1]),
        };

        let sibling = held.take()?;
        let node = held.node_mut(index)?;
        node.keys[..closed::MIN_KEYS].copy_from_slice(&keys[..closed::MIN_KEYS]);
        node.set_len(closed::MIN_KEYS)?;
        if !leaf {
            node.children[..closed::MIN_DEGREE].copy_from_slice(&children[..closed::MIN_DEGREE]);
        }
        let node = held.node_mut(sibling)?;
        node.keys[..closed::MIN_DEGREE].copy_from_slice(&keys[closed::MIN_DEGREE..]);
        node.set_len(closed::MIN_DEGREE)?;
        if !leaf {
            node.children[..=closed::MIN_DEGREE].copy_from_slice(&children[closed::MIN_DEGREE..]);
        }
        Some(Split {
            interval: keys[closed::MIN_KEYS],
            right: sibling,
        })
    }

    fn grow(
        root: &mut RawIndex,
        held: &mut storage::Reserved<'_>,
        split: Split<'owner, L>,
    ) -> Option<Applied> {
        let old: Index<'owner, L> = root.brand();
        let index: Index<'owner, L> = held.take()?;
        let node = held.node_mut(index)?;
        node.keys[0] = split.interval;
        node.children[0] = old.raw();
        node.children[1] = split.right.raw();
        node.set_len(1)?;
        *root = index.raw();
        Some(Applied)
    }
}
