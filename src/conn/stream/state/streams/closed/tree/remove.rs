use crate::conn::stream::state::streams::closed;
use crate::conn::stream::state::streams::closed::storage::index::{Index, RawIndex};
use crate::conn::stream::state::streams::closed::storage::node::{Gap, Key};
use crate::conn::stream::state::streams::closed::tree::edit::Edit;
use crate::conn::stream::state::streams::closed::tree::entry::Location;
use crate::conn::stream::state::streams::closed::tree::path::Path;

pub(super) struct Remove<'edit, 'owner, L> {
    edit: &'edit mut Edit<'owner, L>,
    path: Path<'owner, L>,
    location: Location<'owner, L>,
}

pub(super) struct Removed;

impl<'edit, 'owner, L> Remove<'edit, 'owner, L> {
    pub(super) const fn new(
        edit: &'edit mut Edit<'owner, L>,
        path: Path<'owner, L>,
        location: Location<'owner, L>,
    ) -> Self {
        Self {
            edit,
            path,
            location,
        }
    }

    pub(super) fn commit(mut self) -> Option<Removed> {
        let (leaf, key) = self.leaf()?;
        let node = self.edit.node_mut(leaf)?;
        if !node.is_leaf() {
            return None;
        }
        node.remove::<true>(key)?;
        self.rebalance()?;

        let root = self.edit.root.brand();
        let node = self.edit.node(root)?;
        if node.len() != 0 {
            return Some(Removed);
        }
        *self.edit.root = if node.is_leaf() {
            RawIndex::NONE
        } else {
            node.child(Gap::at::<0>())
        };
        self.edit.release(root)?;
        Some(Removed)
    }

    fn leaf(&mut self) -> Option<(Index<'owner, L>, Key)> {
        let depth = self.location.depth;
        let target = self.location.node;
        let key = self.location.key;
        let node = self.edit.node(target)?;
        if node.is_leaf() {
            return Some((target, key));
        }

        let mut index = node.child(key.widen()).brand();
        self.path.trim(depth, key.widen());
        for _ in 0..closed::MAX_LEVELS {
            let node = self.edit.node(index)?;
            let prior = node.last()?;
            let interval = node.key(prior);
            let gap = node.end();
            let leaf = node.is_leaf();
            let child = (!leaf).then(|| node.child(gap));
            let vacant = self.path.vacant()?;
            vacant.insert(index, gap);
            if leaf {
                *self.edit.node_mut(target)?.key_mut(key)? = interval;
                return Some((index, prior));
            }
            let child = child?;
            index = child.brand();
        }
        None
    }

    fn rebalance(&mut self) -> Option<Removed> {
        let mut path = self.path.steps().rev();
        let mut child = path.next()?;
        for parent in path {
            let index = child.node();
            if self.edit.node(index)?.len() >= closed::MIN_KEYS {
                child = parent;
                continue;
            }
            let at = parent.gap();
            let owner = parent.node();
            let node = self.edit.node(owner)?;
            let left = node.left(at);
            let right = node.right(at);
            if let Some((left, _)) = left
                && self.edit.node(left.brand())?.len() > closed::MIN_KEYS
            {
                self.borrow_left(owner, at)?;
            } else if let Some((right, _)) = right
                && self.edit.node(right.brand())?.len() > closed::MIN_KEYS
            {
                self.borrow_right(owner, at)?;
            } else if let Some((_, key)) = left {
                self.merge(owner, key.widen())?;
            } else if right.is_some() {
                self.merge(owner, at)?;
            } else {
                return None;
            }
            child = parent;
        }
        Some(Removed)
    }

    fn borrow_left(&mut self, parent: Index<'owner, L>, at: Gap) -> Option<Removed> {
        let node = self.edit.node(parent)?;
        let child = node.child(at).brand();
        let (left, key_at) = node.left(at)?;
        let left = left.brand();
        let pivot = node.key(key_at);
        let node = self.edit.node(child)?;
        let len = node.len();
        let leaf = node.is_leaf();
        let node = self.edit.node(left)?;
        let peer_len = node.len();
        if len >= closed::MAX_KEYS || peer_len <= closed::MIN_KEYS || leaf != node.is_leaf() {
            return None;
        }
        let last = node.last()?;
        let key = node.key(last);
        let branch = node.child(node.end());

        let node = self.edit.node_mut(child)?;
        node.insert::<false>(Gap::at::<0>(), pivot, (!leaf).then_some(branch))?;
        *self.edit.node_mut(parent)?.key_mut(key_at)? = key;
        self.edit.node_mut(left)?.set_len(peer_len - 1)?;
        Some(Removed)
    }

    fn borrow_right(&mut self, parent: Index<'owner, L>, at: Gap) -> Option<Removed> {
        let node = self.edit.node(parent)?;
        let child = node.child(at).brand();
        let (right, key_at) = node.right(at)?;
        let right = right.brand();
        let pivot = node.key(key_at);
        let node = self.edit.node(child)?;
        let len = node.len();
        let leaf = node.is_leaf();
        let node = self.edit.node(right)?;
        let peer_len = node.len();
        if len >= closed::MAX_KEYS || peer_len <= closed::MIN_KEYS || leaf != node.is_leaf() {
            return None;
        }
        let first = Key::at::<0>();
        let key = node.key(first);
        let branch = node.child(Gap::at::<0>());

        let node = self.edit.node_mut(child)?;
        node.insert::<true>(node.end(), pivot, (!leaf).then_some(branch))?;
        *self.edit.node_mut(parent)?.key_mut(key_at)? = key;
        let node = self.edit.node_mut(right)?;
        node.remove::<false>(first)?;
        Some(Removed)
    }

    fn merge(&mut self, parent: Index<'owner, L>, gap: Gap) -> Option<Removed> {
        let node = self.edit.node(parent)?;
        let (right, key_at) = node.right(gap)?;
        let left = node.child(gap).brand();
        let right = right.brand();
        let pivot = node.key(key_at);
        let peer = self.edit.node(right)?.snapshot();
        self.edit.node_mut(left)?.append(pivot, peer)?;
        self.edit.node_mut(parent)?.remove::<true>(key_at)?;
        self.edit.release(right)?;
        Some(Removed)
    }
}
