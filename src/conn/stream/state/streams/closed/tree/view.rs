use std::marker;

use crate::conn::stream::state::streams::closed;
use crate::conn::stream::state::streams::closed::half::Number;
use crate::conn::stream::state::streams::closed::storage;
use crate::conn::stream::state::streams::closed::storage::index::{Index, RawIndex};
use crate::conn::stream::state::streams::closed::storage::node::{Interval, Node};

pub(in crate::conn::stream::state::streams::closed) struct View<'owner, L> {
    prefix: &'owner u64,
    root: RawIndex,
    storage: &'owner storage::Pool,
    lane: marker::PhantomData<fn(L) -> L>,
}

impl<'owner, L> View<'owner, L> {
    pub(in crate::conn::stream::state::streams::closed) const fn new(
        prefix: &'owner u64,
        root: RawIndex,
        storage: &'owner storage::Pool,
    ) -> Self {
        Self {
            prefix,
            root,
            storage,
            lane: marker::PhantomData,
        }
    }

    pub(in crate::conn::stream::state::streams::closed) fn contains(&self, number: Number) -> bool {
        number.get() < *self.prefix
            || self
                .predecessor(number.get())
                .is_some_and(|range| number.get() < range.end)
    }

    fn predecessor(&self, start: u64) -> Option<Interval> {
        if self.root.is_none() {
            return None;
        }
        let mut best = None;
        let mut index = self.root.brand();
        for _ in 0..closed::MAX_LEVELS {
            let node = self.node(index)?;
            let search = node.search(start);
            if let Some(key) = search.left() {
                best = Some(node.key(key));
            }
            if node.is_leaf() {
                return best;
            }
            index = node.child(search.gap()).brand();
        }
        None
    }

    fn node(&self, index: Index<'owner, L>) -> Option<&Node> {
        self.storage.get(index.raw())
    }
}
