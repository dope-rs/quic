use std::marker;

use crate::conn::stream::state::streams::closed::storage;
use crate::conn::stream::state::streams::closed::storage::index::{Index, RawIndex};
use crate::conn::stream::state::streams::closed::storage::node::Node;

pub(in crate::conn::stream::state::streams::closed) struct Edit<'owner, L> {
    pub(super) prefix: &'owner mut u64,
    pub(super) root: &'owner mut RawIndex,
    pub(super) storage: &'owner mut storage::Pool,
    lane: marker::PhantomData<fn(L) -> L>,
}

impl<'owner, L> Edit<'owner, L> {
    pub(in crate::conn::stream::state::streams::closed) const fn new(
        prefix: &'owner mut u64,
        root: &'owner mut RawIndex,
        storage: &'owner mut storage::Pool,
    ) -> Self {
        Self {
            prefix,
            root,
            storage,
            lane: marker::PhantomData,
        }
    }

    pub(super) fn node(&self, index: Index<'owner, L>) -> Option<&Node> {
        self.storage.get(index.raw())
    }

    pub(super) fn node_mut(&mut self, index: Index<'owner, L>) -> Option<&mut Node> {
        self.storage.get_mut(index.raw())
    }

    pub(super) fn release(&mut self, index: Index<'owner, L>) -> Option<storage::Released> {
        self.storage.remove(index.raw())
    }
}
