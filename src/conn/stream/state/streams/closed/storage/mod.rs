use crate::conn::stream::state::streams::closed::{self, storage::node::Node};
use index::{Index, RawIndex};
use o3::{
    alloc,
    depot::{arena::linked::slots::fixed, array::copy},
};
use std::mem;

pub(super) mod index;
pub(super) mod node;

pub(super) struct Reserved<'pool>(fixed::Batch<'pool, Node, { closed::MAX_LEVELS + 1 }>);

pub(super) struct Released;

impl Reserved<'_> {
    pub(super) fn take<'owner, L>(&mut self) -> Option<Index<'owner, L>> {
        Some(RawIndex::new(Some(self.0.take()?)).brand())
    }

    pub(super) fn node<L>(&self, index: Index<'_, L>) -> Option<&Node> {
        self.0.get(index.raw().get()?)
    }

    pub(super) fn node_mut<L>(&mut self, index: Index<'_, L>) -> Option<&mut Node> {
        self.0.get_mut(index.raw().get()?)
    }
}

const _: () = {
    assert!(mem::size_of::<Released>() == 0);
};

pub(super) struct Pool(fixed::Fixed<Node>);

impl Pool {
    pub(in crate::conn::stream::state::streams::closed) fn try_new(
        plan: closed::Plan,
    ) -> Result<Self, alloc::Error> {
        const {
            assert!(
                closed::LANES * (1 + (closed::MAX_INTERVALS - 1) / closed::MIN_KEYS)
                    <= u16::MAX as usize
            );
        }
        Ok(Self(fixed::Fixed::try_new(plan.capacity())?))
    }

    pub(in crate::conn::stream::state::streams::closed) fn reserve(
        &mut self,
        leaves: &copy::Vec<bool, { closed::MAX_LEVELS + 1 }>,
    ) -> Option<Reserved<'_>> {
        self.0.reserve(leaves).map(Reserved)
    }

    pub(in crate::conn::stream::state::streams::closed) fn get(
        &self,
        index: RawIndex,
    ) -> Option<&Node> {
        self.0.get(index.get()?)
    }

    pub(in crate::conn::stream::state::streams::closed) fn get_mut(
        &mut self,
        index: RawIndex,
    ) -> Option<&mut Node> {
        self.0.get_mut(index.get()?)
    }

    pub(in crate::conn::stream::state::streams::closed) fn remove(
        &mut self,
        index: RawIndex,
    ) -> Option<Released> {
        self.0.entry(index.get()?)?.remove();
        Some(Released)
    }
}

const _: () = {
    assert!(!mem::needs_drop::<Node>());
    assert!(mem::size_of::<Pool>() == 3 * mem::size_of::<usize>());
};
