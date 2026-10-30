use o3::depot::array;
use std::mem;

use crate::conn::stream::state::streams::closed;
use crate::conn::stream::state::streams::closed::storage::index::Index;
use crate::conn::stream::state::streams::closed::storage::node::Gap;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(super) struct Depth(array::Index<{ closed::MAX_LEVELS }>);

pub(super) struct Step<'owner, L> {
    node: Index<'owner, L>,
    gap: Gap,
}

pub(super) struct Vacant<'path, 'owner, L> {
    node: &'path mut Index<'owner, L>,
    gap: &'path mut Gap,
    len: &'path mut u8,
    depth: Depth,
}

pub(super) struct Path<'owner, L> {
    nodes: [Index<'owner, L>; closed::MAX_LEVELS],
    gaps: [Gap; closed::MAX_LEVELS],
    len: u8,
}

impl Depth {
    pub(super) const fn get(self) -> usize {
        self.0.index()
    }
}

impl<'owner, L> Step<'owner, L> {
    pub(super) const fn node(&self) -> Index<'owner, L> {
        self.node
    }

    pub(super) const fn gap(&self) -> Gap {
        self.gap
    }
}

impl<'owner, L> Vacant<'_, 'owner, L> {
    pub(super) fn insert(self, node: Index<'owner, L>, gap: Gap) -> Depth {
        *self.node = node;
        *self.gap = gap;
        *self.len = self.depth.get() as u8 + 1;
        self.depth
    }
}

impl<'owner, L> Path<'owner, L> {
    pub(super) const fn new() -> Self {
        Self {
            nodes: [Index::NONE; closed::MAX_LEVELS],
            gaps: [Gap::at::<0>(); closed::MAX_LEVELS],
            len: 0,
        }
    }

    pub(super) fn vacant(&mut self) -> Option<Vacant<'_, 'owner, L>> {
        let depth = Depth(array::Index::new(self.len as usize)?);
        Some(Vacant {
            node: depth.0.get_mut(&mut self.nodes),
            gap: depth.0.get_mut(&mut self.gaps),
            len: &mut self.len,
            depth,
        })
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn steps(self) -> impl DoubleEndedIterator<Item = Step<'owner, L>> {
        array::Index::<{ closed::MAX_LEVELS }>::iter()
            .take(self.len as usize)
            .map(move |index| Step {
                node: *index.get(&self.nodes),
                gap: *index.get(&self.gaps),
            })
    }

    pub(super) fn trim(&mut self, depth: Depth, gap: Gap) {
        *depth.0.get_mut(&mut self.gaps) = gap;
        self.len = depth.get() as u8 + 1;
    }
}

impl<L> Clone for Path<'_, L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<L> Copy for Path<'_, L> {}

const _: () = {
    assert!(closed::MAX_LEVELS <= u8::MAX as usize);
    assert!(mem::size_of::<Depth>() == mem::size_of::<u8>());
    assert!(mem::size_of::<Path<'static, ()>>() == 8 * mem::size_of::<u32>());
};
