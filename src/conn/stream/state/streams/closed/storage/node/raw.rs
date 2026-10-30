use crate::conn::stream::state::streams::closed::storage::{
    index::RawIndex,
    node::{Len, Node},
};
use o3::depot::arena;
use std::num::NonZero;

// SAFETY: Node has no drop state and its safe payload operations preserve the
// private link. Construction initializes it once; reset changes only len/leaf.
// These hooks invoke no callbacks and cannot reenter the owning pool.
unsafe impl arena::raw::LinkedNode for Node {
    type Input = bool;

    fn new(leaf: bool) -> Self {
        Node::new(leaf)
    }

    fn reset(&mut self, leaf: bool) {
        self.len = Len::at::<0>();
        self.leaf = leaf;
    }

    fn next(&self) -> Option<NonZero<u32>> {
        self.link.get()
    }

    unsafe fn set_next(&mut self, next: Option<NonZero<u32>>) {
        self.link = RawIndex::new(next);
    }
}
