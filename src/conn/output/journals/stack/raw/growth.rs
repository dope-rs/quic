use o3::alloc;
use std::mem;

use o3::alloc::array;

use crate::conn::output::journals::stack;

#[must_use]
pub(in crate::conn::output::journals) struct Growth<'a, T: Copy, Tag> {
    slab: &'a mut stack::raw::Slab<T, Tag>,
    backing: Option<array::Block<mem::MaybeUninit<stack::raw::Node<T>>, stack::raw::Extent>>,
}

impl<'a, T: Copy, Tag> Growth<'a, T, Tag> {
    pub(in crate::conn::output::journals::stack) fn new(
        slab: &'a mut stack::raw::Slab<T, Tag>,
        backing: Option<array::Block<mem::MaybeUninit<stack::raw::Node<T>>, stack::raw::Extent>>,
    ) -> Self {
        Self { slab, backing }
    }

    pub(in crate::conn::output::journals) fn commit(self) {
        let Self { slab, backing } = self;
        if let Some(spare) = backing {
            let len = usize::from(slab.block.extent().0);
            // SAFETY: try_grow admits a larger backing and preserves every node position.
            unsafe { alloc::raw::relocate(&mut slab.block, spare, [(0, 0, len)]) };
        }
    }
}

const _: () = assert!(size_of::<Growth<'static, (), ()>>() == 24);
