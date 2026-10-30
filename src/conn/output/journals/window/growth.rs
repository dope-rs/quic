use crate::conn::output::journals;
use o3::alloc;
use o3::{alloc::array, depot::capacity::Count};
use std::mem;

#[must_use]
pub(in crate::conn::output::journals) struct Growth<'a> {
    pub(super) window: &'a mut journals::Window,
    pub(super) spare: Option<array::Block<mem::MaybeUninit<journals::Packet>, Count>>,
}

impl Growth<'_> {
    pub(in crate::conn::output::journals) fn commit(self) {
        let Self { window, spare } = self;
        let Some(spare) = spare else {
            return;
        };
        let (head, first, second) = window.block.state().split(window.block.extent().get());
        // SAFETY: try_grow retains this exact window and admits both disjoint runs.
        unsafe {
            alloc::raw::relocate(
                &mut window.block,
                spare,
                [(head, 0, first), (0, first, second)],
            );
        }
        window.block.state_mut().head = Count::EMPTY;
    }
}

const _: () = assert!(size_of::<Growth<'static>>() == 3 * size_of::<usize>());
