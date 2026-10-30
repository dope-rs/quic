use std::{marker, mem};

use o3::alloc::{self, array};
use o3::depot::capacity;

use crate::conn::machine::storage;
use crate::conn::output::journals::stack;

pub(in crate::conn::output::journals) struct Slab<T: Copy, Tag> {
    pub(in crate::conn::output::journals) block:
        array::Block<mem::MaybeUninit<Node<T>>, Extent, State>,
    domain: marker::PhantomData<fn(Tag) -> Tag>,
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(in crate::conn::output::journals) struct Extent(
    pub(in crate::conn::output::journals::stack) u16,
);

unsafe impl alloc::raw::Extent for Extent {
    fn len(&self) -> usize {
        usize::from(self.0)
    }
}

#[repr(C)]
pub(in crate::conn::output::journals) struct Node<T: Copy> {
    pub(in crate::conn::output::journals) value: T,
    pub(in crate::conn::output::journals) next: u16,
}

#[repr(C)]
pub(in crate::conn::output::journals) struct State {
    pub(in crate::conn::output::journals) free: u16,
    pub(in crate::conn::output::journals) live: u16,
    limit: u16,
}

impl<T: Copy, Tag> Slab<T, Tag> {
    pub(in crate::conn::output::journals) fn with_limit(limit: u16) -> Self {
        Self {
            block: array::Block::empty(
                unsafe { alloc::raw::Empty::assume(Extent(0)) },
                State {
                    free: u16::MAX,
                    live: 0,
                    limit,
                },
            ),
            domain: marker::PhantomData,
        }
    }

    /// # Safety
    /// The head owns a disjoint chain in this slab.
    pub(in crate::conn::output::journals) unsafe fn drain(
        &mut self,
        head: &mut stack::Head<Tag>,
    ) -> stack::raw::Drain<'_, T, Tag> {
        stack::raw::Drain::new(self, mem::replace(head, stack::Head::new()))
    }

    pub(in crate::conn::output::journals) fn try_grow(
        &mut self,
        extra: usize,
    ) -> Result<stack::raw::Growth<'_, T, Tag>, capacity::Reason> {
        let state = self.block.state();
        let need = usize::from(state.live)
            .checked_add(extra)
            .ok_or(capacity::Reason::Full)?;
        let limit = usize::from(state.limit);
        if need > limit {
            return Err(capacity::Reason::Full);
        }
        let resident = usize::from(self.block.extent().0);
        let backing = if need <= resident {
            None
        } else {
            let plan =
                storage::Plan::geometric(resident, need, limit).ok_or(capacity::Reason::Full)?;
            Some(
                array::Block::try_new(Extent(plan.capacity().get() as u16), ())
                    .map_err(capacity::Reason::Allocation)?,
            )
        };
        Ok(stack::raw::Growth::new(self, backing))
    }

    pub(in crate::conn::output::journals) fn available(&self) -> usize {
        usize::from(self.block.state().limit - self.block.state().live)
    }

    pub(in crate::conn::output::journals) fn bytes(&self) -> usize {
        usize::from(self.block.extent().0) * size_of::<Node<T>>()
    }
}

const _: () = assert!(size_of::<Slab<(), ()>>() == 16);
