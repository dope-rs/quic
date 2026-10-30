use o3::alloc;
use std::{mem, num::NonZero};

use crate::conn::machine::storage::compact;
use o3::alloc::array;
use o3::depot::arena::slab::external;
use o3::depot::{capacity, queue::links};

pub(in crate::conn) struct Storage<T, G: external::Generation> {
    pub(in crate::conn::machine::storage::compact) slots:
        array::Block<mem::MaybeUninit<compact::Slot<T, G>>, capacity::Count, State>,
}

pub(in crate::conn::machine::storage::compact) struct State {
    pub(in crate::conn::machine::storage::compact) free: Linear,
    initialized: capacity::Count,
    pub(in crate::conn::machine::storage::compact) available: capacity::Count,
}

impl State {
    fn new(room: capacity::Count) -> Self {
        Self {
            free: Linear::default(),
            initialized: capacity::Count::EMPTY,
            available: room,
        }
    }

    pub(super) const fn initialized(&self) -> capacity::Count {
        self.initialized
    }

    pub(super) fn advance(&mut self, next: capacity::Count) {
        self.initialized = next;
    }

    pub(super) const fn available(&self) -> capacity::Count {
        self.available
    }

    pub(super) fn free(&self) -> &Linear {
        &self.free
    }
}

impl<T, G> Storage<T, G>
where
    G: external::Generation,
{
    pub(super) fn empty(room: capacity::Count) -> Self {
        Self {
            slots: array::Block::empty(alloc::raw::Empty::EMPTY, State::new(room)),
        }
    }

    pub(super) fn try_new(cap: capacity::Count) -> Result<Self, alloc::Error> {
        Ok(Self {
            slots: array::Block::try_new(cap, State::new(cap))?,
        })
    }

    pub(in crate::conn) fn capacity(&self) -> capacity::Count {
        *self.slots.extent()
    }

    pub(in crate::conn) fn get(&self, index: u32, epoch: G) -> Option<&T> {
        let slot = slot(self, index)?;
        if slot.next != compact::raw::NONE || slot.generation != epoch {
            return None;
        }
        Some(unsafe { slot.value.assume_init_ref() })
    }

    pub(in crate::conn) fn generation(&self, index: u32) -> Option<G> {
        let slot = slot(self, index)?;
        (slot.next == compact::raw::NONE).then_some(slot.generation)
    }

    pub(in crate::conn) fn entry_at(&self, index: u32) -> Option<(G, &T)> {
        let slot = slot(self, index)?;
        if slot.next != compact::raw::NONE {
            return None;
        }
        Some((slot.generation, unsafe { slot.value.assume_init_ref() }))
    }

    pub(super) fn take_free(&mut self, free: compact::raw::Free) -> links::Index {
        let (state, slots) = self.slots.parts_mut();
        state.free.pop(slots, free)
    }

    pub(super) const fn state(&self) -> &State {
        self.slots.state()
    }

    pub(in crate::conn::machine::storage::compact) fn state_mut(&mut self) -> &mut State {
        self.slots.state_mut()
    }

    pub(in crate::conn::machine::storage::compact) unsafe fn slot(
        &self,
        index: links::Index,
    ) -> &compact::Slot<T, G> {
        unsafe { (&*self.slots.as_ptr().add(index.get())).assume_init_ref() }
    }

    pub(in crate::conn::machine::storage::compact) unsafe fn slot_mut(
        &mut self,
        index: links::Index,
    ) -> &mut compact::Slot<T, G> {
        unsafe { (&mut *self.slots.as_mut_ptr().add(index.get())).assume_init_mut() }
    }
}

fn slot<T, G>(store: &Storage<T, G>, index: u32) -> Option<&compact::Slot<T, G>>
where
    G: external::Generation,
{
    (index < store.state().initialized().raw())
        .then(|| unsafe { store.slot(links::Index::from(NonZero::new_unchecked(index + 1))) })
}

impl<T, G> Drop for Storage<T, G>
where
    G: external::Generation,
{
    fn drop(&mut self) {
        for index in 0..self.state().initialized().raw() {
            // SAFETY: this iteration stays in the initialized prefix.
            let index = unsafe { links::Index::from(NonZero::new_unchecked(index + 1)) };
            if unsafe { self.slot(index) }.next == compact::raw::NONE {
                unsafe { self.slot_mut(index).value.assume_init_drop() };
            }
        }
    }
}

#[derive(Default)]
pub(in crate::conn) struct Linear {
    head: Option<links::Index>,
}

impl Linear {
    pub(super) fn peek(&self) -> Option<compact::raw::Free> {
        self.head.map(compact::raw::Free)
    }

    pub(super) fn pop<T, G>(
        &mut self,
        slots: &mut [mem::MaybeUninit<compact::Slot<T, G>>],
        free: compact::raw::Free,
    ) -> links::Index {
        let compact::raw::Free(index) = free;
        // SAFETY: the retained Recycled reservation owns this free member;
        // its successor is a bounded member or the same terminal member.
        let slot = unsafe { slots.get_unchecked_mut(index.get()).assume_init_mut() };
        let next = unsafe { links::Index::from(NonZero::new_unchecked(slot.next + 1)) };
        self.head = if next == index { None } else { Some(next) };
        slot.next = compact::raw::NONE;
        index
    }

    pub(super) fn push(&mut self, index: links::Index) -> links::Index {
        match self.head.replace(index) {
            Some(head) => head,
            None => index,
        }
    }
}

const _: () = assert!(mem::size_of::<Linear>() == mem::size_of::<u32>());
