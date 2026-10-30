use std::{mem, num::NonZero, ptr, slice};

use o3::alloc::array;
use o3::depot::capacity;

/// Inline cells or one exact demand allocation.
#[repr(transparent)]
pub(in crate::conn::wire::storage) struct Backing<T> {
    storage: Cells<T>,
}

#[repr(C)]
union Cells<T> {
    inline: mem::ManuallyDrop<Inline<T>>,
    block: mem::ManuallyDrop<array::Block<mem::MaybeUninit<T>, NonZero<u32>, capacity::Count>>,
}

#[repr(C)]
struct Inline<T> {
    state: State,
    entries: [mem::MaybeUninit<T>; 2],
}

/// Logical prefix length and optional demand capacity.
#[repr(C)]
struct State {
    resident: Option<NonZero<u32>>,
    len: capacity::Count,
}

impl<T> Backing<T> {
    pub(in crate::conn::wire::storage) const fn inline() -> Self {
        Self {
            storage: Cells {
                inline: mem::ManuallyDrop::new(Inline {
                    state: State {
                        resident: None,
                        len: capacity::Count::EMPTY,
                    },
                    entries: [const { mem::MaybeUninit::uninit() }; 2],
                }),
            },
        }
    }

    pub(in crate::conn::wire::storage) fn install(
        &mut self,
        mut next: array::Block<mem::MaybeUninit<T>, NonZero<u32>, capacity::Count>,
    ) {
        let source = self.as_slice();
        if !source.is_empty() && mem::size_of::<T>() != 0 {
            unsafe {
                ptr::copy_nonoverlapping(source.as_ptr(), next.as_mut_ptr().cast(), source.len())
            };
        }
        self.storage.block = mem::ManuallyDrop::new(next);
    }

    /// Reads the identical resident-and-length prefix of either union arm.
    const fn state(&self) -> &State {
        unsafe { &*ptr::from_ref(&self.storage).cast::<State>() }
    }

    pub(in crate::conn::wire::storage) const fn len(&self) -> capacity::Count {
        self.state().len
    }

    const fn is_spilled(&self) -> bool {
        self.state().resident.is_some()
    }

    pub(in crate::conn::wire::storage) const fn capacity(&self) -> usize {
        match self.state().resident {
            Some(capacity) => capacity.get() as usize,
            None => 2,
        }
    }

    pub(in crate::conn::wire::storage) fn as_slice(&self) -> &[T] {
        let entries = if self.is_spilled() {
            unsafe { self.storage.block.as_ptr() }
        } else {
            unsafe { self.storage.inline.entries.as_ptr() }
        };
        unsafe { slice::from_raw_parts(entries.cast(), self.len().get()) }
    }

    pub(in crate::conn::wire::storage) fn parts_mut(
        &mut self,
    ) -> (&mut capacity::Count, &mut [mem::MaybeUninit<T>]) {
        if self.is_spilled() {
            let block = unsafe { &mut self.storage.block };
            block.parts_mut()
        } else {
            let inline = unsafe { &mut *self.storage.inline };
            (&mut inline.state.len, &mut inline.entries)
        }
    }
}

impl<T> Drop for Backing<T> {
    fn drop(&mut self) {
        if self.is_spilled() {
            unsafe { mem::ManuallyDrop::drop(&mut self.storage.block) };
        }
    }
}

const _: () = assert!(mem::size_of::<State>() == mem::size_of::<u64>());
