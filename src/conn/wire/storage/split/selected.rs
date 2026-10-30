use std::{mem, ptr};

use o3::depot::capacity;

use crate::conn::wire::storage;

/// An initialized value retaining its exclusive owner and admitted phase.
/// As a projection predicate, the ready form requires a current ready index
/// in this exact owner, including all prior compactions.
#[must_use]
pub(crate) struct Selected<'a, T, const MAX: usize, const READY: bool> {
    pub(super) owner: &'a mut storage::Split<T, MAX>,
    pub(super) index: usize,
}

impl<T, const MAX: usize, const READY: bool> Selected<'_, T, MAX, READY> {
    pub(crate) fn take(self) -> T {
        let (len, entries) = self.owner.values.backing.parts_mut();
        let last = len.raw() - 1;
        let entries = entries.as_mut_ptr();
        let value = unsafe { entries.add(self.index).read().assume_init() };
        let hole = if READY || self.index < self.owner.ready.get() {
            let ready = self.owner.ready.raw() - 1;
            self.owner.ready = capacity::Count::new(ready);
            if self.index != ready as usize {
                unsafe { ptr::copy(entries.add(ready as usize), entries.add(self.index), 1) };
            }
            ready as usize
        } else {
            self.index
        };
        if hole != last as usize {
            unsafe { ptr::copy(entries.add(last as usize), entries.add(hole), 1) };
        }
        *len = capacity::Count::new(last);
        value
    }
}

impl<T, const MAX: usize> Selected<'_, T, MAX, true> {
    pub(crate) fn get(&self) -> &T {
        unsafe { self.owner.values.get_unchecked(self.index) }
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        // SAFETY: selection retains this exact initialized position exclusively.
        unsafe { self.owner.values.get_unchecked_mut(self.index) }
    }

    pub(crate) fn relocation(&self) -> Option<(usize, usize)> {
        let last = self.owner.ready.get() - 1;
        (last != self.index).then_some((last, self.index))
    }
}

const _: () = {
    assert!(mem::size_of::<Selected<'static, u64, 64, true>>() == 2 * mem::size_of::<usize>());
    assert!(
        mem::size_of::<Option<Selected<'static, u64, 64, true>>>() == 2 * mem::size_of::<usize>()
    );
};
