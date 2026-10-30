use crate::conn::wire::storage;
use o3::depot::capacity;
use std::{mem, ops, ptr, slice};
use storage::growth;

mod backing;

/// Two inline values followed by one retained allocation at the path limit.
#[repr(C)]
pub(crate) struct Vec<T, const MAX: usize> {
    pub(in crate::conn::wire::storage) backing: backing::Backing<T>,
}

impl<T, const MAX: usize> Vec<T, MAX> {
    pub(crate) const fn new() -> Self {
        const { assert!(MAX <= u32::MAX as usize) };
        Self {
            backing: backing::Backing::inline(),
        }
    }

    pub(crate) fn try_insert(&mut self) -> Result<storage::Insert<'_, T, MAX>, capacity::Reason> {
        Ok(storage::Insert {
            growth: growth::Growth::try_new(self, 1)?,
        })
    }

    pub(crate) fn try_reuse(&mut self) -> Result<storage::Vacant<'_, T, MAX>, capacity::Reason> {
        if MAX == 0 {
            return Err(capacity::Reason::Full);
        }
        if self.backing.len().get() == MAX {
            let (len, entries) = self.backing.parts_mut();
            let last = len.raw() - 1;
            let entries = entries.as_mut_ptr();
            if last != 0 && mem::size_of::<T>() != 0 {
                unsafe { ptr::swap_nonoverlapping(entries, entries.add(last as usize), 1) };
            }
            *len = capacity::Count::new(last);
            unsafe { (*entries.add(last as usize)).assume_init_drop() };
        } else {
            growth::Growth::try_new(self, 1)?.grow();
        }
        Ok(storage::Vacant { values: self })
    }

    pub(crate) fn remove(&mut self, test: impl FnMut(&T) -> bool) {
        let Some(index) = self.backing.as_slice().iter().position(test) else {
            return;
        };
        let (len, entries) = self.backing.parts_mut();
        let last = len.raw() - 1;
        let entries = entries.as_mut_ptr();
        if index != last as usize && mem::size_of::<T>() != 0 {
            unsafe { ptr::swap_nonoverlapping(entries.add(index), entries.add(last as usize), 1) };
        }
        *len = capacity::Count::new(last);
        unsafe { (*entries.add(last as usize)).assume_init_drop() };
    }

    pub(in crate::conn::wire::storage) fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let (len, entries) = self.backing.parts_mut();
        let original = len.raw();
        *len = capacity::Count::EMPTY;
        let mut deleted = 0;
        for index in 0..original {
            let entry = unsafe { entries.as_mut_ptr().add(index as usize) };
            if keep(unsafe { (*entry).assume_init_ref() }) {
                if deleted != 0 {
                    unsafe { ptr::copy(entry, entry.sub(deleted as usize), 1) };
                }
            } else {
                deleted += 1;
                unsafe { (*entry).assume_init_drop() };
            }
        }
        *len = capacity::Count::new(original - deleted);
    }
}

impl<T, const MAX: usize> ops::Deref for Vec<T, MAX> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.backing.as_slice()
    }
}

impl<T, const MAX: usize> ops::DerefMut for Vec<T, MAX> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let (len, entries) = self.backing.parts_mut();
        unsafe { slice::from_raw_parts_mut(entries.as_mut_ptr().cast(), len.get()) }
    }
}

impl<T, const MAX: usize> Drop for Vec<T, MAX> {
    fn drop(&mut self) {
        let (len, entries) = self.backing.parts_mut();
        while len.raw() != 0 {
            let index = len.raw() - 1;
            *len = capacity::Count::new(index);
            unsafe { entries.get_unchecked_mut(index as usize).assume_init_drop() };
        }
    }
}

const _: () = {
    assert!(mem::size_of::<Vec<(), 64>>() == 2 * mem::size_of::<usize>());
    assert!(mem::size_of::<Vec<u64, 64>>() == 3 * mem::size_of::<usize>());
    assert!(mem::size_of::<Vec<[u8; 8], 64>>() == 3 * mem::size_of::<usize>());
};
