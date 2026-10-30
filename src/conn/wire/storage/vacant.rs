use std::mem;

use o3::depot::capacity;

use crate::conn::wire::storage;

/// Exclusive proof that one value can be published without allocating.
///
/// Dropping a vacancy changes no logical state. Prepared demand backing remains
/// resident for the next admission.
#[must_use]
#[repr(transparent)]
pub(crate) struct Vacant<'a, T, const MAX: usize> {
    pub(in crate::conn::wire::storage) values: &'a mut storage::Vec<T, MAX>,
}

impl<'a, T, const MAX: usize> Vacant<'a, T, MAX> {
    /// This retained vacancy keeps index below MAX, admitted within u32.
    pub(crate) fn push(self, value: T) {
        let (len, entries) = self.values.backing.parts_mut();
        let index = len.raw();
        let entry = unsafe { entries.get_unchecked_mut(index as usize) };
        *entry = mem::MaybeUninit::new(value);
        *len = capacity::Count::new(index + 1);
    }
}

const _: () = assert!(mem::size_of::<Vacant<'static, (), 64>>() == mem::size_of::<usize>());
