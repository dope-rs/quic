use std::mem;

use o3::depot::capacity;

use crate::conn::wire::storage;

/// The first pending value and its one consuming transition into the ready prefix.
#[must_use]
#[repr(transparent)]
pub(crate) struct Pending<'a, T, const MAX: usize> {
    pub(super) owner: &'a mut storage::Split<T, MAX>,
}

impl<T, const MAX: usize> Pending<'_, T, MAX> {
    pub(crate) fn get_mut(&mut self) -> &mut T {
        unsafe { self.owner.values.get_unchecked_mut(self.owner.ready.get()) }
    }

    /// The pending value retains ready < len <= MAX under this owner loan.
    pub(crate) fn commit(self) {
        self.owner.ready = capacity::Count::new(self.owner.ready.raw() + 1);
    }
}

const _: () = {
    assert!(mem::size_of::<Pending<'static, u64, 64>>() == mem::size_of::<usize>());
    assert!(mem::size_of::<Option<Pending<'static, u64, 64>>>() == mem::size_of::<usize>());
};
