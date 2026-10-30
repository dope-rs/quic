use crate::conn::wire::storage;
use o3::depot::capacity;
pub(crate) use pending::Pending;
pub(crate) use selected::Selected;
use std::{mem, ops};
use storage::growth;

mod pending;
mod raw;
mod selected;

/// An initialized ready prefix followed by pending values, under one owner.
pub(crate) struct Split<T, const MAX: usize> {
    values: storage::Vec<T, MAX>,
    ready: capacity::Count,
}

impl<T, const MAX: usize> Split<T, MAX> {
    pub(crate) const fn new() -> Self {
        Self {
            values: storage::Vec::new(),
            ready: capacity::Count::EMPTY,
        }
    }

    pub(crate) fn try_insert(&mut self) -> Result<storage::Insert<'_, T, MAX>, capacity::Reason> {
        self.values.try_insert()
    }

    pub(crate) fn try_extend<'a, 'b, U>(
        &'a mut self,
        input: &'b [U],
    ) -> Result<storage::Batch<'a, 'b, T, U, MAX>, capacity::Reason> {
        Ok(storage::Batch {
            growth: growth::Growth::try_new(&mut self.values, input.len())?,
            input,
        })
    }

    pub(crate) fn ready_mut(&mut self) -> &mut [T] {
        unsafe { self.values.get_unchecked_mut(..self.ready.get()) }
    }

    pub(crate) fn ready(&self) -> &[T] {
        // SAFETY: the ready prefix remains initialized under this shared loan.
        unsafe { self.values.get_unchecked(..self.ready.get()) }
    }

    pub(crate) fn first(&mut self) -> Option<Pending<'_, T, MAX>> {
        if self.ready.get() == self.values.len() {
            return None;
        }
        Some(Pending { owner: self })
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.ready.get() != self.values.len()
    }

    pub(crate) fn select(
        &mut self,
        test: impl FnMut(&T) -> bool,
    ) -> Option<Selected<'_, T, MAX, true>> {
        let index = self.ready_mut().iter().position(test)?;
        Some(Selected { owner: self, index })
    }

    pub(crate) fn retain_ready(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let mut left = self.ready.raw();
        self.ready = capacity::Count::EMPTY;
        let mut ready = capacity::Count::EMPTY;
        self.values.retain(|value| {
            if left == 0 {
                return true;
            }
            left -= 1;
            if !keep(value) {
                return false;
            }
            ready = capacity::Count::new(ready.raw() + 1);
            true
        });
        self.ready = ready;
    }

    /// Removes matching values and retains the resulting publication slot.
    pub(crate) fn remove_all(
        &mut self,
        mut test: impl FnMut(&T) -> bool,
        mut removed: impl FnMut(T),
    ) -> Option<storage::Vacant<'_, T, MAX>> {
        let index = self.values.iter().rposition(&mut test)?;
        removed(Selected::<_, MAX, false> { owner: self, index }.take());
        let mut index = index;
        while index != 0 {
            index -= 1;
            if test(unsafe { self.values.get_unchecked(index) }) {
                removed(Selected::<_, MAX, false> { owner: self, index }.take());
            }
        }
        Some(storage::Vacant {
            values: &mut self.values,
        })
    }
}

impl<T, const MAX: usize> ops::Deref for Split<T, MAX> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.values
    }
}

const _: () = {
    assert!(mem::size_of::<Split<u64, 64>>() == 4 * mem::size_of::<usize>());
};
