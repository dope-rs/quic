use std::{mem, num::NonZero};

use o3::{alloc::array, depot::capacity};

use crate::conn::wire::storage;

pub(super) struct Growth<'a, T, const MAX: usize> {
    pub(super) values: &'a mut storage::Vec<T, MAX>,
    next: Option<array::Block<mem::MaybeUninit<T>, NonZero<u32>, capacity::Count>>,
}

impl<'a, T, const MAX: usize> Growth<'a, T, MAX> {
    /// A spill exceeds the two inline slots; Vec admits MAX <= u32::MAX.
    pub(super) fn try_new(
        values: &'a mut storage::Vec<T, MAX>,
        request: usize,
    ) -> Result<Self, capacity::Reason> {
        let len = values.backing.len();
        let target = len
            .get()
            .checked_add(request)
            .ok_or(capacity::Reason::Full)?;
        if target > MAX {
            return Err(capacity::Reason::Full);
        }
        let next = if target <= values.backing.capacity() {
            None
        } else {
            let capacity = NonZero::<u32>::MIN.saturating_add(MAX as u32 - 1);
            Some(array::Block::try_new(capacity, len).map_err(capacity::Reason::Allocation)?)
        };
        Ok(Self { values, next })
    }

    pub(super) fn grow(&mut self) {
        if let Some(next) = self.next.take() {
            self.values.backing.install(next);
        }
    }
}

const _: () = assert!(mem::size_of::<Growth<'static, (), 64>>() == 3 * mem::size_of::<usize>());
