use crate::conn::wire::storage;
use std::mem;
use storage::growth;

/// One admitted insertion retaining its original owner until publication.
#[must_use]
#[repr(transparent)]
pub(crate) struct Insert<'a, T, const MAX: usize> {
    pub(super) growth: growth::Growth<'a, T, MAX>,
}

impl<T, const MAX: usize> Insert<'_, T, MAX> {
    pub(crate) fn push(mut self, value: T) {
        self.growth.grow();
        storage::Vacant {
            values: self.growth.values,
        }
        .push(value);
    }
}

const _: () = {
    assert!(mem::size_of::<Insert<'static, (), 64>>() == 3 * mem::size_of::<usize>());
    assert!(mem::size_of::<Option<Insert<'static, (), 64>>>() == 3 * mem::size_of::<usize>());
};
