use crate::conn::wire::storage;
use std::mem;
use storage::growth;

/// Staged backing retaining the exact source slice and exclusive destination.
#[must_use]
pub(crate) struct Batch<'a, 'b, T, U, const MAX: usize> {
    pub(super) growth: growth::Growth<'a, T, MAX>,
    pub(super) input: &'b [U],
}

impl<'b, T, U, const MAX: usize> Batch<'_, 'b, T, U, MAX> {
    pub(crate) fn commit(mut self, mut map: impl FnMut(&'b U) -> T) {
        self.growth.grow();
        for item in self.input {
            storage::Vacant {
                values: self.growth.values,
            }
            .push(map(item));
        }
    }
}

const _: () = {
    assert!(mem::size_of::<Batch<'static, 'static, (), (), 64>>() == 5 * mem::size_of::<usize>());
    assert!(
        mem::size_of::<Option<Batch<'static, 'static, (), (), 64>>>()
            == 5 * mem::size_of::<usize>()
    );
};
