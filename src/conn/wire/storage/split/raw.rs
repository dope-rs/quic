use crate::conn::wire::storage::{Selected, Split};
use o3::depot;

// SAFETY: the caller retains this owner's initialized ready position, with
// every earlier compaction reflected in the selected index.
unsafe impl<'a, T, const N: usize> depot::raw::Project<usize, Selected<'a, T, N, true>>
    for &'a mut Split<T, N>
{
    type Output = Selected<'a, T, N, true>;

    unsafe fn project(self, index: usize) -> Self::Output {
        Selected { owner: self, index }
    }
}
