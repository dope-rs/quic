use o3::depot;

use crate::conn::output::control;
use control::{encode, journal, revision};

pub(super) struct Selected<'a> {
    pub(super) owner: &'a mut control::Pending,
    pub(super) selected: encode::Written,
}

// SAFETY: Records owns this selected control and its original connection;
// admission cannot replace its slot or delivery state.
unsafe impl depot::raw::Source<journal::State> for Selected<'_> {
    type Key = revision::Key;

    fn key(&self) -> Self::Key {
        self.selected.handle()
    }
}

const _: () = assert!(
    std::mem::size_of::<Selected<'static>>()
        == std::mem::size_of::<encode::Written>() + std::mem::size_of::<usize>()
);
