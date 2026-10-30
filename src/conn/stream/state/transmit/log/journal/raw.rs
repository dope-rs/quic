use o3::buffer;
use o3::depot::array;

use crate::conn;
use crate::conn::stream::state::transmit;
use transmit::log::journal;

/// # Safety
/// Keep the original state and Fresh-free lists; Context excludes both.
/// Finish preserves them in Output without mutable state access or rescheduling.
pub(in crate::conn) unsafe trait Schedule: Sized {
    type Send: buffer::raw::Segment;
    type Output: Owner<Send = Self::Send>;
    type Context<'a>
    where
        Self: 'a;

    fn parts(
        &mut self,
    ) -> (
        &mut transmit::State<Self::Send>,
        &mut array::Vec<journal::Entry, { conn::PACKET_STREAM_CAPACITY }>,
        Self::Context<'_>,
    );

    fn finish(self) -> Self::Output;
}

/// # Safety
/// Retain original state and frozen lists; Context excludes both, while other projections stay original and disjoint.
/// Discard both lists unpublished; consuming publication drains their original entries exactly once.
pub(in crate::conn) unsafe trait Owner {
    type Send: buffer::raw::Segment;
    type Selection;
    type Context<'a>
    where
        Self: 'a;

    fn parts(
        &mut self,
    ) -> (
        &mut transmit::State<Self::Send>,
        &mut array::Vec<journal::Entry, { conn::PACKET_STREAM_CAPACITY }>,
        Self::Context<'_>,
    );

    fn selection(&mut self) -> &mut Option<Self::Selection>;

    fn scratch(&mut self) -> &mut conn::Scratch;

    fn discard(&mut self);
}
