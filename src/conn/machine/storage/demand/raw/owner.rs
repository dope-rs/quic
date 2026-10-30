use crate::conn::machine::storage::demand;
use o3::depot;
use o3::depot::index::Initialized;
use o3::depot::queue::links;

/// # Safety
/// Own one resident vacancy; context must exclude backing and vacancy mutation.
/// `build` proves `Plane`; `finish` consumes the vacancy, retaining its table and lifetime.
pub(in crate::conn) unsafe trait Owner<const MAX: u32 = { u32::MAX }>:
    Sized
{
    type Value;
    type Tag;
    type Plane;
    type Output;
    type Context<'a>
    where
        Self: 'a;

    fn parts(
        &mut self,
    ) -> (
        &mut demand::Table<Self::Value, Self::Tag, MAX>,
        Self::Context<'_>,
    );

    fn finish(self) -> Self::Output;

    fn build<'a>(index: links::Index, context: Self::Context<'a>) -> Self::Value
    where
        Self: 'a;

    /// Initializes the admitted slot without checking capacity again.
    fn insert(self) -> depot::raw::Proof<(Self::Output, links::Index), Initialized<Self::Plane>> {
        demand::Table::<Self::Value, Self::Tag, MAX>::insert(self)
    }
}
