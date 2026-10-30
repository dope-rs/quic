use crate::conn::wire::crypto::tx;

/// # Safety
/// Selection belongs to the retained Tx. All mutable context is disjoint from
/// Tx; neither shared access nor context may invalidate the selected entries.
pub(in crate::conn) unsafe trait Owner {
    type Input;
    type Output;
    type Context<'a>
    where
        Self: 'a;

    fn tx(&self) -> &tx::Tx;

    fn select(input: Self::Input) -> (Self, Option<tx::Commit>)
    where
        Self: Sized;

    fn reject(self, selected: tx::Commit) -> Self::Input;

    fn parts(&mut self) -> (&mut tx::Tx, Self::Context<'_>);

    fn finish(self) -> Self::Output;
}
