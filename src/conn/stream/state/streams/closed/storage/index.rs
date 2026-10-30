use std::{marker, num::NonZero};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(in crate::conn::stream::state::streams::closed) struct RawIndex(Option<NonZero<u32>>);

impl RawIndex {
    pub(in crate::conn::stream::state::streams::closed) const NONE: Self = Self(None);

    pub(in crate::conn::stream::state::streams::closed) const fn is_none(self) -> bool {
        self.0.is_none()
    }

    pub(in crate::conn::stream::state::streams::closed) fn brand<'owner, L>(
        self,
    ) -> Index<'owner, L> {
        Index(self, marker::PhantomData)
    }

    pub(super) const fn get(self) -> Option<NonZero<u32>> {
        self.0
    }

    pub(super) const fn new(index: Option<NonZero<u32>>) -> Self {
        Self(index)
    }
}

#[repr(transparent)]
pub(in crate::conn::stream::state::streams::closed) struct Index<'owner, L>(
    RawIndex,
    marker::PhantomData<fn(&'owner mut L) -> &'owner mut L>,
);

impl<L> Index<'_, L> {
    pub(in crate::conn::stream::state::streams::closed) const NONE: Self =
        Self(RawIndex::NONE, marker::PhantomData);

    pub(in crate::conn::stream::state::streams::closed) const fn raw(self) -> RawIndex {
        self.0
    }
}

impl<L> Clone for Index<'_, L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<L> Copy for Index<'_, L> {}

const _: () = {
    assert!(std::mem::size_of::<RawIndex>() == std::mem::size_of::<u32>());
    assert!(std::mem::size_of::<Index<'static, ()>>() == std::mem::size_of::<u32>());
};
