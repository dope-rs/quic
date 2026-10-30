use std::ops;

use o3::buffer::bytes::scope;

use crate::wire::frame::Projection;

/// Authenticated frame bytes retained through ingress planning and commit.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Body<'wire, 'id>(scope::View<'wire, 'id>);

impl<'wire, 'id> Body<'wire, 'id> {
    pub(crate) fn with<R>(
        bytes: &'wire [u8],
        run: impl for<'scope> FnOnce(Body<'wire, 'scope>) -> R,
    ) -> R {
        scope::Owner::with(bytes, |owner| run(Body(owner.borrow())))
    }

    pub(crate) const fn as_ref(&self) -> &'wire [u8] {
        self.0.as_slice()
    }

    pub(crate) const fn len(&self) -> usize {
        self.0.as_slice().len()
    }

    #[inline]
    pub(crate) fn locate(&self, bytes: &[u8]) -> ops::Range<usize> {
        self.0
            .as_slice()
            .subslice_range(bytes)
            .map_or(usize::MAX..usize::MAX, Into::into)
    }

    pub(crate) fn resolve(&self, range: ops::Range<usize>) -> Result<&'wire [u8], Projection> {
        self.0.as_slice().get(range).ok_or(Projection)
    }

    pub(crate) fn get<P: scope::raw::Select<'id>>(&self, proof: P) -> &'wire [u8] {
        self.0.get(proof).0
    }

    pub(crate) fn part(
        &self,
        outer: &ops::Range<usize>,
        inner: ops::Range<usize>,
    ) -> Result<&'wire [u8], Projection> {
        self.resolve(outer.clone())?.get(inner).ok_or(Projection)
    }
}

const _: () = assert!(std::mem::size_of::<Body<'_, '_>>() == std::mem::size_of::<&[u8]>());
