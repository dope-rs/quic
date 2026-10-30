use std::mem;

use o3::alloc::{self, BoxArrayExt};
use o3::base::marker::ThreadBound;

use crate::conn::stream::state::receive::recv::map::scope::bound::Bound;
use crate::{conn, stream};

pub(in crate::conn::stream::state::receive::recv::map::scope) const WORDS: usize = {
    let owned = mem::size_of::<Bound<'_, '_, '_, Vec<u8>>>();
    let adaptive = mem::size_of::<Bound<'_, '_, '_, stream::RecvBuffer<'_, true>>>();
    let retained = mem::size_of::<Bound<'_, '_, '_, stream::RecvBuffer<'_, false>>>();
    let bytes = if owned > adaptive { owned } else { adaptive };
    let bytes = if bytes > retained { bytes } else { retained };
    bytes.div_ceil(mem::size_of::<usize>())
};

/// Uninitialized memory reused by one serialized receive workspace.
pub(in crate::conn) struct Storage {
    block: Box<[mem::MaybeUninit<[usize; WORDS]>; conn::MAX_FRAMES_PER_PACKET]>,
    _bound: ThreadBound,
}

const _: () = {
    assert!(mem::size_of::<Storage>() == mem::size_of::<usize>());
    assert!(
        mem::size_of::<[usize; WORDS]>()
            == mem::size_of::<Bound<'_, '_, '_, stream::RecvBuffer<'_>>>()
    );
};

impl Storage {
    pub(in crate::conn) fn try_new() -> Result<Self, alloc::Exhausted> {
        const {
            assert!(conn::MAX_FRAMES_PER_PACKET != 0);
        }
        Ok(Self {
            block: Box::try_uninit()?,
            _bound: ThreadBound::NEW,
        })
    }
}

impl Storage {
    pub(super) fn entries(
        &mut self,
    ) -> &mut [mem::MaybeUninit<[usize; WORDS]>; conn::MAX_FRAMES_PER_PACKET] {
        &mut self.block
    }
}
