use std::ops;

/// One physical receive extent issued with its bounded range part.
#[doc(hidden)]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Extent {
    from: u32,
    to: u32,
}

impl Extent {
    pub(crate) const fn new(from: u32, to: u32) -> Self {
        Self { from, to }
    }

    pub(crate) const fn range(self) -> ops::Range<usize> {
        self.from as usize..self.to as usize
    }
}

const _: () = {
    assert!(usize::BITS >= u32::BITS);
    assert!(size_of::<Extent>() == size_of::<u64>());
};
