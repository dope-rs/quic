/// Exact number of additional ACK ranges selected for one frame.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Count(u16);

impl Count {
    pub(crate) const ZERO: Self = Self(0);

    pub(super) const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    pub(crate) const fn advance(self) -> Self {
        Self(self.0 + 1)
    }

    pub(crate) const fn into_u16(self) -> u16 {
        self.0
    }

    pub(crate) const fn len(self) -> usize {
        self.0 as usize
    }
}

const _: () = assert!(size_of::<Count>() == size_of::<u16>());
const _: () = assert!(!std::mem::needs_drop::<Count>());
