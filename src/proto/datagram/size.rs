use std::num;

/// Valid QUIC UDP payload capacity for one receive slot.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct Size(num::NonZero<u16>);

impl Size {
    pub(crate) const MIN: Self = Self(num::NonZero::<u16>::MIN.saturating_add(1199));

    pub(crate) const fn new(bytes: u32) -> Option<Self> {
        if bytes < Self::MIN.get() as u32 || bytes > u16::MAX as u32 {
            return None;
        }
        let Some(bytes) = num::NonZero::<u16>::new(bytes as u16) else {
            return None;
        };
        Some(Self(bytes))
    }

    pub(crate) const fn get(self) -> u16 {
        self.0.get()
    }
}

impl From<Size> for num::NonZero<u16> {
    fn from(size: Size) -> Self {
        size.0
    }
}

const _: () = assert!(std::mem::size_of::<Size>() == std::mem::size_of::<u16>());
const _: () = assert!(std::mem::size_of::<Option<Size>>() == std::mem::size_of::<Size>());
