use std::num;

use o3::base::num::bounded;

use crate::wire::{Mark, stream::Id};

/// Niche-preserving stored form of one proved QUIC stream identifier and flag.
#[doc(hidden)]
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Packed(num::NonZero<u64>);

impl Packed {
    const MARK: u64 = 1 << 63;

    #[doc(hidden)]
    pub const fn new(id: Id, mark: Mark) -> Self {
        let marker = match mark {
            Mark::Clear => 0,
            Mark::Set => Self::MARK,
        };
        let raw = id.get() | marker;
        Self(num::NonZero::<u64>::MIN.saturating_add(raw))
    }

    #[doc(hidden)]
    pub const fn id(self) -> Id {
        Id::from_bounded(bounded::U64::mask(self.0.get() - 1))
    }

    #[doc(hidden)]
    pub const fn mark(self) -> Mark {
        if (self.0.get() - 1) & Self::MARK == 0 {
            Mark::Clear
        } else {
            Mark::Set
        }
    }
}

const _: () = assert!(size_of::<Packed>() == size_of::<u64>());
