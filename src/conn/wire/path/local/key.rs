use std::num;

use crate::conn;
use crate::conn::wire::path::local::routes;
use o3::depot::array;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct LocalCidKey(pub(super) num::NonZero<u64>);

impl LocalCidKey {
    pub(crate) const INITIAL: Self = Self(num::NonZero::<u64>::MIN);

    pub(in crate::conn) fn new(slot: usize, epoch: u32) -> Option<Self> {
        if slot >= conn::MAX_ACTIVE_CONNECTION_IDS {
            return None;
        }
        let slot = u32::try_from(slot).ok()?.checked_add(1)?;
        num::NonZero::<u64>::new((u64::from(epoch) << 32) | u64::from(slot)).map(Self)
    }

    pub(crate) const fn slot(self) -> usize {
        ((self.0.get() as u32) - 1) as usize
    }

    pub(crate) fn slot_index(self) -> array::Index<{ conn::MAX_ACTIVE_CONNECTION_IDS }> {
        array::Index::from_bit(routes::Index::from_key(self))
    }

    pub(in crate::conn) const fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }
}

/// Local CID generation distinct from the TLS-bound initial identity.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct RouteKey(pub(super) LocalCidKey);

impl RouteKey {
    pub(crate) const fn local(self) -> LocalCidKey {
        self.0
    }
}
