use std::{mem, num::NonZero};

use crate::conn;

/// One exact bounded allocation at the journal growth floor.
#[repr(transparent)]
pub(in crate::conn) struct Plan {
    target: NonZero<u32>,
}

impl Plan {
    pub(in crate::conn) const fn geometric(
        current: usize,
        required: usize,
        limit: usize,
    ) -> Option<Self> {
        if current >= required || required > limit || limit > u32::MAX as usize {
            return None;
        }
        let growth = match required.checked_next_power_of_two() {
            Some(target) => target,
            None => limit,
        };
        let target = if growth < conn::MAX_BATCH_PACKETS {
            conn::MAX_BATCH_PACKETS
        } else {
            growth
        };
        let target = if target > limit { limit } else { target };
        if target < required {
            return None;
        }
        Some(Self {
            target: NonZero::<u32>::MIN.saturating_add(target as u32 - 1),
        })
    }

    pub(in crate::conn) const fn capacity(self) -> NonZero<u32> {
        self.target
    }
}

const _: () = {
    assert!(mem::size_of::<Plan>() == mem::size_of::<u32>());
    assert!(mem::size_of::<Option<Plan>>() == mem::size_of::<u32>());
};
