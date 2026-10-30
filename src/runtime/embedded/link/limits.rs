use std::{mem, num};

use crate::runtime::embedded::plan;

#[derive(Clone, Copy)]
pub(in crate::runtime::embedded) struct Limits {
    pub(super) entries: num::NonZero<u32>,
    flight: num::NonZero<u32>,
}

impl Limits {
    pub(in crate::runtime::embedded) fn try_new(
        capacity: usize,
        flight: u32,
    ) -> Result<Self, plan::Error> {
        let Ok(entries) = u32::try_from(capacity) else {
            return Err(plan::Error::LinkCapacity {
                actual: capacity,
                maximum: u32::MAX as usize,
            });
        };
        let Some(entries) = num::NonZero::<u32>::new(entries) else {
            return Err(plan::Error::LinkCapacity {
                actual: capacity,
                maximum: u32::MAX as usize,
            });
        };
        let Some(flight) = num::NonZero::<u32>::new(flight) else {
            return Err(plan::Error::Flight { actual: flight });
        };
        if (entries.get() as usize)
            .checked_mul(flight.get() as usize)
            .is_none()
        {
            return Err(plan::Error::Retained {
                capacity,
                flight: flight.get(),
            });
        }
        Ok(Self { entries, flight })
    }

    pub(in crate::runtime::embedded) const fn capacity(self) -> num::NonZero<u32> {
        self.entries
    }

    pub(super) const fn flight(self) -> usize {
        self.flight.get() as usize
    }

    pub(super) const fn retained(self) -> usize {
        self.entries.get() as usize * self.flight()
    }
}

const _: () = assert!(mem::size_of::<Limits>() == mem::size_of::<u64>());
const _: () = assert!(!mem::needs_drop::<Limits>());
