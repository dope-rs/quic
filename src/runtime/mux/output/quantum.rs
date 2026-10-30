use std::{mem, num::NonZero};

use crate::conn;
use crate::runtime::mux;

#[repr(transparent)]
pub(in crate::runtime) struct Quantum(usize);

pub(in crate::runtime) struct Credit<'a> {
    quota: &'a mut Quantum,
    limit: NonZero<usize>,
}

pub(in crate::runtime) struct Reservation<'a> {
    quota: &'a mut Quantum,
    next: NonZero<usize>,
}

impl Quantum {
    pub(in crate::runtime) const fn new() -> Self {
        Self(0)
    }

    pub(in crate::runtime) fn credit(&mut self) -> Option<Credit<'_>> {
        let limit = if self.0 == 0 {
            conn::MAX_BATCH_PACKETS
        } else {
            mux::FLUSH_PACKET_QUANTUM.checked_sub(self.0)?
        };
        Some(Credit {
            limit: NonZero::new(limit)?,
            quota: self,
        })
    }

    pub(in crate::runtime) const fn is_exhausted(&self) -> bool {
        self.0 >= mux::FLUSH_PACKET_QUANTUM
    }

    pub(in crate::runtime) const fn packets(&self) -> usize {
        self.0
    }
}

impl<'a> Credit<'a> {
    pub(in crate::runtime) fn try_reserve(
        self,
        packets: NonZero<usize>,
    ) -> Option<Reservation<'a>> {
        if packets > self.limit {
            return None;
        }
        Some(self.reserve(packets))
    }

    pub(in crate::runtime) fn one(self) -> Reservation<'a> {
        self.reserve(NonZero::<usize>::MIN)
    }

    fn reserve(self, packets: NonZero<usize>) -> Reservation<'a> {
        Reservation {
            next: packets.saturating_add(self.quota.0),
            quota: self.quota,
        }
    }
}

impl<'a> Reservation<'a> {
    pub(in crate::runtime) fn commit(self) -> &'a Quantum {
        self.quota.0 = self.next.get();
        self.quota
    }
}

const _: () = {
    assert!(mem::size_of::<Quantum>() == mem::size_of::<usize>());
    assert!(mem::size_of::<Credit<'_>>() == 2 * mem::size_of::<usize>());
    assert!(mem::size_of::<Reservation<'_>>() == 2 * mem::size_of::<usize>());
    assert!(mem::size_of::<Option<Reservation<'_>>>() == mem::size_of::<Reservation<'_>>());
};
