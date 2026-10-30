use o3::{base::num::bounded, buffer};

use crate::stream::outbound;
use o3::depot::capacity::Extent as _;

use crate::conn::life::options;
use crate::conn::stream::event::queue;
use crate::stream::send;
use std::{mem, num};

pub(super) enum Denied {
    Blocked,
    TooLarge,
}

struct Limit {
    wire: num::NonZero<usize>,
    resident: num::NonZero<usize>,
    parts: options::Parts,
}

/// Connection-wide ownership accounting and edge-triggered retry wakeup.
pub(super) struct Budget {
    used: outbound::Charge,
    limit: Limit,
    wake: bounded::U32<0, 1>,
}

impl Budget {
    pub(super) const fn new(
        wire: num::NonZero<usize>,
        resident: num::NonZero<usize>,
        parts: options::Parts,
    ) -> Self {
        Self {
            used: outbound::Charge {
                wire_bytes: 0,
                resident_bytes: 0,
                segments: 0,
            },
            limit: Limit {
                wire,
                resident,
                parts,
            },
            wake: bounded::U32::exact::<0>(),
        }
    }

    fn fits_limit(&self, charge: outbound::Charge) -> bool {
        charge.wire_bytes <= self.limit.wire.get()
            && charge.resident_bytes <= self.limit.resident.get()
            && charge.segments <= self.limit.parts.get()
    }

    pub(super) fn admit(&mut self, charge: outbound::Charge) -> Result<(), Denied> {
        if !self.fits_limit(charge) {
            return Err(Denied::TooLarge);
        }
        if charge.wire_bytes > self.limit.wire.get() - self.used.wire_bytes
            || charge.resident_bytes > self.limit.resident.get() - self.used.resident_bytes
            || charge.segments > self.limit.parts.get() - self.used.segments
        {
            self.wake = bounded::U32::exact::<1>();
            return Err(Denied::Blocked);
        }
        Ok(())
    }

    /// The queue retains this exact budget unchanged between admission and publication.
    pub(super) fn commit(&mut self, charge: outbound::Charge, buffers: &mut outbound::BufferCache) {
        self.used.wire_bytes += charge.wire_bytes;
        self.used.resident_bytes += charge.resident_bytes;
        self.used.segments += charge.segments;
        self.trim(buffers);
    }

    /// Includes cache residency kept below the configured limit by every mutation.
    pub(super) fn used(&self, buffers: &outbound::BufferCache) -> outbound::Charge {
        let resident = self.used.resident_bytes + buffers.resident();
        outbound::Charge {
            wire_bytes: self.used.wire_bytes,
            resident_bytes: resident,
            segments: self.used.segments,
        }
    }

    pub(super) const fn resident(&self) -> usize {
        self.used.resident_bytes
    }

    /// Returns an uncommitted internal copy to the evictable cache. The same
    /// resident ceiling applies even when an allocator rounds capacity up.
    pub(super) fn recycle<D: buffer::raw::Segment>(
        &mut self,
        buffers: &mut outbound::BufferCache,
        parts: send::Parts<D>,
    ) {
        parts.recycle_into(buffers);
        self.trim(buffers);
    }

    /// The returned prefix retains the same queue whose admission charged these bytes.
    pub(super) fn release(&mut self, released: outbound::Charge, events: &mut queue::Pending) {
        self.used.wire_bytes -= released.wire_bytes;
        self.used.resident_bytes -= released.resident_bytes;
        self.used.segments -= released.segments;
        if self.wake.get() != 0 && released != outbound::Charge::default() {
            self.wake = bounded::U32::exact::<0>();
            events.set_writable();
        }
    }

    /// Every balance is admitted below this limit; release only decreases it.
    fn trim(&mut self, buffers: &mut outbound::BufferCache) {
        buffers.trim_to(self.limit.resident.get() - self.used.resident_bytes);
    }
}

const _: () = assert!(mem::size_of::<Budget>() == 7 * mem::size_of::<usize>());
