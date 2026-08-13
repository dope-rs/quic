use super::records::Records;
use super::{NONE, Pending, lane};
use crate::conn::delivery::{Control, Handle};

/// A zero-allocation selection view tied to the pending-control owner.
pub(in crate::conn) struct Cursor<'a, const MASK: u16> {
    pending: &'a Pending,
    remaining: u16,
    current: u32,
}

impl<'a, const MASK: u16> Cursor<'a, MASK> {
    pub(super) fn new(pending: &'a Pending) -> Self {
        Self {
            pending,
            remaining: pending.ready_bits & MASK,
            current: NONE,
        }
    }
}

impl<const MASK: u16> Iterator for Cursor<'_, MASK> {
    type Item = (Handle<Control>, Control);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current != NONE {
                let entry = self.pending.slots[self.current as usize]
                    .entry
                    .as_ref()
                    .unwrap();
                let handle = self.pending.handle(self.current as usize).unwrap();
                self.current = entry.ready.prev;
                return Some((handle, entry.record));
            }
            if self.remaining == 0 {
                return None;
            }
            let bit = 1 << self.remaining.trailing_zeros();
            self.remaining &= !bit;
            self.current = self.pending.ready[lane(bit)].tail;
        }
    }
}
