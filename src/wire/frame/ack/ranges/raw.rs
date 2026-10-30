use std::ops;

use o3::buffer::bytes::scope;

use crate::wire::frame::ack::ranges::Proof;

// SAFETY: record admitted these private offsets in this exact immutable Body.
// Its invariant identity retains the original source and extent; borrowing the
// proof cannot change the admitted bounds or the validated ACK topology.
unsafe impl<'id> scope::raw::Select<'id> for &Proof<'id> {
    fn bounds(self) -> ops::Range<usize> {
        let start = usize::from(self.start);
        start..start + usize::from(self.len)
    }
}
