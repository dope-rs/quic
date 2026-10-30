use o3::buffer;
use std::mem;

use crate::conn;
use crate::stream;

/// Live slot backing retained by the three delivery journals.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Backing {
    /// Sent-packet and carrier slots.
    pub packet_bytes: usize,
    /// Retransmittable control slots.
    pub control_bytes: usize,
    /// Retransmittable stream slots.
    pub stream_bytes: usize,
}

impl Backing {
    pub(super) fn new<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
        conn: &conn::Machine<DOMAIN, B, D>,
    ) -> Self {
        Self {
            packet_bytes: conn.egress.recovery.packet_journals.resident(),
            control_bytes: conn.control.ready().bytes(),
            stream_bytes: conn.streams.transmit.deliveries().resident(),
        }
    }

    #[must_use]
    pub const fn total(self) -> usize {
        self.packet_bytes
            .saturating_add(self.control_bytes)
            .saturating_add(self.stream_bytes)
    }
}

const _: () = {
    assert!(mem::size_of::<Backing>() == mem::size_of::<[usize; 3]>());
    assert!(mem::align_of::<Backing>() == mem::align_of::<usize>());
    assert!(!mem::needs_drop::<Backing>());
};
