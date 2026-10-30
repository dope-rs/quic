use o3::buffer;
use std::ops;

use crate::wire::packet::{cid, header};

pub struct Opened<P> {
    pub(super) packet: P,
    pub(super) packet_number: header::Number,
    pub(super) body: ops::Range<usize>,
    pub(super) reserved_bits: u8,
    pub(super) cid: cid::Len,
}

impl<P: buffer::raw::Source> Opened<P> {
    pub(crate) const fn number(&self) -> header::Number {
        self.packet_number
    }

    pub fn body(&self) -> &[u8] {
        // SAFETY: authentication admits this range in the original stable
        // source. This owner exposes no operation that changes its extent.
        unsafe { self.packet.as_ref().get_unchecked(self.body.clone()) }
    }

    pub(crate) const fn cid_len(&self) -> cid::Len {
        self.cid
    }

    pub fn into_parts(self) -> (header::Number, P, ops::Range<usize>) {
        (self.packet_number, self.packet, self.body)
    }

    pub(crate) const fn is_valid(&self) -> bool {
        self.reserved_bits == 0
    }
}
