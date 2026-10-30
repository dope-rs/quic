use crate::{security::crypto, wire::packet::header};

pub(crate) struct Failure<P> {
    pub(crate) packet: P,
    pub(crate) error: crypto::Error,
}

/// The adjacent header and body borrowed from one admitted packet.
pub(crate) struct Plain<'packet> {
    pub(super) head: &'packet [u8],
    pub(super) body: &'packet mut [u8],
    pub(super) packet_number: header::Number,
    pub(super) first: u8,
}
