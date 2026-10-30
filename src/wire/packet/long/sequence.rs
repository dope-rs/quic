use std::mem;

use dope::manifold::network::datagram::packet;
use o3::buffer::storage::provided;
use o3::buffer::write::consume;

use crate::wire::packet::{decode, long};

/// Takes one checked packet while the original owner retains the remaining bytes.
pub(crate) trait Sequence {
    type First: long::Buffer;

    fn first(self) -> Result<long::Parsed<Self::First>, decode::Error>;
}

impl<'a, 'turn, 'd, T: provided::Mutable<'d>> Sequence for &'a mut packet::Packet<'turn, 'd, T> {
    type First = packet::Head<'a, 'turn, 'd, T::Prefix<'a>>;

    fn first(self) -> Result<long::Parsed<Self::First>, decode::Error> {
        let read = long::Read::first(self.as_ref())?;
        let packet = self.try_take(read.len).map_err(decode::Error::Packet)?;
        Ok(read.bind(packet))
    }
}

impl<'a> Sequence for &'a mut &mut [u8] {
    type First = &'a mut [u8];

    fn first(self) -> Result<long::Parsed<Self::First>, decode::Error> {
        let read = long::Read::first(self)?;
        consume::Error::check(read.len.get(), self.len()).map_err(decode::Error::Packet)?;
        let (head, tail) = mem::take(self).split_at_mut(read.len.get());
        *self = tail;
        Ok(read.bind(head))
    }
}
