use o3::buffer::pool::borrowed;

use crate::proto::datagram::{self, batch};

#[must_use = "a writable batch owns every packet until encoding is complete"]
pub struct Writable<'pool, const N: usize, const SUFFIX: usize = 0> {
    packets: [borrowed::Frame<'pool>; N],
}

impl<'pool, const N: usize, const SUFFIX: usize> Writable<'pool, N, SUFFIX> {
    pub(super) const fn new(packets: [borrowed::Frame<'pool>; N]) -> Self {
        Self { packets }
    }

    pub fn prefixes_mut(&mut self) -> [&mut [u8]; N] {
        self.packets.each_mut().map(borrowed::Frame::prefix_mut)
    }

    pub fn suffixes_mut(&mut self) -> [&mut [u8; SUFFIX]; N] {
        self.packets.each_mut().map(|packet| {
            // SAFETY: Source retains the exact SUFFIX partition through acquisition;
            // each private Frame keeps that length and this exclusive borrow, including zero.
            unsafe { &mut *packet.payload_mut().as_mut_ptr().cast::<[u8; SUFFIX]>() }
        })
    }

    pub fn finish(self) -> batch::Pending<'pool, N> {
        let packets = self.packets.map(|packet| datagram::Packet {
            lease: packet.join(),
        });
        batch::Pending::new(packets)
    }
}
