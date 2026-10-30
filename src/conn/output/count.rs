use std::mem;

use o3::depot::array;

use crate::conn;

/// Number of control or stream carriers in one packet plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Count(u8);

impl Count {
    pub(in crate::conn::output) const fn new<const N: usize>(len: array::Len<N>) -> Self {
        const {
            assert!(conn::PACKET_CONTROL_CAPACITY == conn::PACKET_STREAM_CAPACITY);
            assert!(N == conn::PACKET_CONTROL_CAPACITY);
            assert!(N < 1usize << u8::BITS);
        }
        Self(len.get() as u8)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

const _: () = assert!(mem::size_of::<Count>() == 1);
