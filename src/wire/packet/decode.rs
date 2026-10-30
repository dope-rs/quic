use o3::buffer::write::consume;

use crate::wire::varint;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    Underflow {
        actual: usize,
        required: usize,
    },
    Form {
        first: u8,
    },
    Version {
        actual: u32,
    },
    Cid(consume::Error),
    Packet(consume::Error),
    VarInt {
        offset: usize,
        error: varint::Error,
    },
    Type {
        first: u8,
    },
    Fixed {
        first: u8,
    },
    Size {
        actual: usize,
        minimum: usize,
    },
    Trailing {
        packet: NonZero<usize>,
        datagram: usize,
    },
}
use std::num::NonZero;
