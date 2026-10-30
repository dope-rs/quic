use o3::{buffer::write::consume, depot::array::sorted};

use crate::wire::varint;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    VarInt(varint::Error),
    Cid {
        id: u64,
        cause: consume::Error,
    },
    /// The preferred-address connection-ID length must be in 1..=20.
    PreferredCidLength {
        actual: u8,
    },
    Underflow {
        offset: usize,
        required: usize,
        remaining: usize,
    },
    Id(sorted::Error<u64>),
    Length {
        id: u64,
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    OutOfRange {
        id: u64,
        value: u64,
        minimum: u64,
        maximum: u64,
    },
}

impl From<varint::Error> for Error {
    fn from(error: varint::Error) -> Self {
        Self::VarInt(error)
    }
}
