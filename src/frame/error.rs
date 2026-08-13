use std::{error, fmt};

use crate::varint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decode {
    Underflow,
    BadVarInt,
    BadType,
    InvalidAckRange,
}

impl fmt::Display for Decode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Underflow => "truncated frame",
            Self::BadVarInt => "invalid frame integer",
            Self::BadType => "invalid frame type",
            Self::InvalidAckRange => "invalid ACK range",
        })
    }
}

impl error::Error for Decode {}

impl From<varint::Error> for Decode {
    fn from(_: varint::Error) -> Self {
        Self::BadVarInt
    }
}
