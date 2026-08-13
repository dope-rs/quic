use crate::varint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decode {
    Underflow,
    BadVarInt,
    BadType,
    InvalidAckRange,
}

impl_error!(Decode {
    Self::Underflow => "truncated frame",
    Self::BadVarInt => "invalid frame integer",
    Self::BadType => "invalid frame type",
    Self::InvalidAckRange => "invalid ACK range",
});

impl From<varint::Error> for Decode {
    fn from(_: varint::Error) -> Self {
        Self::BadVarInt
    }
}
