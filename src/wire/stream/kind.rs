use crate::wire::stream::{Direction, Initiator};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    ClientBidi,
    ServerBidi,
    ClientUni,
    ServerUni,
}

impl Kind {
    pub(crate) const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::ClientBidi,
            1 => Self::ServerBidi,
            2 => Self::ClientUni,
            3 => Self::ServerUni,
            _ => Self::ServerUni,
        }
    }

    pub const fn direction(self) -> Direction {
        match self {
            Self::ClientBidi | Self::ServerBidi => Direction::Bidi,
            Self::ClientUni | Self::ServerUni => Direction::Uni,
        }
    }

    pub const fn initiator(self) -> Initiator {
        match self {
            Self::ClientBidi | Self::ClientUni => Initiator::Client,
            Self::ServerBidi | Self::ServerUni => Initiator::Server,
        }
    }
}
