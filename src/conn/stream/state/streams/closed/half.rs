use crate::wire::stream;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(super) struct Number(u64);

impl Number {
    fn from_id(id: stream::Id) -> Self {
        Self(id.number())
    }

    pub(super) const fn get(self) -> u64 {
        self.0
    }

    /// Returns the successor; both constructors retain a number shifted right by two bits.
    pub(super) const fn next(self) -> u64 {
        self.0 + 1
    }
}

#[derive(Clone, Copy)]
pub(super) enum Kind {
    LocalBidiRecv,
    PeerBidiRecv,
    PeerUniRecv,
    PeerBidiSend,
}

impl Kind {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::LocalBidiRecv => 0,
            Self::PeerBidiRecv => 1,
            Self::PeerUniRecv => 2,
            Self::PeerBidiSend => 3,
        }
    }

    const fn from_bits(low: bool, high: bool) -> Self {
        match (low, high) {
            (false, false) => Self::LocalBidiRecv,
            (true, false) => Self::PeerBidiRecv,
            (false, true) => Self::PeerUniRecv,
            (true, true) => Self::PeerBidiSend,
        }
    }
}

/// A stream half whose closed state must outlive its resident entry.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn) struct Half(u64);

impl Half {
    fn new(number: Number, kind: Kind) -> Self {
        Self(number.get() << 2 | u64::from(kind.code()))
    }

    pub(super) const fn number(self) -> Number {
        Number(self.0 >> 2)
    }

    pub(super) const fn kind(self) -> Kind {
        Kind::from_bits(self.0 & 0x1 != 0, self.0 & 0x2 != 0)
    }
}

impl Half {
    pub(in crate::conn) fn try_receive(id: stream::Id, local: stream::Initiator) -> Option<Self> {
        let local = id.initiator() == local;
        let dir = id.direction();
        let number = Number::from_id(id);
        match (local, dir) {
            (true, stream::Direction::Bidi) => Some(Self::new(number, Kind::LocalBidiRecv)),
            (false, stream::Direction::Bidi) => Some(Self::new(number, Kind::PeerBidiRecv)),
            (false, stream::Direction::Uni) => Some(Self::new(number, Kind::PeerUniRecv)),
            (true, stream::Direction::Uni) => None,
        }
    }

    pub(in crate::conn) fn try_send(id: stream::Id, local: stream::Initiator) -> Option<Self> {
        (id.initiator() != local && matches!(id.direction(), stream::Direction::Bidi))
            .then_some(Self::new(Number::from_id(id), Kind::PeerBidiSend))
    }

    pub(in crate::conn) fn peer_send(id: stream::Id) -> Self {
        Self::new(Number::from_id(id), Kind::PeerBidiSend)
    }
}

const _: () = assert!(std::mem::size_of::<Number>() == std::mem::size_of::<u64>());
const _: () = assert!(std::mem::size_of::<Half>() == std::mem::size_of::<u64>());
