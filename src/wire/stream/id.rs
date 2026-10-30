use o3::base::num::bounded;

use crate::wire::{stream, varint};

/// A QUIC stream identifier with its variable-integer width cached in-band.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(varint::VarInt);

impl Id {
    pub const ZERO: Self = Self(varint::VarInt::ZERO);
    pub const MAX: u64 = varint::VarInt::MAX;

    pub const fn new(value: u64) -> Option<Self> {
        match varint::VarInt::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(crate) const fn from_varint(value: varint::VarInt) -> Self {
        Self(value)
    }

    pub(crate) const fn from_u8(value: u8) -> Self {
        Self(varint::VarInt::from_u8(value))
    }

    pub(crate) const fn from_bounded(value: bounded::U64<0, { Self::MAX }>) -> Self {
        Self(varint::VarInt::from_bounded(value))
    }

    pub(crate) const fn relative(self, local: stream::Initiator) -> Self {
        match local {
            stream::Initiator::Client => self,
            stream::Initiator::Server => Self(self.0.flip()),
        }
    }

    pub(crate) const fn varint(self) -> varint::VarInt {
        self.0
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn number(self) -> u64 {
        self.get() >> 2
    }

    pub const fn kind(self) -> stream::Kind {
        stream::Kind::from_bits(self.get() as u8)
    }

    pub const fn direction(self) -> stream::Direction {
        self.kind().direction()
    }

    pub const fn initiator(self) -> stream::Initiator {
        self.kind().initiator()
    }
}

impl From<Id> for u64 {
    fn from(value: Id) -> Self {
        value.get()
    }
}

impl TryFrom<u64> for Id {
    type Error = varint::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(varint::VarInt::try_from(value)?))
    }
}

const _: () = assert!(size_of::<Id>() == size_of::<u64>());
