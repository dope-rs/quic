use o3::num::BoundedU64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Underflow,
}

impl_error!(Error {
    Self::TooLarge => "integer exceeds the QUIC variable-length range",
    Self::Underflow => "truncated QUIC variable-length integer",
});

type Value = BoundedU64<0, { (1u64 << 62) - 1 }>;

/// A QUIC variable-length integer with its minimal wire width cached in-band.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

impl std::fmt::Debug for VarInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VarInt").field(&self.get()).finish()
    }
}

impl VarInt {
    pub const MAX: u64 = (1u64 << 62) - 1;
    pub const ZERO: Self = Self(0);

    const TAG_SHIFT: u32 = 62;
    const VALUE_MASK: u64 = Self::MAX;

    pub const fn new(value: u64) -> Option<Self> {
        match Value::new(value) {
            Some(value) => Some(Self::from_proven_raw(value.get())),
            None => None,
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        Self::from_proven_raw(value as u64)
    }

    pub const fn from_usize(value: usize) -> Option<Self> {
        match Value::from_usize(value) {
            Some(value) => Some(Self::from_proven_raw(value.get())),
            None => None,
        }
    }

    const fn from_proven_raw(value: u64) -> Self {
        let tag = if value <= 63 {
            0
        } else if value <= 16_383 {
            1
        } else if value <= 1_073_741_823 {
            2
        } else {
            3
        };
        Self(value | (tag << Self::TAG_SHIFT))
    }

    pub const fn get(self) -> u64 {
        self.0 & Self::VALUE_MASK
    }

    pub const fn encoded_len(self) -> usize {
        1 << (self.0 >> Self::TAG_SHIFT)
    }

    pub fn encode(self, out: &mut impl Extend<u8>) {
        let value = self.get();
        match self.0 >> Self::TAG_SHIFT {
            0 => out.extend([value as u8]),
            1 => {
                let wire = (value as u16) | 0x4000;
                out.extend(wire.to_be_bytes());
            }
            2 => {
                let wire = (value as u32) | 0x8000_0000;
                out.extend(wire.to_be_bytes());
            }
            _ => {
                let wire = value | 0xC000_0000_0000_0000;
                out.extend(wire.to_be_bytes());
            }
        }
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        let first = *input.first().ok_or(Error::Underflow)?;
        let len = 1usize << (first >> 6);
        if input.len() < len {
            return Err(Error::Underflow);
        }
        let mut buf = [0u8; 8];
        buf[8 - len..].copy_from_slice(&input[..len]);
        let mut value = u64::from_be_bytes(buf);
        value &= (1u64 << (len * 8 - 2)) - 1;
        let value = Value::new(value).ok_or(Error::TooLarge)?;
        Ok((Self::from_proven_raw(value.get()), len))
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.get()
    }
}

impl TryFrom<u64> for VarInt {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(Error::TooLarge)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::from_usize(value).ok_or(Error::TooLarge)
    }
}
