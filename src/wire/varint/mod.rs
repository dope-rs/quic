use std::num::NonZero;

use o3::{
    base::num::bounded,
    buffer::{storage::inline, write},
};

use crate::wire::packet::header;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge { value: u64 },
    Underflow { actual: usize, required: usize },
}

/// A truncated wire integer; both lengths are bounded by its eight-byte width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Underflow {
    actual: u8,
    required: NonZero<u8>,
}

impl From<Underflow> for Error {
    fn from(error: Underflow) -> Self {
        Self::Underflow {
            actual: usize::from(error.actual),
            required: usize::from(error.required.get()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overflow {
    pub value: NonZero<usize>,
}

/// A QUIC variable-length integer with its minimal wire width cached in-band.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

/// Retains the cached wire representation with a niche for an absent value.
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Stored(NonZero<u64>);

impl From<VarInt> for Stored {
    fn from(value: VarInt) -> Self {
        // SAFETY: minimal-width tagging never encodes zero with the two-byte tag.
        // Flipping that tag bit therefore maps every admitted integer to nonzero.
        Self(unsafe { NonZero::new_unchecked(value.0 ^ (1 << VarInt::TAG_SHIFT)) })
    }
}

impl Stored {
    pub(crate) const fn get(self) -> VarInt {
        VarInt(self.0.get() ^ (1 << VarInt::TAG_SHIFT))
    }
}

const _: () = assert!(size_of::<Option<Stored>>() == size_of::<VarInt>());

/// An ordered interval whose endpoints remain valid wire integers.
#[derive(Clone, Copy)]
pub(crate) struct Span {
    start: VarInt,
    end: VarInt,
}

impl Span {
    pub(crate) const ZERO: Self = Self::empty(VarInt::ZERO);

    pub(crate) const fn empty(at: VarInt) -> Self {
        Self { start: at, end: at }
    }

    pub(crate) const fn from_zero(end: VarInt) -> Self {
        Self {
            start: VarInt::ZERO,
            end,
        }
    }

    pub(crate) const fn start(self) -> VarInt {
        self.start
    }

    pub(crate) const fn end(self) -> VarInt {
        self.end
    }

    pub(crate) const fn len(self) -> u64 {
        self.end.get() - self.start.get()
    }

    /// Admits an extension once, retaining both ordered endpoints.
    pub(crate) const fn try_extend(self, added: u64) -> Option<Self> {
        if added > VarInt::MAX - self.end.get() {
            return None;
        }
        let value = self.end.get() + added;
        Some(Self {
            start: self.start,
            end: VarInt(value | VarInt::tag(value)),
        })
    }

    /// Splits at most `limit` bytes from this exact interval.
    pub(crate) fn split_prefix(self, limit: u64) -> (Self, Self) {
        let value = self.start.get() + limit.min(self.len());
        let middle = VarInt(value | VarInt::tag(value));
        (
            Self {
                start: self.start,
                end: middle,
            },
            Self {
                start: middle,
                end: self.end,
            },
        )
    }
}

pub(crate) struct Decoded<'wire> {
    value: VarInt,
    rest: &'wire [u8],
}

impl<'wire> Decoded<'wire> {
    pub(crate) fn parse(input: &'wire [u8]) -> Result<Self, Underflow> {
        let first = *input.first().ok_or(Underflow {
            actual: 0,
            required: NonZero::<u8>::MIN,
        })?;
        match first >> 6 {
            0 => Self::read::<1>(input),
            1 => Self::read::<2>(input),
            2 => Self::read::<4>(input),
            _ => Self::read::<8>(input),
        }
    }

    fn read<const N: usize>(input: &'wire [u8]) -> Result<Self, Underflow> {
        let Some((bytes, rest)) = input.split_first_chunk::<N>() else {
            return Err(Underflow {
                actual: input.len() as u8,
                required: NonZero::<u8>::MIN.saturating_add((N - 1) as u8),
            });
        };
        Ok(Self::from_parts(bytes, rest))
    }

    fn from_parts<const N: usize>(bytes: &[u8; N], rest: &'wire [u8]) -> Self {
        const { assert!(N == 1 || N == 2 || N == 4 || N == 8) };
        let mut buf = [0u8; 8];
        buf[8 - N..].copy_from_slice(bytes);
        let mut value = u64::from_be_bytes(buf);
        value &= (1u64 << (N * 8 - 2)) - 1;
        Self {
            value: VarInt(value | VarInt::tag(value)),
            rest,
        }
    }

    pub(crate) const fn value(&self) -> VarInt {
        self.value
    }

    pub(crate) const fn rest(&self) -> &'wire [u8] {
        self.rest
    }
}

pub(in crate::wire) mod raw;

impl VarInt {
    pub const MAX: u64 = (1u64 << 62) - 1;
    pub const MAX_VALUE: Self = Self(Self::MAX | Self::tag(Self::MAX));
    pub const ZERO: Self = Self(0);

    const TAG_SHIFT: u32 = 62;
    const VALUE_MASK: u64 = Self::MAX;

    pub const fn new(value: u64) -> Option<Self> {
        match bounded::U64::<0, { Self::MAX }>::new(value) {
            Some(value) => Some(Self(value.get() | Self::tag(value.get()))),
            None => None,
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        let value = value as u64;
        let tag = if value <= 63 { 0 } else { 1 };
        Self(value | (tag << Self::TAG_SHIFT))
    }

    pub const fn from_u16(value: u16) -> Self {
        let value = value as u64;
        Self(value | Self::tag(value))
    }

    pub(crate) const fn from_bounded(value: bounded::U64<0, { Self::MAX }>) -> Self {
        Self(value.get() | Self::tag(value.get()))
    }

    pub(crate) const fn flip(self) -> Self {
        Self(self.0 ^ 1)
    }

    pub(crate) const fn saturate(value: u128) -> Self {
        if value > Self::MAX as u128 {
            Self::MAX_VALUE
        } else {
            let value = value as u64;
            Self(value | Self::tag(value))
        }
    }

    pub const fn from_usize(value: usize) -> Option<Self> {
        match bounded::U64::<0, { Self::MAX }>::from_usize(value) {
            Some(value) => Some(Self(value.get() | Self::tag(value.get()))),
            None => None,
        }
    }

    const fn tag(value: u64) -> u64 {
        let tag = if value <= 63 {
            0
        } else if value <= 16_383 {
            1
        } else if value <= 1_073_741_823 {
            2
        } else {
            3
        };
        tag << Self::TAG_SHIFT
    }

    pub const fn get(self) -> u64 {
        self.0 & Self::VALUE_MASK
    }

    pub const fn encoded_len(self) -> u8 {
        1 << (self.0 >> Self::TAG_SHIFT)
    }

    pub(crate) const fn width(value: usize) -> usize {
        if value < 1 << 6 {
            1
        } else if value < 1 << 14 {
            2
        } else if value < 1 << 30 {
            4
        } else {
            8
        }
    }

    pub fn pack(self) -> inline::Bytes<8> {
        pack_minimum(self, bounded::NonZeroU32::exact::<1>())
    }

    pub fn encode<W: write::Sink>(self, out: &mut W) -> Result<(), W::Error> {
        out.write_slice(self.pack().as_ref())
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        let decoded = Decoded::parse(input)?;
        Ok((decoded.value, input.len() - decoded.rest.len()))
    }

    pub(crate) fn skip(input: &[u8]) -> Result<&[u8], Error> {
        Ok(Self::split(input)?.1)
    }

    fn split(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
        let first = *input.first().ok_or(Error::Underflow {
            actual: 0,
            required: 1,
        })?;
        let len = 1usize << (first >> 6);
        input.split_at_checked(len).ok_or(Error::Underflow {
            actual: input.len(),
            required: len,
        })
    }
}

pub(crate) fn pack_minimum(number: VarInt, minimum: bounded::NonZeroU32<1, 2>) -> inline::Bytes<8> {
    let value = number.get();
    match (number.0 >> VarInt::TAG_SHIFT).max(u64::from(minimum.get() - 1)) {
        0 => inline::Bytes::from([value as u8]),
        1 => inline::Bytes::from(((value as u16) | 0x4000).to_be_bytes()),
        2 => inline::Bytes::from(((value as u32) | 0x8000_0000).to_be_bytes()),
        _ => inline::Bytes::from((value | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

impl From<header::Number> for VarInt {
    fn from(value: header::Number) -> Self {
        Self(value.get() | Self::tag(value.get()))
    }
}

impl From<bounded::U64<0, { 1 << 60 }>> for VarInt {
    fn from(value: bounded::U64<0, { 1 << 60 }>) -> Self {
        Self(value.get() | Self::tag(value.get()))
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
        Self::new(value).ok_or(Error::TooLarge { value })
    }
}

impl TryFrom<usize> for VarInt {
    type Error = Overflow;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let Some(value) = NonZero::new(value) else {
            return Ok(Self::ZERO);
        };
        Self::try_from(value)
    }
}

impl TryFrom<NonZero<usize>> for VarInt {
    type Error = Overflow;

    fn try_from(value: NonZero<usize>) -> Result<Self, Self::Error> {
        match bounded::U64::<0, { Self::MAX }>::from_usize(value.get()) {
            Some(value) => Ok(Self::from_bounded(value)),
            None => Err(Overflow { value }),
        }
    }
}
