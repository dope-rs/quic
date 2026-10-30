use std::{marker, mem};

mod body;
mod prefix;
pub(crate) mod widths;

pub(crate) use body::Body;
pub(crate) use prefix::Prefix;

/// A packet number proven to fit QUIC's nonce domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Number(u64);

impl Number {
    pub(crate) const ZERO: Self = Self(0);

    pub(crate) const fn new(value: u64) -> Option<Self> {
        if value <= widths::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    pub(crate) const fn decode(next: u64, short: u64, width: widths::Width) -> Option<Self> {
        let window = 1u64 << (width.get() * 8);
        let half = window / 2;
        let mask = window - 1;
        let value = (next & !mask) | short;
        let value = if value <= widths::MAX - window && value.saturating_add(half) <= next {
            value + window
        } else if value > next.saturating_add(half) && value >= window {
            value - window
        } else {
            value
        };
        Self::new(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn from_masked(value: u64) -> Self {
        Self(value & widths::MAX)
    }
}

use crate::wire::packet::kind;

pub(crate) const SAMPLE_OFFSET: usize = 4;
pub(crate) const SAMPLE_LEN: usize = 16;
pub(crate) const SAMPLE_END: usize = SAMPLE_OFFSET + SAMPLE_LEN;

#[repr(transparent)]
pub(crate) struct Payload(usize);

impl Payload {
    pub(crate) const fn new(source: usize, width: widths::Width) -> Self {
        Self(source + Self::padding(source, width))
    }

    pub(crate) const fn padding(source: usize, width: widths::Width) -> usize {
        (SAMPLE_END - (width.get() + super::TAG_LEN)).saturating_sub(source)
    }

    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

const _: () = assert!(widths::MAX_LEN as usize + super::TAG_LEN <= SAMPLE_END);

pub(crate) struct Layout<K: kind::Kind> {
    packet_number: widths::Encoding,
    pn_offset: usize,
    marker: marker::PhantomData<fn() -> K>,
}

impl<K: kind::Kind> Layout<K> {
    pub(in crate::wire::packet) const fn new(number: widths::Encoding, offset: usize) -> Self {
        Self {
            packet_number: number,
            pn_offset: offset,
            marker: marker::PhantomData,
        }
    }

    pub(crate) const fn number(&self) -> Number {
        self.packet_number.number()
    }

    pub(crate) const fn encoding(&self) -> widths::Encoding {
        self.packet_number
    }

    pub(crate) const fn pn_offset(&self) -> usize {
        self.pn_offset
    }
}

/// An encoded header branded with its packet kind and packet number.
#[must_use = "an encoded header must be consumed by a wire packet path"]
pub struct Encoded<K: kind::Kind> {
    bytes: Vec<u8>,
    _layout: marker::PhantomData<Layout<K>>,
}

impl<K: kind::Kind> Encoded<K> {
    pub(in crate::wire::packet) const fn new(bytes: Vec<u8>, _layout: Layout<K>) -> Self {
        Self {
            bytes,
            _layout: marker::PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) struct Ref<'header, K: kind::Kind> {
    bytes: &'header [u8],
    layout: Layout<K>,
}

impl<'header, K: kind::Kind> Ref<'header, K> {
    pub(in crate::wire::packet) const fn new(bytes: &'header [u8], layout: Layout<K>) -> Self {
        Self { bytes, layout }
    }

    pub(crate) fn into_parts(self) -> (&'header [u8], Layout<K>) {
        (self.bytes, self.layout)
    }
}

const _: () = {
    assert!(mem::size_of::<kind::Initial>() == 0);
    assert!(mem::size_of::<kind::Handshake>() == 0);
    assert!(mem::size_of::<kind::ZeroRtt>() == 0);
    assert!(mem::size_of::<kind::OneRtt>() == 0);
};
const _: () = {
    assert!(mem::size_of::<Layout<kind::OneRtt>>() == 2 * mem::size_of::<usize>());
};
