use std::{mem, ops};

use o3::buffer::{bytes, storage::inline, write::consume};

use crate::wire::packet;

const CAPACITY: usize = packet::MAX_CONNECTION_ID_LEN;

#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Id(inline::Bytes<CAPACITY>);

impl Id {
    pub const MAX_LEN: usize = CAPACITY;

    pub(crate) fn from_array<const N: usize>(bytes: [u8; N]) -> Self {
        Self(inline::Bytes::from(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn length(&self) -> Len {
        Len(self.0.len() as u8)
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// Borrows this ID for no longer than its owner.
    pub fn as_ref_id(&self) -> Ref<'_> {
        Ref(bytes::Prefix::from(&self.0))
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl ops::Deref for Id {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl TryFrom<&[u8]> for Id {
    type Error = consume::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(inline::Bytes::from_slice(bytes)?))
    }
}

impl TryFrom<Vec<u8>> for Id {
    type Error = consume::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(inline::Bytes::from_slice(&bytes)?))
    }
}

impl<const N: usize> TryFrom<[u8; N]> for Id {
    type Error = consume::Error;

    fn try_from(bytes: [u8; N]) -> Result<Self, Self::Error> {
        Ok(Self(inline::Bytes::from_slice(&bytes)?))
    }
}

/// A checked short-header destination connection-ID length.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Len(u8);

impl Len {
    pub const fn get(self) -> u8 {
        self.0
    }

    pub(crate) fn end(self) -> usize {
        1 + usize::from(self.get())
    }
}

impl TryFrom<u8> for Len {
    type Error = consume::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        consume::Error::check(usize::from(value), CAPACITY)?;
        Ok(Self(value))
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Span {
    start: u8,
    len: Len,
}

impl Span {
    pub(super) const fn new(start: u8, len: Len) -> Self {
        Self { start, len }
    }

    pub(super) fn range(self) -> ops::Range<usize> {
        let start = usize::from(self.start);
        start..start + usize::from(self.len.get())
    }

    /// # Safety
    /// This span was admitted in this exact input, whose extent is unchanged.
    pub(super) unsafe fn get<'wire>(self, input: &'wire [u8]) -> Ref<'wire> {
        use o3::buffer::bytes::bounded::raw::Input;

        // SAFETY: the retained owner admits the range, and Len bounds the
        // resulting CID by CAPACITY without another dynamic admission.
        let proof = unsafe { Input::new(input.get_unchecked(self.range())) };
        Ref(bytes::Prefix::from_raw(proof))
    }
}

/// A validated connection ID borrowing its wire storage.
#[repr(transparent)]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct Ref<'wire>(bytes::Prefix<'wire, CAPACITY>);

impl<'wire> Ref<'wire> {
    pub fn new(bytes: &'wire [u8]) -> Result<Self, consume::Error> {
        Ok(Self(bytes::Prefix::try_new(bytes)?))
    }

    pub const fn into_slice(self) -> &'wire [u8] {
        self.0.into_slice()
    }

    pub const fn len(self) -> usize {
        self.0.as_slice().len()
    }

    pub const fn is_empty(self) -> bool {
        self.0.as_slice().is_empty()
    }

    pub const fn length(self) -> Len {
        Len(self.0.as_slice().len() as u8)
    }

    pub fn into_owned(self) -> Id {
        Id(inline::Bytes::from(self.0))
    }
}

impl AsRef<[u8]> for Ref<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl ops::Deref for Ref<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Ref<'_> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.0.as_slice() == other
    }
}

impl PartialEq<Vec<u8>> for Ref<'_> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.0.as_slice() == other.as_slice()
    }
}

const _: () = assert!(CAPACITY < 1usize << u8::BITS);
const _: () = assert!(mem::size_of::<Id>() == CAPACITY + 1);
const _: () = assert!(mem::size_of::<Len>() == 1);
const _: () = assert!(mem::size_of::<Span>() == 2);
const _: () = assert!(mem::size_of::<Ref<'static>>() == mem::size_of::<&[u8]>());
