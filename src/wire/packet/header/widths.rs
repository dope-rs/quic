use o3::depot::array;

use crate::wire::packet::header::Number;

pub(crate) const MAX: u64 = (1 << 62) - 1;
pub(crate) const MAX_LEN: u8 = 4;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Width(array::Index<4>);

impl Width {
    pub(crate) const fn from_first(first: u8) -> Self {
        Self(array::Index::mask(first))
    }

    pub(crate) const fn from_pn(number: Encoding) -> Self {
        Self(array::Index::mask((number.0 >> 62) as u8))
    }

    pub(crate) const fn get(self) -> usize {
        self.0.index() + 1
    }
}

/// A bounded packet number and its width packed into one word.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub(crate) struct Encoding(u64);

impl Encoding {
    pub(crate) const fn new(number: Number, len: u8) -> Option<Self> {
        if len >= 1 && len <= MAX_LEN {
            Some(Self(number.get() | (((len - 1) as u64) << 62)))
        } else {
            None
        }
    }

    pub(crate) const fn number(self) -> Number {
        Number(self.0 & MAX)
    }

    pub(crate) const fn len(self) -> u8 {
        ((self.0 >> 62) as u8) + 1
    }
}

const _: () = {
    assert!(size_of::<Number>() == size_of::<u64>());
    assert!(align_of::<Number>() == align_of::<u64>());
    assert!(!std::mem::needs_drop::<Number>());
    assert!(size_of::<Encoding>() == size_of::<u64>());
    assert!(align_of::<Encoding>() == align_of::<u64>());
    assert!(!std::mem::needs_drop::<Encoding>());
    assert!(size_of::<Width>() == size_of::<u8>());
    assert!(!std::mem::needs_drop::<Width>());
};
