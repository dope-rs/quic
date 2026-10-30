mod id;
mod kind;

pub use id::Id;
pub use kind::Kind;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[derive(Debug)]
pub enum Direction {
    Bidi,
    Uni,
}

const _: () = {
    assert!(core::mem::size_of::<Direction>() == core::mem::size_of::<bool>());
    assert!(core::mem::align_of::<Direction>() == core::mem::align_of::<bool>());
};

impl Direction {
    pub(crate) const ALL: [Self; 2] = [Self::Bidi, Self::Uni];

    pub(crate) const fn bind<T>(self, values: &[T; 2]) -> &T {
        match self {
            Self::Bidi => &values[0],
            Self::Uni => &values[1],
        }
    }

    pub(crate) const fn bind_mut<T>(self, values: &mut [T; 2]) -> &mut T {
        match self {
            Self::Bidi => &mut values[0],
            Self::Uni => &mut values[1],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Initiator {
    Client,
    Server,
}

const _: () = {
    assert!(core::mem::size_of::<Initiator>() == core::mem::size_of::<bool>());
    assert!(core::mem::align_of::<Initiator>() == core::mem::align_of::<bool>());
};
