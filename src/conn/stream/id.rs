use crate::runtime::brand;

use std::{marker, mem};

use crate::wire::stream::Id;

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Identity<'conn, Kind>(Id, brand::Token<'conn>, marker::PhantomData<Kind>);

impl<'conn, Kind> Identity<'conn, Kind> {
    const fn new(brand: brand::Token<'conn>, id: Id) -> Self {
        Self(id, brand, marker::PhantomData)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }

    const fn id(self) -> Id {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SendKind;

/// Authority for a send half in one connection scope.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Send<'conn>(Identity<'conn, SendKind>);

impl<'conn> Send<'conn> {
    pub(super) const fn new(brand: brand::Token<'conn>, id: Id) -> Self {
        Self(Identity::new(brand, id))
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn id(self) -> Id {
        self.0.id()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ReceiveKind;

/// Authority for a receive half in one connection scope.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Receive<'conn>(Identity<'conn, ReceiveKind>);

impl<'conn> Receive<'conn> {
    pub(super) const fn new(brand: brand::Token<'conn>, id: Id) -> Self {
        Self(Identity::new(brand, id))
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn id(self) -> Id {
        self.0.id()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct BidiKind;

/// Authority for both halves of a bidirectional stream in one scope.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bidi<'conn>(Identity<'conn, BidiKind>);

impl<'conn> Bidi<'conn> {
    pub(super) const fn new(brand: brand::Token<'conn>, id: Id) -> Self {
        Self(Identity::new(brand, id))
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn id(self) -> Id {
        self.0.id()
    }

    pub const fn send(self) -> Send<'conn> {
        Send(Identity(self.0.0, self.0.1, marker::PhantomData))
    }

    pub const fn receive(self) -> Receive<'conn> {
        Receive(Identity(self.0.0, self.0.1, marker::PhantomData))
    }
}

const _: () = {
    assert!(mem::size_of::<Send<'static>>() == mem::size_of::<u64>());
    assert!(mem::size_of::<Receive<'static>>() == mem::size_of::<u64>());
    assert!(mem::size_of::<Bidi<'static>>() == mem::size_of::<u64>());
};
