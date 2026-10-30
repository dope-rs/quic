use o3::buffer;

use crate::runtime::brand;

use std::mem;

use crate::{conn, stream};
use conn::stream::{
    recv::{Receive, credit},
    state::receive,
};
use receive::{credits, recv};
use recv::map;

/// A receive buffer retaining stream and connection flow-control credit in one scope.
/// Its invariant brand prevents cross-connection escape; long storage uses [`Self::detach`].
///
/// A retained driver owner keeps its independent storage lifetime too:
#[must_use = "receive credit remains held until this value is released"]
pub struct Held<'conn, B: stream::Recv> {
    receipt: LocalReceipt<'conn, map::Held<B>>,
}

impl<'conn, B: stream::Recv> Held<'conn, B> {
    pub(in crate::conn) fn new(held: map::Held<B>, brand: brand::Token<'conn>) -> Self {
        Self {
            receipt: LocalReceipt::new(brand, held),
        }
    }

    pub fn len(&self) -> usize {
        self.receipt.value().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn into_parts(self) -> (B, credit::Credit<'conn>) {
        let (held, brand) = self.receipt.into_parts();
        let (buffer, credit) = held.into_parts();
        (
            buffer,
            credit::Credit::new(LocalReceipt::new(brand, credit)),
        )
    }

    /// Converts a scoped hold into the owner-tagged representation
    /// required for storage beyond this connection scope.
    pub fn detach<const DOMAIN: u8, const RECONCILE: bool, D: buffer::raw::Segment>(
        self,
        streams: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) -> Detached<B> {
        Detached {
            receipt: streams.detach(self.receipt),
        }
    }

    pub fn release<const DOMAIN: u8, const RECONCILE: bool, D: buffer::raw::Segment>(
        self,
        streams: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) -> B {
        let (buffer, credit) = self.into_parts();
        credit.release(streams);
        buffer
    }
}

impl<B: stream::Recv> AsRef<[u8]> for Held<'_, B> {
    fn as_ref(&self) -> &[u8] {
        self.receipt.value().as_ref()
    }
}

/// Owner-tagged receive storage spanning connection scopes. Release performs
/// one owner comparison before the shared settlement kernel.
#[must_use = "receive credit remains held until this value is released"]
pub struct Detached<B: stream::Recv> {
    receipt: credits::Receipt<map::Held<B>>,
}

impl<B: stream::Recv> Detached<B> {
    pub fn len(&self) -> usize {
        self.receipt.value().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn into_parts(self) -> (B, credit::Detached) {
        let (origin, held) = self.receipt.into_parts();
        let (buffer, credit) = held.into_parts();
        (
            buffer,
            credit::Detached::from_receipt(credits::Receipt::new(origin, credit)),
        )
    }

    /// Re-establishes compile-time connection auth after one dynamic
    /// owner check.
    pub fn rebind<'conn, const DOMAIN: u8, const RECONCILE: bool, D: buffer::raw::Segment>(
        self,
        streams: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) -> Result<Held<'conn, B>, ReleaseError<Self>> {
        match streams.try_bind(self.receipt) {
            Ok(receipt) => Ok(Held { receipt }),
            Err(error) => Err(ReleaseError::new(
                error.kind(),
                Self {
                    receipt: error.into_inner(),
                },
            )),
        }
    }

    pub fn release<const DOMAIN: u8, const RECONCILE: bool, D: buffer::raw::Segment>(
        self,
        streams: &mut Receive<'_, '_, DOMAIN, B, RECONCILE, D>,
    ) -> Result<B, ReleaseError<Self>> {
        self.rebind(streams).map(|held| held.release(streams))
    }
}

impl<B: stream::Recv> AsRef<[u8]> for Detached<B> {
    fn as_ref(&self) -> &[u8] {
        self.receipt.value().as_ref()
    }
}

pub(in crate::conn) type LocalReceipt<'conn, T = map::Credit> = brand::Branded<'conn, T>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A detached capability was rebound to a different connection.
    ForeignConnection,
}

#[derive(Debug)]
pub struct ReleaseError<T> {
    kind: ErrorKind,
    value: T,
}

impl<T> ReleaseError<T> {
    pub(in crate::conn) fn new(kind: ErrorKind, value: T) -> Self {
        Self { kind, value }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn into_inner(self) -> T {
        self.value
    }
}

const _: () = {
    assert!(mem::size_of::<LocalReceipt<'static>>() == 2 * mem::size_of::<u64>());
    assert!(
        mem::size_of::<Held<'static, Vec<u8>>>()
            == mem::size_of::<Vec<u8>>() + 2 * mem::size_of::<u64>()
    );
    assert!(
        mem::size_of::<Detached<Vec<u8>>>()
            == mem::size_of::<Vec<u8>>() + 3 * mem::size_of::<u64>()
    );
};
