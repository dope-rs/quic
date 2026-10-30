use o3::buffer;

use std::{marker, mem, num::NonZero};

use crate::{
    conn::stream::{
        recv::{
            Receive,
            hold::{LocalReceipt, ReleaseError},
        },
        state::receive::{credits, recv::map},
    },
    runtime::brand,
    stream,
};

/// Credit for both the connection and stream windows.
#[derive(Debug)]
pub enum Shared {}

/// Credit remaining only in the stream window.
#[derive(Debug)]
pub enum Local {}

/// A connection-branded linear receive-credit capability.
#[must_use = "receive credit remains held until this value is released"]
pub struct Credit<'conn, K = Shared> {
    receipt: LocalReceipt<'conn>,
    kind: marker::PhantomData<fn() -> K>,
}

impl<'conn, K> Credit<'conn, K> {
    pub fn len(&self) -> usize {
        self.receipt.value().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn try_merge(&mut self, other: Self) -> Result<(), Self> {
        let (other, brand) = other.receipt.into_parts();
        self.receipt
            .value_mut()
            .try_merge(other)
            .map_err(|other| Self::new(LocalReceipt::new(brand, other)))
    }

    pub fn take_prefix(&mut self, bytes: NonZero<usize>) -> Option<Self> {
        let brand = self.receipt.brand();
        self.receipt
            .value_mut()
            .take_prefix(bytes)
            .map(|credit| Self::new(LocalReceipt::new(brand, credit)))
    }

    pub fn detach<
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) -> Detached<K> {
        Detached::new(recv.detach(self.receipt))
    }

    pub(super) const fn new(receipt: LocalReceipt<'conn>) -> Self {
        Self {
            receipt,
            kind: marker::PhantomData,
        }
    }

    pub(in crate::conn) fn into_receipt(self) -> LocalReceipt<'conn> {
        self.receipt
    }

    pub(in crate::conn) const fn bytes(&self) -> usize {
        self.receipt.value().len()
    }
}

impl<'conn> Credit<'conn> {
    pub fn release<
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) {
        recv.apply::<true, _>(self)
    }

    pub fn release_conn<
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) -> Credit<'conn, Local> {
        recv.commit_conn(self)
    }

    pub(in crate::conn) fn into_stream(self) -> Credit<'conn, Local> {
        Credit {
            receipt: self.receipt,
            kind: marker::PhantomData,
        }
    }
}

impl<'conn> Credit<'conn, Local> {
    pub fn release<
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) {
        recv.apply::<false, _>(self)
    }
}

/// Explicit owner-tagged credit for storage across connection scopes.
#[must_use = "receive credit remains held until this value is released"]
#[derive(Debug)]
pub struct Detached<K = Shared> {
    receipt: credits::Receipt,
    kind: marker::PhantomData<fn() -> K>,
}

/// An admitted handoff retaining the exact target and unchanged incoming credit.
/// Dropping or returning the incoming credit leaves the target unchanged.
#[must_use = "commit the handoff or recover its incoming credit"]
pub struct Merge<'target, 'conn> {
    merge: map::Merge<'target>,
    brand: brand::Token<'conn>,
}

impl<K> Detached<K> {
    pub fn len(&self) -> usize {
        self.receipt.value().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn try_merge(&mut self, other: Self) -> Result<(), Self> {
        if self.receipt.origin() != other.receipt.origin() {
            return Err(other);
        }
        let (origin, other) = other.receipt.into_parts();
        self.receipt
            .value_mut()
            .try_merge(other)
            .map_err(|other| Self::new(credits::Receipt::new(origin, other)))
    }

    pub fn take_prefix(&mut self, bytes: NonZero<usize>) -> Option<Self> {
        let origin = self.receipt.origin();
        self.receipt
            .value_mut()
            .take_prefix(bytes)
            .map(|credit| Self::new(credits::Receipt::new(origin, credit)))
    }

    pub fn rebind<
        'conn,
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) -> Result<Credit<'conn, K>, ReleaseError<Self>> {
        match recv.try_bind(self.receipt) {
            Ok(proof) => Ok(Credit::new(proof)),
            Err(error) => Err(ReleaseError::new(
                error.kind(),
                Self::new(error.into_inner()),
            )),
        }
    }

    const fn new(receipt: credits::Receipt) -> Self {
        Self {
            receipt,
            kind: marker::PhantomData,
        }
    }
}

impl Detached {
    pub(super) const fn from_receipt(proof: credits::Receipt) -> Self {
        Self::new(proof)
    }

    pub fn release<
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, '_, DOMAIN, B, RECONCILE, D>,
    ) -> Result<(), ReleaseError<Self>> {
        self.rebind(recv).map(|credit| credit.release(recv))
    }

    pub fn release_conn<
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, '_, DOMAIN, B, RECONCILE, D>,
    ) -> Result<Detached<Local>, ReleaseError<Self>> {
        self.rebind(recv)
            .map(|credit| credit.release_conn(recv).detach(recv))
    }
}

impl Detached<Local> {
    /// Checks receipt identity and combined size before either window changes.
    pub fn try_admit<
        'target,
        'conn,
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        &'target mut self,
        incoming: Credit<'conn>,
        recv: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) -> Result<Merge<'target, 'conn>, Credit<'conn>> {
        if !recv.is_origin(&self.receipt) {
            return Err(incoming);
        }
        let (incoming, brand) = incoming.receipt.into_parts();
        self.receipt
            .value_mut()
            .try_admit(incoming)
            .map(|merge| Merge { merge, brand })
            .map_err(|incoming| Credit::new(LocalReceipt::new(brand, incoming)))
    }

    pub fn release<
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, '_, DOMAIN, B, RECONCILE, D>,
    ) -> Result<(), ReleaseError<Self>> {
        self.rebind(recv).map(|credit| credit.release(recv))
    }
}

impl<'conn> Merge<'_, 'conn> {
    /// Returns the unchanged shared credit without committing either window.
    pub fn into_input(self) -> Credit<'conn> {
        Credit::new(LocalReceipt::new(self.brand, self.merge.into_input()))
    }

    /// Releases connection credit and transfers the admitted stream credit once.
    pub fn commit<
        const DOMAIN: u8,
        B: stream::Recv,
        const RECONCILE: bool,
        D: buffer::raw::Segment,
    >(
        self,
        recv: &mut Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>,
    ) {
        recv.commit_merge(self.merge);
    }
}

const _: () = {
    assert!(mem::size_of::<Credit<'static>>() == 2 * mem::size_of::<u64>());
    assert!(mem::size_of::<Credit<'static, Local>>() == mem::size_of::<Credit<'static>>());
    assert!(mem::size_of::<Detached>() == 3 * mem::size_of::<u64>());
    assert!(mem::size_of::<Detached<Local>>() == mem::size_of::<Detached>());
};
