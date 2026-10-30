use crate::stream::release;

use crate::runtime::brand;

use o3::buffer::{self, resident::Shared};

use crate::conn;
use crate::conn::stream::{Error, SendOutcome, id, resident, state::transmit};
use crate::stream::{self, send};
use crate::wire::stream::Direction;
use send::admit;
use std::mem;

/// Scoped send operations.
#[repr(transparent)]
pub struct Writer<
    'access,
    'conn,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    const RECONCILE: bool = false,
    D: buffer::raw::Segment = Shared<'conn>,
> {
    connection: &'access mut conn::Machine<DOMAIN, B, D>,
    brand: brand::Token<'conn>,
}

impl<const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Writer<'_, '_, DOMAIN, B, RECONCILE, D>
{
    fn kernel(&mut self) -> transmit::Writer<'_, DOMAIN, B, D> {
        transmit::Writer::new(self.connection)
    }

    fn track(&mut self) {
        self.connection.record::<RECONCILE>(conn::Effects::STREAMS);
    }
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Writer<'_, 'conn, DOMAIN, B, RECONCILE, D>
{
    pub(super) fn new<'access>(
        conn: &'access mut conn::Machine<DOMAIN, B, D>,
        brand: brand::Token<'conn>,
    ) -> Writer<'access, 'conn, DOMAIN, B, RECONCILE, D> {
        Writer {
            connection: conn,
            brand,
        }
    }

    #[doc(hidden)]
    pub fn open_handle(&mut self, dir: Direction) -> Result<resident::Handle<'conn>, Error> {
        let result = self.kernel().open(dir).map(resident::Handle::new);
        if result.is_ok() {
            self.track();
        }
        result
    }

    pub fn open_bidi(&mut self) -> Result<id::Bidi<'conn>, Error> {
        let brand = self.brand;
        self.open_handle(Direction::Bidi)
            .map(|handle| id::Bidi::new(brand, handle.id()))
    }

    pub fn open_uni(&mut self) -> Result<id::Send<'conn>, Error> {
        let brand = self.brand;
        self.open_handle(Direction::Uni)
            .map(|handle| id::Send::new(brand, handle.id()))
    }

    pub fn send(&mut self, stream: id::Send<'conn>, data: &[u8]) -> Result<(), Error> {
        let result = self.kernel().send(stream.id(), data);
        if result.is_ok() {
            self.track();
        }
        result
    }

    pub fn try_buffer(
        &mut self,
        stream: id::Send<'conn>,
        data: send::Buffer<D>,
    ) -> SendOutcome<send::Buffer<D>> {
        let result = self.kernel().try_buffer(stream.id(), data);
        if matches!(&result, SendOutcome::Accepted) {
            self.track();
        }
        result
    }

    pub fn try_parts(
        &mut self,
        stream: id::Send<'conn>,
        parts: send::Parts<D>,
    ) -> SendOutcome<send::Parts<D>> {
        let result = self.kernel().try_parts(stream.id(), parts);
        if matches!(&result, SendOutcome::Accepted) {
            self.track();
        }
        result
    }

    pub fn try_admit<C, W>(
        &mut self,
        stream: id::Send<'conn>,
        owner: W,
        commit: C,
    ) -> admit::Outcome<D, C, Error, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        let result = self.kernel().try_admit(stream.id(), owner, commit);
        if matches!(
            &result,
            admit::Outcome::Retained(_) | admit::Outcome::Discarded(_)
        ) {
            self.track();
        }
        result
    }

    pub fn finish(&mut self, stream: id::Send<'conn>) -> Result<(), Error> {
        let result = self.kernel().finish(stream.id());
        if result.is_ok() {
            self.track();
        }
        result
    }

    pub fn reset(
        &mut self,
        stream: id::Send<'conn>,
        code: crate::errors::Code,
    ) -> Result<(), Error> {
        let result = self.kernel().reset(stream.id(), code);
        if result.is_ok() {
            self.track();
        }
        result
    }

    pub fn reset_with<E: release::Sink>(
        &mut self,
        stream: id::Send<'conn>,
        code: crate::errors::Code,
        sink: &mut E,
    ) -> Result<(), Error> {
        let result = self.kernel().reset_with(stream.id(), code, sink);
        if result.is_ok() {
            self.track();
        }
        result
    }
}

const _: () = {
    assert!(
        mem::size_of::<Writer<'static, 'static, 0>>()
            == mem::size_of::<&mut conn::Machine<0, Vec<u8>, Shared<'_>>>()
    );
};
