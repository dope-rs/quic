pub mod hook;
pub mod net;

use std::{mem, time};

use o3::buffer::{self, resident};

use crate::runtime::brand;
use crate::runtime::mux::handler::hook::{life::create, set};
use crate::{conn, stream};
use conn::{id, scope};

/// One generative borrow of a live slot's application and transport state.
pub struct Slot<'scope, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    app: &'scope mut C,
    conn: scope::Access<'scope, DOMAIN, B, true, D>,
}

impl<'scope, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Slot<'scope, C, DOMAIN, B, D>
{
    pub(crate) fn new(app: &'scope mut C, conn: scope::Access<'scope, DOMAIN, B, true, D>) -> Self {
        Self { app, conn }
    }

    pub fn application(&mut self) -> &mut C {
        self.app
    }

    pub(crate) const fn brand(&self) -> brand::Token<'scope> {
        self.conn.brand()
    }

    pub fn transport(&mut self) -> &mut scope::Access<'scope, DOMAIN, B, true, D> {
        &mut self.conn
    }

    pub fn set_ready(&mut self, ready: bool) {
        self.conn.application().set_ready(ready);
    }

    pub fn ready(&mut self) {
        self.set_ready(true);
    }

    pub fn idle(&mut self) {
        self.set_ready(false);
    }

    pub fn split(&mut self) -> (&mut C, &mut scope::Access<'scope, DOMAIN, B, true, D>) {
        (&mut *self.app, &mut self.conn)
    }
}

/// Branded observation issued by the txn retiring one connection.
#[repr(transparent)]
pub struct Close<'scope>(brand::Branded<'scope, time::Instant>);

impl<'scope> Close<'scope> {
    pub(crate) fn new(brand: brand::Token<'scope>, at: time::Instant) -> Self {
        Self(brand::Branded::new(brand, at))
    }

    pub(crate) fn at(&self) -> time::Instant {
        *self.0.value()
    }

    pub(crate) const fn brand(&self) -> brand::Token<'scope> {
        self.0.brand()
    }
}

/// Slot-local protocol callbacks coupled to the mux txn lifetime.
pub trait Handler<
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal = id::Static,
>: Sized
{
    type Connection;
    type Create: create::Mode<Self, DOMAIN, B, D, I>;
    type Events: set::Dispatch<Self, DOMAIN, B, D, I>;
}

const _: () = {
    assert!(
        mem::size_of::<Slot<'static, (), 0, Vec<u8>, resident::Shared<'static>>>()
            == mem::size_of::<(*mut (), *mut ())>()
    );
    assert!(
        mem::align_of::<Slot<'static, (), 0, Vec<u8>, resident::Shared<'static>>>()
            == mem::align_of::<(*mut (), *mut ())>()
    );
    assert!(!mem::needs_drop::<
        Slot<'static, (), 0, Vec<u8>, resident::Shared<'static>>,
    >());
};
const _: () = {
    assert!(mem::size_of::<Close<'static>>() == mem::size_of::<time::Instant>());
    assert!(!mem::needs_drop::<Close<'static>>());
};
