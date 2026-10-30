pub mod bindings;
mod query;
mod usage;
mod view;

pub use usage::Usage;
pub use view::View;

use crate::stream::release;

use crate::runtime::brand;

use crate::conn;
use crate::conn::stream::{
    event,
    recv::{Receive, hold::Held},
    resident,
    send::Writer,
    state::{receive, transmit},
};
use crate::stream::{self, send};
use o3::buffer::{self, resident::Shared};
use send::admit;
use std::mem;

/// Invariant stream auth for exactly one connection scope.
#[repr(transparent)]
pub struct Streams<
    'access,
    'conn,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
> {
    connection: &'access mut conn::Machine<DOMAIN, B, D>,
    brand: brand::Token<'conn>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Streams<'_, 'conn, DOMAIN, B, RECONCILE, D>
{
    pub(in crate::conn) fn new<'access>(
        conn: &'access mut conn::Machine<DOMAIN, B, D>,
        brand: brand::Token<'conn>,
    ) -> Streams<'access, 'conn, DOMAIN, B, RECONCILE, D> {
        Streams {
            connection: conn,
            brand,
        }
    }

    pub fn send(&mut self) -> Writer<'_, 'conn, DOMAIN, B, RECONCILE, D> {
        Writer::new(self.connection, self.brand)
    }

    pub fn receive(&mut self) -> Receive<'_, 'conn, DOMAIN, B, RECONCILE, D> {
        Receive::new(self.connection, self.brand)
    }

    pub fn view(&self) -> View<'_, 'conn, DOMAIN, B, D> {
        View::new(self.connection, self.brand)
    }

    pub fn events(&mut self) -> event::Queue<'_, 'conn, DOMAIN, B, RECONCILE, D> {
        event::Queue::new(self.connection, self.brand)
    }

    pub fn binding(&mut self) -> bindings::Scope<'_, 'conn, DOMAIN, B, RECONCILE, D> {
        bindings::Scope::new(self.connection, self.brand)
    }

    pub fn resident(&self) -> resident::View<'_, 'conn, DOMAIN, B, D> {
        resident::View::new(self.connection, self.brand)
    }

    fn track(&mut self) {
        self.connection.record::<RECONCILE>(conn::Effects::STREAMS);
    }

    /// Receives through a generation-checked resident slot without hashing.
    pub fn try_hold(
        &mut self,
        handle: resident::Handle<'conn>,
    ) -> Result<Option<Held<'conn, B>>, resident::Stale> {
        let (held, _) = receive::Receive::new(self.connection).try_hold(handle.local())?;
        self.track();
        Ok(held.map(|held| Held::new(held, self.brand)))
    }

    /// Receives and observes the resulting EOF after one resident admission.
    pub fn try_hold_eof(
        &mut self,
        handle: resident::Handle<'conn>,
    ) -> Result<(Option<Held<'conn, B>>, bool), resident::Stale> {
        let (held, eof) = receive::Receive::new(self.connection).try_hold(handle.local())?;
        self.track();
        let held = held.map(|held| Held::new(held, self.brand));
        Ok((
            held,
            eof || self.connection.streams.is_recv_done(handle.id()),
        ))
    }

    /// Observes receive EOF through the same generation-checked resident key.
    pub fn try_recv_eof(&self, handle: resident::Handle<'conn>) -> Result<bool, resident::Stale> {
        self.view().try_recv_eof(handle)
    }

    /// Sends through an exact wire/generation pair without a hash lookup.
    pub fn try_write<C, W>(
        &mut self,
        handle: resident::Handle<'conn>,
        owner: W,
        commit: C,
    ) -> admit::Outcome<D, C, resident::Error, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        let result =
            transmit::Writer::new(self.connection).try_local(handle.local(), owner, commit);
        if matches!(
            &result,
            admit::Outcome::Retained(_) | admit::Outcome::Discarded(_)
        ) {
            self.track();
        }
        result
    }

    /// Resets an exact wire/generation pair without a hash lookup.
    pub fn try_reset<E: release::Sink>(
        &mut self,
        handle: resident::Handle<'conn>,
        code: crate::errors::Code,
        proof: &mut E,
    ) -> Result<(), resident::Error> {
        let result = transmit::Writer::new(self.connection).try_reset(handle.local(), code, proof);
        if result.is_ok() {
            self.track();
        }
        result
    }

    /// Stops an exact receive wire/generation pair without hashing.
    pub fn try_stop(
        &mut self,
        handle: resident::Handle<'conn>,
        code: crate::errors::Code,
    ) -> Result<(), resident::Error> {
        let result = receive::Receive::new(self.connection).try_stop(handle.local(), code);
        if result.is_ok() {
            self.track();
        }
        result
    }
}

const _: () = {
    assert!(
        mem::size_of::<Streams<'_, '_, 0, Vec<u8>, false, Shared<'_>>>()
            == mem::size_of::<&mut conn::Machine<0, Vec<u8>, Shared<'_>>>()
    );
};
