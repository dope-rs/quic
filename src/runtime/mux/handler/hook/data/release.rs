use crate::runtime::mux::handler::hook::Boundary;
use o3::buffer;
use o3::buffer::hold::evidence;
use std::pin;

use crate::conn::{self, id};
use crate::runtime::mux::handler::hook::set;
use crate::runtime::mux::{app, handler::Handler};
use crate::stream::{self, release, send::admit};

pub trait Mode<H, const DOMAIN: u8, B, D, I: id::Temporal>: Boundary {
    type Evidence: release::Mode;

    /// Releases all send owners after slot detachment, consuming final readiness.
    fn retire(
        handler: pin::Pin<&mut H>,
        conn: conn::Connection<DOMAIN, B, D>,
        handle: id::Handle<I, DOMAIN>,
    ) where
        B: stream::Recv,
        D: buffer::raw::Segment;

    fn release(
        handler: pin::Pin<&mut H>,
        handle: id::Handle<I, DOMAIN>,
        proof: <Self::Evidence as evidence::Mode>::Projection,
        source: admit::Source,
        cause: release::Cause,
    ) -> app::Readiness;
}

impl<H, const DOMAIN: u8, B, D, I: id::Temporal> Mode<H, DOMAIN, B, D, I> for set::Off {
    type Evidence = evidence::Off;

    fn retire(_: pin::Pin<&mut H>, conn: conn::Connection<DOMAIN, B, D>, _: id::Handle<I, DOMAIN>)
    where
        B: stream::Recv,
        D: buffer::raw::Segment,
    {
        conn.retire(release::Cause::Closed, &mut release::Ignore);
    }

    fn release(
        _: pin::Pin<&mut H>,
        _: id::Handle<I, DOMAIN>,
        proof: evidence::Off,
        _: admit::Source,
        _: release::Cause,
    ) -> app::Readiness {
        let evidence::Off = proof;
        app::Readiness::Preserve
    }
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for set::On
where
    H: Sink<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Evidence = evidence::On;

    fn retire(
        mut handler: pin::Pin<&mut H>,
        conn: conn::Connection<DOMAIN, B, D>,
        handle: id::Handle<I, DOMAIN>,
    ) {
        conn.retire(
            release::Cause::Closed,
            &mut |release| match H::release(Event::new(handler.as_mut(), handle, release)) {
                app::Readiness::Preserve | app::Readiness::Idle | app::Readiness::Ready => (),
            },
        );
    }

    fn release(
        handler: pin::Pin<&mut H>,
        handle: id::Handle<I, DOMAIN>,
        proof: <evidence::On as evidence::Mode>::Projection,
        source: admit::Source,
        cause: release::Cause,
    ) -> app::Readiness {
        H::release(Event::new(
            handler,
            handle,
            release::Event {
                source,
                charge: proof,
                cause,
            },
        ))
    }
}

pub struct Event<'scope, H, const DOMAIN: u8, I: id::Temporal> {
    handler: pin::Pin<&'scope mut H>,
    handle: id::Handle<I, DOMAIN>,
    release: release::Event,
}

impl<'scope, H, const DOMAIN: u8, I: id::Temporal> Event<'scope, H, DOMAIN, I> {
    pub(crate) fn new(
        sink: pin::Pin<&'scope mut H>,
        handle: id::Handle<I, DOMAIN>,
        event: release::Event,
    ) -> Self {
        Self {
            handler: sink,
            handle,
            release: event,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        pin::Pin<&'scope mut H>,
        id::Handle<I, DOMAIN>,
        release::Event,
    ) {
        (self.handler, self.handle, self.release)
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn release<'scope>(event: Event<'scope, Self, DOMAIN, I>) -> app::Readiness;
}
