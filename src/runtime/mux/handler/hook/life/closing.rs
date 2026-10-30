use crate::runtime::mux::handler::hook::Boundary;
use o3::buffer;
use std::pin;

use crate::conn::{self, id, life, scope};
use crate::runtime::{brand, mux::handler};
use crate::stream;
use handler::hook::{data::release::Mode as _, set::Dispatch};
use handler::{Handler, Slot};

pub struct Event<'scope, H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    handler: pin::Pin<&'scope mut H>,
    slot: Slot<'scope, H::Connection, DOMAIN, B, D>,
    handle: id::Handle<I, DOMAIN>,
}

impl<'scope, H, const DOMAIN: u8, B, D, I> Event<'scope, H, DOMAIN, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    /// Moves reconnect ownership from the transport retired after this callback.
    pub fn into_saved(mut self) -> (Self, Option<life::Reconnect>) {
        let saved = self.slot.transport().security().take_final();
        (self, saved)
    }
}

impl<'scope, H, const DOMAIN: u8, B, D, I> From<Event<'scope, H, DOMAIN, B, D, I>>
    for (
        pin::Pin<&'scope mut H>,
        Slot<'scope, H::Connection, DOMAIN, B, D>,
        id::Handle<I, DOMAIN>,
    )
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn from(value: Event<'scope, H, DOMAIN, B, D, I>) -> Self {
        (value.handler, value.slot, value.handle)
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn closing<'scope>(event: Event<'scope, Self, DOMAIN, B, D, I>);
}

pub struct On;
pub struct Off;

/// Retires the original transport owner after its optional closing callback.
pub trait Mode<H, const DOMAIN: u8, B, D, I>: Boundary
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn retire(
        handler: pin::Pin<&mut H>,
        conn: conn::Connection<DOMAIN, B, D>,
        app: &mut H::Connection,
        brand: brand::Token<'_>,
        handle: id::Handle<I, DOMAIN>,
    );
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for On
where
    H: Sink<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn retire(
        mut handler: pin::Pin<&mut H>,
        mut conn: conn::Connection<DOMAIN, B, D>,
        app: &mut H::Connection,
        brand: brand::Token<'_>,
        handle: id::Handle<I, DOMAIN>,
    ) {
        H::closing(Event {
            handler: handler.as_mut(),
            slot: Slot::new(
                app,
                scope::Access::new(conn.machine_mut(), brand.reborrow()),
            ),
            handle,
        });
        <H::Events as Dispatch<H, DOMAIN, B, D, I>>::Release::retire(handler, conn, handle);
    }
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn retire(
        handler: pin::Pin<&mut H>,
        conn: conn::Connection<DOMAIN, B, D>,
        _: &mut H::Connection,
        _: brand::Token<'_>,
        handle: id::Handle<I, DOMAIN>,
    ) {
        <H::Events as Dispatch<H, DOMAIN, B, D, I>>::Release::retire(handler, conn, handle);
    }
}
