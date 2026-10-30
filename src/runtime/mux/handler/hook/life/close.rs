use o3::buffer;
use std::pin;

use crate::conn::id;
use crate::runtime::mux::handler::{Close, Handler};
use crate::stream;

pub struct Event<'scope, H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    handler: pin::Pin<&'scope mut H>,
    scope: Close<'scope>,
    conn: H::Connection,
    handle: id::Handle<I, DOMAIN>,
}

impl<'scope, H, const DOMAIN: u8, B, D, I> Event<'scope, H, DOMAIN, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    pub fn into_parts(
        self,
    ) -> (
        pin::Pin<&'scope mut H>,
        Close<'scope>,
        H::Connection,
        id::Handle<I, DOMAIN>,
    ) {
        (self.handler, self.scope, self.conn, self.handle)
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn close<'scope>(event: Event<'scope, Self, DOMAIN, B, D, I>);
}

pub struct On;
pub struct Off;

pub trait Mode<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn close<'scope>(
        handler: pin::Pin<&'scope mut H>,
        scope: Close<'scope>,
        conn: H::Connection,
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
    fn close<'scope>(
        handler: pin::Pin<&'scope mut H>,
        scope: Close<'scope>,
        conn: H::Connection,
        handle: id::Handle<I, DOMAIN>,
    ) {
        H::close(Event {
            handler,
            scope,
            conn,
            handle,
        });
    }
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn close<'scope>(
        _: pin::Pin<&'scope mut H>,
        _: Close<'scope>,
        conn: H::Connection,
        _: id::Handle<I, DOMAIN>,
    ) {
        drop(conn);
    }
}
