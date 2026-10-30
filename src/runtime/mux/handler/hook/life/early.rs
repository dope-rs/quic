use o3::buffer;
use std::pin;

use crate::conn::id;
use crate::runtime::mux::handler::Handler;
use crate::stream;

pub struct Event<'scope, H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    handler: pin::Pin<&'scope mut H>,
    conn: &'scope mut H::Connection,
    handle: id::Handle<I, DOMAIN>,
}

impl<'scope, H, const DOMAIN: u8, B, D, I> Event<'scope, H, DOMAIN, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    pub(crate) fn new(
        handler: pin::Pin<&'scope mut H>,
        conn: &'scope mut H::Connection,
        handle: id::Handle<I, DOMAIN>,
    ) -> Self {
        Self {
            handler,
            conn,
            handle,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        pin::Pin<&'scope mut H>,
        &'scope mut H::Connection,
        id::Handle<I, DOMAIN>,
    ) {
        (self.handler, self.conn, self.handle)
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn rejected<'scope>(event: Event<'scope, Self, DOMAIN, B, D, I>);
}
