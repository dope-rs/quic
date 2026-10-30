use o3::buffer;
use std::pin;

use crate::conn::id;
use crate::runtime::mux::handler::{Handler, net};
use crate::stream;

pub struct Event<'scope, H, const DOMAIN: u8, I: id::Temporal> {
    handler: pin::Pin<&'scope mut H>,
    event: net::Event<'scope, I, DOMAIN>,
}

impl<'scope, H, const DOMAIN: u8, I: id::Temporal> Event<'scope, H, DOMAIN, I> {
    pub(crate) fn new(
        handler: pin::Pin<&'scope mut H>,
        event: net::Event<'scope, I, DOMAIN>,
    ) -> Self {
        Self { handler, event }
    }

    pub fn into_parts(self) -> (pin::Pin<&'scope mut H>, net::Event<'scope, I, DOMAIN>) {
        (self.handler, self.event)
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn socket<'scope>(event: Event<'scope, Self, DOMAIN, I>);
}
