use o3::buffer;
use std::pin;

use crate::conn::id;
use crate::runtime::mux::handler::{Handler, Slot};
use crate::stream;

type Observation<I> = <I as id::Temporal>::Observation;

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
    at: Observation<I>,
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
        slot: Slot<'scope, H::Connection, DOMAIN, B, D>,
        handle: id::Handle<I, DOMAIN>,
        at: Observation<I>,
    ) -> Self {
        Self {
            handler,
            slot,
            handle,
            at,
        }
    }
}

impl<'scope, H, const DOMAIN: u8, B, D, I> From<Event<'scope, H, DOMAIN, B, D, I>>
    for (
        pin::Pin<&'scope mut H>,
        Slot<'scope, H::Connection, DOMAIN, B, D>,
        id::Handle<I, DOMAIN>,
        Observation<I>,
    )
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn from(value: Event<'scope, H, DOMAIN, B, D, I>) -> Self {
        (value.handler, value.slot, value.handle, value.at)
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn established<'scope>(event: Event<'scope, Self, DOMAIN, B, D, I>);
}
