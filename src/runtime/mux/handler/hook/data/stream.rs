use o3::buffer;
use std::pin;

use crate::conn::{id, stream::BoundEvent};
use crate::runtime::mux::{
    self,
    handler::{Handler, Slot},
};
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
    event: BoundEvent<'scope>,
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
        event: BoundEvent<'scope>,
        at: Observation<I>,
    ) -> Self {
        Self {
            handler,
            slot,
            handle,
            event,
            at,
        }
    }
}

impl<'scope, H, const DOMAIN: u8, B, D, I> From<Event<'scope, H, DOMAIN, B, D, I>>
    for (
        pin::Pin<&'scope mut H>,
        Slot<'scope, H::Connection, DOMAIN, B, D>,
        id::Handle<I, DOMAIN>,
        BoundEvent<'scope>,
        Observation<I>,
    )
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn from(value: Event<'scope, H, DOMAIN, B, D, I>) -> Self {
        (
            value.handler,
            value.slot,
            value.handle,
            value.event,
            value.at,
        )
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn stream<'scope>(event: Event<'scope, Self, DOMAIN, B, D, I>) -> mux::Disposition;

    fn early<'scope>(event: Event<'scope, Self, DOMAIN, B, D, I>) -> mux::Disposition {
        Self::stream(event)
    }
}
