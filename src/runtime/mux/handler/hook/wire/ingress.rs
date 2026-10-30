use o3::buffer;
use std::pin;

use crate::conn::id;
use crate::runtime::mux::handler::{Handler, net};
use crate::stream;

pub struct Event<'scope, 'driver, H> {
    handler: pin::Pin<&'scope mut H>,
    ingress: net::Ingress<'driver>,
}

impl<'scope, 'driver, H> Event<'scope, 'driver, H> {
    pub(crate) fn new(handler: pin::Pin<&'scope mut H>, ingress: net::Ingress<'driver>) -> Self {
        Self { handler, ingress }
    }

    pub fn into_parts(self) -> (pin::Pin<&'scope mut H>, net::Ingress<'driver>) {
        (self.handler, self.ingress)
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn ingress<'scope, 'driver>(event: Event<'scope, 'driver, Self>);
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
    fn finish<'scope, 'driver, T>(result: T, take: impl FnOnce() -> Event<'scope, 'driver, H>) -> T
    where
        H: 'scope;
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for On
where
    H: Sink<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn finish<'scope, 'driver, T>(result: T, take: impl FnOnce() -> Event<'scope, 'driver, H>) -> T
    where
        H: 'scope,
    {
        H::ingress(take());
        result
    }
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn finish<'scope, 'driver, T>(result: T, take: impl FnOnce() -> Event<'scope, 'driver, H>) -> T
    where
        H: 'scope,
    {
        drop(take);
        result
    }
}
