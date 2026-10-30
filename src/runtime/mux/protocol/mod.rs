pub(crate) mod control;
pub(crate) mod dgram;
pub(crate) mod dial;
pub(crate) mod recv;
pub mod rotation;

use std::{marker, pin};

use crate::{
    conn::id,
    runtime::{mux, routing},
    stream,
};
use mux::{auth, handler, router};

#[repr(transparent)]
pub struct Io<
    'a,
    'tls,
    H,
    const DOMAIN: u8,
    B = Vec<u8>,
    A = auth::Pooled<'tls, routing::Plain, id::Static>,
> where
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
{
    pub(crate) mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>,
    lifetime: marker::PhantomData<&'tls ()>,
}

impl<'a, 'tls, H, const DOMAIN: u8, B, A> Io<'a, 'tls, H, DOMAIN, B, A>
where
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
{
    pub(crate) fn new(mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>) -> Self {
        Self {
            mux,
            lifetime: marker::PhantomData,
        }
    }
}
