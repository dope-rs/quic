use crate::errors::detail::Diagnostic;
use o3::buffer;
use std::{net, pin};

use crate::conn::id;
use crate::errors;
use crate::stream;

#[derive(Debug)]
pub enum Failure<'a> {
    Receive(errors::Receive),
    Diagnostic(&'a Diagnostic),
}

impl From<errors::Receive> for Failure<'_> {
    fn from(error: errors::Receive) -> Self {
        Self::Receive(error)
    }
}

pub struct Event<'scope, H> {
    handler: pin::Pin<&'scope mut H>,
    from: net::SocketAddr,
    error: Failure<'scope>,
    len: usize,
}

impl<'scope, H> Event<'scope, H> {
    pub(crate) fn new(
        app: pin::Pin<&'scope mut H>,
        from: net::SocketAddr,
        error: impl Into<Failure<'scope>>,
        len: usize,
    ) -> Self {
        Self {
            handler: app,
            from,
            error: error.into(),
            len,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        pin::Pin<&'scope mut H>,
        net::SocketAddr,
        Failure<'scope>,
        usize,
    ) {
        (self.handler, self.from, self.error, self.len)
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Sized
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn packet<'scope>(event: Event<'scope, Self>);
}

pub struct On;
pub struct Off;

pub trait Mode<H, const DOMAIN: u8, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Output;
    fn observe<'scope>(take: impl FnOnce() -> Event<'scope, H>)
    where
        H: 'scope;

    fn finish<'scope>(
        result: Result<(), errors::Receive>,
        take: impl FnOnce(errors::Receive) -> Event<'scope, H>,
    ) -> Self::Output
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
    type Output = ();
    fn observe<'scope>(take: impl FnOnce() -> Event<'scope, H>)
    where
        H: 'scope,
    {
        H::packet(take());
    }

    fn finish<'scope>(
        result: Result<(), errors::Receive>,
        take: impl FnOnce(errors::Receive) -> Event<'scope, H>,
    ) where
        H: 'scope,
    {
        if let Err(error) = result {
            H::packet(take(error));
        }
    }
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for Off
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Output = Result<(), errors::Receive>;
    fn observe<'scope>(take: impl FnOnce() -> Event<'scope, H>)
    where
        H: 'scope,
    {
        drop(take);
    }

    fn finish<'scope>(
        result: Result<(), errors::Receive>,
        take: impl FnOnce(errors::Receive) -> Event<'scope, H>,
    ) -> Self::Output
    where
        H: 'scope,
    {
        drop(take);
        result
    }
}
