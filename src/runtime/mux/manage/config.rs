use std::{marker, num, pin};

use dope::manifold::network::datagram;

use crate::{
    conn,
    runtime::{mux, routing},
    stream,
};
use conn::{id, wire};
use mux::{auth, handler, manage, router};
use wire::packet;

#[repr(transparent)]
pub struct Config<
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
    mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>,
    lifetime: marker::PhantomData<&'tls ()>,
}

impl<
    'a,
    'tls,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
> Config<'a, 'tls, H, DOMAIN, B, A>
{
    pub(crate) fn new(mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>) -> Self {
        Self {
            mux,
            lifetime: marker::PhantomData,
        }
    }

    pub fn enable_gso(&mut self) -> Result<(), manage::GsoError> {
        let Some(limits) =
            datagram::GSO_LIMITS.filter(|limits| limits.capacity().count() <= usize::from(u8::MAX))
        else {
            return Err(manage::GsoError::Unavailable);
        };
        self.mux.as_mut().project().state.outgoing.cache.batch = Some(packet::Gso::new(limits));
        Ok(())
    }

    pub fn disable_gso(&mut self) {
        self.mux.as_mut().project().state.outgoing.cache.batch = None;
    }

    pub fn try_resize(&mut self, max: usize) -> Result<(), ResizeError> {
        let state = self.mux.as_mut().project().state;
        if state.lifecycle.shutting_down {
            return Err(ResizeError::ShuttingDown);
        }
        state.registry.try_resize(max)
    }

    /// Rejects future early data without discarding the native ticket cache.
    pub fn reject_early(&mut self) -> Result<(), TlsError> {
        let Some(server) = self.mux.as_mut().project().state.server.as_ref() else {
            return Err(TlsError::NoServer);
        };
        A::reject_early(server);
        Ok(())
    }

    pub fn reconfigure(&mut self, config: rustls::ServerConfig) -> Result<(), TlsError> {
        let Some(server) = self.mux.as_mut().project().state.server.as_mut() else {
            return Err(TlsError::NoServer);
        };
        A::reconfigure(server, config).map_err(TlsError::Configuration)
    }
}

pub enum ResizeError {
    Active { actual: num::NonZero<usize> },
    Storage(router::Error),
    Limit { requested: usize, maximum: usize },
    ShuttingDown,
    Zero,
}

#[derive(Debug)]
pub enum TlsError {
    NoServer,
    Configuration(crate::errors::Connect),
}
