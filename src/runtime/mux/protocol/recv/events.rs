use crate::conn::wire::ingress::events;
use crate::errors::detail::Diagnostic;
use std::{marker, mem};

use o3::buffer::hold::evidence;

use crate::stream::{release, send::admit};

pub(in crate::runtime::mux::protocol::recv) enum Event<'wire, P> {
    Diagnostic(&'wire Diagnostic),
    Certificate(&'wire rustls::Error),
    Release {
        proof: P,
        source: admit::Source,
        cause: release::Cause,
    },
}

#[repr(transparent)]
pub(in crate::runtime::mux::protocol::recv) struct Events<F, M> {
    consume: F,
    mode: marker::PhantomData<M>,
}

impl<F, M: release::Mode> Events<F, M>
where
    F: for<'wire> FnMut(Event<'wire, <M as evidence::Mode>::Projection>),
{
    pub(in crate::runtime::mux::protocol::recv) fn new(consume: F) -> Self {
        const {
            assert!(mem::size_of::<Self>() == mem::size_of::<F>());
            assert!(mem::align_of::<Self>() == mem::align_of::<F>());
        }
        Self {
            consume,
            mode: marker::PhantomData,
        }
    }
}

impl<F, M: release::Mode> release::Sink for Events<F, M>
where
    F: for<'wire> FnMut(Event<'wire, <M as evidence::Mode>::Projection>),
{
    type Mode = M;

    fn release(
        &mut self,
        proof: <M as evidence::Mode>::Projection,
        source: admit::Source,
        cause: release::Cause,
    ) {
        (self.consume)(Event::Release {
            proof,
            source,
            cause,
        });
    }
}

impl<F, M: release::Mode> events::Sink for Events<F, M>
where
    F: for<'wire> FnMut(Event<'wire, <M as evidence::Mode>::Projection>),
{
    fn certificate(&mut self, failure: &rustls::Error) {
        (self.consume)(Event::Certificate(failure));
    }

    type Observer<'a>
        = &'a mut Self
    where
        Self: 'a;
    fn observer(&mut self) -> Option<Self::Observer<'_>> {
        Some(self)
    }
}

impl<F, M: release::Mode> events::Observe for &mut Events<F, M>
where
    F: for<'wire> FnMut(Event<'wire, <M as evidence::Mode>::Projection>),
{
    fn observe(self, detail: &Diagnostic) {
        (self.consume)(Event::Diagnostic(detail));
    }
}
