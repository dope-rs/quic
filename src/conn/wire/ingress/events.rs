use crate::errors::detail::Diagnostic;
use o3::buffer::hold::evidence;
use std::convert::Infallible;

use crate::stream::{release, send::admit};

pub(in crate::conn) struct Context<F> {
    failure: F,
}

impl<F> Context<F> {
    pub(in crate::conn) fn new(failure: F) -> Self {
        Self { failure }
    }
}

impl<F> release::Sink for Context<F> {
    type Mode = evidence::Off;

    fn release(&mut self, proof: evidence::Off, _: admit::Source, _: release::Cause) {
        let evidence::Off = proof;
    }
}

/// All observations of a received packet share the packet's original borrow.
pub trait Sink: release::Sink {
    type Observer<'a>: Observe
    where
        Self: 'a;
    fn certificate(&mut self, error: &rustls::Error);
    fn observer(&mut self) -> Option<Self::Observer<'_>>;
}

pub trait Observe {
    fn observe(self, detail: &Diagnostic);
}

impl Observe for Infallible {
    fn observe(self, _: &Diagnostic) {
        match self {}
    }
}

impl<F: FnMut(&rustls::Error)> Sink for Context<F> {
    type Observer<'a>
        = Infallible
    where
        Self: 'a;
    fn certificate(&mut self, error: &rustls::Error) {
        (self.failure)(error);
    }

    fn observer(&mut self) -> Option<Self::Observer<'_>> {
        None
    }
}
