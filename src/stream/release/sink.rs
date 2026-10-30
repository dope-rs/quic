use o3::buffer::hold;

use crate::stream::{release, send::admit};
use hold::evidence;

/// Statically dispatched release-evidence consumer and projection mode.
pub trait Sink {
    type Mode: release::Mode;

    fn release(
        &mut self,
        proof: <Self::Mode as evidence::Mode>::Projection,
        source: admit::Source,
        cause: release::Cause,
    );
}

impl<F: FnMut(release::Event)> Sink for F {
    type Mode = evidence::On;

    fn release(
        &mut self,
        proof: <Self::Mode as evidence::Mode>::Projection,
        source: admit::Source,
        cause: release::Cause,
    ) {
        self(release::Event::new(source, proof, cause));
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Ignore;

impl Sink for Ignore {
    type Mode = evidence::Off;

    fn release(
        &mut self,
        proof: <Self::Mode as evidence::Mode>::Projection,
        _: admit::Source,
        _: release::Cause,
    ) {
        let evidence::Off = proof;
    }
}

pub(crate) struct Forward<'a, E: ?Sized>(&'a mut E);

impl<'a, E: Sink + ?Sized> Forward<'a, E> {
    pub(crate) fn new(evidence: &'a mut E) -> Self {
        Self(evidence)
    }
}

impl<E: Sink + ?Sized> Sink for Forward<'_, E> {
    type Mode = E::Mode;

    fn release(
        &mut self,
        proof: <Self::Mode as evidence::Mode>::Projection,
        source: admit::Source,
        cause: release::Cause,
    ) {
        self.0.release(proof, source, cause);
    }
}
