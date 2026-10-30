use std::marker;

use o3::buffer::{self, storage};

use crate::{stream::send, wire::stream};

/// Exact stream source presented to one atomic send admission.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Source(stream::Id);

impl Source {
    pub const fn new(id: stream::Id) -> Self {
        Self(id)
    }

    pub const fn id(self) -> stream::Id {
        self.0
    }
}

/// Exact send owner at the QUIC queue linearization point.
pub struct Admission<'a, O: buffer::raw::Segment, W> {
    source: Source,
    parts: &'a send::Parts<O>,
    operation: marker::PhantomData<fn(W) -> W>,
}

impl<'a, O: buffer::raw::Segment, W> Admission<'a, O, W> {
    pub(crate) const fn new(source: Source, parts: &'a send::Parts<O>) -> Self {
        Self {
            source,
            parts,
            operation: marker::PhantomData,
        }
    }

    pub const fn source(&self) -> Source {
        self.source
    }

    pub const fn boundary(&self) -> send::Boundary {
        self.parts.boundary
    }

    /// Owners retained by queue nodes. Empty buffers are discarded at admission.
    pub fn retained(&self) -> impl Iterator<Item = &'a O> + use<'a, O, W> {
        let first = match &self.parts.first {
            send::Buffer::Retained(owner) if !owner.as_ref().is_empty() => Some(owner),
            _ => None,
        };
        let buffer = match &self.parts.tail {
            Some(send::Tail::Buffer(send::Buffer::Retained(owner)))
                if !owner.as_ref().is_empty() =>
            {
                Some(owner)
            }
            _ => None,
        };
        let chain = match &self.parts.tail {
            Some(send::Tail::Chain(chain)) => Some(chain.as_chain()),
            _ => None,
        };
        first
            .into_iter()
            .chain(buffer)
            .chain(chain.into_iter().flat_map(|chain| chain.segments()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    PeerRetired,
    Reset,
    Finished,
    Retired,
}

/// A rejected send owner tied to the source whose queue was not mutated.
pub struct Discard<W> {
    source: Source,
    cause: Cause,
    operation: marker::PhantomData<fn(W) -> W>,
}

impl<W> Discard<W> {
    pub(crate) const fn new(source: Source, cause: Cause) -> Self {
        Self {
            source,
            cause,
            operation: marker::PhantomData,
        }
    }

    pub const fn source(&self) -> Source {
        self.source
    }

    pub const fn cause(&self) -> Cause {
        self.cause
    }
}

pub trait Commit<O: buffer::raw::Segment, W> {
    type Retained;
    type Discarded;

    fn retained(self, admit: Admission<'_, O, W>) -> Self::Retained;
    fn discarded(self, cause: Discard<W>) -> Self::Discarded;
}

#[must_use]
pub enum Outcome<O: buffer::raw::Segment, C: Commit<O, W>, E, W = send::Parts<O>> {
    Retained(C::Retained),
    Discarded(C::Discarded),
    Blocked { owner: W, commit: C },
    Failed { owner: W, commit: C, error: E },
}

const _: () = {
    assert!(size_of::<Source>() == size_of::<u64>());
    assert!(
        size_of::<Admission<'static, storage::Shared, send::Parts<storage::Shared>>>()
            == 2 * size_of::<usize>()
    );
    assert!(size_of::<Discard<send::Parts<storage::Shared>>>() == 2 * size_of::<usize>());
};
