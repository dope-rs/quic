use crate::stream::{outbound, send};
pub(crate) use cache::BufferCache;
pub(crate) use capacity::Charge;
use o3::depot::capacity::{Count, Shortage};
use o3::{buffer, depot};
use send::admit;
pub(crate) use sender::{Acked, Append, Open, Prepared, Range, Sender, Written};
use std::{array, convert};

mod cache;
mod capacity;
pub(crate) mod chunk;
mod sender;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Finish {
    #[default]
    More,
    Marked,
    Sent,
    Acked,
}

const _: () = assert!(std::mem::size_of::<Finish>() == std::mem::size_of::<bool>());
const _: () = assert!(std::mem::align_of::<Finish>() == std::mem::align_of::<bool>());

/// The original batch and its measured physical node demand.
pub(crate) struct Input<W> {
    owner: W,
    count: Count,
}

pub(crate) struct Observed<W, C> {
    input: Input<W>,
    source: admit::Source,
    commit: C,
}

pub(crate) struct Rejected<W, C> {
    pub(crate) owner: W,
    pub(crate) commit: C,
    pub(crate) error: Shortage,
}

struct Nodes<O: buffer::raw::Segment, C> {
    items: array::IntoIter<Option<chunk::Node<O>>, 2>,
    output: C,
}

impl<W> Input<W> {
    pub(crate) fn try_new<O: buffer::raw::Segment>(
        owner: W,
    ) -> Result<(Self, outbound::Charge), (W, send::Overflow)>
    where
        W: send::raw::Batch<O>,
    {
        let demand = match owner.demand() {
            Ok(demand) => demand,
            Err(error) => return Err((owner, error)),
        };
        let charge = outbound::Charge {
            wire_bytes: demand.wire_bytes,
            resident_bytes: demand.resident_bytes,
            segments: demand.segments,
        };
        let count = demand.chunks;
        Ok((Self { owner, count }, charge))
    }

    pub(crate) fn into_owner(self) -> W {
        self.owner
    }

    pub(crate) fn observe<C>(self, source: admit::Source, commit: C) -> outbound::Observed<W, C> {
        Observed {
            input: self,
            source,
            commit,
        }
    }
}

impl<O: buffer::raw::Segment, C> Nodes<O, C> {
    fn new(parts: send::Parts<O>, complete: impl FnOnce(&send::Parts<O>) -> C) -> Self {
        use chunk::Node;

        let output = complete(&parts);
        let (first, tail, _) = parts.into_tail();
        let first = (!first.is_empty()).then_some(Node::Buffer(first));
        let tail = match tail {
            None => None,
            Some(send::Tail::Buffer(buffer)) => {
                (!buffer.is_empty()).then_some(Node::Buffer(buffer))
            }
            Some(send::Tail::Chain(chain)) => Some(Node::Segments(chain)),
        };
        Self {
            items: [first, tail].into_iter(),
            output,
        }
    }
}

// SAFETY: Input owns the unchanged batch measured by its constructor.
unsafe impl<O: buffer::raw::Segment, W: send::raw::Batch<O>> depot::raw::Input<chunk::Node<O>>
    for Input<W>
{
    type Item = chunk::Node<O>;
    type Error = outbound::Rejected<W, ()>;
    type Context = ();
    type Output = send::Boundary;

    fn count(&self) -> Count {
        self.count
    }

    fn reject(self, error: Shortage) -> Self::Error {
        Rejected {
            owner: self.owner,
            commit: (),
            error,
        }
    }
}

// SAFETY: decomposition preserves the admitted batch and its exact boundary.
unsafe impl<O: buffer::raw::Segment, W: send::raw::Batch<O>> depot::raw::Start<chunk::Node<O>>
    for Input<W>
{
    fn start(
        self,
    ) -> (
        impl depot::raw::Exact<Item = Self::Item, Output = Self::Output>,
        (),
    ) {
        (
            Nodes::new(self.owner.into_parts(), |parts| parts.boundary),
            (),
        )
    }
}

// SAFETY: observation retains the same input and runs only after physical admission.
unsafe impl<O: buffer::raw::Segment, W: send::raw::Batch<O>, C: admit::Commit<O, W>>
    depot::raw::Input<chunk::Node<O>> for Observed<W, C>
{
    type Item = chunk::Node<O>;
    type Error = outbound::Rejected<W, C>;
    type Context = ();
    type Output = (send::Boundary, C::Retained);

    fn count(&self) -> Count {
        self.input.count
    }

    fn reject(self, error: Shortage) -> Self::Error {
        Rejected {
            owner: self.input.owner,
            commit: self.commit,
            error,
        }
    }
}

// SAFETY: the observer retains its original admission and completion in the traversal.
unsafe impl<O: buffer::raw::Segment, W: send::raw::Batch<O>, C: admit::Commit<O, W>>
    depot::raw::Start<chunk::Node<O>> for Observed<W, C>
{
    fn start(
        self,
    ) -> (
        impl depot::raw::Exact<Item = Self::Item, Output = Self::Output>,
        (),
    ) {
        let nodes = Nodes::new(self.input.owner.into_parts(), |parts| {
            (
                parts.boundary,
                self.commit
                    .retained(admit::Admission::new(self.source, parts)),
            )
        });
        (nodes, ())
    }
}

impl<O: buffer::raw::Segment, C> Iterator for Nodes<O, C> {
    type Item = chunk::Node<O>;
    fn next(&mut self) -> Option<Self::Item> {
        self.items.find_map(convert::identity)
    }
}

// SAFETY: each present array element is yielded once; the terminal state is retained.
unsafe impl<O: buffer::raw::Segment, C> depot::raw::Exact for Nodes<O, C> {
    type Output = C;
    fn remaining(&self) -> Count {
        Count::new(self.items.as_slice().iter().flatten().count() as u32)
    }
    unsafe fn finish(self) -> C {
        self.output
    }
}
