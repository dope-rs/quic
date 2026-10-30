use std::{mem, num::NonZero, ops::ControlFlow};

use o3::buffer::{self, segments::Nonempty};

use crate::stream::outbound::{chunk, sender::Head};
use crate::stream::{outbound, release, send};

/// Progress within the retained first physical owner of one sender queue.
#[derive(Default)]
pub(in crate::stream::outbound) struct Cursor {
    offset: usize,
}

impl Cursor {
    pub(in crate::stream::outbound) const fn offset(&self) -> usize {
        self.offset
    }
}

pub(in crate::stream) struct Prefix<'a, 'b, O: buffer::raw::Segment> {
    entry: chunk::Front<'a, O>,
    front: &'b mut Cursor,
    amount: NonZero<usize>,
}

impl<'a, 'b, O: buffer::raw::Segment> Prefix<'a, 'b, O> {
    pub(in crate::stream::outbound) fn new(
        head: Head<'a, 'b, O>,
    ) -> ControlFlow<Self, (chunk::Front<'a, O>, Option<NonZero<usize>>)> {
        let (mut entry, front, amount) = head.into_parts();
        let free = entry.get_mut().len() - front.offset;
        if amount.get() >= free {
            return ControlFlow::Continue((entry, NonZero::new(amount.get() - free)));
        }
        ControlFlow::Break(Self {
            entry,
            front,
            amount,
        })
    }
}

impl<O: buffer::raw::Segment> Prefix<'_, '_, O> {
    /// Exclusively retains an empty, allocation-free buffer during restoration.
    /// Replacing that buffer never forgets a retained owner.
    pub(in crate::stream) fn retire<M: release::Mode>(
        self,
        released: &mut outbound::Charge,
        proof: &mut M::Projection,
    ) {
        let Self {
            mut entry,
            front,
            amount,
        } = self;
        let value = entry.get_mut();
        let len = match value {
            chunk::Node::Buffer(_) | chunk::Node::One(_) => {
                front.offset += amount.get();
                return;
            }
            chunk::Node::Segments(owners) => owners.front().as_ref().len(),
        };
        let mut free = len - front.offset;
        if amount.get() < free {
            front.offset += amount.get();
            return;
        }
        let mut owners =
            match mem::replace(value, chunk::Node::Buffer(send::Buffer::Owned(Vec::new()))) {
                owner @ (chunk::Node::Buffer(_) | chunk::Node::One(_)) => {
                    front.offset += amount.get();
                    mem::forget(mem::replace(value, owner));
                    return;
                }
                chunk::Node::Segments(owners) => owners,
            };
        let mut left = amount;
        let owner = loop {
            let (rest, charge) = owners.discard();
            released.resident_bytes += charge.resident_bytes;
            released.segments += 1;
            M::add(proof, charge);
            let restlen = left.get() - free;
            owners = match rest {
                Nonempty::One(owner) => {
                    front.offset = restlen;
                    break chunk::Node::One(owner);
                }
                Nonempty::Many(owners) => {
                    let Some(next) = NonZero::new(restlen) else {
                        front.offset = 0;
                        break chunk::Node::Segments(owners);
                    };
                    left = next;
                    free = owners.front().as_ref().len();
                    if restlen < free {
                        front.offset = restlen;
                        break chunk::Node::Segments(owners);
                    }
                    owners
                }
            };
        };
        mem::forget(mem::replace(value, owner));
    }
}

const _: () = assert!(size_of::<Cursor>() == size_of::<usize>());
