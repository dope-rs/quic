use crate::{
    conn::{
        stream::state::receive::recv::{self, map},
        wire::ingress::frames,
    },
    errors::detail,
    stream,
    wire::{
        frame,
        ranges::{self, inserts, plan},
    },
};
use map::ready;
use o3::depot;
use o3::depot::arena::linked::slots;
use o3::depot::capacity;
use std::{mem, ops};

pub struct Write<'a, 'b, B: stream::Recv> {
    pub(in crate::conn::stream::state::receive::recv::map) entry: &'b mut recv::Entry<B>,
    pub(in crate::conn::stream::state::receive::recv::map) arena:
        &'a depot::raw::Arena<map::Node<B>, map::Tag>,
}

impl<'a, 'b, B: stream::Recv> Write<'a, 'b, B> {
    pub(in crate::conn::stream::state::receive::recv::map) fn apply<'body>(
        &mut self,
        permit: &frames::CommitPermit<'_>,
        prepared: recv::Prepared<'body, B>,
        reserve: &mut slots::Reserve<'a, map::Node<B>, map::Tag>,
    ) where
        B: 'a,
    {
        self.append(permit, prepared.ranges, reserve);
        self.entry
            .state
            .progress
            .record(prepared.end, frame::Boundary::More);
        if let Some(end) = prepared.final_size {
            self.entry.state.progress.record(end, frame::Boundary::End);
        }
    }

    pub(in crate::conn::stream::state::receive::recv::map) fn clear(&mut self) {
        while unsafe { self.arena.pop_front(&mut self.entry.buffer.head) }.is_some() {}
        self.entry.buffer.ranges = 0;
        <B::Ready as ready::raw::Queue<B>>::clear(self);
    }

    pub(in crate::conn::stream::state::receive::recv::map) fn read(
        &mut self,
        dst: &mut Vec<u8>,
    ) -> Result<usize, stream::Capacity> {
        let count = <B::Ready as ready::raw::Queue<B>>::read_into(self, dst)?;
        self.entry.state.deliver(count);
        Ok(count)
    }

    pub(in crate::conn::stream::state::receive::recv::map) fn read_owned(
        &mut self,
    ) -> Result<Option<Vec<u8>>, stream::Capacity> {
        let bytes = <B::Ready as ready::raw::Queue<B>>::read_owned(self)?;
        if let Some(bytes) = &bytes {
            self.entry.state.deliver(bytes.len());
        }
        Ok(bytes)
    }

    pub(in crate::conn::stream::state::receive::recv::map) fn read_buffer(
        &mut self,
    ) -> Option<(B, usize)> {
        let bytes = <B::Ready as ready::raw::Queue<B>>::pop_front(self)?;
        let count = bytes.as_ref().len();
        self.entry.state.deliver(count);
        Some((bytes, count))
    }

    fn append<'body>(
        &mut self,
        permit: &frames::CommitPermit<'_>,
        prepared: plan::Prepared<'body, B>,
        reserve: &mut slots::Reserve<'a, map::Node<B>, map::Tag>,
    ) where
        B: 'a,
    {
        prepared.consume(|piece| match piece {
            plan::Piece::Ready { part, bytes } => {
                let end = part.end();
                <B::Ready as ready::raw::Queue<B>>::append(self, permit, bytes, |bytes| unsafe {
                    slots::Reserve::claim(
                        depot::raw::Proof::new(&mut *reserve),
                        map::Node::ready(bytes),
                    )
                });
                self.entry.buffer.next = end;
                self.drain(permit, reserve);
            }
            plan::Piece::Gap { part, bytes } => {
                let start = part.start();
                let buffer = &mut self.entry.buffer;
                let mut cursor = unsafe { self.arena.cursor(&mut buffer.head) };
                while cursor.current().is_some_and(|node| node.start() < start) {
                    cursor.advance();
                }
                unsafe {
                    slots::Cursor::insert(depot::raw::Proof::new((
                        &mut cursor,
                        slots::Reserve::claim(
                            depot::raw::Proof::new(&mut *reserve),
                            map::Node::piece(part, bytes),
                        ),
                    )))
                };
                buffer.ranges += 1;
            }
        });
    }

    fn drain(
        &mut self,
        permit: &frames::CommitPermit<'_>,
        reserve: &mut slots::Reserve<'a, map::Node<B>, map::Tag>,
    ) where
        B: 'a,
    {
        while let Some(entry) = unsafe { self.arena.front_entry(&mut self.entry.buffer.head) } {
            let start = entry.get().start();
            if start > self.entry.buffer.next {
                break;
            }
            let end = entry.get().end();
            let (node, slot) = entry.take();
            if end > self.entry.buffer.next {
                let skip = (self.entry.buffer.next - start) as usize;
                let bytes = node.into_bytes().into_suffix(skip);
                if <B::Ready as ready::raw::Queue<B>>::SEGMENTED {
                    <B::Ready as ready::raw::Queue<B>>::push_back(self, permit, bytes, |bytes| {
                        slot.insert(map::Node::ready(bytes))
                    });
                } else {
                    unsafe {
                        slots::Reserve::recycle(depot::raw::Proof::new((&mut *reserve, slot)))
                    };
                    <B::Ready as ready::raw::Queue<B>>::push_back(
                        self,
                        permit,
                        bytes,
                        |bytes| unsafe {
                            slots::Reserve::claim(
                                depot::raw::Proof::new(&mut *reserve),
                                map::Node::ready(bytes),
                            )
                        },
                    );
                }
                self.entry.buffer.next = end;
            } else {
                unsafe { slots::Reserve::recycle(depot::raw::Proof::new((&mut *reserve, slot))) };
            }
            self.entry.buffer.ranges -= 1;
        }
    }
}

const _: () =
    assert!(mem::size_of::<Write<'static, 'static, Vec<u8>>>() == 2 * mem::size_of::<usize>());

pub(in crate::conn) struct Input<'a, 'b, 'c, 'body, B: stream::Recv> {
    target: Write<'a, 'b, B>,
    plan: plan::Plan<'c>,
    ranges: plan::Prepared<'body, B>,
    old: usize,
    peak: usize,
    end: u64,
    final_size: Option<u64>,
    readable: bool,
}

impl<'a, 'b, 'c, 'body, B: stream::Recv> Input<'a, 'b, 'c, 'body, B> {
    pub(in crate::conn) fn try_collect<E: From<ranges::Error>>(
        target: Write<'a, 'b, B>,
        segs: &'c mut Vec<ops::Range<u64>>,
        parts: &'c mut Vec<inserts::Part>,
        source: impl Iterator<Item = Result<Option<recv::Pending<'body, B>>, E>>,
    ) -> Result<recv::Prepared<'body, B>, E> {
        let old = target.entry.buffer.ranges;
        let mut buffered = Ok(0usize);
        let plan = Read::new(&target.entry.buffer, target.arena)
            .try_plan(segs, parts, |bytes| {
                buffered = buffered.and_then(|current| {
                    let added = bytes.as_ref().len();
                    current
                        .checked_add(added)
                        .ok_or(stream::Capacity::Overflow {
                            current,
                            additional: added,
                        })
                });
            })
            .map_err(stream::Capacity::from)
            .map_err(ranges::Error::from)?;
        let mut input = Self {
            target,
            plan,
            ranges: plan::Prepared::Empty,
            old,
            peak: old,
            end: 0,
            final_size: None,
            readable: false,
        };
        for value in source {
            if let Some(value) = value? {
                input.try_push(value)?;
            }
        }
        Ok(input.try_finish(buffered)?)
    }

    fn try_push(&mut self, input: recv::Pending<'body, B>) -> Result<(), ranges::Error> {
        let end = input.record.end(input.offset);
        self.readable |= input.record.len() != 0 || matches!(input.boundary, frame::Boundary::End);
        input
            .record
            .prepare(&mut self.plan, input.offset, input.data, &mut self.ranges)?;
        if !<B::Ready as ready::raw::Queue<B>>::SEGMENTED {
            self.peak = self.peak.max(self.plan.len());
        }
        self.end = self.end.max(end);
        if matches!(input.boundary, frame::Boundary::End) {
            self.final_size = Some(end);
        }
        Ok(())
    }

    /// Original gap owners and their lengths stay unchanged during preparation.
    /// The captured sum's error follows source and slot checks, preserving failure order.
    fn try_finish(
        self,
        buffered: Result<usize, stream::Capacity>,
    ) -> Result<recv::Prepared<'body, B>, ranges::Error> {
        let slots = capacity::Count::try_from(if <B::Ready as ready::raw::Queue<B>>::SEGMENTED {
            self.ranges.slots()
        } else {
            self.peak - self.old
        })
        .map_err(stream::Capacity::Count)?;
        let buffered = buffered?;
        let accepted = self.ranges.bytes()?;
        let bytes = buffered
            .checked_add(accepted)
            .ok_or(stream::Capacity::Overflow {
                current: buffered,
                additional: accepted,
            })?;
        let ready = !<B::Ready as ready::raw::Queue<B>>::SEGMENTED && self.ranges.has_ready();
        <B::Ready as ready::raw::Queue<B>>::try_reserve(
            &mut self.target.entry.buffer.assembled,
            bytes,
            ready,
        )?;
        Ok(recv::Prepared {
            ranges: self.ranges,
            end: self.end,
            final_size: self.final_size,
            slots,
            readable: self.readable,
        })
    }
}

pub(in crate::conn::stream::state::receive::recv::map) struct Read<'a, B: stream::Recv> {
    buffer: &'a recv::Buffer<B>,
    arena: &'a depot::raw::Arena<map::Node<B>, map::Tag>,
}

impl<'a, B: stream::Recv> Read<'a, B> {
    pub(in crate::conn::stream::state::receive::recv::map) fn new(
        buffer: &'a recv::Buffer<B>,
        arena: &'a depot::raw::Arena<map::Node<B>, map::Tag>,
    ) -> Self {
        Self { buffer, arena }
    }

    pub(in crate::conn::stream::state::receive::recv::map) fn try_plan<'b>(
        &self,
        segs: &'b mut Vec<ops::Range<u64>>,
        parts: &'b mut Vec<inserts::Part>,
        mut record: impl FnMut(&B),
    ) -> Result<plan::Plan<'b>, detail::Ranges> {
        use o3::alloc::raw::VecExt as _;

        segs.clear();
        for node in unsafe { self.arena.iter(&self.buffer.head) } {
            if segs.len() == segs.capacity() {
                return Err(detail::Ranges::Ranges {
                    current: segs.len(),
                    additional: 1,
                    capacity: segs.capacity(),
                });
            }
            // SAFETY: the current exclusive owner admitted this exact next slot.
            unsafe { segs.vacancy() }.insert(node.start()..node.end());
            record(node.bytes());
        }
        parts.clear();
        Ok(plan::Plan::new(self.buffer.next, segs, parts))
    }
}

const _: () = assert!(mem::size_of::<Read<'static, Vec<u8>>>() == 2 * mem::size_of::<usize>());
