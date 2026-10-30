use std::ops;

use crate::{
    stream,
    wire::{
        ranges::{self, plan},
        varint,
    },
};

const SOURCE_BITS: u32 = u16::BITS;
const SOURCE_MASK: u32 = u16::MAX as u32;

#[derive(Clone, Copy)]
pub(super) struct Input {
    start: u64,
    end: u64,
    len: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct Part {
    start: u64,
    source: u32,
    compact: u32,
}

impl Input {
    pub(super) fn new(offset: varint::VarInt, record: plan::Record) -> Self {
        let start = offset.get();
        let len = record.bounded_len();
        let end = start + u64::from(len);
        Self { start, end, len }
    }

    pub(super) const fn start(self) -> u64 {
        self.start
    }

    pub(super) const fn end(self) -> u64 {
        self.end
    }

    pub(super) const fn len(self) -> usize {
        self.len as usize
    }

    pub(super) fn part(self, gap: ops::Range<u64>, compact: u32) -> Part {
        let from = self.local(gap.start);
        let to = self.local(gap.end);
        let len = to - from;
        Part {
            start: self.start + u64::from(from),
            source: from | (len << SOURCE_BITS),
            compact,
        }
    }

    const fn local(self, absolute: u64) -> u32 {
        let distance = absolute.saturating_sub(self.start);
        if distance >= self.len as u64 {
            self.len as u32
        } else {
            distance as u32
        }
    }
}

impl Part {
    pub(crate) const fn start(self) -> u64 {
        self.start
    }

    pub(crate) fn end(self) -> u64 {
        self.start + u64::from(self.width())
    }

    pub(super) const fn len(self) -> usize {
        self.width() as usize
    }

    pub(super) const fn range(self) -> ops::Range<usize> {
        let from = self.source & SOURCE_MASK;
        from as usize..(from + self.width()) as usize
    }

    pub(super) const fn extent(self, layout: stream::Layout) -> stream::Extent {
        let from = match layout {
            stream::Layout::Full => self.source & SOURCE_MASK,
            stream::Layout::Compact => self.compact,
        };
        stream::Extent::new(from, from + self.width())
    }

    const fn compact_end(self) -> u32 {
        self.compact + self.width()
    }

    const fn width(self) -> u32 {
        self.source >> SOURCE_BITS
    }
}

struct Missing<I> {
    segments: I,
    cursor: u64,
    input: Input,
    accepted: u32,
    done: bool,
}

impl<I> Missing<I> {
    fn new(segs: I, input: Input, next: u64) -> Self {
        Self {
            segments: segs,
            cursor: input.start.max(next),
            input,
            accepted: 0,
            done: false,
        }
    }

    fn part(&mut self, gap: ops::Range<u64>) -> Part {
        let part = self.input.part(gap, self.accepted);
        self.accepted = part.compact_end();
        part
    }

    fn tail(&mut self) -> Option<Part> {
        if self.cursor >= self.input.end {
            return None;
        }
        Some(self.part(self.cursor..self.input.end))
    }
}

impl<I> Iterator for Missing<I>
where
    I: Iterator<Item = ops::Range<u64>>,
{
    type Item = Part;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let Some(seg) = self.segments.next() else {
                self.done = true;
                return self.tail();
            };
            if seg.end <= self.cursor {
                continue;
            }
            if seg.start >= self.input.end {
                self.done = true;
                return self.tail();
            }
            let gap = (seg.start > self.cursor).then_some(self.cursor..seg.start);
            self.cursor = seg.end;
            if self.cursor >= self.input.end {
                self.done = true;
            }
            if let Some(gap) = gap {
                return Some(self.part(gap));
            }
            if self.done {
                return None;
            }
        }
    }
}

pub(super) fn try_collect<E>(
    parts: &mut Vec<Part>,
    segs: impl IntoIterator<Item = ops::Range<u64>>,
    input: Input,
    next: u64,
    cap: usize,
    full: impl FnOnce(usize, usize) -> E,
) -> Result<(), E> {
    use o3::alloc::raw::VecExt as _;

    parts.clear();
    let cap = cap.min(parts.capacity());
    for part in Missing::new(segs.into_iter(), input, next) {
        if parts.len() >= cap {
            return Err(full(parts.len(), cap));
        }
        // SAFETY: the same admission bounds this exclusive vector's length by
        // both the protocol limit and physical capacity before issuing its slot.
        unsafe { parts.vacancy() }.insert(part);
    }
    Ok(())
}

const _: () = {
    assert!(usize::BITS >= u32::BITS);
    assert!(ranges::MAX <= u32::MAX as usize / u16::MAX as usize);
    assert!(size_of::<Part>() <= size_of::<(u64, ops::Range<usize>)>());
    assert!(size_of::<Input>() <= 3 * size_of::<u64>());
};
