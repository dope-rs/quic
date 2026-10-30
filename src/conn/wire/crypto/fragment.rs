use std::{mem, ops};

use o3::alloc::{self, tail};
use o3::mem::slice::Ext as _;

use crate::conn;
use crate::wire::ranges;

pub(super) const MAX: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(super) struct Span {
    start: u32,
    end: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct Count(u16);

#[derive(Clone, Copy)]
pub(super) struct Insert {
    merged: Span,
    input: Span,
    before: Count,
    after: Count,
    first: u16,
    tail: u16,
}

struct Index {
    base: u64,
    ranges: Count,
    spans: [Span; ranges::MAX],
}

pub(super) struct Fragment {
    workspace: tail::Block<Index, u8>,
}

pub(super) struct Shadow<'a> {
    base: u64,
    spans: &'a mut Vec<Span>,
}

struct Copied;

struct Written;

struct Changed;

impl Span {
    const EMPTY: Self = Self { start: 0, end: 0 };

    pub(super) fn new(start: usize, end: usize) -> Option<Self> {
        if start > end || end > MAX {
            return None;
        }
        Some(Self {
            start: start as u32,
            end: end as u32,
        })
    }

    pub(super) const fn start(self) -> usize {
        self.start as usize
    }

    pub(super) const fn end(self) -> usize {
        self.end as usize
    }

    const fn range(self) -> ops::Range<usize> {
        self.start()..self.end()
    }

    fn merge(self, active: &mut [Self], first: usize, after: usize) -> Option<Changed> {
        let tail = active.get_mut(first..)?;
        let (head, rest) = tail.split_first_mut()?;
        let removed = after.checked_sub(first.checked_add(1)?)?;
        if removed != 0 {
            rest.copy_tail(removed)?;
        }
        *head = self;
        Some(Changed)
    }
}

impl Insert {
    fn copy(self, target: &mut [u8], body: &[u8], source: usize, span: Span) -> Option<Copied> {
        let source = source.checked_add(span.start().checked_sub(self.input.start())?)?;
        let len = span.end().checked_sub(span.start())?;
        let source = body.get(source..source.checked_add(len)?)?;
        let target = target.get_mut(span.range())?;
        target.copy_from_slice(source);
        Some(Copied)
    }

    fn write(
        self,
        covered: &[Span],
        target: &mut [u8],
        body: &[u8],
        source: usize,
    ) -> Option<Written> {
        let mut cursor = self.input.start;
        for &prior in covered {
            if prior.end <= cursor {
                continue;
            }
            if prior.start >= self.input.end {
                break;
            }
            let end = prior.start.min(self.input.end);
            if cursor < end {
                self.copy(target, body, source, Span { start: cursor, end })?;
            }
            cursor = cursor.max(prior.end.min(self.input.end));
            if cursor == self.input.end {
                break;
            }
        }
        if cursor < self.input.end {
            self.copy(
                target,
                body,
                source,
                Span {
                    start: cursor,
                    end: self.input.end,
                },
            )?;
        }
        Some(Written)
    }
}

impl Count {
    const ZERO: Self = Self(0);

    const fn new(count: usize) -> Option<Self> {
        if count > ranges::MAX || count > u16::MAX as usize {
            return None;
        }
        Some(Self(count as u16))
    }

    const fn get(self) -> usize {
        self.0 as usize
    }
}

impl Index {
    const fn new(base: u64) -> Self {
        Self {
            base,
            ranges: Count::ZERO,
            spans: [Span::EMPTY; ranges::MAX],
        }
    }

    fn spans(&self, count: Count) -> Option<&[Span]> {
        self.spans.get(..count.get())
    }

    fn insert(&mut self, count: Count, index: usize, span: Span) -> Option<Changed> {
        let window = self.spans.get_mut(index..=count.get())?;
        if window.is_empty() {
            return None;
        }
        window.rotate_right(1);
        window[0] = span;
        Some(Changed)
    }

    fn consume(&mut self, end: usize) -> Option<Changed> {
        let count = self.ranges.get();
        let active = self.spans.get_mut(..count)?;
        let first = active.first_mut()?;
        if first.end() != end {
            let span = Span::new(end, first.end())?;
            *first = span;
            return Some(Changed);
        }
        self.ranges = Count::new(active.copy_tail(1)?.len())?;
        Some(Changed)
    }

    fn apply(&mut self, edit: Insert) -> Option<Changed> {
        if self.ranges != edit.before {
            return None;
        }
        let first = edit.first as usize;
        let tail = edit.tail as usize;
        if first == tail {
            self.insert(edit.before, first, edit.merged)?;
        } else {
            edit.merged
                .merge(self.spans.get_mut(..edit.before.get())?, first, tail)?;
        }
        self.ranges = edit.after;
        Some(Changed)
    }
}

impl Fragment {
    pub(super) fn try_new(base: u64) -> Result<Self, alloc::Exhausted> {
        let plan = tail::Plan::fixed::<MAX>();
        let index = Index::new(base);
        let memory = plan.try_allocate()?;
        Ok(Self {
            workspace: memory.repeat(index, 0),
        })
    }

    pub(super) fn reset(&mut self, base: u64) {
        let index = self.workspace.header_mut();
        index.base = base;
        index.ranges = Count::ZERO;
    }

    pub(super) fn bytes(&self, span: Span) -> Option<&[u8]> {
        tail::View::new(&self.workspace)
            .as_slice()
            .get(span.range())
    }

    pub(super) fn consume(&mut self, span: Span) -> Result<(), conn::Error> {
        self.workspace
            .header_mut()
            .consume(span.end())
            .ok_or(conn::Error::CryptoBufferExceeded)?;
        Ok(())
    }

    pub(super) fn shadow<'a>(&self, spans: &'a mut Vec<Span>) -> Option<Shadow<'a>> {
        let index = tail::View::new(&self.workspace).header();
        spans.clear();
        let source = index.spans(index.ranges)?;
        let len = source.len();
        if len > spans.capacity() {
            return None;
        }
        // SAFETY: admission bounds this exact source by the exclusive empty
        // vector's spare capacity. The complete copied prefix is published once.
        unsafe {
            spans
                .spare_capacity_mut()
                .get_unchecked_mut(..len)
                .write_copy_of_slice(source);
            spans.set_len(len);
        }
        Some(Shadow {
            base: index.base,
            spans,
        })
    }

    pub(super) fn apply(
        &mut self,
        edit: Insert,
        source: usize,
        body: &[u8],
    ) -> Result<(), conn::Error> {
        let (index, target) = self.workspace.parts_mut();
        edit.write(
            index
                .spans(index.ranges)
                .ok_or(conn::Error::CryptoBufferExceeded)?,
            target,
            body,
            source,
        )
        .ok_or(conn::Error::CryptoBufferExceeded)?;
        index.apply(edit).ok_or(conn::Error::CryptoBufferExceeded)?;
        Ok(())
    }
}

impl<'a> Shadow<'a> {
    pub(super) fn new(base: u64, spans: &'a mut Vec<Span>) -> Self {
        spans.clear();
        Self { base, spans }
    }

    pub(super) fn first(&self) -> Option<Span> {
        self.spans.first().copied()
    }

    pub(super) fn position(&self, offset: u64) -> Result<usize, conn::Error> {
        let Some(position) = offset.checked_sub(self.base) else {
            return Err(conn::Error::CryptoBufferExceeded);
        };
        if position > MAX as u64 {
            return Err(conn::Error::CryptoBufferExceeded);
        }
        Ok(position as usize)
    }

    pub(super) fn stage(&mut self, offset: u64, len: usize) -> Result<Insert, conn::Error> {
        let start = self.position(offset)?;
        let Some(end) = start.checked_add(len).filter(|end| *end <= MAX) else {
            return Err(conn::Error::CryptoBufferExceeded);
        };
        let inserted = Span::new(start, end).ok_or(conn::Error::CryptoBufferExceeded)?;
        let before = self.spans.len();
        let before_n = Count::new(before).ok_or(conn::Error::CryptoBufferExceeded)?;
        let gap = alloc::Gap::partition(self.spans, |span| span.end < inserted.start);
        let first = gap.index();
        let mut merged = inserted;
        let mut tail = first;
        for span in gap.tail() {
            if span.start > merged.end {
                break;
            }
            merged.start = merged.start.min(span.start);
            merged.end = merged.end.max(span.end);
            tail += 1;
        }
        if first == tail && before == ranges::MAX {
            return Err(conn::Error::CryptoBufferExceeded);
        }
        let removed = if first == tail {
            0
        } else {
            tail.checked_sub(first)
                .and_then(|count| count.checked_sub(1))
                .ok_or(conn::Error::CryptoBufferExceeded)?
        };
        let after = before
            .checked_add(usize::from(first == tail))
            .and_then(|count| count.checked_sub(removed))
            .ok_or(conn::Error::CryptoBufferExceeded)?;
        let after_n = Count::new(after).ok_or(conn::Error::CryptoBufferExceeded)?;
        if first == tail {
            gap.try_insert(merged)
                .map_err(|_| conn::Error::CryptoBufferExceeded)?;
        } else {
            merged
                .merge(self.spans, first, tail)
                .ok_or(conn::Error::CryptoBufferExceeded)?;
            self.spans.truncate(after);
        }
        Ok(Insert {
            merged,
            input: inserted,
            before: before_n,
            after: after_n,
            first: first as u16,
            tail: tail as u16,
        })
    }

    pub(super) fn consume(&mut self, end: usize) -> Result<(), conn::Error> {
        let first = self
            .spans
            .first_mut()
            .ok_or(conn::Error::CryptoBufferExceeded)?;
        if first.end() != end {
            let span = Span::new(end, first.end()).ok_or(conn::Error::CryptoBufferExceeded)?;
            *first = span;
            return Ok(());
        }
        let remain = self
            .spans
            .copy_tail(1)
            .ok_or(conn::Error::CryptoBufferExceeded)?
            .len();
        self.spans.truncate(remain);
        Ok(())
    }

    pub(super) fn reset(&mut self, base: u64) -> Result<(), conn::Error> {
        if !self.spans.is_empty() {
            return Err(conn::Error::CryptoBufferExceeded);
        }
        self.base = base;
        Ok(())
    }
}

const _: () = assert!(
    mem::size_of::<Index>() == 2 * mem::size_of::<u64>() + ranges::MAX * mem::size_of::<Span>()
);
const _: () = assert!(mem::size_of::<Fragment>() == mem::size_of::<usize>());
const _: () = assert!(mem::size_of::<Insert>() == 3 * mem::size_of::<u64>());
const _: () = assert!(
    tail::Plan::<Index, u8>::fixed::<MAX>().size()
        == mem::size_of::<Index>() + mem::size_of::<usize>() + MAX
);
