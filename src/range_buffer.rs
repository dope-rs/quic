use std::ops;

use crate::stream;
use crate::stream::ReadyBuffer as _;
use crate::stream::ReceiveBuffer as _;

pub(crate) const MAX_RANGES: usize = 256;
const NONE: u32 = u32::MAX;

#[derive(Debug)]
pub struct ReadySegments {
    head: u32,
    tail: u32,
    bytes: usize,
    segments: usize,
}

impl Default for ReadySegments {
    fn default() -> Self {
        Self {
            head: NONE,
            tail: NONE,
            bytes: 0,
            segments: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InsertError {
    BufferFull,
    TooManyRanges,
    OffsetOverflow,
}

#[derive(Clone, Copy)]
pub(crate) struct InsertLimits {
    max_bytes: usize,
    max_ranges: usize,
}

impl InsertLimits {
    pub(crate) const fn new(max_bytes: usize, max_ranges: usize) -> Self {
        Self {
            max_bytes,
            max_ranges,
        }
    }
}

pub(crate) struct InsertData<T> {
    source: T,
    offset: u64,
    len: usize,
}

impl<T> InsertData<T> {
    pub(crate) const fn new(offset: u64, len: usize, source: T) -> Self {
        Self {
            source,
            offset,
            len,
        }
    }
}

struct InsertContext<'a, B: stream::ReceiveBuffer> {
    arena: &'a mut Arena<B>,
    parts: &'a mut Vec<(u64, ops::Range<usize>)>,
    limits: InsertLimits,
}

fn collect_missing(
    parts: &mut Vec<(u64, ops::Range<usize>)>,
    segments: impl IntoIterator<Item = Result<ops::Range<u64>, InsertError>>,
    offset: u64,
    end: u64,
    data_len: usize,
    next: u64,
    part_capacity: usize,
) -> Result<(), InsertError> {
    parts.clear();
    let mut cursor = offset.max(next);
    for segment in segments {
        let segment = segment?;
        if segment.end <= cursor {
            continue;
        }
        if segment.start >= end {
            break;
        }
        if segment.start > cursor {
            if parts.len() == part_capacity {
                return Err(InsertError::TooManyRanges);
            }
            let part_end = segment.start.min(end);
            let from = usize::try_from(cursor - offset).map_err(|_| InsertError::OffsetOverflow)?;
            let to = usize::try_from(part_end - offset).map_err(|_| InsertError::OffsetOverflow)?;
            parts.push((cursor, from..to));
        }
        cursor = cursor.max(segment.end);
        if cursor >= end {
            break;
        }
    }
    if cursor < end {
        if parts.len() == part_capacity {
            return Err(InsertError::TooManyRanges);
        }
        let from = usize::try_from(cursor - offset).map_err(|_| InsertError::OffsetOverflow)?;
        parts.push((cursor, from..data_len));
    }
    Ok(())
}

struct Node<B> {
    start: u64,
    bytes: Option<B>,
    next: u32,
}

/// One fixed node allocation shared by every receive stream on a connection.
///
/// A stream owns only an intrusive head index. Retained packet owners remain
/// in their natural `B` values, while metadata slots move between streams
/// without allocation.
pub struct Arena<B: stream::ReceiveBuffer> {
    nodes: Vec<Node<B>>,
    free: u32,
    live: usize,
    limit: usize,
}

#[derive(Debug)]
pub(crate) struct Store<B: stream::ReceiveBuffer> {
    next: u64,
    buffered: usize,
    head: u32,
    ranges: usize,
    marker: std::marker::PhantomData<fn() -> B>,
}

/// Metadata-only insertion model used to prove a packet's receive commit
/// before any driver-owned range escapes its dispatch turn.
pub(crate) struct Plan<'a> {
    next: u64,
    segments: &'a mut Vec<ops::Range<u64>>,
    parts: &'a mut Vec<(u64, ops::Range<usize>)>,
}

impl<B: stream::ReceiveBuffer> Arena<B> {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(capacity),
            free: NONE,
            live: 0,
            limit: capacity,
        }
    }

    pub(crate) fn remaining_capacity(&self) -> usize {
        self.limit - self.live
    }

    fn node(&self, index: u32) -> &Node<B> {
        debug_assert_ne!(index, NONE);
        &self.nodes[index as usize]
    }

    fn node_mut(&mut self, index: u32) -> &mut Node<B> {
        debug_assert_ne!(index, NONE);
        &mut self.nodes[index as usize]
    }

    fn allocate(&mut self, start: u64, bytes: B, next: u32) -> Result<u32, B> {
        let index = if self.free == NONE {
            if self.nodes.len() == self.limit {
                return Err(bytes);
            }
            let index = self.nodes.len() as u32;
            self.nodes.push(Node {
                start,
                bytes: Some(bytes),
                next,
            });
            index
        } else {
            let index = self.free;
            self.free = self.node(index).next;
            let node = self.node_mut(index);
            node.start = start;
            node.bytes = Some(bytes);
            node.next = next;
            index
        };
        self.live += 1;
        Ok(index)
    }

    fn release(&mut self, index: u32) -> B {
        let free = self.free;
        let node = self.node_mut(index);
        let bytes = node
            .bytes
            .take()
            .expect("a linked range node retains its receive owner");
        node.next = free;
        self.free = index;
        self.live -= 1;
        bytes
    }

    fn ready_push_back(&mut self, ready: &mut ReadySegments, bytes: B) -> Result<(), B> {
        let len = bytes.as_ref().len();
        if len == 0 {
            return Ok(());
        }
        let Some(total) = ready.bytes.checked_add(len) else {
            return Err(bytes);
        };
        let index = self.allocate(0, bytes, NONE)?;
        self.link_ready(ready, index, len, total);
        Ok(())
    }

    fn link_ready(&mut self, ready: &mut ReadySegments, index: u32, len: usize, total: usize) {
        self.node_mut(index).next = NONE;
        if ready.tail == NONE {
            ready.head = index;
        } else {
            self.node_mut(ready.tail).next = index;
        }
        ready.tail = index;
        ready.bytes = total;
        ready.segments += 1;
        debug_assert_eq!(
            self.node(index)
                .bytes
                .as_ref()
                .map(|bytes| bytes.as_ref().len()),
            Some(len)
        );
    }

    pub(crate) fn ready_pop_front(&mut self, ready: &mut ReadySegments) -> Option<B> {
        let index = ready.head;
        if index == NONE {
            return None;
        }
        let next = self.node(index).next;
        let bytes = self.release(index);
        ready.head = next;
        ready.segments -= 1;
        ready.bytes -= bytes.as_ref().len();
        if next == NONE {
            ready.tail = NONE;
        }
        Some(bytes)
    }

    pub(crate) fn ready_clear(&mut self, ready: &mut ReadySegments) {
        while let Some(bytes) = self.ready_pop_front(ready) {
            drop(bytes);
        }
    }
}

impl ReadySegments {
    pub(crate) const fn len(&self) -> usize {
        self.bytes
    }

    pub(crate) const fn segment_count(&self) -> usize {
        self.segments
    }

    pub(crate) fn push_back<B: stream::ReceiveBuffer>(
        &mut self,
        arena: &mut Arena<B>,
        bytes: B,
    ) -> Result<(), B> {
        arena.ready_push_back(self, bytes)
    }

    pub(crate) fn pop_front<B: stream::ReceiveBuffer>(
        &mut self,
        arena: &mut Arena<B>,
    ) -> Option<B> {
        arena.ready_pop_front(self)
    }

    pub(crate) fn clear<B: stream::ReceiveBuffer>(&mut self, arena: &mut Arena<B>) {
        arena.ready_clear(self);
    }
}

impl<B: stream::ReceiveBuffer> Default for Store<B> {
    fn default() -> Self {
        Self {
            next: 0,
            buffered: 0,
            head: NONE,
            ranges: 0,
            marker: std::marker::PhantomData,
        }
    }
}

impl<B: stream::ReceiveBuffer> Store<B> {
    pub(crate) fn plan<'a>(
        &self,
        arena: &Arena<B>,
        segments: &'a mut Vec<ops::Range<u64>>,
        parts: &'a mut Vec<(u64, ops::Range<usize>)>,
    ) -> Plan<'a> {
        segments.clear();
        let mut current = self.head;
        while current != NONE {
            let node = arena.node(current);
            let bytes = node
                .bytes
                .as_ref()
                .expect("a linked range node retains its receive owner");
            segments.push(
                node.start
                    ..node
                        .start
                        .checked_add(bytes.as_ref().len() as u64)
                        .expect("stored receive ranges have validated ends"),
            );
            current = node.next;
        }
        parts.clear();
        Plan {
            next: self.next,
            segments,
            parts,
        }
    }

    pub(crate) fn range_count(&self) -> usize {
        self.ranges
    }

    pub(crate) fn recycle(&mut self, arena: &mut Arena<B>) {
        let mut current = self.head;
        while current != NONE {
            let next = arena.node(current).next;
            drop(arena.release(current));
            current = next;
        }
        self.next = 0;
        self.buffered = 0;
        self.head = NONE;
        self.ranges = 0;
    }

    pub(crate) fn insert_and_drain_into(
        &mut self,
        arena: &mut Arena<B>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
        offset: u64,
        data: B,
        limits: InsertLimits,
        output: &mut B::Ready,
    ) -> Result<(), InsertError> {
        let end = offset
            .checked_add(
                u64::try_from(data.as_ref().len()).map_err(|_| InsertError::OffsetOverflow)?,
            )
            .ok_or(InsertError::OffsetOverflow)?;
        let overlaps_buffered_range = self.has_start_in(arena, self.next, end);
        if offset <= self.next && end > self.next && !overlaps_buffered_range {
            let skip =
                usize::try_from(self.next - offset).map_err(|_| InsertError::OffsetOverflow)?;
            output
                .try_push_back(arena, data.into_suffix(skip))
                .map_err(|_| InsertError::BufferFull)?;
            self.next = end;
        } else {
            self.insert(offset, data, limits, arena, parts)?;
        }
        self.drain_contiguous_into(arena, output);
        Ok(())
    }

    pub(crate) fn insert(
        &mut self,
        offset: u64,
        data: B,
        limits: InsertLimits,
        arena: &mut Arena<B>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
    ) -> Result<(), InsertError> {
        let len = data.as_ref().len();
        self.insert_with(
            InsertData::new(offset, len, data),
            InsertContext {
                arena,
                parts,
                limits,
            },
            |data, range| data.slice(range),
            |data, range| data.into_range(range),
        )
    }

    fn insert_with<T>(
        &mut self,
        data: InsertData<T>,
        context: InsertContext<'_, B>,
        mut slice: impl FnMut(&T, ops::Range<usize>) -> B,
        take: impl FnOnce(T, ops::Range<usize>) -> B,
    ) -> Result<(), InsertError> {
        let InsertData {
            source,
            offset,
            len: data_len,
        } = data;
        let InsertContext {
            arena,
            parts,
            limits:
                InsertLimits {
                    max_bytes,
                    max_ranges,
                },
        } = context;
        let end = offset
            .checked_add(u64::try_from(data_len).map_err(|_| InsertError::OffsetOverflow)?)
            .ok_or(InsertError::OffsetOverflow)?;
        if data_len == 0 || end <= self.next {
            return Ok(());
        }

        let part_capacity = max_ranges
            .saturating_sub(self.ranges)
            .min(arena.remaining_capacity());
        let mut current = self.head;
        let segments = std::iter::from_fn(|| {
            if current == NONE {
                return None;
            }
            let node = arena.node(current);
            let bytes = node
                .bytes
                .as_ref()
                .expect("a linked range node retains its receive owner");
            let start = node.start;
            let next = node.next;
            let len = match u64::try_from(bytes.as_ref().len()) {
                Ok(len) => len,
                Err(_) => return Some(Err(InsertError::OffsetOverflow)),
            };
            current = next;
            Some(
                start
                    .checked_add(len)
                    .ok_or(InsertError::OffsetOverflow)
                    .map(|end| start..end),
            )
        });
        collect_missing(
            parts,
            segments,
            offset,
            end,
            data_len,
            self.next,
            part_capacity,
        )?;
        if parts.is_empty() {
            return Ok(());
        }

        let added = parts.iter().try_fold(0usize, |total, (_, range)| {
            total
                .checked_add(range.len())
                .ok_or(InsertError::BufferFull)
        })?;
        let buffered = self
            .buffered
            .checked_add(added)
            .ok_or(InsertError::BufferFull)?;
        if buffered > max_bytes {
            return Err(InsertError::BufferFull);
        }
        if self
            .ranges
            .checked_add(parts.len())
            .is_none_or(|ranges| ranges > max_ranges)
            || parts.len() > arena.remaining_capacity()
        {
            return Err(InsertError::TooManyRanges);
        }

        let Some((last_start, last_range)) = parts.pop() else {
            return Ok(());
        };
        let mut previous = NONE;
        let mut current = self.head;
        for (part_start, range) in parts.drain(..) {
            let bytes = slice(&source, range);
            self.insert_reserved(arena, part_start, bytes, &mut previous, &mut current);
        }
        self.insert_reserved(
            arena,
            last_start,
            take(source, last_range),
            &mut previous,
            &mut current,
        );
        self.buffered = buffered;
        Ok(())
    }

    fn insert_reserved(
        &mut self,
        arena: &mut Arena<B>,
        start: u64,
        bytes: B,
        previous: &mut u32,
        current: &mut u32,
    ) {
        while *current != NONE && arena.node(*current).start < start {
            *previous = *current;
            *current = arena.node(*current).next;
        }
        let inserted = arena
            .allocate(start, bytes, *current)
            .unwrap_or_else(|_| unreachable!("the receive plan reserved every range node"));
        if *previous == NONE {
            self.head = inserted;
        } else {
            arena.node_mut(*previous).next = inserted;
        }
        *previous = inserted;
        self.ranges += 1;
    }

    fn has_start_in(&self, arena: &Arena<B>, start: u64, end: u64) -> bool {
        let mut current = self.head;
        while current != NONE {
            let node = arena.node(current);
            if node.start >= end {
                return false;
            }
            if node.start >= start {
                return true;
            }
            current = node.next;
        }
        false
    }

    pub(crate) fn drain_contiguous_into(&mut self, arena: &mut Arena<B>, output: &mut B::Ready) {
        while self.head != NONE {
            let start = arena.node(self.head).start;
            if start > self.next {
                break;
            }
            let index = self.head;
            self.head = arena.node(index).next;
            let segment = arena.release(index);
            self.ranges -= 1;
            self.buffered -= segment.as_ref().len();
            let end = start + segment.as_ref().len() as u64;
            if end > self.next {
                let skip = (self.next - start) as usize;
                if output
                    .try_push_back(arena, segment.into_suffix(skip))
                    .is_err()
                {
                    unreachable!("range byte length was already validated");
                }
                self.next = end;
            }
        }
    }
}

impl Plan<'_> {
    pub(crate) fn empty<'a>(
        segments: &'a mut Vec<ops::Range<u64>>,
        parts: &'a mut Vec<(u64, ops::Range<usize>)>,
    ) -> Plan<'a> {
        segments.clear();
        parts.clear();
        Plan {
            next: 0,
            segments,
            parts,
        }
    }

    pub(crate) fn range_count(&self) -> usize {
        self.segments.len()
    }

    /// Applies the bounded range transition while
    /// exposing each newly accepted source subrange before the scratch parts
    /// are consumed. This lets a compact owner be materialized without
    /// retaining an unbounded fragment journal.
    pub(crate) fn insert_observed<E>(
        &mut self,
        offset: u64,
        len: usize,
        max_ranges: usize,
        mut observe: impl FnMut(ops::Range<usize>) -> Result<(), E>,
    ) -> Result<usize, E>
    where
        E: From<InsertError>,
    {
        let end = offset
            .checked_add(u64::try_from(len).map_err(|_| E::from(InsertError::OffsetOverflow))?)
            .ok_or_else(|| E::from(InsertError::OffsetOverflow))?;
        if len == 0 || end <= self.next {
            return Ok(0);
        }

        let overlaps_buffered_range = end > self.next
            && self
                .segments
                .iter()
                .any(|segment| segment.start >= self.next && segment.start < end);
        if offset <= self.next && !overlaps_buffered_range {
            let from = usize::try_from(self.next - offset)
                .map_err(|_| E::from(InsertError::OffsetOverflow))?;
            let accepted = len - from;
            observe(from..len)?;
            self.next = end;
            self.drain_contiguous();
            return Ok(accepted);
        }

        let part_capacity = max_ranges.saturating_sub(self.segments.len());
        collect_missing(
            self.parts,
            self.segments.iter().cloned().map(Ok),
            offset,
            end,
            len,
            self.next,
            part_capacity,
        )
        .map_err(E::from)?;
        if self.parts.is_empty() {
            return Ok(0);
        }
        if self
            .segments
            .len()
            .checked_add(self.parts.len())
            .is_none_or(|ranges| ranges > max_ranges)
        {
            return Err(E::from(InsertError::TooManyRanges));
        }

        let accepted = self.parts.iter().try_fold(0usize, |total, (_, bytes)| {
            total
                .checked_add(bytes.len())
                .ok_or_else(|| E::from(InsertError::BufferFull))
        })?;
        for (_, bytes) in self.parts.iter() {
            observe(bytes.clone())?;
        }
        for (start, bytes) in self.parts.drain(..) {
            let end = start
                .checked_add(
                    u64::try_from(bytes.len()).map_err(|_| E::from(InsertError::OffsetOverflow))?,
                )
                .ok_or_else(|| E::from(InsertError::OffsetOverflow))?;
            let part = start..end;
            let at = self
                .segments
                .binary_search_by_key(&part.start, |segment| segment.start)
                .unwrap_or_else(|at| at);
            self.segments.insert(at, part);
        }
        self.drain_contiguous();
        Ok(accepted)
    }

    fn drain_contiguous(&mut self) {
        let mut drained = 0;
        for segment in self.segments.iter() {
            if segment.start > self.next {
                break;
            }
            self.next = self.next.max(segment.end);
            drained += 1;
        }
        if drained != 0 {
            self.segments.drain(..drained);
        }
    }
}

impl Store<Vec<u8>> {
    fn insert_copy(
        &mut self,
        offset: u64,
        data: &[u8],
        limits: InsertLimits,
        arena: &mut Arena<Vec<u8>>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
    ) -> Result<(), InsertError> {
        let len = data.len();
        self.insert_with(
            InsertData::new(offset, len, data),
            InsertContext {
                arena,
                parts,
                limits,
            },
            |data, range| data[range].to_vec(),
            |data, range| data[range].to_vec(),
        )
    }

    pub(crate) fn insert_copy_and_drain_into(
        &mut self,
        arena: &mut Arena<Vec<u8>>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
        offset: u64,
        data: &[u8],
        limits: InsertLimits,
        output: &mut Vec<u8>,
    ) -> Result<(), InsertError> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| InsertError::OffsetOverflow)?)
            .ok_or(InsertError::OffsetOverflow)?;
        let overlaps_buffered_range = self.has_start_in(arena, self.next, end);
        if offset <= self.next && end > self.next && !overlaps_buffered_range {
            let skip =
                usize::try_from(self.next - offset).map_err(|_| InsertError::OffsetOverflow)?;
            output.extend_from_slice(&data[skip..]);
            self.next = end;
        } else {
            self.insert_copy(offset, data, limits, arena, parts)?;
        }
        self.drain_copy_into(arena, output);
        Ok(())
    }

    fn drain_copy_into(&mut self, arena: &mut Arena<Vec<u8>>, output: &mut Vec<u8>) {
        while self.head != NONE {
            let start = arena.node(self.head).start;
            if start > self.next {
                break;
            }
            let index = self.head;
            self.head = arena.node(index).next;
            let segment = arena.release(index);
            self.ranges -= 1;
            self.buffered -= segment.len();
            let end = start + segment.len() as u64;
            if end > self.next {
                let skip = (self.next - start) as usize;
                output.extend_from_slice(&segment[skip..]);
                self.next = end;
            }
        }
    }
}

impl<'d> Store<stream::RecvBuffer<'d>> {
    pub(crate) fn insert_retained_and_drain_into(
        &mut self,
        arena: &mut Arena<stream::RecvBuffer<'d>>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
        offset: u64,
        data: stream::RecvBuffer<'d>,
        limits: InsertLimits,
        output: &mut ReadySegments,
    ) -> Result<(), InsertError> {
        let end = offset
            .checked_add(
                u64::try_from(data.as_ref().len()).map_err(|_| InsertError::OffsetOverflow)?,
            )
            .ok_or(InsertError::OffsetOverflow)?;
        let overlaps_buffered_range = self.has_start_in(arena, self.next, end);
        if offset <= self.next && end > self.next && !overlaps_buffered_range {
            let skip =
                usize::try_from(self.next - offset).map_err(|_| InsertError::OffsetOverflow)?;
            output
                .push_back(arena, data.into_suffix(skip))
                .map_err(|_| InsertError::BufferFull)?;
            self.next = end;
        } else {
            self.insert(offset, data, limits, arena, parts)?;
        }
        self.drain_contiguous_into_ready(arena, output)?;
        Ok(())
    }

    /// Inserts bytes that were compacted from only the source ranges accepted
    /// by the packet plan. `data_len` remains the original STREAM frame length;
    /// `data` is the concatenation of its accepted parts in range order.
    pub(crate) fn insert_compact_and_drain_into(
        &mut self,
        arena: &mut Arena<stream::RecvBuffer<'d>>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
        data: InsertData<o3::buffer::storage::Shared>,
        limits: InsertLimits,
        output: &mut ReadySegments,
    ) -> Result<(), InsertError> {
        let InsertData {
            source: data,
            offset,
            len: data_len,
        } = data;
        let end = offset
            .checked_add(u64::try_from(data_len).map_err(|_| InsertError::OffsetOverflow)?)
            .ok_or(InsertError::OffsetOverflow)?;
        let compact_len = data.len();
        let overlaps_buffered_range = self.has_start_in(arena, self.next, end);
        if data_len != 0 && offset <= self.next && end > self.next && !overlaps_buffered_range {
            let accepted =
                usize::try_from(end - self.next).map_err(|_| InsertError::OffsetOverflow)?;
            debug_assert_eq!(compact_len, accepted);
            if compact_len != accepted {
                return Err(InsertError::BufferFull);
            }
            output
                .push_back(arena, stream::RecvBuffer::compact(data))
                .map_err(|_| InsertError::BufferFull)?;
            self.next = end;
        } else {
            use std::cell::Cell;

            let cursor = Cell::new(0usize);
            self.insert_with(
                InsertData::new(offset, data_len, data),
                InsertContext {
                    arena,
                    parts,
                    limits,
                },
                |data, range| {
                    let start = cursor.get();
                    let end = start + range.len();
                    cursor.set(end);
                    stream::RecvBuffer::compact(
                        data.get(start..end)
                            .expect("the receive plan bounded every compact part"),
                    )
                },
                |mut data, range| {
                    let start = cursor.get();
                    let end = start + range.len();
                    cursor.set(end);
                    debug_assert_eq!(end, data.len());
                    if start != 0 {
                        assert!(data.try_advance(start));
                    }
                    stream::RecvBuffer::compact(data)
                },
            )?;
            debug_assert_eq!(cursor.get(), compact_len);
            if cursor.get() != compact_len {
                return Err(InsertError::BufferFull);
            }
        }
        self.drain_contiguous_into_ready(arena, output)?;
        Ok(())
    }

    fn drain_contiguous_into_ready(
        &mut self,
        arena: &mut Arena<stream::RecvBuffer<'d>>,
        output: &mut ReadySegments,
    ) -> Result<(), InsertError> {
        while self.head != NONE {
            let start = arena.node(self.head).start;
            if start > self.next {
                break;
            }
            let index = self.head;
            self.head = arena.node(index).next;
            self.ranges -= 1;
            let original_len = arena
                .node(index)
                .bytes
                .as_ref()
                .expect("a linked range node retains its receive owner")
                .len();
            self.buffered -= original_len;
            let end = start
                .checked_add(u64::try_from(original_len).map_err(|_| InsertError::OffsetOverflow)?)
                .ok_or(InsertError::OffsetOverflow)?;
            if end <= self.next {
                drop(arena.release(index));
                continue;
            }
            let skip =
                usize::try_from(self.next - start).map_err(|_| InsertError::OffsetOverflow)?;
            if skip != 0 {
                let bytes = arena
                    .node_mut(index)
                    .bytes
                    .take()
                    .expect("a linked range node retains its receive owner")
                    .into_suffix(skip);
                arena.node_mut(index).bytes = Some(bytes);
            }
            let len = usize::try_from(end - self.next).map_err(|_| InsertError::OffsetOverflow)?;
            let total = output
                .bytes
                .checked_add(len)
                .ok_or(InsertError::BufferFull)?;
            arena.link_ready(output, index, len, total);
            self.next = end;
        }
        Ok(())
    }
}
