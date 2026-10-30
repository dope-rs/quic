use crate::errors::detail;
use std::{mem, ops, ptr, slice};

use o3::alloc::{self, VecExt as _};
use o3::depot::array::copy;

use crate::conn::stream::state::receive::recv::map;
use crate::stream;
use crate::wire::{
    ranges::{self, inserts},
    varint,
};
use map::ready;

/// Metadata commit proof keeping driver-owned ranges within their dispatch turn.
/// Segments remain sorted gaps strictly beyond `next` between operations.
/// Prefix pieces use no gap slots; their independent `MAX` bound fits replay scratch.
pub(crate) struct Plan<'a> {
    next: u64,
    segments: &'a mut Vec<ops::Range<u64>>,
    parts: &'a mut Vec<inserts::Part>,
}

pub(crate) struct Added {
    record: Record,
}

pub(crate) enum Piece<'body, B: stream::Recv> {
    Ready {
        part: inserts::Part,
        bytes: <B::Ready as ready::raw::Queue<B>>::Input<'body>,
    },
    Gap {
        part: inserts::Part,
        bytes: stream::Projection<B>,
    },
}

impl<'body, B: stream::Recv> Piece<'body, B> {
    fn try_new(
        part: inserts::Part,
        place: Placement,
        payload: stream::Payload<'body, stream::Projection<B>>,
    ) -> Result<Self, stream::Capacity> {
        Ok(match place {
            Placement::Ready => Self::Ready {
                part,
                bytes: <B::Ready as ready::raw::Queue<B>>::try_prepare(payload)?,
            },
            Placement::Gap => Self::Gap {
                part,
                bytes: payload.try_owned()?,
            },
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Ready { bytes, .. } => bytes.as_ref(),
            Self::Gap { bytes, .. } => bytes.as_ref(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Placement {
    Ready,
    Gap,
}

pub(crate) enum Prepared<'body, B: stream::Recv> {
    Empty,
    One(Piece<'body, B>),
    Many(Vec<Piece<'body, B>>),
}

#[derive(Clone, Copy)]
struct Span {
    part: inserts::Part,
    place: Placement,
}

impl Span {
    const fn new(part: inserts::Part, place: Placement) -> Self {
        Self { part, place }
    }

    fn slice<'body, B: stream::Recv>(
        self,
        data: &stream::Payload<'body, B>,
        layout: stream::Layout,
    ) -> Result<Piece<'body, B>, stream::Capacity> {
        Piece::try_new(
            self.part,
            self.place,
            data.try_slice(self.part.extent(layout))?,
        )
    }

    fn project<'body, B: stream::Recv>(
        self,
        data: stream::Payload<'body, B>,
        layout: stream::Layout,
    ) -> Result<Piece<'body, B>, stream::Capacity> {
        Piece::try_new(
            self.part,
            self.place,
            data.try_project(self.part.extent(layout))?,
        )
    }
}

impl<'body, B: stream::Recv> Prepared<'body, B> {
    fn pieces(&self) -> &[Piece<'body, B>] {
        match self {
            Self::Empty => &[],
            Self::One(piece) => slice::from_ref(piece),
            Self::Many(pieces) => pieces,
        }
    }

    pub(crate) fn has_ready(&self) -> bool {
        self.pieces()
            .iter()
            .any(|piece| matches!(piece, Piece::Ready { .. }))
    }

    pub(crate) fn consume(self, mut consume: impl FnMut(Piece<'body, B>)) {
        match self {
            Self::Empty => {}
            Self::One(piece) => consume(piece),
            Self::Many(pieces) => {
                for piece in pieces {
                    consume(piece);
                }
            }
        }
    }

    fn try_append(
        &mut self,
        spans: &[Span],
        data: stream::Payload<'body, B>,
        layout: stream::Layout,
    ) -> Result<(), ranges::Error> {
        use o3::alloc::raw::VecExt as _;

        let Some((last, prefix)) = spans.split_last() else {
            return Ok(());
        };
        if matches!(self, Self::Empty) && prefix.is_empty() {
            *self = Self::One(last.project(data, layout)?);
            return Ok(());
        }
        let count = spans.len();
        let append = |pieces: &mut Vec<Piece<'body, B>>| -> Result<(), ranges::Error> {
            for span in prefix {
                let piece = span.slice(&data, layout)?;
                // SAFETY: both callers reserve count = prefix.len() + 1 slots
                // in this exact vector. Each source inserts once; construction
                // cannot access the retained vector or change its capacity.
                unsafe { pieces.vacancy() }.insert(piece);
            }
            let piece = last.project(data, layout)?;
            // SAFETY: the same reservation retains the final source's slot.
            unsafe { pieces.vacancy() }.insert(piece);
            Ok(())
        };
        match self {
            Self::Many(pieces) => {
                pieces
                    .try_grow(count)
                    .map_err(|error| stream::Capacity::Allocation {
                        error,
                        requested: count,
                    })?;
                append(pieces)
            }
            Self::Empty | Self::One(_) => {
                let required = self.pieces().len() + count;
                let mut pieces =
                    Vec::try_new(required).map_err(|error| stream::Capacity::Allocation {
                        error,
                        requested: required,
                    })?;
                if let Self::One(piece) = mem::replace(self, Self::Empty) {
                    // SAFETY: required includes this old owner and all new spans.
                    unsafe { pieces.vacancy() }.insert(piece);
                }
                let result = append(&mut pieces);
                *self = Self::Many(pieces);
                result
            }
        }
    }

    pub(crate) fn slots(&self) -> usize {
        self.pieces()
            .iter()
            .filter(|piece| {
                <B::Ready as ready::raw::Queue<B>>::SEGMENTED || matches!(piece, Piece::Gap { .. })
            })
            .count()
    }

    pub(crate) fn bytes(&self) -> Result<usize, stream::Capacity> {
        self.pieces().iter().try_fold(0usize, |current, piece| {
            let extra = piece.bytes().len();
            current
                .checked_add(extra)
                .ok_or(stream::Capacity::Overflow {
                    current,
                    additional: extra,
                })
        })
    }
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub(crate) struct Record {
    len: u16,
    bytes: u16,
}

impl Added {
    pub(crate) const fn bytes(&self) -> usize {
        self.record.bytes()
    }

    pub(crate) const fn record(&self) -> Record {
        self.record
    }
}

impl Record {
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self {
            len: bits as u16,
            bytes: (bits >> u16::BITS) as u16,
        }
    }

    pub(crate) fn full(len: usize) -> Option<Self> {
        let len = u16::try_from(len).ok()?;
        Some(Self { len, bytes: len })
    }

    pub(crate) const fn len(self) -> usize {
        self.len as usize
    }

    pub(super) const fn bounded_len(self) -> u16 {
        self.len
    }

    pub(crate) const fn bytes(self) -> usize {
        self.bytes as usize
    }

    pub(crate) fn end(self, offset: varint::VarInt) -> u64 {
        offset.get() + u64::from(self.len)
    }

    pub(crate) const fn bits(self) -> u32 {
        self.len as u32 | (self.bytes as u32) << u16::BITS
    }

    fn with_bytes(self, bytes: usize) -> Self {
        Self {
            len: self.len,
            bytes: bytes as u16,
        }
    }

    pub(crate) fn try_copy(
        self,
        plan: &mut Plan<'_>,
        offset: varint::VarInt,
        mut copy: impl FnMut(ops::Range<usize>),
    ) -> Result<(), stream::Capacity> {
        plan.try_copy(offset, self, |part, _place| copy(part.range()))
    }

    pub(crate) fn prepare<'body, B: stream::Recv>(
        self,
        plan: &mut Plan<'_>,
        offset: varint::VarInt,
        data: stream::Payload<'body, B>,
        prepared: &mut Prepared<'body, B>,
    ) -> Result<(), ranges::Error> {
        let mut spans = copy::Vec::<Span, { ranges::MAX }>::new();
        let layout = data.layout();
        let mut full = false;
        plan.try_copy(offset, self, |part, place| {
            let Some(span) = spans.vacancy() else {
                full = true;
                return;
            };
            span.insert(Span::new(part, place));
        })?;
        if full {
            return Err(ranges::Error::Capacity(stream::Capacity::Limit {
                required: spans.len() + 1,
                available: ranges::MAX,
            }));
        }
        prepared.try_append(spans.as_slice(), data, layout)
    }
}

impl Plan<'_> {
    pub(crate) fn empty<'a>(
        segs: &'a mut Vec<ops::Range<u64>>,
        parts: &'a mut Vec<inserts::Part>,
    ) -> Plan<'a> {
        segs.clear();
        parts.clear();
        Plan {
            next: 0,
            segments: segs,
            parts,
        }
    }

    pub(crate) fn new<'a>(
        next: u64,
        segs: &'a mut Vec<ops::Range<u64>>,
        parts: &'a mut Vec<inserts::Part>,
    ) -> Plan<'a> {
        Plan {
            next,
            segments: segs,
            parts,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.segments.len()
    }

    fn has_overlap(&self, end: u64) -> bool {
        self.segments.first().is_some_and(|seg| seg.start < end)
    }

    pub(crate) fn try_insert(
        &mut self,
        offset: varint::VarInt,
        record: Record,
    ) -> Result<Added, detail::Ranges> {
        let extent = inserts::Input::new(offset, record);
        if extent.len() == 0 || extent.end() <= self.next {
            return Ok(Added {
                record: record.with_bytes(0),
            });
        }

        let prefix = extent.start() <= self.next;
        if prefix && !self.has_overlap(extent.end()) {
            let bytes = extent.part(self.next..extent.end(), 0).len();
            self.next = extent.end();
            Self::drain(&mut self.next, self.segments);
            return Ok(Added {
                record: record.with_bytes(bytes),
            });
        }

        let cap = if prefix {
            ranges::MAX
        } else {
            ranges::MAX - self.segments.len()
        };
        inserts::try_collect(
            self.parts,
            self.segments.iter().cloned(),
            extent,
            self.next,
            cap,
            |current, capacity| detail::Ranges::Ranges {
                current,
                additional: 1,
                capacity,
            },
        )?;
        if self.parts.is_empty() {
            return Ok(Added {
                record: record.with_bytes(0),
            });
        }

        let bytes = self.parts.iter().map(|part| part.len()).sum();
        if prefix {
            self.parts.clear();
            self.next = extent.end();
            Self::drain(&mut self.next, self.segments);
        } else {
            for added in self.parts.drain(..) {
                let part = added.start()..added.end();
                alloc::Gap::partition(self.segments, |seg| seg.start < part.start)
                    .try_insert(part)
                    .map_err(|_| detail::Ranges::Ranges {
                        current: self.segments.len(),
                        additional: 1,
                        capacity: self.segments.capacity(),
                    })?;
            }
        }
        Ok(Added {
            record: record.with_bytes(bytes),
        })
    }

    fn try_copy(
        &mut self,
        offset: varint::VarInt,
        record: Record,
        mut copy: impl FnMut(inserts::Part, Placement),
    ) -> Result<(), stream::Capacity> {
        let extent = inserts::Input::new(offset, record);
        if extent.len() == 0 || extent.end() <= self.next {
            return Ok(());
        }

        if extent.start() <= self.next && !self.has_overlap(extent.end()) {
            copy(extent.part(self.next..extent.end(), 0), Placement::Ready);
            self.next = extent.end();
            Self::drain(&mut self.next, self.segments);
            return Ok(());
        }

        let cap = self.parts.capacity();
        inserts::try_collect(
            self.parts,
            self.segments.iter().cloned(),
            extent,
            self.next,
            cap,
            |current, bound| stream::Capacity::Limit {
                required: current + 1,
                available: bound,
            },
        )?;
        if self.parts.is_empty() {
            return Ok(());
        }

        for part in self.parts.drain(..) {
            let start = part.start();
            let end = part.end();
            if start == self.next {
                copy(part, Placement::Ready);
                self.next = end;
                Self::drain(&mut self.next, self.segments);
                continue;
            }
            copy(part, Placement::Gap);
            let part = start..end;
            alloc::Gap::partition(self.segments, |seg| seg.start < part.start)
                .try_insert(part)
                .map_err(|_| stream::Capacity::Limit {
                    required: self.segments.len() + 1,
                    available: self.segments.capacity(),
                })?;
        }
        Ok(())
    }

    fn drain(next: &mut u64, segments: &mut Vec<ops::Range<u64>>) {
        let mut count = 0;
        for seg in segments.iter() {
            if seg.start > *next {
                break;
            }
            *next = (*next).max(seg.end);
            count += 1;
        }
        if count != 0 {
            let keep = segments.len() - count;
            // SAFETY: traversal counted a prefix of this unchanged exclusive
            // vector. Range<u64> owns no drop state. Moving the retained suffix
            // and shortening the initialized length removes exactly that prefix.
            unsafe {
                let base = segments.as_mut_ptr();
                ptr::copy(base.add(count), base, keep);
                segments.set_len(keep);
            }
        }
    }
}

const _: () = assert!(usize::BITS <= u64::BITS);
const _: () = assert!(std::mem::size_of::<Record>() == 2 * std::mem::size_of::<u16>());
const _: () = assert!(std::mem::size_of::<Span>() <= 3 * std::mem::size_of::<usize>());
