use std::marker;

use crate::wire::frame::{self, decode::error};
use crate::wire::varint;

mod raw;

/// Inclusive absolute ACK interval yielded only by validated topology.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    smallest: u64,
    largest: u64,
}

impl Span {
    pub(crate) const fn smallest(self) -> u64 {
        self.smallest
    }

    pub(crate) const fn largest(self) -> u64 {
        self.largest
    }
}

#[derive(Clone, Copy)]
struct Cursor {
    previous_smallest: u64,
}

impl Cursor {
    fn first(largest: u64, range: u64) -> Result<(Self, Span), error::Fault> {
        let Some(smallest) = largest.checked_sub(range) else {
            return Err(error::Fault::AckFirst { largest, range });
        };
        Ok((
            Self {
                previous_smallest: smallest,
            },
            Span { smallest, largest },
        ))
    }

    fn try_advance(&mut self, gap: varint::VarInt, range: u64) -> Result<Span, error::Fault> {
        let gap = gap.get();
        let Some(largest) = self.previous_smallest.checked_sub(gap + 2) else {
            return Err(error::Fault::AckGap {
                previous_smallest: self.previous_smallest,
                gap,
            });
        };
        let Some(smallest) = largest.checked_sub(range) else {
            return Err(error::Fault::AckRange { largest, range });
        };
        self.previous_smallest = smallest;
        Ok(Span { smallest, largest })
    }

    /// Replay a transition proved by `Validated` without another branch.
    fn advance(&mut self, gap: varint::VarInt, range: u64) -> Span {
        let largest = self.previous_smallest - (gap.get() + 2);
        let smallest = largest - range;
        self.previous_smallest = smallest;
        Span { smallest, largest }
    }
}

fn decode_pair(
    input: &[u8],
    offset: usize,
) -> Result<((varint::VarInt, varint::VarInt), &[u8]), error::Fault> {
    let gap = varint::Decoded::parse(input).map_err(|source| error::Fault::VarInt {
        offset,
        source: source.into(),
    })?;
    let at = offset.saturating_add(input.len() - gap.rest().len());
    let range = varint::Decoded::parse(gap.rest()).map_err(|source| error::Fault::VarInt {
        offset: at,
        source: source.into(),
    })?;
    Ok(((gap.value(), range.value()), range.rest()))
}

fn checked_count(count: u64) -> Result<u16, error::Fault> {
    if count > frame::MAX_ADDITIONAL_ACK_RANGES as u64 {
        return Err(error::Fault::AckCount {
            actual: count,
            maximum: frame::MAX_ADDITIONAL_ACK_RANGES as u64,
        });
    }
    Ok(count as u16)
}

/// Checked ACK topology borrowing its authenticated packet backing.
#[must_use = "validated ACK topology must be consumed or explicitly discarded"]
pub(crate) struct Validated<'wire> {
    input: &'wire [u8],
    remaining: u16,
    first: Span,
}

impl<'wire> Validated<'wire> {
    pub(in crate::wire::frame) const fn count(&self) -> u16 {
        self.remaining
    }

    pub(crate) const fn largest(&self) -> u64 {
        self.first.largest
    }

    pub(crate) fn into_ranges(self) -> Set<'wire> {
        Set {
            input: self.input,
            remaining: self.remaining,
        }
    }

    pub(crate) fn spans(self) -> (Span, Spans<'wire>) {
        let first = self.first;
        (
            first,
            Spans {
                pairs: self.into_ranges(),
                cursor: Cursor {
                    previous_smallest: first.smallest,
                },
            },
        )
    }

    /// Record compact topology while the ingress plan retains its body owner.
    pub(crate) fn record<'id>(
        self,
        body: &frame::Body<'_, 'id>,
    ) -> Result<Proof<'id>, error::Fault> {
        let range = body.locate(self.input);
        if range.start > u16::MAX as usize || self.input.len() > u16::MAX as usize {
            return Err(error::Fault::AckStorage {
                body: body.len(),
                offset: range.start,
                length: self.input.len(),
                maximum: u16::MAX as usize,
            });
        }
        Ok(Proof {
            largest: self.first.largest,
            first_smallest: self.first.smallest,
            start: range.start as u16,
            len: self.input.len() as u16,
            count: self.remaining,
            brand: marker::PhantomData,
        })
    }
}

/// Compact, allocation-free proof stored between ingress plan and commit.
/// Its fields are private so byte offsets and topology evidence cannot diverge.
pub(crate) struct Proof<'id> {
    largest: u64,
    first_smallest: u64,
    start: u16,
    len: u16,
    count: u16,
    brand: marker::PhantomData<*mut &'id ()>,
}

impl<'id> Proof<'id> {
    /// Project the proof through the body retained by the same ingress plan.
    pub(crate) fn resolve<'wire>(&self, body: &frame::Body<'wire, 'id>) -> Validated<'wire> {
        Validated {
            input: body.get(self),
            remaining: self.count,
            first: Span {
                smallest: self.first_smallest,
                largest: self.largest,
            },
        }
    }
}

/// Raw relative ranges exposed by the borrowed frame-decoding API.
///
/// Values of this type can only originate from a completely validated ACK
/// topology, and the iterator remains tied to the input packet lifetime.
#[derive(Clone, PartialEq, Eq)]
pub struct Set<'wire> {
    input: &'wire [u8],
    remaining: u16,
}

impl Iterator for Set<'_> {
    type Item = (varint::VarInt, varint::VarInt);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        // SAFETY: construction validated every pair in this exact immutable
        // extent. A compact Proof can restore it only through the same Body
        // identity. The remaining count therefore admits both next varints;
        // advancing to the second rest preserves that proof for the suffix.
        let (gap, range) = unsafe {
            let gap = varint::raw::replay(self.input);
            let range = varint::raw::replay(gap.rest());
            (gap, range)
        };
        self.input = range.rest();
        self.remaining -= 1;
        Some((gap.value(), range.value()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining as usize;
        (len, Some(len))
    }
}

impl ExactSizeIterator for Set<'_> {}

/// Consuming iterator over validated additional absolute ACK spans.
pub(crate) struct Spans<'wire> {
    pairs: Set<'wire>,
    cursor: Cursor,
}

impl Iterator for Spans<'_> {
    type Item = Span;

    fn next(&mut self) -> Option<Self::Item> {
        let (gap, range) = self.pairs.next()?;
        Some(self.cursor.advance(gap, range.get()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.pairs.size_hint()
    }
}

impl ExactSizeIterator for Spans<'_> {}

/// Validate and borrow all additional ACK range bytes in one mandatory decode
/// pass. The returned proof is the sole constructor path for `Validated`.
pub(in crate::wire::frame) fn validate<'wire>(
    source: &mut &'wire [u8],
    offset: usize,
    count: varint::VarInt,
    largest: varint::VarInt,
    range: varint::VarInt,
) -> Result<Validated<'wire>, error::Fault> {
    let input = *source;
    let count = checked_count(count.get())?;
    let (mut cursor, first) = Cursor::first(largest.get(), range.get())?;
    let mut rest = input;
    let mut parsed = 0;
    while parsed < count {
        let ((gap, range), tail) =
            decode_pair(rest, offset.saturating_add(input.len() - rest.len()))?;
        cursor.try_advance(gap, range.get())?;
        rest = tail;
        parsed += 1;
    }
    let consumed = input.len() - rest.len();
    // SAFETY: every pair decoder retains the actual suffix of its borrowed
    // input. The unchanged original owner therefore contains this prefix.
    let bytes = unsafe { input.get_unchecked(..consumed) };
    *source = rest;
    Ok(Validated {
        input: bytes,
        remaining: count,
        first,
    })
}

/// Use the same authoritative topology state machine for public frame encode.
pub(in crate::wire::frame) fn validate_pairs(
    largest: varint::VarInt,
    first: varint::VarInt,
    pairs: &[(varint::VarInt, varint::VarInt)],
) -> Result<u16, error::Fault> {
    let count = checked_count(pairs.len() as u64)?;
    let (mut cursor, _) = Cursor::first(largest.get(), first.get())?;
    for &(gap, range) in pairs {
        cursor.try_advance(gap, range.get())?;
    }
    Ok(count)
}

const _: () = assert!(std::mem::size_of::<Proof<'_>>() == 24);
