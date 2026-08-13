use super::Error;
use crate::range_buffer::MAX_RANGES;
use std::mem::MaybeUninit;

const MAX_CRYPTO_BUFFERED: usize = 64 * 1024;
const STORAGE_WORDS: usize = MAX_CRYPTO_BUFFERED / size_of::<u64>();
const WORKSPACE_WORDS: usize = STORAGE_WORDS + MAX_RANGES;

#[derive(Clone, Copy)]
struct Span {
    start: u32,
    end: u32,
}

struct Fragmented {
    base: u64,
    words: Vec<MaybeUninit<u64>>,
    ranges: u16,
}

#[derive(Default)]
pub(super) struct Crypto {
    next: u64,
    fragmented: Option<Fragmented>,
}

impl Crypto {
    /// Preflights every CRYPTO frame from one packet. A fragmented path
    /// acquires its one fixed workspace before packet commit mutates state.
    pub(super) fn prepare<'a>(
        &mut self,
        frames: impl IntoIterator<Item = (u64, &'a [u8])>,
    ) -> Result<(), Error> {
        if self.fragmented.is_some() {
            return Ok(());
        }
        let mut next = self.next;
        for (offset, data) in frames {
            let end = offset
                .checked_add(u64::try_from(data.len()).map_err(|_| Error::CryptoBufferExceeded)?)
                .ok_or(Error::CryptoBufferExceeded)?;
            if data.is_empty() || end <= next {
                continue;
            }
            let skip = usize::try_from(next.saturating_sub(offset))
                .map_err(|_| Error::CryptoBufferExceeded)?;
            let offset = offset.max(next);
            let input = data.get(skip..).ok_or(Error::CryptoBufferExceeded)?;
            let consumed = Self::complete_prefix(next, offset, input)?;
            next = next
                .checked_add(u64::try_from(consumed).map_err(|_| Error::CryptoBufferExceeded)?)
                .ok_or(Error::CryptoBufferExceeded)?;
            if consumed != input.len() {
                self.fragmented = Some(Fragmented::new(self.next)?);
                break;
            }
        }
        Ok(())
    }

    pub(super) fn accept(
        &mut self,
        offset: u64,
        data: &[u8],
        mut consume: impl for<'message> FnMut(&'message [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Error::CryptoBufferExceeded)?)
            .ok_or(Error::CryptoBufferExceeded)?;
        if data.is_empty() || end <= self.next {
            return Ok(());
        }
        let skip = usize::try_from(self.next.saturating_sub(offset))
            .map_err(|_| Error::CryptoBufferExceeded)?;
        let offset = offset.max(self.next);
        let input = data.get(skip..).ok_or(Error::CryptoBufferExceeded)?;

        if self.fragmented.as_ref().is_none_or(Fragmented::is_empty) {
            let consumed = Self::consume_borrowed(self.next, offset, input, &mut consume)?;
            self.next = self
                .next
                .checked_add(u64::try_from(consumed).map_err(|_| Error::CryptoBufferExceeded)?)
                .ok_or(Error::CryptoBufferExceeded)?;
            if consumed == input.len() {
                if let Some(fragmented) = &mut self.fragmented {
                    fragmented.reset(self.next);
                }
                return Ok(());
            }
            let consumed_u64 = u64::try_from(consumed).map_err(|_| Error::CryptoBufferExceeded)?;
            self.fragmented
                .as_mut()
                .ok_or(Error::CryptoBufferExceeded)?
                .buffer(
                    offset
                        .checked_add(consumed_u64)
                        .ok_or(Error::CryptoBufferExceeded)?,
                    &input[consumed..],
                )?;
        } else {
            self.fragmented
                .as_mut()
                .ok_or(Error::CryptoBufferExceeded)?
                .buffer(offset, input)?;
        }
        self.consume_buffered(&mut consume)
    }

    pub(super) fn discard(&mut self) {
        self.next = 0;
        self.fragmented = None;
    }

    fn complete_prefix(next: u64, offset: u64, input: &[u8]) -> Result<usize, Error> {
        if offset != next {
            return Ok(0);
        }
        let mut consumed = 0usize;
        while input.len() - consumed >= 4 {
            let total = Self::message_len(&input[consumed..])?;
            if input.len() - consumed < total {
                break;
            }
            consumed = consumed
                .checked_add(total)
                .ok_or(Error::CryptoBufferExceeded)?;
        }
        Ok(consumed)
    }

    fn consume_borrowed(
        next: u64,
        offset: u64,
        input: &[u8],
        consume: &mut impl for<'message> FnMut(&'message [u8]) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        let consumed = Self::complete_prefix(next, offset, input)?;
        let mut start = 0;
        while start < consumed {
            let total = Self::message_len(&input[start..])?;
            let end = start
                .checked_add(total)
                .ok_or(Error::CryptoBufferExceeded)?;
            consume(&input[start..end])?;
            start = end;
        }
        Ok(consumed)
    }

    fn message_len(bytes: &[u8]) -> Result<usize, Error> {
        let total = shin::wire::handshake::encoded_message_len(bytes)
            .map_err(|_| Error::CryptoBufferExceeded)?;
        if total > MAX_CRYPTO_BUFFERED {
            return Err(Error::CryptoBufferExceeded);
        }
        Ok(total)
    }

    fn consume_buffered(
        &mut self,
        consume: &mut impl for<'message> FnMut(&'message [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        loop {
            let fragmented = self
                .fragmented
                .as_mut()
                .ok_or(Error::CryptoBufferExceeded)?;
            let start = fragmented.position(self.next)?;
            let Some(covered) = fragmented.first() else {
                fragmented.reset(self.next);
                return Ok(());
            };
            if covered.start as usize > start || covered.end as usize - start < 4 {
                return Ok(());
            }
            let total = Self::message_len(fragmented.bytes(start, covered.end as usize))?;
            let end = start
                .checked_add(total)
                .ok_or(Error::CryptoBufferExceeded)?;
            if end > covered.end as usize {
                return Ok(());
            }
            consume(fragmented.bytes(start, end))?;
            self.next = self
                .next
                .checked_add(u64::try_from(total).map_err(|_| Error::CryptoBufferExceeded)?)
                .ok_or(Error::CryptoBufferExceeded)?;
            fragmented.consume_prefix(u32::try_from(end).map_err(|_| Error::CryptoBufferExceeded)?);
        }
    }
}

impl Fragmented {
    fn new(base: u64) -> Result<Self, Error> {
        let mut words = Vec::new();
        words
            .try_reserve_exact(WORKSPACE_WORDS)
            .map_err(|_| Error::CryptoBufferExceeded)?;
        // SAFETY: `MaybeUninit<u64>` has no initialization or drop
        // requirement. The storage and range accessors expose only positions
        // that have subsequently been written.
        unsafe { words.set_len(WORKSPACE_WORDS) };
        Ok(Self {
            base,
            words,
            ranges: 0,
        })
    }

    fn reset(&mut self, base: u64) {
        self.base = base;
        self.ranges = 0;
    }

    fn len(&self) -> usize {
        self.ranges as usize
    }

    fn is_empty(&self) -> bool {
        self.ranges == 0
    }

    fn position(&self, offset: u64) -> Result<usize, Error> {
        usize::try_from(
            offset
                .checked_sub(self.base)
                .ok_or(Error::CryptoBufferExceeded)?,
        )
        .map_err(|_| Error::CryptoBufferExceeded)
    }

    fn bytes(&self, start: usize, end: usize) -> &[u8] {
        debug_assert!(start <= end && end <= MAX_CRYPTO_BUFFERED);
        // SAFETY: callers request only a subrange covered by a recorded Span.
        // Span insertion writes every byte before publishing its metadata, so
        // this exact region is initialized and remains live with `self`.
        unsafe {
            std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>().add(start), end - start)
        }
    }

    fn span(&self, index: usize) -> Span {
        // SAFETY: indices below `ranges` are initialized by `set_span` before
        // the range count is increased.
        let encoded = unsafe { self.words[STORAGE_WORDS + index].assume_init() };
        Span {
            start: (encoded >> 32) as u32,
            end: encoded as u32,
        }
    }

    fn set_span(&mut self, index: usize, span: Span) {
        self.words[STORAGE_WORDS + index]
            .write((u64::from(span.start) << 32) | u64::from(span.end));
    }

    fn first(&self) -> Option<Span> {
        (!self.is_empty()).then(|| self.span(0))
    }

    fn buffer(&mut self, offset: u64, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return Ok(());
        }
        let start = self.position(offset)?;
        let end = start
            .checked_add(input.len())
            .filter(|&end| end <= MAX_CRYPTO_BUFFERED)
            .ok_or(Error::CryptoBufferExceeded)?;
        let inserted = Span {
            start: u32::try_from(start).map_err(|_| Error::CryptoBufferExceeded)?,
            end: u32::try_from(end).map_err(|_| Error::CryptoBufferExceeded)?,
        };
        self.copy_uncovered(inserted, input);
        self.merge(inserted)
    }

    fn copy_uncovered(&mut self, inserted: Span, input: &[u8]) {
        let mut cursor = inserted.start;
        for index in 0..self.len() {
            let covered = self.span(index);
            if covered.end <= cursor {
                continue;
            }
            if covered.start >= inserted.end {
                break;
            }
            let gap_end = covered.start.min(inserted.end);
            if cursor < gap_end {
                self.copy_part(
                    inserted.start,
                    Span {
                        start: cursor,
                        end: gap_end,
                    },
                    input,
                );
            }
            cursor = cursor.max(covered.end.min(inserted.end));
            if cursor == inserted.end {
                return;
            }
        }
        if cursor < inserted.end {
            self.copy_part(
                inserted.start,
                Span {
                    start: cursor,
                    end: inserted.end,
                },
                input,
            );
        }
    }

    fn copy_part(&mut self, input_start: u32, part: Span, input: &[u8]) {
        let source = (part.start - input_start) as usize..(part.end - input_start) as usize;
        debug_assert!((part.end as usize) <= MAX_CRYPTO_BUFFERED);
        // SAFETY: the destination lies in the reserved byte-storage prefix,
        // the source range was derived from `input`, and a caller-held mutable
        // borrow prevents either region from aliasing this workspace.
        unsafe {
            std::ptr::copy_nonoverlapping(
                input[source].as_ptr(),
                self.words
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(part.start as usize),
                (part.end - part.start) as usize,
            );
        }
    }

    fn merge(&mut self, inserted: Span) -> Result<(), Error> {
        let len = self.len();
        let mut first = 0;
        while first < len && self.span(first).end < inserted.start {
            first += 1;
        }
        let mut merged = inserted;
        let mut after = first;
        while after < len && self.span(after).start <= merged.end {
            let span = self.span(after);
            merged.start = merged.start.min(span.start);
            merged.end = merged.end.max(span.end);
            after += 1;
        }
        if first == after {
            if len == MAX_RANGES {
                return Err(Error::CryptoBufferExceeded);
            }
            for index in (first..len).rev() {
                self.set_span(index + 1, self.span(index));
            }
            self.set_span(first, merged);
            self.ranges += 1;
            return Ok(());
        }

        self.set_span(first, merged);
        let removed = after - first - 1;
        if removed != 0 {
            for index in after..len {
                self.set_span(index - removed, self.span(index));
            }
            self.ranges -= u16::try_from(removed).map_err(|_| Error::CryptoBufferExceeded)?;
        }
        Ok(())
    }

    fn consume_prefix(&mut self, end: u32) {
        let len = self.len();
        let first = self.span(0);
        if first.end == end {
            for index in 1..len {
                self.set_span(index - 1, self.span(index));
            }
            self.ranges -= 1;
        } else {
            self.set_span(
                0,
                Span {
                    start: end,
                    end: first.end,
                },
            );
        }
    }
}
