use std::collections::BTreeMap;

use o3::buffer::{
    Bytes, CapacityError, INLINE_BYTES_CAPACITY, InlineBytes, Retained, RetainedSegmentQueue,
};

use crate::range_buffer::{InsertError, MAX_RANGES, RangeBuffer};

const MAX_SEND_SEGMENTS: usize = 4096;
pub const INLINE_SEND_CAPACITY: usize = INLINE_BYTES_CAPACITY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    TooManyRanges,
    OffsetOverflow,
}

impl_error!(RecvError {
    Self::TooManyRanges => "stream reassembly capacity exceeded",
    Self::OffsetOverflow => "stream offset overflow",
});

impl From<InsertError> for RecvError {
    fn from(error: InsertError) -> Self {
        match error {
            InsertError::TooManyRanges | InsertError::BufferFull => Self::TooManyRanges,
            InsertError::OffsetOverflow => Self::OffsetOverflow,
        }
    }
}

#[derive(Debug, Default)]
pub struct RecvStream {
    assembled: Vec<u8>,
    delivered_to: u64,
    highest_offset: u64,
    gaps: RangeBuffer,
    final_size: Option<u64>,
    reset_error: Option<u64>,
}

impl RecvStream {
    pub fn highest_offset(&self) -> u64 {
        self.highest_offset
    }

    pub fn insert(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<(), RecvError> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| RecvError::OffsetOverflow)?)
            .ok_or(RecvError::OffsetOverflow)?;
        if end > self.highest_offset {
            self.highest_offset = end;
        }
        if fin {
            self.final_size = Some(end);
        }
        self.gaps
            .insert_and_drain_into(offset, data, usize::MAX, MAX_RANGES, &mut self.assembled)
            .map_err(RecvError::from)?;
        Ok(())
    }

    pub fn read(&mut self, dst: &mut Vec<u8>) -> usize {
        let n = self.assembled.len();
        if n == 0 {
            return 0;
        }
        if dst.is_empty() {
            std::mem::swap(dst, &mut self.assembled);
        } else {
            dst.extend_from_slice(&self.assembled);
            self.assembled.clear();
        }
        self.delivered_to += n as u64;
        n
    }

    pub fn read_owned(&mut self) -> Option<Vec<u8>> {
        if self.assembled.is_empty() {
            return None;
        }
        let bytes = std::mem::take(&mut self.assembled);
        self.delivered_to += bytes.len() as u64;
        Some(bytes)
    }

    pub fn is_eof(&self) -> bool {
        matches!(self.final_size, Some(size) if size == self.delivered_to)
    }

    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    pub fn reset(&mut self, error_code: u64, final_size: u64) {
        self.reset_error = Some(error_code);
        self.final_size = Some(final_size);
        if final_size > self.highest_offset {
            self.highest_offset = final_size;
        }
    }

    pub fn reset_error(&self) -> Option<u64> {
        self.reset_error
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendBuffer {
    Inline(InlineBytes),
    Owned(Vec<u8>),
    Retained(Bytes<Retained>),
}

impl SendBuffer {
    pub fn inline(bytes: &[u8]) -> Result<Self, CapacityError> {
        InlineBytes::from_slice(bytes).map(Self::Inline)
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline(bytes) => bytes.as_slice(),
            Self::Owned(bytes) => bytes,
            Self::Retained(bytes) => bytes.as_slice(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl AsRef<[u8]> for SendBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for SendBuffer {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Owned(bytes)
    }
}

impl From<Bytes<Retained>> for SendBuffer {
    fn from(bytes: Bytes<Retained>) -> Self {
        Self::Retained(bytes)
    }
}

#[derive(Debug, Default)]
pub struct SendStream {
    chunks: RetainedSegmentQueue<SendBuffer>,
    spare: Vec<u8>,
    base_offset: u64,
    sent_rel: usize,
    acked: BTreeMap<u64, u64>,
    fin_marked: bool,
    fin_sent: bool,
    fin_acked: bool,
    stop_sending_error: Option<u64>,
    reset_sent: bool,
    scheduled: bool,
    schedule_generation: bool,
}

impl SendStream {
    pub fn write(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        if matches!(self.chunks.back(), Some(SendBuffer::Owned(_))) {
            return self
                .chunks
                .try_mutate_back(data.len(), |tail| {
                    let SendBuffer::Owned(tail) = tail else {
                        return false;
                    };
                    tail.extend_from_slice(data);
                    true
                })
                .unwrap_or(false);
        }
        let mut owned = std::mem::take(&mut self.spare);
        owned.extend_from_slice(data);
        self.write_buffer(owned.into())
    }

    pub fn write_buffer(&mut self, data: SendBuffer) -> bool {
        if data.is_empty() {
            return true;
        }
        if self.chunks.len().checked_add(data.len()).is_none() {
            return false;
        }
        if self.chunks.segment_count() >= MAX_SEND_SEGMENTS {
            self.coalesce();
        }
        self.chunks.try_push_back(data).is_ok()
    }

    pub fn mark_fin(&mut self) {
        self.fin_marked = true;
    }

    pub fn has_pending(&self) -> bool {
        self.sent_rel < self.len() || (self.fin_marked && !self.fin_sent)
    }

    pub(crate) fn schedule(&mut self) -> Option<bool> {
        if self.scheduled || !self.has_pending() {
            return None;
        }
        self.scheduled = true;
        self.schedule_generation = !self.schedule_generation;
        Some(self.schedule_generation)
    }

    pub(crate) fn is_scheduled(&self, generation: bool) -> bool {
        self.scheduled && self.schedule_generation == generation
    }

    pub(crate) fn unschedule(&mut self) -> bool {
        std::mem::replace(&mut self.scheduled, false)
    }

    pub fn next_offset(&self) -> u64 {
        self.base_offset.saturating_add(self.sent_rel as u64)
    }

    pub fn unsent_len(&self) -> usize {
        self.chunks.len().saturating_sub(self.sent_rel)
    }

    pub fn would_fin(&self, take: usize) -> bool {
        self.fin_marked && self.sent_rel.saturating_add(take) >= self.len()
    }

    pub fn blocked(&self) -> bool {
        self.fin_sent || self.reset_sent
    }

    pub fn range_available(&self, offset: u64, len: u64) -> bool {
        if len == 0 {
            return offset == self.next_offset();
        }
        if offset < self.base_offset {
            return false;
        }
        let Some(start) = usize::try_from(offset - self.base_offset).ok() else {
            return false;
        };
        let Some(len) = usize::try_from(len).ok() else {
            return false;
        };
        self.chunks.range_available(start, len)
    }

    pub fn append_range(&self, out: &mut Vec<u8>, offset: u64, len: usize) -> bool {
        if u64::try_from(len).is_err() || offset < self.base_offset {
            return false;
        }
        let Ok(offset) = usize::try_from(offset - self.base_offset) else {
            return false;
        };
        if len == 0 {
            return offset < self.chunks.len();
        }
        self.chunks.extend_range(offset, len, out)
    }

    pub fn advance_sent(&mut self, n: usize, fin_now: bool) {
        self.sent_rel += n;
        if fin_now {
            self.fin_sent = true;
        }
    }

    pub fn mark_fin_acked(&mut self) {
        self.fin_acked = true;
    }

    pub fn ack(&mut self, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        let mut start = offset;
        let Some(mut end) = offset.checked_add(len) else {
            return;
        };
        if end <= self.base_offset {
            return;
        }
        let mut overlapping: Vec<u64> = Vec::new();
        for (&s, &e) in self.acked.range(..=end) {
            if e >= start {
                start = start.min(s);
                end = end.max(e);
                overlapping.push(s);
            }
        }
        for s in overlapping {
            self.acked.remove(&s);
        }
        if start <= self.base_offset {
            let drain_n = usize::try_from(end - self.base_offset)
                .unwrap_or(usize::MAX)
                .min(self.len());
            self.discard_prefix(drain_n);
            self.base_offset += drain_n as u64;
            self.sent_rel = self.sent_rel.saturating_sub(drain_n);
        } else {
            self.acked.insert(start, end);
        }
    }

    pub fn is_fully_acked(&self) -> bool {
        self.fin_acked && self.len() == 0
    }

    pub(crate) fn recycle(&mut self) {
        self.chunks.clear();
        self.base_offset = 0;
        self.sent_rel = 0;
        self.acked.clear();
        self.fin_marked = false;
        self.fin_sent = false;
        self.fin_acked = false;
        self.stop_sending_error = None;
        self.reset_sent = false;
        self.scheduled = false;
        self.schedule_generation = false;
    }

    pub fn stop(&mut self, error_code: u64) {
        self.stop_sending_error = Some(error_code);
        self.chunks.clear();
        self.sent_rel = 0;
    }

    pub fn stop_sending_error(&self) -> Option<u64> {
        self.stop_sending_error
    }

    pub fn mark_reset_sent(&mut self) {
        self.reset_sent = true;
        self.chunks.clear();
        self.sent_rel = 0;
    }

    pub fn reset_sent(&self) -> bool {
        self.reset_sent
    }

    fn len(&self) -> usize {
        self.chunks.len()
    }

    fn discard_prefix(&mut self, len: usize) {
        let Self { chunks, spare, .. } = self;
        chunks.consume_prefix_up_to(len, |segment| {
            if let SendBuffer::Owned(mut bytes) = segment {
                bytes.clear();
                if bytes.capacity() > spare.capacity() {
                    *spare = bytes;
                }
            }
        });
    }

    fn coalesce(&mut self) {
        let mut bytes = std::mem::take(&mut self.spare);
        let buffered_len = self.chunks.len();
        bytes.reserve(buffered_len);
        let appended = self.append_range(&mut bytes, self.base_offset, buffered_len);
        debug_assert!(appended);
        if !appended {
            bytes.clear();
            self.spare = bytes;
            return;
        }
        self.chunks.clear();
        self.chunks
            .try_push_back(SendBuffer::Owned(bytes))
            .unwrap_or_else(|_| unreachable!("coalesced length was already represented"));
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::{INLINE_SEND_CAPACITY, MAX_SEND_SEGMENTS, RecvStream, SendBuffer, SendStream};

    #[test]
    fn owned_read_moves_the_assembled_allocation() {
        let mut stream = RecvStream::default();
        stream.insert(0, b"owned", false).unwrap();
        let assembled = stream.assembled.as_ptr();

        let bytes = stream.read_owned().unwrap();

        assert_eq!(bytes, b"owned");
        assert_eq!(bytes.as_ptr(), assembled);
        assert!(stream.read_owned().is_none());
    }

    #[test]
    fn empty_destination_exchanges_its_spare_allocation() {
        let mut stream = RecvStream::default();
        stream.insert(0, b"ready", false).unwrap();
        let assembled = stream.assembled.as_ptr();
        let mut destination = Vec::with_capacity(64);
        let spare = destination.as_ptr();

        assert_eq!(stream.read(&mut destination), 5);

        assert_eq!(destination, b"ready");
        assert_eq!(destination.as_ptr(), assembled);
        assert_eq!(stream.assembled.as_ptr(), spare);
    }

    #[test]
    fn contiguous_input_absorbs_overlapping_gaps_once() {
        let mut stream = RecvStream::default();
        stream.insert(3, b"def", true).unwrap();
        stream.insert(0, b"abcd", false).unwrap();

        assert_eq!(stream.read_owned().unwrap(), b"abcdef");
        assert!(stream.is_eof());
    }

    #[test]
    fn overlapping_input_preserves_the_first_received_bytes() {
        let mut stream = RecvStream::default();
        stream.insert(3, b"XYZ", true).unwrap();
        stream.insert(0, b"abcdef", false).unwrap();

        assert_eq!(stream.read_owned().unwrap(), b"abcXYZ");
        assert!(stream.is_eof());
    }

    #[test]
    fn send_stream_appends_across_owned_segments() {
        let first = b"frame".to_vec();
        let second = b"-body".to_vec();
        let mut stream = SendStream::default();
        assert!(stream.write_buffer(SendBuffer::Owned(first)));
        assert!(stream.write_buffer(SendBuffer::Owned(second)));

        let mut out = Vec::new();
        assert!(stream.append_range(&mut out, 0, 10));
        assert_eq!(out, b"frame-body");
        assert_eq!(stream.unsent_len(), 10);
    }

    #[test]
    fn empty_send_ranges_keep_the_existing_boundary_semantics() {
        let mut stream = SendStream::default();
        let mut out = Vec::new();
        assert!(!stream.append_range(&mut out, 0, 0));

        assert!(stream.write(b"body"));
        assert!(stream.append_range(&mut out, 0, 0));
        assert!(!stream.append_range(&mut out, 4, 0));
        assert!(out.is_empty());
    }

    #[test]
    fn inline_send_buffer_stays_within_the_existing_segment_footprint() {
        let bytes = [b'x'; INLINE_SEND_CAPACITY];
        let inline = SendBuffer::inline(&bytes).unwrap();

        assert_eq!(inline.as_slice(), bytes);
        assert_eq!(size_of::<SendBuffer>(), 32);
        assert!(SendBuffer::inline(&[0; INLINE_SEND_CAPACITY + 1]).is_err());
        assert_eq!(size_of::<SendStream>(), 136);
    }

    #[test]
    fn send_stream_releases_acked_prefix_segments() {
        let mut stream = SendStream::default();
        assert!(stream.write_buffer(SendBuffer::Owned(b"head".to_vec())));
        assert!(stream.write_buffer(SendBuffer::Owned(b"payload".to_vec())));
        stream.advance_sent(11, false);

        stream.ack(0, 6);

        let mut out = Vec::new();
        assert!(stream.append_range(&mut out, 6, 5));
        assert_eq!(out, b"yload");
        assert_eq!(stream.next_offset(), 11);
    }

    #[test]
    fn out_of_order_ack_joins_the_prefix_without_losing_credit() {
        let mut stream = SendStream::default();
        assert!(stream.write(b"abcdefgh"));
        stream.advance_sent(8, false);

        stream.ack(4, 4);
        assert_eq!(stream.base_offset, 0);
        assert_eq!(stream.acked.get(&4), Some(&8));

        stream.ack(0, 4);
        assert_eq!(stream.base_offset, 8);
        assert!(stream.acked.is_empty());
        assert_eq!(stream.unsent_len(), 0);
    }

    #[test]
    fn borrowed_writes_reuse_the_acked_allocation() {
        let mut stream = SendStream::default();
        assert!(stream.write(b"first"));
        let first_ptr = stream.chunks.front().unwrap().as_slice().as_ptr();
        stream.advance_sent(5, false);
        stream.ack(0, 5);

        assert!(stream.write(b"next"));

        assert_eq!(
            stream.chunks.front().unwrap().as_slice().as_ptr(),
            first_ptr
        );
    }

    #[test]
    fn recycled_stream_reuses_its_segment_storage() {
        let mut stream = SendStream::default();
        assert!(stream.write_buffer(SendBuffer::inline(b"first").unwrap()));
        let first = stream.chunks.front().unwrap() as *const SendBuffer;

        stream.recycle();
        assert!(stream.write_buffer(SendBuffer::inline(b"next").unwrap()));

        assert_eq!(stream.chunks.front().unwrap() as *const SendBuffer, first);
    }

    #[test]
    fn excessive_segments_are_coalesced() {
        let mut stream = SendStream::default();
        for _ in 0..=MAX_SEND_SEGMENTS {
            assert!(stream.write_buffer(SendBuffer::Owned(vec![b'x'])));
        }

        assert!(stream.chunks.segment_count() <= 2);
        let mut out = Vec::new();
        assert!(stream.append_range(&mut out, 0, MAX_SEND_SEGMENTS + 1));
        assert!(out.iter().all(|byte| *byte == b'x'));
    }
}
