use std::collections::BTreeMap;

use crate::range_buffer::{InsertError, MAX_RANGES, RangeBuffer};

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

#[derive(Debug, Default)]
pub struct SendStream {
    buf: Vec<u8>,
    start: usize,
    base_offset: u64,
    sent_rel: usize,
    acked: BTreeMap<u64, u64>,
    fin_marked: bool,
    fin_sent: bool,
    fin_acked: bool,
    stop_sending_error: Option<u64>,
    reset_sent: bool,
}

impl SendStream {
    pub fn write(&mut self, data: &[u8]) {
        self.compact();
        self.buf.extend_from_slice(data);
    }

    pub fn mark_fin(&mut self) {
        self.fin_marked = true;
    }

    pub fn has_pending(&self) -> bool {
        self.sent_rel < self.len() || (self.fin_marked && !self.fin_sent)
    }

    pub fn next_offset(&self) -> u64 {
        self.base_offset.saturating_add(self.sent_rel as u64)
    }

    pub fn unsent(&self) -> (u64, &[u8]) {
        (
            self.base_offset.saturating_add(self.sent_rel as u64),
            &self.buf[self.start + self.sent_rel..],
        )
    }

    pub fn would_fin(&self, take: usize) -> bool {
        self.fin_marked && self.sent_rel.saturating_add(take) >= self.len()
    }

    pub fn blocked(&self) -> bool {
        self.fin_sent || self.reset_sent
    }

    pub fn chunk_at(&self, offset: u64, len: u64) -> Option<&[u8]> {
        if offset < self.base_offset {
            return None;
        }
        let start = usize::try_from(offset - self.base_offset).ok()?;
        let len = usize::try_from(len).ok()?;
        let end = start.checked_add(len)?;
        if end > self.len() {
            return None;
        }
        Some(&self.buf[self.start + start..self.start + end])
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
        self.acked.insert(start, end);

        if let Some((&s0, &e0)) = self.acked.iter().next()
            && s0 <= self.base_offset
            && e0 > self.base_offset
        {
            let drain_n = usize::try_from(e0 - self.base_offset)
                .unwrap_or(usize::MAX)
                .min(self.len());
            self.start += drain_n;
            self.base_offset += drain_n as u64;
            self.sent_rel = self.sent_rel.saturating_sub(drain_n);
            self.acked.remove(&s0);
            self.compact();
        }
    }

    pub fn is_fully_acked(&self) -> bool {
        self.fin_acked && self.len() == 0
    }

    pub fn stop(&mut self, error_code: u64) {
        self.stop_sending_error = Some(error_code);
        self.buf.clear();
        self.start = 0;
        self.sent_rel = 0;
    }

    pub fn stop_sending_error(&self) -> Option<u64> {
        self.stop_sending_error
    }

    pub fn mark_reset_sent(&mut self) {
        self.reset_sent = true;
        self.buf.clear();
        self.start = 0;
        self.sent_rel = 0;
    }

    pub fn reset_sent(&self) -> bool {
        self.reset_sent
    }

    fn len(&self) -> usize {
        self.buf.len() - self.start
    }

    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start >= self.buf.len() / 2 {
            let len = self.len();
            self.buf.copy_within(self.start.., 0);
            self.buf.truncate(len);
            self.start = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RecvStream;

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
}
