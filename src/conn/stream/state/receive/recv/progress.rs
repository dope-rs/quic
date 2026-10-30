use crate::conn::wire::ingress::frames;
use crate::{
    errors,
    wire::{frame, ranges::plan, varint},
};

#[derive(Default)]
pub(in crate::conn) struct Progress {
    delivered_to: u64,
    highest_offset: u64,
    final_size: Option<u64>,
    reset_error: Option<errors::Code>,
}

impl Progress {
    pub(in crate::conn) fn high(&self) -> u64 {
        self.highest_offset
    }

    pub(in crate::conn) const fn delivered_to(&self) -> u64 {
        self.delivered_to
    }

    pub(in crate::conn) fn is_eof(&self) -> bool {
        matches!(self.final_size, Some(size) if size == self.delivered_to)
    }

    pub(in crate::conn) fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    pub(in crate::conn) fn reset(&mut self, code: errors::Code, end: u64) {
        self.reset_error = Some(code);
        self.final_size = Some(end);
        self.highest_offset = self.highest_offset.max(end);
    }

    pub(in crate::conn) fn reset_error(&self) -> Option<errors::Code> {
        self.reset_error
    }

    pub(in crate::conn::stream::state::receive::recv) fn record(
        &mut self,
        end: u64,
        boundary: frame::Boundary,
    ) {
        self.highest_offset = self.highest_offset.max(end);
        if matches!(boundary, frame::Boundary::End) {
            self.final_size = Some(end);
        }
    }

    pub(in crate::conn::stream::state::receive::recv) fn deliver(&mut self, amount: usize) {
        if let Some(end) = self.delivered_to.checked_add(amount as u64) {
            self.delivered_to = end;
        }
    }

    pub(in crate::conn::stream::state::receive::recv) fn recycle(&mut self) {
        *self = Self::default();
    }
    pub(in crate::conn) fn observe(
        &mut self,
        frames::CommitPermit { .. }: frames::CommitPermit<'_>,
        offset: varint::VarInt,
        record: plan::Record,
        boundary: frame::Boundary,
    ) {
        self.record(record.end(offset), boundary);
    }
}
