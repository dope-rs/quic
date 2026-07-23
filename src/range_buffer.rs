use std::collections::BTreeMap;
use std::mem::take;
use std::ops::Range;

pub(crate) const MAX_RANGES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InsertError {
    BufferFull,
    TooManyRanges,
    OffsetOverflow,
}

#[derive(Debug, Default)]
pub(crate) struct RangeBuffer {
    next: u64,
    buffered: usize,
    segments: BTreeMap<u64, Vec<u8>>,
    scratch_parts: Vec<(u64, Range<usize>)>,
}

impl RangeBuffer {
    pub(crate) fn insert_and_drain_into(
        &mut self,
        offset: u64,
        data: &[u8],
        max_bytes: usize,
        max_ranges: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), InsertError> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| InsertError::OffsetOverflow)?)
            .ok_or(InsertError::OffsetOverflow)?;
        let overlaps_buffered_range =
            end > self.next && self.segments.range(self.next..end).next().is_some();
        if offset <= self.next && end > self.next && !overlaps_buffered_range {
            let skip =
                usize::try_from(self.next - offset).map_err(|_| InsertError::OffsetOverflow)?;
            output.extend_from_slice(&data[skip..]);
            self.next = end;
        } else {
            self.insert(offset, data, max_bytes, max_ranges)?;
        }
        self.drain_contiguous_into(output);
        Ok(())
    }

    pub(crate) fn insert(
        &mut self,
        offset: u64,
        data: &[u8],
        max_bytes: usize,
        max_ranges: usize,
    ) -> Result<(), InsertError> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| InsertError::OffsetOverflow)?)
            .ok_or(InsertError::OffsetOverflow)?;
        if data.is_empty() || end <= self.next {
            return Ok(());
        }

        let (start, data) = if offset < self.next {
            let skip =
                usize::try_from(self.next - offset).map_err(|_| InsertError::OffsetOverflow)?;
            (self.next, &data[skip..])
        } else {
            (offset, data)
        };
        let end = start
            .checked_add(u64::try_from(data.len()).map_err(|_| InsertError::OffsetOverflow)?)
            .ok_or(InsertError::OffsetOverflow)?;
        let scan_start = self
            .segments
            .range(..=start)
            .next_back()
            .map(|(&segment_start, _)| segment_start)
            .unwrap_or(start);

        let mut cursor = start;
        let mut parts = take(&mut self.scratch_parts);
        parts.clear();
        for (&segment_start, segment) in self.segments.range(scan_start..end) {
            let segment_end = segment_start
                .checked_add(u64::try_from(segment.len()).map_err(|_| InsertError::OffsetOverflow)?)
                .ok_or(InsertError::OffsetOverflow)?;
            if segment_end <= cursor {
                continue;
            }
            if segment_start > cursor {
                let part_end = segment_start.min(end);
                let from =
                    usize::try_from(cursor - start).map_err(|_| InsertError::OffsetOverflow)?;
                let to =
                    usize::try_from(part_end - start).map_err(|_| InsertError::OffsetOverflow)?;
                parts.push((cursor, from..to));
            }
            cursor = cursor.max(segment_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            let from = usize::try_from(cursor - start).map_err(|_| InsertError::OffsetOverflow)?;
            parts.push((cursor, from..data.len()));
        }
        if parts.is_empty() {
            self.scratch_parts = parts;
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
        let ranges = self
            .segments
            .len()
            .checked_add(parts.len())
            .ok_or(InsertError::TooManyRanges)?;
        if buffered > max_bytes {
            self.scratch_parts = parts;
            return Err(InsertError::BufferFull);
        }
        if ranges > max_ranges {
            self.scratch_parts = parts;
            return Err(InsertError::TooManyRanges);
        }

        for (part_start, range) in parts.drain(..) {
            self.segments.insert(part_start, data[range].to_vec());
        }
        self.buffered = buffered;
        self.scratch_parts = parts;
        Ok(())
    }

    pub(crate) fn drain_contiguous_into(&mut self, output: &mut Vec<u8>) {
        while let Some((&start, _)) = self.segments.first_key_value() {
            if start > self.next {
                break;
            }
            let segment = self
                .segments
                .remove(&start)
                .expect("first range must remain present");
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
