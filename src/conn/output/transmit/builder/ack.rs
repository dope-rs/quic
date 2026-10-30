use std::time;

use crate::conn::output::transmit;
use crate::proto::recovery::numbers::{self, count};
use crate::{
    conn,
    security::crypto,
    wire::{frame, varint},
};
use o3::{alloc, buffer::write::Sink};

fn base(largest: varint::VarInt, delay: varint::VarInt, first: varint::VarInt) -> usize {
    1usize
        + usize::from(largest.encoded_len())
        + usize::from(delay.encoded_len())
        + usize::from(varint::VarInt::ZERO.encoded_len())
        + usize::from(first.encoded_len())
}

fn select(base: usize, ranges: numbers::Iter<'_>, room: usize) -> (count::Count, usize) {
    let mut encoded = base;
    let mut selected = count::Count::ZERO;
    for (gap, range) in ranges {
        let next = selected.advance();
        let old_len = varint::VarInt::from_u16(selected.into_u16()).encoded_len();
        let new_len = varint::VarInt::from_u16(next.into_u16()).encoded_len();
        let size = encoded - usize::from(old_len)
            + usize::from(new_len)
            + usize::from(gap.encoded_len())
            + usize::from(range.encoded_len());
        if size > room {
            break;
        }
        selected = next;
        encoded = size;
    }
    (selected, encoded)
}

pub(in crate::conn::output::transmit) fn minimum<K: numbers::AckSpace, const DUE: bool>(
    spaces: &numbers::Spaces,
    now: time::Instant,
) -> Option<usize> {
    let (ranges, _) = if DUE {
        spaces.due_ack::<K>(now)?.into_parts()
    } else {
        spaces.pending_ack::<K>(now)?.into_parts()
    };
    Some(base(ranges.largest, ranges.delay, ranges.first_range))
}

pub(in crate::conn::output::transmit) fn encoded_len<K: numbers::AckSpace, const DUE: bool>(
    spaces: &numbers::Spaces,
    now: time::Instant,
    limit: usize,
) -> Option<usize> {
    let (ranges, _) = if DUE {
        spaces.due_ack::<K>(now)?.into_parts()
    } else {
        spaces.pending_ack::<K>(now)?.into_parts()
    };
    let base = base(ranges.largest, ranges.delay, ranges.first_range);
    (base <= limit).then(|| select(base, ranges.additional, limit).1)
}

pub(in crate::conn::output::transmit) fn append<K: numbers::AckSpace, const DUE: bool>(
    spaces: &numbers::Spaces,
    now: time::Instant,
    out: &mut (impl Sink<Error = alloc::Error> + AsRef<[u8]>),
    limit: usize,
) -> Result<numbers::AckCommit, transmit::Admission<crypto::Dimensions>> {
    let parts = if DUE {
        spaces.due_ack::<K>(now).map(numbers::DueAck::into_parts)
    } else {
        spaces
            .pending_ack::<K>(now)
            .map(numbers::PendingAck::into_parts)
    };
    let Some((ranges, commit)) = parts else {
        return Ok(numbers::AckCommit::NONE);
    };
    let largest = ranges.largest;
    let delay = ranges.delay;
    let first = ranges.first_range;
    let room = limit.saturating_sub(out.as_ref().len());
    let base = base(largest, delay, first);
    if base > room {
        return Ok(numbers::AckCommit::NONE);
    }
    let selected = if room >= conn::MAX_GENERATED_ACK_FRAME_BYTES {
        ranges.additional.remaining()
    } else {
        select(base, ranges.additional.clone(), room).0
    };

    let count = varint::VarInt::from_u16(selected.into_u16());
    let needed = base + usize::from(count.encoded_len()) - 1;
    out.write_slices([
        &[frame::TYPE_ACK],
        largest.pack().as_ref(),
        delay.pack().as_ref(),
        count.pack().as_ref(),
        first.pack().as_ref(),
    ])
    .map_err(|error| transmit::Admission::Payload {
        error,
        requested: needed,
    })?;
    for (gap, range) in ranges.additional.take(selected.len()) {
        let needed = usize::from(gap.encoded_len() + range.encoded_len());
        out.write_slices([gap.pack().as_ref(), range.pack().as_ref()])
            .map_err(|error| transmit::Admission::Payload {
                error,
                requested: needed,
            })?;
    }
    Ok(commit)
}
