use std::collections::BTreeSet;

/// Compact record of fully-retired stream halves: contiguous receive
/// watermarks per stream type, one peer-bidi send watermark, and a shared
/// overflow set for out-of-order retirement. Local send retirement is already
/// encoded by its opened watermark plus absence from the live send maps.
#[derive(Default)]
pub(super) struct Streams {
    recv_contiguous: [u64; 4],
    peer_bidi_send_contiguous: u64,
    overflow: BTreeSet<u64>,
}

impl Streams {
    const SEND_TAG: u64 = 1 << 63;

    fn retire_sequence(
        contiguous: &mut u64,
        overflow: &mut BTreeSet<u64>,
        index: u64,
        encode: impl Fn(u64) -> u64,
    ) {
        if index == *contiguous {
            *contiguous += 1;
            while overflow.remove(&encode(*contiguous)) {
                *contiguous += 1;
            }
        } else if index > *contiguous {
            overflow.insert(encode(index));
        }
    }

    pub(super) fn retire_recv(&mut self, id: u64) {
        let stream_type = (id & 0x3) as usize;
        Self::retire_sequence(
            &mut self.recv_contiguous[stream_type],
            &mut self.overflow,
            id >> 2,
            |index| index << 2 | stream_type as u64,
        );
    }

    pub(super) fn recv_contains(&self, id: u64) -> bool {
        (id >> 2) < self.recv_contiguous[(id & 0x3) as usize] || self.overflow.contains(&id)
    }

    pub(super) fn retire_peer_bidi_send(&mut self, id: u64) {
        let stream_type = id & 0x3;
        Self::retire_sequence(
            &mut self.peer_bidi_send_contiguous,
            &mut self.overflow,
            id >> 2,
            |index| Self::SEND_TAG | index << 2 | stream_type,
        );
    }

    pub(super) fn peer_bidi_send_contains(&self, id: u64) -> bool {
        (id >> 2) < self.peer_bidi_send_contiguous || self.overflow.contains(&(Self::SEND_TAG | id))
    }
}
