use std::time;

use crate::frame;

pub(crate) const MAX_ACK_INTERVALS: usize = frame::MAX_ADDITIONAL_ACK_RANGES + 1;
const RECEIVED_WINDOW_BITS: usize = MAX_ACK_INTERVALS * 2 - 1;
const RECEIVED_WINDOW_WORDS: usize = RECEIVED_WINDOW_BITS.div_ceil(u64::BITS as usize);

/// Fixed packet-number history shared by replay rejection and ACK generation.
/// Numbers below `base()` are retired; QUIC retransmits frames under new packet
/// numbers, so bounded reordering cannot make old packets fresh again.
#[derive(Debug)]
struct ReceivedPackets {
    words: [u64; RECEIVED_WINDOW_WORDS],
    largest: u64,
    first_smallest: u64,
    ranges: u16,
}

impl Default for ReceivedPackets {
    fn default() -> Self {
        Self {
            words: [0; RECEIVED_WINDOW_WORDS],
            largest: 0,
            first_smallest: 0,
            ranges: 0,
        }
    }
}

/// Borrowed ACK description. Its lifetime prevents the receive window from
/// advancing between range selection and wire encoding.
pub(crate) struct AckView<'space> {
    pub(crate) largest: u64,
    pub(crate) first_range: u64,
    pub(crate) additional: GeneratedAckRanges<'space>,
}

impl ReceivedPackets {
    fn bit_index(pn: u64) -> (usize, u64) {
        let slot = (pn % RECEIVED_WINDOW_BITS as u64) as usize;
        (slot / u64::BITS as usize, 1 << (slot % u64::BITS as usize))
    }

    fn bit(&self, pn: u64) -> bool {
        let (word, bit) = Self::bit_index(pn);
        self.words[word] & bit != 0
    }

    fn set_bit(&mut self, pn: u64) {
        let (word, bit) = Self::bit_index(pn);
        self.words[word] |= bit;
    }

    fn clear_bit(&mut self, pn: u64) {
        let (word, bit) = Self::bit_index(pn);
        self.words[word] &= !bit;
    }

    fn base(&self) -> u64 {
        self.largest.saturating_sub(RECEIVED_WINDOW_BITS as u64 - 1)
    }

    fn contains(&self, pn: u64) -> bool {
        let Some(largest) = self.largest() else {
            return false;
        };
        pn < self.base() || pn <= largest && self.bit(pn)
    }

    fn admits(&self, pn: u64) -> bool {
        !self.contains(pn)
    }

    fn remove_bit(&mut self, pn: u64, largest: u64) {
        if !self.bit(pn) {
            return;
        }
        let joins_previous = pn > self.base() && self.bit(pn - 1);
        let joins_next = pn < largest && self.bit(pn + 1);
        self.ranges = match (joins_previous, joins_next) {
            (false, false) => self.ranges - 1,
            (true, true) => self.ranges + 1,
            _ => self.ranges,
        };
        self.clear_bit(pn);
    }

    fn add_bit(&mut self, pn: u64, largest: u64) {
        debug_assert!(!self.bit(pn));
        let joins_previous = pn > self.base() && self.bit(pn - 1);
        let joins_next = pn < largest && self.bit(pn + 1);
        self.ranges = match (joins_previous, joins_next) {
            (false, false) => self.ranges + 1,
            (true, true) => self.ranges - 1,
            _ => self.ranges,
        };
        self.set_bit(pn);
    }

    fn insert(&mut self, pn: u64) {
        debug_assert!(self.admits(pn));
        let Some(previous_largest) = self.largest() else {
            self.largest = pn;
            self.first_smallest = pn;
            self.ranges = 1;
            self.set_bit(pn);
            return;
        };

        if pn > previous_largest {
            let new_base = pn.saturating_sub(RECEIVED_WINDOW_BITS as u64 - 1);
            let old_base = self.base();
            let retired = new_base.saturating_sub(old_base);
            if retired >= RECEIVED_WINDOW_BITS as u64 {
                self.words.fill(0);
                self.ranges = 0;
            } else {
                for offset in 0..retired {
                    self.remove_bit(old_base + offset, previous_largest);
                }
            }
            self.largest = pn;
            self.add_bit(pn, pn);
            self.first_smallest = if previous_largest.checked_add(1) == Some(pn) {
                self.first_smallest.max(new_base)
            } else {
                pn
            };
            return;
        }

        self.add_bit(pn, previous_largest);
        if pn.checked_add(1) == Some(self.first_smallest) {
            let mut first = pn;
            while first > self.base() && self.bit(first - 1) {
                first -= 1;
            }
            self.first_smallest = first;
        }
    }

    fn largest(&self) -> Option<u64> {
        (self.ranges != 0).then_some(self.largest)
    }

    fn ack_ranges(&self) -> Option<AckView<'_>> {
        let largest = self.largest()?;
        let additional = GeneratedAckRanges {
            received: self,
            cursor: self
                .first_smallest
                .checked_sub(1)
                .filter(|&pn| pn >= self.base()),
            previous_smallest: self.first_smallest,
            remaining: usize::from(self.ranges.saturating_sub(1)),
        };
        Some(AckView {
            largest,
            first_range: largest - self.first_smallest,
            additional,
        })
    }
}

#[derive(Clone)]
pub(crate) struct GeneratedAckRanges<'space> {
    received: &'space ReceivedPackets,
    cursor: Option<u64>,
    previous_smallest: u64,
    remaining: usize,
}

impl Iterator for GeneratedAckRanges<'_> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            self.cursor = None;
            return None;
        }
        let mut cursor = self.cursor?;
        while !self.received.bit(cursor) {
            if cursor == self.received.base() {
                self.cursor = None;
                self.remaining = 0;
                return None;
            }
            cursor -= 1;
        }
        let largest = cursor;
        while cursor > self.received.base() && self.received.bit(cursor - 1) {
            cursor -= 1;
        }
        let smallest = cursor;
        self.cursor = smallest
            .checked_sub(1)
            .filter(|&pn| pn >= self.received.base());
        self.remaining -= 1;
        let gap = self
            .previous_smallest
            .checked_sub(largest)
            .and_then(|distance| distance.checked_sub(2))
            .expect("disjoint received ranges");
        self.previous_smallest = smallest;
        Some((gap, largest - smallest))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for GeneratedAckRanges<'_> {}

#[derive(Debug, Default)]
pub struct PnSpace {
    pub next_pn: u64,
    pub largest_acked: Option<u64>,
    pub time_of_last_ack_eliciting: Option<time::Instant>,
    pub ack_eliciting_in_flight: usize,
}

#[derive(Debug, Default)]
pub(crate) struct Receive {
    packets: ReceivedPackets,
    pub(crate) largest_time: Option<time::Instant>,
    pub(crate) ack_eliciting: bool,
    pub(crate) ack_pending: bool,
}

#[must_use = "a fresh packet number is meaningful only inside a receive transaction"]
#[repr(transparent)]
pub(crate) struct Fresh(u64);

impl Receive {
    pub fn expected_pn(&self) -> u64 {
        self.packets
            .largest()
            .and_then(|pn| pn.checked_add(1))
            .unwrap_or(0)
    }

    pub(crate) fn admit(&self, pn: u64) -> Option<Fresh> {
        self.packets.admits(pn).then_some(Fresh(pn))
    }

    pub(crate) fn commit(&mut self, Fresh(pn): Fresh, ack_eliciting: bool, now: time::Instant) {
        debug_assert!(self.packets.admits(pn));
        let previous_largest = self.packets.largest();
        self.packets.insert(pn);
        if previous_largest.is_none_or(|largest| pn > largest) {
            self.largest_time = Some(now);
        }
        if ack_eliciting {
            self.ack_eliciting = true;
            self.ack_pending = true;
        }
    }

    pub(crate) fn build_ack_ranges(&self) -> Option<AckView<'_>> {
        self.packets.ack_ranges()
    }
}

const _: () = assert!(std::mem::size_of::<ReceivedPackets>() <= 96);
const _: () = assert!(!std::mem::needs_drop::<ReceivedPackets>());
const _: () = assert!(std::mem::size_of::<Fresh>() == std::mem::size_of::<u64>());
const _: () = assert!(!std::mem::needs_drop::<Fresh>());
const _: () = assert!(MAX_ACK_INTERVALS <= u16::MAX as usize);
const _: () = assert!(RECEIVED_WINDOW_BITS <= 16_384);
