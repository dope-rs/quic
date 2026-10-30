use std::{mem, num};

use crate::wire::packet::header;

use crate::{
    proto::recovery::numbers::{self, count},
    wire::{frame, varint},
};

const MAX_ACK_INTERVALS: usize = frame::MAX_ADDITIONAL_ACK_RANGES + 1;
const WINDOW_BITS: usize = MAX_ACK_INTERVALS * 2 - 1;
const WINDOW_WORDS: usize = WINDOW_BITS.div_ceil(u64::BITS as usize);

/// Fixed receive history shared by replay rejection and ACK generation.
/// Numbers below `base()` are retired; QUIC retransmits frames under new packet
/// numbers, so bounded reordering cannot make old packets fresh again.
pub(super) struct Window {
    words: [u64; WINDOW_WORDS],
    largest: header::Number,
    first_range: u16,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            words: [0; WINDOW_WORDS],
            largest: header::Number::ZERO,
            first_range: 0,
        }
    }
}

/// Borrowed ACK description. Its lifetime prevents the receive window from
/// advancing between range selection and wire encoding.
pub(crate) struct AckView<'space> {
    pub(crate) largest: varint::VarInt,
    pub(crate) delay: varint::VarInt,
    pub(crate) first_range: varint::VarInt,
    pub(crate) additional: Iter<'space>,
}

impl Window {
    fn bit_index(pn: u64) -> (usize, u64) {
        let slot = (pn % WINDOW_BITS as u64) as usize;
        (slot / u64::BITS as usize, 1 << (slot % u64::BITS as usize))
    }

    fn is_set(&self, pn: u64) -> bool {
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
        self.largest.get().saturating_sub(WINDOW_BITS as u64 - 1)
    }

    pub(super) fn contains(&self, pn: header::Number) -> bool {
        let Some(largest) = self.largest() else {
            return false;
        };
        let raw = pn.get();
        raw < self.base() || pn <= largest && self.is_set(raw)
    }

    pub(super) fn is_fresh(&self, pn: header::Number) -> bool {
        !self.contains(pn)
    }

    fn remove_bit(&mut self, pn: u64, largest: u64) {
        if pn <= largest {
            self.clear_bit(pn);
        }
    }

    pub(super) fn insert(&mut self, numbers::Fresh(pn): numbers::Fresh) {
        let raw = pn.get();
        let Some(old) = self.largest() else {
            self.largest = pn;
            self.first_range = 0;
            self.set_bit(raw);
            return;
        };
        let old = old.get();

        if raw > old {
            let new_base = raw.saturating_sub(WINDOW_BITS as u64 - 1);
            let old_base = self.base();
            let retired = new_base.saturating_sub(old_base);
            if retired >= WINDOW_BITS as u64 {
                self.words.fill(0);
            } else {
                for offset in 0..retired {
                    self.remove_bit(old_base + offset, old);
                }
            }
            self.largest = pn;
            self.set_bit(raw);
            self.first_range = if old + 1 == raw {
                self.first_range.min((WINDOW_BITS - 2) as u16) + 1
            } else {
                0
            };
            return;
        }

        self.set_bit(raw);
        let first = old - u64::from(self.first_range);
        if raw + 1 == first {
            let mut first = raw;
            while first > self.base() && self.is_set(first - 1) {
                first -= 1;
            }
            self.first_range = (old - first) as u16;
        }
    }

    /// Every completed insertion retains its maximum bit.
    pub(super) fn largest(&self) -> Option<header::Number> {
        self.is_set(self.largest.get()).then_some(self.largest)
    }

    /// Counts below the retained first..=largest range; the bounded window
    /// admits at most MAX_ACK_INTERVALS - 1 earlier runs.
    fn count_before(&self, first: u64) -> u16 {
        let mut ranges = 0;
        let mut active = false;
        for pn in self.base()..first {
            let received = self.is_set(pn);
            ranges += u16::from(received && !active);
            active = received;
        }
        ranges
    }

    pub(super) fn ack(&self) -> Option<AckView<'_>> {
        let largest = self.largest()?;
        let first = largest.get() - u64::from(self.first_range);
        let left = self.count_before(first);
        let scan = match num::NonZero::<u16>::new(left) {
            None => Scan::Done,
            Some(left) => {
                let cursor = first.checked_sub(1)?;
                let cursor = GapCursor::new(self, cursor)?;
                Scan::More {
                    cursor,
                    remaining: left,
                }
            }
        };
        let iter = Iter {
            received: self,
            scan,
        };
        Some(AckView {
            largest: varint::VarInt::from(largest),
            delay: varint::VarInt::ZERO,
            first_range: varint::VarInt::from_u16(self.first_range),
            additional: iter,
        })
    }
}

#[derive(Clone)]
pub(crate) struct Iter<'space> {
    received: &'space Window,
    scan: Scan,
}

#[derive(Clone, Copy)]
struct GapCursor(u64);

impl GapCursor {
    fn new(received: &Window, cursor: u64) -> Option<Self> {
        (cursor > received.base() && !received.is_set(cursor)).then_some(Self(cursor))
    }
}

#[derive(Clone, Copy)]
enum Scan {
    Done,
    More {
        cursor: GapCursor,
        remaining: num::NonZero<u16>,
    },
}

impl Iter<'_> {
    pub(crate) fn remaining(&self) -> count::Count {
        let left = match self.scan {
            Scan::Done => 0,
            Scan::More {
                remaining: left, ..
            } => left.get(),
        };
        count::Count::from_raw(left)
    }
}

impl Iterator for Iter<'_> {
    type Item = (varint::VarInt, varint::VarInt);

    fn next(&mut self) -> Option<Self::Item> {
        let Scan::More {
            cursor: GapCursor(mut cursor),
            remaining: left,
        } = self.scan
        else {
            return None;
        };
        let mut gap = 1;
        cursor -= 1;
        while !self.received.is_set(cursor) {
            if cursor == self.received.base() {
                self.scan = Scan::Done;
                return None;
            }
            gap += 1;
            cursor -= 1;
        }
        let mut range = 0;
        while cursor > self.received.base() && self.received.is_set(cursor - 1) {
            cursor -= 1;
            range += 1;
        }
        let smallest = cursor;
        self.scan = match num::NonZero::<u16>::new(left.get() - 1) {
            None => Scan::Done,
            Some(left) => smallest
                .checked_sub(1)
                .and_then(|cursor| GapCursor::new(self.received, cursor))
                .map_or(Scan::Done, |cursor| Scan::More {
                    cursor,
                    remaining: left,
                }),
        };
        Some((
            varint::VarInt::from_u16(gap - 1),
            varint::VarInt::from_u16(range),
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.remaining().len();
        (left, Some(left))
    }
}

impl ExactSizeIterator for Iter<'_> {}

const _: () = assert!(mem::size_of::<Window>() <= 96);
const _: () = assert!(mem::size_of::<Iter<'_>>() <= 3 * mem::size_of::<usize>());
const _: () = assert!(!mem::needs_drop::<Window>());
const _: () = assert!(!mem::needs_drop::<Iter<'_>>());
const _: () = assert!(MAX_ACK_INTERVALS <= u16::MAX as usize);
const _: () = assert!(WINDOW_BITS <= 16_384);
