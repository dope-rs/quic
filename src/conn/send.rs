use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};
use std::ops::{Deref, DerefMut};

use crate::stream::SendStream;
use crate::varint::VarInt;

use super::{STREAM_SCHEDULE_CAPACITY, STREAM_SCHEDULE_WORK_LIMIT};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Ticket(u64);

impl Ticket {
    const GENERATION_BIT: u64 = 1 << 63;

    fn new(stream_id: u64, generation: bool) -> Self {
        debug_assert!(stream_id <= VarInt::MAX);
        Self(stream_id | (u64::from(generation) * Self::GENERATION_BIT))
    }

    pub(super) fn stream_id(self) -> u64 {
        self.0 & VarInt::MAX
    }

    pub(super) fn generation(self) -> bool {
        self.0 & Self::GENERATION_BIT != 0
    }
}

#[derive(Default)]
pub(super) struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, _: &[u8]) {
        unreachable!("send stream map is keyed only by u64 stream IDs")
    }

    fn write_u64(&mut self, stream_id: u64) {
        const SEQUENCE_MIX: u64 = 0x9e37_79b9_7f4a_7c15;
        const KIND_MIX: u64 = 0xd6e8_feb8_6659_fd93;
        self.0 =
            (stream_id >> 2).wrapping_mul(SEQUENCE_MIX) ^ (stream_id & 0x3).wrapping_mul(KIND_MIX);
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(super) struct Credit(u64);

impl Credit {
    fn new(limit: u64) -> Self {
        debug_assert!(limit <= VarInt::MAX);
        Self(limit)
    }

    pub(super) fn limit(self) -> u64 {
        self.0
    }

    pub(super) fn raise(&mut self, limit: u64) -> bool {
        debug_assert!(limit <= VarInt::MAX);
        if limit <= self.limit() {
            return false;
        }
        self.0 = limit;
        true
    }
}

pub(super) struct Entry {
    pub(super) stream: SendStream,
    pub(super) credit: Credit,
}

impl Entry {
    pub(super) fn new(stream: SendStream, credit: u64) -> Self {
        Self {
            stream,
            credit: Credit::new(credit),
        }
    }
}

impl Deref for Entry {
    type Target = SendStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl DerefMut for Entry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

pub(super) type Map = HashMap<u64, Entry, BuildHasherDefault<IdHasher>>;

pub(super) struct Schedule {
    pending: VecDeque<Ticket>,
    active: usize,
    single: Option<Ticket>,
}

impl Schedule {
    pub(super) fn new() -> Self {
        Self {
            pending: VecDeque::with_capacity(STREAM_SCHEDULE_CAPACITY),
            active: 0,
            single: None,
        }
    }

    pub(super) fn activate(&mut self, stream_id: u64, generation: bool) {
        let scheduled = Ticket::new(stream_id, generation);
        self.pending.push_back(scheduled);
        self.single = (self.active == 0).then_some(scheduled);
        self.active += 1;
    }

    pub(super) fn deactivate(&mut self) {
        self.active = self.active.saturating_sub(1);
        self.single = None;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.active == 0
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Ticket> {
        self.pending.iter()
    }

    pub(super) fn snapshot(&mut self, streams: &mut Map, out: &mut Vec<u64>) {
        out.clear();
        if self.active == 1
            && let Some(scheduled) = self.single
        {
            while self
                .pending
                .front()
                .is_some_and(|front| *front != scheduled)
            {
                self.pending.pop_front();
            }
            if self.pending.front() == Some(&scheduled) {
                out.push(scheduled.stream_id());
                return;
            }
            self.single = None;
        }

        let work = self.pending.len().min(STREAM_SCHEDULE_WORK_LIMIT);
        let mut sole_active = None;
        let mut active_seen = 0;
        for _ in 0..work {
            let scheduled = self.pending.pop_front().expect("bounded by queue length");
            let stream_id = scheduled.stream_id();
            let active = streams.get_mut(&stream_id).is_some_and(|stream| {
                if !stream.is_scheduled(scheduled.generation()) {
                    return false;
                }
                if stream.has_pending() {
                    return true;
                }
                if stream.unschedule() {
                    self.deactivate();
                }
                false
            });
            if active {
                out.push(stream_id);
                self.pending.push_back(scheduled);
                if active_seen == 0 {
                    sole_active = Some(scheduled);
                }
                active_seen += 1;
            }
        }
        if self.active == 1 {
            self.single = sole_active;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn entry_packs_credit_without_padding_growth() {
        assert_eq!(size_of::<Credit>(), size_of::<u64>());
        assert_eq!(
            size_of::<Entry>(),
            size_of::<SendStream>() + size_of::<u64>()
        );
    }

    #[test]
    fn raised_credit_updates_the_limit() {
        let mut credit = Credit::new(10);
        assert!(credit.raise(11));
        assert_eq!(credit.limit(), 11);
        assert!(!credit.raise(10));
    }
}
