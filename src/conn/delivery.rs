use std::marker::PhantomData;
use std::num::NonZeroU64;

use super::Epoch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Control {
    HandshakeDone,
    NewConnectionId(u64),
    RetireConnectionId(u64),
    StopSending(u64, u64),
    ResetStream(u64, u64, u64),
    MaxData(u64),
    MaxStreamData(u64, u64),
    MaxStreams(bool, u64),
    PathResponse([u8; 8]),
    PathChallenge([u8; 8]),
    DataBlocked(u64),
    StreamDataBlocked(u64, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Stream {
    pub(super) stream_id: u64,
    pub(super) offset: u64,
    pub(super) len: u64,
    pub(super) fin: bool,
    pub(super) retransmit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Crypto {
    pub(super) offset: u64,
    pub(super) len: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Handle<T>(NonZeroU64, PhantomData<fn() -> T>);

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Handle<T> {}

impl<T> Handle<T> {
    fn new(index: usize, generation: u32) -> Option<Self> {
        let encoded_index = u32::try_from(index).ok()?.checked_add(1)?;
        let raw = (u64::from(generation) << 32) | u64::from(encoded_index);
        Some(Self(NonZeroU64::new(raw)?, PhantomData))
    }

    fn index(self) -> usize {
        ((self.0.get() as u32) - 1) as usize
    }

    fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Entry<T> {
    pub(super) epoch: Epoch,
    pub(super) record: T,
    pub(super) carriers: u16,
    pub(super) probe_pending: bool,
}

const NO_FREE_SLOT: u32 = u32::MAX;

struct Bucket<T> {
    generation: u32,
    next_free: u32,
    value: Option<T>,
}

// Generational slots make journal handles O(1) without a parallel record index.
// Producers own record uniqueness; insert defends that invariant in debug builds.
pub(super) struct Tracker<T> {
    buckets: Vec<Bucket<Entry<T>>>,
    free_head: u32,
    len: usize,
    limit: usize,
    probe_cursor: usize,
}

impl<T: Copy + Eq> Tracker<T> {
    pub(super) fn new(active_limit: usize) -> Self {
        let limit = active_limit.min((u32::MAX - 1) as usize);
        Self {
            buckets: Vec::new(),
            free_head: NO_FREE_SLOT,
            len: 0,
            limit,
            probe_cursor: 0,
        }
    }

    fn grow(&mut self) -> bool {
        if self.buckets.len() == self.limit {
            return false;
        }
        let old_len = self.buckets.len();
        let next_len = old_len.max(32).saturating_mul(2).min(self.limit);
        if next_len == old_len {
            return false;
        }
        self.buckets.reserve(next_len - old_len);
        for index in old_len..next_len {
            self.buckets.push(Bucket {
                generation: 0,
                next_free: if index + 1 == next_len {
                    self.free_head
                } else {
                    (index + 1) as u32
                },
                value: None,
            });
        }
        self.free_head = old_len as u32;
        true
    }

    fn handle_at(&self, index: usize) -> Option<Handle<T>> {
        Handle::new(index, self.buckets.get(index)?.generation)
    }

    pub(super) fn insert(&mut self, epoch: Epoch, record: T) -> Option<Handle<T>> {
        debug_assert!(!self.buckets.iter().any(|bucket| {
            bucket
                .value
                .is_some_and(|entry| entry.epoch == epoch && entry.record == record)
        }));
        if self.free_head == NO_FREE_SLOT && !self.grow() {
            return None;
        }
        let index = self.free_head as usize;
        let handle = self.handle_at(index)?;
        let bucket = &mut self.buckets[index];
        self.free_head = bucket.next_free;
        bucket.next_free = NO_FREE_SLOT;
        bucket.value = Some(Entry {
            epoch,
            record,
            carriers: 1,
            probe_pending: false,
        });
        self.len += 1;
        Some(handle)
    }

    pub(super) fn get_mut(&mut self, handle: Handle<T>) -> Option<&mut Entry<T>> {
        let bucket = self.buckets.get_mut(handle.index())?;
        (bucket.generation == handle.generation())
            .then_some(bucket.value.as_mut())
            .flatten()
    }

    pub(super) fn remove(&mut self, handle: Handle<T>) -> Option<Entry<T>> {
        let index = handle.index();
        let bucket = self.buckets.get_mut(index)?;
        if bucket.generation != handle.generation() {
            return None;
        }
        let entry = bucket.value.take()?;
        if bucket.generation == u32::MAX {
            bucket.next_free = NO_FREE_SLOT;
        } else {
            bucket.generation += 1;
            bucket.next_free = self.free_head;
            self.free_head = index as u32;
        }
        self.len -= 1;
        Some(entry)
    }

    pub(super) fn release(&mut self, handle: Handle<T>) -> Option<Entry<T>> {
        let entry = self.get_mut(handle)?;
        if entry.carriers > 1 {
            entry.carriers -= 1;
            return None;
        }
        self.remove(handle)
    }

    pub(super) fn add_probe_carrier(&mut self, handle: Handle<T>) -> bool {
        let index = handle.index();
        let Some(entry) = self.get_mut(handle) else {
            return false;
        };
        let Some(carriers) = entry.carriers.checked_add(1) else {
            return false;
        };
        entry.carriers = carriers;
        entry.probe_pending = false;
        self.probe_cursor = self.probe_cursor.max(index.saturating_add(1));
        true
    }

    pub(super) fn arm_probes(&mut self, epoch: Epoch) {
        self.probe_cursor = 0;
        for bucket in &mut self.buckets {
            if let Some(entry) = &mut bucket.value {
                entry.probe_pending = entry.epoch == epoch;
            }
        }
    }

    pub(super) fn next_probe(
        &self,
        epoch: Epoch,
        mut excluded: impl FnMut(Handle<T>) -> bool,
    ) -> Option<(Handle<T>, T)> {
        for index in self.probe_cursor..self.buckets.len() {
            let Some(entry) = self.buckets[index].value else {
                continue;
            };
            let Some(handle) = self.handle_at(index) else {
                continue;
            };
            if entry.epoch == epoch && entry.probe_pending && !excluded(handle) {
                return Some((handle, entry.record));
            }
        }
        None
    }

    pub(super) fn remove_where(&mut self, mut predicate: impl FnMut(&Entry<T>) -> bool) {
        for index in 0..self.buckets.len() {
            let remove = self.buckets[index]
                .value
                .as_ref()
                .is_some_and(&mut predicate);
            if remove && let Some(handle) = self.handle_at(index) {
                self.remove(handle);
            }
        }
    }

    pub(super) fn has_room(&self, needed: usize) -> bool {
        self.len.saturating_add(needed) <= self.limit
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn optional_handle_is_one_word() {
        assert_eq!(size_of::<Option<Handle<u8>>>(), size_of::<u64>());
    }

    #[test]
    fn generation_rejects_a_recycled_handle() {
        let mut tracker = Tracker::new(1);
        let stale = tracker.insert(Epoch::Application, 1u8).expect("first slot");
        assert_eq!(tracker.remove(stale).map(|entry| entry.record), Some(1));
        let current = tracker
            .insert(Epoch::Application, 2u8)
            .expect("recycled slot");
        assert_ne!(stale, current);
        assert!(tracker.get_mut(stale).is_none());
        assert_eq!(tracker.remove(current).map(|entry| entry.record), Some(2));
    }

    #[test]
    fn zero_capacity_is_fallible() {
        let mut tracker = Tracker::<u8>::new(0);
        assert!(tracker.insert(Epoch::Application, 1).is_none());
    }

    #[test]
    fn exhausted_generation_retires_the_bucket() {
        let mut tracker = Tracker::new(1);
        let handle = tracker.insert(Epoch::Application, 1u8).expect("only slot");
        tracker.buckets[handle.index()].generation = u32::MAX;
        let final_handle = tracker
            .handle_at(handle.index())
            .expect("valid bucket index");

        assert_eq!(
            tracker.remove(final_handle).map(|entry| entry.record),
            Some(1)
        );
        assert!(tracker.insert(Epoch::Application, 2).is_none());
        assert!(tracker.get_mut(final_handle).is_none());
    }

    #[test]
    fn probe_carrier_overflow_is_rejected() {
        let mut tracker = Tracker::new(1);
        let handle = tracker
            .insert(Epoch::Application, 1u8)
            .expect("delivery slot");
        tracker.get_mut(handle).expect("delivery").carriers = u16::MAX;

        assert!(!tracker.add_probe_carrier(handle));
        assert_eq!(
            tracker.get_mut(handle).expect("delivery").carriers,
            u16::MAX
        );
    }
}
