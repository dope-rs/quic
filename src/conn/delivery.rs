use std::hash::{Hash, Hasher};

use super::Epoch;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum ControlRecord {
    HandshakeDone,
    NewConnectionId(u64),
    RetireConnectionId(u64),
    StopSending(u64, u64),
    ResetStream(u64, u64, u64),
    MaxData(u64),
    MaxStreamData(u64, u64),
    MaxStreamsBidi(u64),
    PathResponse([u8; 8]),
    PathChallenge([u8; 8]),
    DataBlocked(u64),
    StreamDataBlocked(u64, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct StreamRecord {
    pub(super) stream_id: u64,
    pub(super) offset: u64,
    pub(super) len: u64,
    pub(super) fin: bool,
    pub(super) retransmit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct CryptoRecord {
    pub(super) offset: u64,
    pub(super) len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeliveryHandle {
    pub(super) index: u16,
    pub(super) generation: u32,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DeliveryEntry<T> {
    pub(super) epoch: Epoch,
    pub(super) record: T,
    pub(super) carriers: u16,
    pub(super) probe_pending: bool,
}

pub(super) struct DeliveryBucket<T> {
    pub(super) generation: u32,
    pub(super) next_free: Option<u16>,
    pub(super) entry: Option<DeliveryEntry<T>>,
}

#[derive(Clone, Copy)]
pub(super) struct DeliveryIndex<T> {
    pub(super) epoch: Epoch,
    pub(super) record: T,
}

pub(super) enum DeliveryLookup {
    Occupied(usize),
    Vacant(usize),
    Full,
}

pub(super) struct DeliveryHasher(u64);

impl DeliveryHasher {
    pub(super) fn new() -> Self {
        Self(0x517c_c1b7_2722_0a95)
    }
}

impl Hasher for DeliveryHasher {
    fn finish(&self) -> u64 {
        let mut value = self.0;
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            let mut word = [0; 8];
            word.copy_from_slice(chunk);
            self.0 = (self.0.rotate_left(5) ^ u64::from_ne_bytes(word))
                .wrapping_mul(0x517c_c1b7_2722_0a95);
        }
        let mut tail = [0; 8];
        let remainder = chunks.remainder();
        tail[..remainder.len()].copy_from_slice(remainder);
        self.0 = (self.0.rotate_left(5) ^ u64::from_ne_bytes(tail) ^ remainder.len() as u64)
            .wrapping_mul(0x517c_c1b7_2722_0a95);
    }
}

pub(super) struct DeliveryTable<T> {
    pub(super) buckets: Vec<DeliveryBucket<T>>,
    pub(super) index: Vec<Option<DeliveryIndex<T>>>,
    pub(super) free_head: Option<u16>,
    pub(super) len: usize,
    pub(super) limit: usize,
    pub(super) probe_cursor: usize,
}

impl<T: Copy + Eq + Hash> DeliveryTable<T> {
    pub(super) fn new(active_limit: usize) -> Self {
        Self {
            buckets: Vec::new(),
            index: Vec::new(),
            free_head: None,
            len: 0,
            limit: active_limit.min(u16::MAX as usize),
            probe_cursor: 0,
        }
    }

    pub(super) fn grow(&mut self) -> bool {
        if self.buckets.len() == self.limit {
            return false;
        }
        let old_len = self.buckets.len();
        let next_len = old_len.max(32).saturating_mul(2).min(self.limit);
        self.buckets.reserve(next_len - old_len);
        for index in old_len..next_len {
            self.buckets.push(DeliveryBucket {
                generation: 0,
                next_free: if index + 1 == next_len {
                    self.free_head
                } else {
                    Some((index + 1) as u16)
                },
                entry: None,
            });
        }
        self.free_head = Some(old_len as u16);
        let index_capacity = next_len.saturating_mul(2).next_power_of_two();
        let mut replacement = vec![None; index_capacity];
        for entry in self.index.iter().flatten().copied() {
            let mut hasher = DeliveryHasher::new();
            entry.epoch.hash(&mut hasher);
            entry.record.hash(&mut hasher);
            let start = hasher.finish() as usize & (index_capacity - 1);
            let Some(slot) = (0..index_capacity)
                .map(|distance| (start + distance) & (index_capacity - 1))
                .find(|slot| replacement[*slot].is_none())
            else {
                return false;
            };
            replacement[slot] = Some(entry);
        }
        self.index = replacement;
        true
    }

    pub(super) fn key_index(&self, epoch: Epoch, record: T) -> usize {
        let mut hasher = DeliveryHasher::new();
        epoch.hash(&mut hasher);
        record.hash(&mut hasher);
        hasher.finish() as usize & (self.index.len() - 1)
    }

    pub(super) fn handle_at(&self, index: usize) -> DeliveryHandle {
        DeliveryHandle {
            index: index as u16,
            generation: self.buckets[index].generation,
        }
    }

    pub(super) fn lookup(&self, epoch: Epoch, record: T) -> DeliveryLookup {
        let start = self.key_index(epoch, record);
        for distance in 0..self.index.len() {
            let index = (start + distance) & (self.index.len() - 1);
            match self.index[index] {
                Some(entry) if entry.epoch == epoch && entry.record == record => {
                    return DeliveryLookup::Occupied(index);
                }
                Some(_) => {}
                None => return DeliveryLookup::Vacant(index),
            }
        }
        DeliveryLookup::Full
    }

    pub(super) fn find_index(&self, epoch: Epoch, record: T) -> Option<usize> {
        if self.index.is_empty() {
            return None;
        }
        match self.lookup(epoch, record) {
            DeliveryLookup::Occupied(index) => Some(index),
            DeliveryLookup::Vacant(_) | DeliveryLookup::Full => None,
        }
    }

    pub(super) fn contains(&self, epoch: Epoch, record: T) -> bool {
        self.find_index(epoch, record).is_some()
    }

    pub(super) fn insert(&mut self, epoch: Epoch, record: T) -> Option<DeliveryHandle> {
        if self.free_head.is_none() && !self.grow() {
            return None;
        }
        let index_slot = match self.lookup(epoch, record) {
            DeliveryLookup::Occupied(_) => return None,
            DeliveryLookup::Vacant(index) => index,
            DeliveryLookup::Full => return None,
        };
        let index = self.free_head? as usize;
        let bucket = &mut self.buckets[index];
        self.free_head = bucket.next_free;
        bucket.next_free = None;
        bucket.entry = Some(DeliveryEntry {
            epoch,
            record,
            carriers: 1,
            probe_pending: false,
        });
        let handle = self.handle_at(index);
        self.index[index_slot] = Some(DeliveryIndex { epoch, record });
        self.len += 1;
        Some(handle)
    }

    pub(super) fn get_mut(&mut self, handle: DeliveryHandle) -> Option<&mut DeliveryEntry<T>> {
        let bucket = self.buckets.get_mut(handle.index as usize)?;
        (bucket.generation == handle.generation)
            .then_some(bucket.entry.as_mut())
            .flatten()
    }

    pub(super) fn remove(&mut self, handle: DeliveryHandle) -> Option<DeliveryEntry<T>> {
        let index = handle.index as usize;
        let entry = {
            let bucket = self.buckets.get(index)?;
            if bucket.generation != handle.generation {
                return None;
            }
            bucket.entry?
        };
        let index_slot = self.find_index(entry.epoch, entry.record)?;
        self.remove_index(index_slot);
        let bucket = &mut self.buckets[index];
        let entry = bucket.entry.take()?;
        bucket.generation = bucket.generation.wrapping_add(1);
        bucket.next_free = self.free_head;
        self.free_head = Some(index as u16);
        self.len -= 1;
        Some(entry)
    }

    pub(super) fn remove_index(&mut self, mut hole: usize) {
        let mask = self.index.len() - 1;
        let mut scan = (hole + 1) & mask;
        while let Some(entry) = self.index[scan] {
            let home = self.key_index(entry.epoch, entry.record);
            let scan_distance = scan.wrapping_sub(home) & mask;
            let hole_distance = hole.wrapping_sub(home) & mask;
            if hole_distance < scan_distance {
                self.index[hole] = Some(entry);
                hole = scan;
            }
            scan = (scan + 1) & mask;
        }
        self.index[hole] = None;
    }

    pub(super) fn release(&mut self, handle: DeliveryHandle) -> Option<DeliveryEntry<T>> {
        let entry = self.get_mut(handle)?;
        if entry.carriers > 1 {
            entry.carriers -= 1;
            return None;
        }
        self.remove(handle)
    }

    pub(super) fn add_probe_carrier(&mut self, handle: DeliveryHandle) -> bool {
        let index = handle.index as usize;
        let Some(entry) = self.get_mut(handle) else {
            return false;
        };
        entry.carriers = entry.carriers.saturating_add(1);
        entry.probe_pending = false;
        self.probe_cursor = self.probe_cursor.max(index.saturating_add(1));
        true
    }

    pub(super) fn arm_probes(&mut self, epoch: Epoch) {
        self.probe_cursor = 0;
        for bucket in &mut self.buckets {
            if let Some(entry) = &mut bucket.entry {
                entry.probe_pending = entry.epoch == epoch;
            }
        }
    }

    pub(super) fn next_probe(
        &self,
        epoch: Epoch,
        mut excluded: impl FnMut(DeliveryHandle) -> bool,
    ) -> Option<(DeliveryHandle, T)> {
        for index in self.probe_cursor..self.buckets.len() {
            let bucket = &self.buckets[index];
            let Some(entry) = bucket.entry else {
                continue;
            };
            let handle = self.handle_at(index);
            if entry.epoch == epoch && entry.probe_pending && !excluded(handle) {
                return Some((handle, entry.record));
            }
        }
        None
    }

    pub(super) fn remove_where(&mut self, mut predicate: impl FnMut(&DeliveryEntry<T>) -> bool) {
        for index in 0..self.buckets.len() {
            let remove = self.buckets[index]
                .entry
                .as_ref()
                .is_some_and(&mut predicate);
            if remove {
                let handle = self.handle_at(index);
                self.remove(handle);
            }
        }
    }

    pub(super) fn has_room(&self, needed: usize) -> bool {
        self.len.saturating_add(needed) <= self.limit
    }
}
