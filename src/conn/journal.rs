use std::time::{Duration, Instant};

use crate::frame::AckRanges;
use crate::rtt::PACKET_THRESHOLD;

use super::delivery::DeliveryHandle;
use super::{Epoch, PACKET_CONTROL_CAPACITY, PACKET_STREAM_CAPACITY};

#[derive(Debug, Clone, Copy)]
pub(super) struct PacketJournal {
    pub(super) epoch: Epoch,
    pub(super) pn: u64,
    pub(super) early_data: bool,
    pub(super) sent_time: Instant,
    pub(super) ack_eliciting: bool,
    pub(super) in_flight: bool,
    pub(super) bytes_sent: usize,
    pub(super) pto_protected: bool,
    pub(super) crypto: Option<DeliveryHandle>,
    pub(super) controls: [Option<DeliveryHandle>; PACKET_CONTROL_CAPACITY],
    pub(super) control_len: usize,
    pub(super) streams: [Option<DeliveryHandle>; PACKET_STREAM_CAPACITY],
    pub(super) stream_len: usize,
}

#[derive(Default)]
pub(super) struct PacketJournalRing {
    pub(super) slots: Box<[Option<PacketJournal>]>,
    pub(super) len: usize,
    pub(super) lowest: Option<u64>,
    pub(super) highest: Option<u64>,
}

impl PacketJournalRing {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            slots: vec![None; capacity].into_boxed_slice(),
            len: 0,
            lowest: None,
            highest: None,
        }
    }

    pub(super) fn slot(&self, pn: u64) -> usize {
        pn as usize % self.slots.len()
    }

    pub(super) fn insert(&mut self, journal: PacketJournal) -> bool {
        if self.slots.is_empty() {
            return false;
        }
        let slot = self.slot(journal.pn);
        if self.slots[slot].is_some() {
            return false;
        }
        self.slots[slot] = Some(journal);
        self.len += 1;
        self.lowest = Some(self.lowest.map_or(journal.pn, |pn| pn.min(journal.pn)));
        self.highest = Some(self.highest.map_or(journal.pn, |pn| pn.max(journal.pn)));
        true
    }

    pub(super) fn get(&self, pn: u64) -> Option<&PacketJournal> {
        if self.slots.is_empty() {
            return None;
        }
        self.slots[self.slot(pn)]
            .as_ref()
            .filter(|journal| journal.pn == pn)
    }

    pub(super) fn remove(&mut self, pn: u64) -> Option<PacketJournal> {
        let journal = self.remove_unindexed(pn)?;
        if self.len == 0 || self.lowest == Some(pn) || self.highest == Some(pn) {
            self.reindex();
        }
        Some(journal)
    }

    fn remove_unindexed(&mut self, pn: u64) -> Option<PacketJournal> {
        if self.slots.is_empty() {
            return None;
        }
        let slot = self.slot(pn);
        if self.slots[slot].as_ref()?.pn != pn {
            return None;
        }
        let journal = self.slots[slot].take()?;
        self.len -= 1;
        Some(journal)
    }

    fn reindex(&mut self) {
        self.lowest = None;
        self.highest = None;
        for present in self.slots.iter().flatten() {
            self.lowest = Some(self.lowest.map_or(present.pn, |low| low.min(present.pn)));
            self.highest = Some(self.highest.map_or(present.pn, |high| high.max(present.pn)));
        }
    }

    pub(super) fn drain_range(
        &mut self,
        smallest: u64,
        largest: u64,
        emit: &mut impl FnMut(PacketJournal),
    ) {
        let (Some(lowest), Some(highest)) = (self.lowest, self.highest) else {
            return;
        };
        let smallest = smallest.max(lowest);
        let largest = largest.min(highest);
        if smallest > largest {
            return;
        }
        let mut removed = false;
        for pn in smallest..=largest {
            if let Some(journal) = self.remove_unindexed(pn) {
                removed = true;
                emit(journal);
            }
        }
        if removed {
            self.reindex();
        }
    }

    pub(super) fn drain_where(
        &mut self,
        mut predicate: impl FnMut(&PacketJournal) -> bool,
        emit: &mut impl FnMut(PacketJournal),
    ) {
        let mut removed = false;
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(&mut predicate) {
                let Some(journal) = slot.take() else {
                    continue;
                };
                self.len -= 1;
                removed = true;
                emit(journal);
            }
        }
        if removed {
            self.reindex();
        }
    }

    pub(super) fn vacant(&self, pn: u64) -> bool {
        !self.slots.is_empty() && self.slots[self.slot(pn)].is_none()
    }

    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = &mut PacketJournal> {
        self.slots.iter_mut().filter_map(Option::as_mut)
    }
}

#[derive(Default)]
pub(super) struct PacketJournalTable {
    pub(super) rings: [PacketJournalRing; 3],
    pub(super) len: usize,
    pub(super) limit: usize,
}

impl PacketJournalTable {
    pub(super) fn new(limit: usize) -> Self {
        let crypto_capacity = limit.min(128);
        Self {
            rings: [
                PacketJournalRing::new(crypto_capacity),
                PacketJournalRing::new(crypto_capacity),
                PacketJournalRing::new(limit),
            ],
            len: 0,
            limit,
        }
    }

    pub(super) fn ring(&self, epoch: Epoch) -> &PacketJournalRing {
        &self.rings[epoch as usize]
    }

    pub(super) fn ring_mut(&mut self, epoch: Epoch) -> &mut PacketJournalRing {
        &mut self.rings[epoch as usize]
    }

    pub(super) fn insert(&mut self, journal: PacketJournal) -> bool {
        if self.len == self.limit || !self.ring_mut(journal.epoch).insert(journal) {
            return false;
        }
        self.len += 1;
        true
    }

    pub(super) fn remove(&mut self, epoch: Epoch, pn: u64) -> Option<PacketJournal> {
        let journal = self.ring_mut(epoch).remove(pn)?;
        self.len -= 1;
        Some(journal)
    }

    pub(super) fn drain_application_ack(
        &mut self,
        largest: u64,
        first_range: u64,
        additional: AckRanges<'_>,
        mut emit: impl FnMut(PacketJournal),
    ) {
        let ring = self.ring_mut(Epoch::Application);
        let first_smallest = largest.saturating_sub(first_range);
        ring.drain_range(first_smallest, largest, &mut emit);
        let mut previous_smallest = first_smallest;
        for (gap, range) in additional {
            let next_largest = previous_smallest - gap.get() - 2;
            let next_smallest = next_largest - range.get();
            ring.drain_range(next_smallest, next_largest, &mut emit);
            previous_smallest = next_smallest;
        }
        self.len = self.rings.iter().map(|ring| ring.len).sum();
    }

    pub(super) fn drain_application_lost(
        &mut self,
        largest_acked: u64,
        lost_send_time: Instant,
        mut emit: impl FnMut(PacketJournal),
    ) {
        let ring = self.ring_mut(Epoch::Application);
        let Some(lowest) = ring.lowest else {
            return;
        };
        let highest = ring.highest.unwrap_or(lowest).min(largest_acked);
        for pn in lowest..=highest {
            let Some(journal) = ring.get(pn).copied() else {
                continue;
            };
            let lost = largest_acked.saturating_sub(pn) >= PACKET_THRESHOLD
                || (!journal.pto_protected && journal.sent_time <= lost_send_time);
            if lost {
                if let Some(journal) = ring.remove_unindexed(pn) {
                    emit(journal);
                }
            } else if !journal.pto_protected {
                break;
            }
        }
        ring.reindex();
        self.len = self.rings.iter().map(|ring| ring.len).sum();
    }

    pub(super) fn drain_where(
        &mut self,
        predicate: impl Copy + Fn(&PacketJournal) -> bool,
        mut emit: impl FnMut(PacketJournal),
    ) {
        for ring in &mut self.rings {
            ring.drain_where(predicate, &mut emit);
        }
        self.len = self.rings.iter().map(|ring| ring.len).sum();
    }

    pub(super) fn application_iter_mut(&mut self) -> impl Iterator<Item = &mut PacketJournal> {
        self.ring_mut(Epoch::Application).iter_mut()
    }

    pub(super) fn application_loss_candidate(
        &self,
        largest_acked: u64,
        loss_delay: Duration,
    ) -> Option<Instant> {
        let lowest = largest_acked.saturating_sub(PACKET_THRESHOLD - 1);
        (lowest..=largest_acked)
            .filter_map(|pn| self.ring(Epoch::Application).get(pn))
            .filter(|journal| !journal.pto_protected)
            .map(|journal| journal.sent_time + loss_delay)
            .min()
    }

    pub(super) fn has_room_for(&self, epoch: Epoch, pn: u64, needed: usize) -> bool {
        self.len.saturating_add(needed) <= self.limit
            && (0..needed).all(|offset| self.ring(epoch).vacant(pn.saturating_add(offset as u64)))
    }

    pub(super) fn count_epoch(&self, epoch: Epoch) -> usize {
        self.ring(epoch).len
    }
}
