use std::time::{Duration, Instant};

use o3::collections::{FixedIndexTable, StackArena, StackDrain};

use crate::frame::AckRanges;
use crate::rtt::PACKET_THRESHOLD;

use super::Epoch;
use super::delivery::{self, Handle};

#[derive(Debug, Clone, Copy)]
pub(super) struct Packet {
    pub(super) epoch: Epoch,
    pub(super) pn: u64,
    pub(super) early_data: bool,
    pub(super) sent_time: Instant,
    pub(super) ack_eliciting: bool,
    pub(super) in_flight: bool,
    pub(super) bytes_sent: usize,
    pub(super) pto_protected: bool,
    pub(super) crypto: Option<Handle<delivery::Crypto>>,
}

pub(super) type ControlDrain<'a> = StackDrain<'a, Handle<delivery::Control>>;
pub(super) type StreamDrain<'a> = StackDrain<'a, Handle<delivery::Stream>>;

#[derive(Clone, Copy)]
pub(super) struct PacketKey {
    epoch: Epoch,
    slot: usize,
}

struct Ring {
    slots: FixedIndexTable<Packet>,
    controls: StackArena<Handle<delivery::Control>>,
    streams: StackArena<Handle<delivery::Stream>>,
    lowest: Option<u64>,
    highest: Option<u64>,
}

impl Default for Ring {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

impl Ring {
    fn new(capacity: usize, control_capacity: usize, stream_capacity: usize) -> Self {
        let carrier_lanes = if control_capacity == 0 && stream_capacity == 0 {
            0
        } else {
            capacity
        };
        Self {
            slots: FixedIndexTable::with_capacity(capacity),
            controls: StackArena::with_capacity(control_capacity, carrier_lanes),
            streams: StackArena::with_capacity(stream_capacity, carrier_lanes),
            lowest: None,
            highest: None,
        }
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn slot(&self, pn: u64) -> usize {
        pn as usize % self.slots.capacity()
    }

    fn insert(&mut self, journal: Packet) -> Option<usize> {
        if self.slots.capacity() == 0 {
            return None;
        }
        let slot = self.slot(journal.pn);
        if self.slots.try_insert(slot, journal).is_err() {
            return None;
        }
        self.lowest = Some(self.lowest.map_or(journal.pn, |pn| pn.min(journal.pn)));
        self.highest = Some(self.highest.map_or(journal.pn, |pn| pn.max(journal.pn)));
        Some(slot)
    }

    fn push_control(&mut self, slot: usize, handle: Handle<delivery::Control>) -> bool {
        debug_assert!(self.slots.contains(slot));
        self.controls.push(slot, handle).is_ok()
    }

    fn push_stream(&mut self, slot: usize, handle: Handle<delivery::Stream>) -> bool {
        debug_assert!(self.slots.contains(slot));
        self.streams.push(slot, handle).is_ok()
    }

    fn get(&self, pn: u64) -> Option<&Packet> {
        if self.slots.capacity() == 0 {
            return None;
        }
        self.slots
            .get(self.slot(pn))
            .filter(|journal| journal.pn == pn)
    }

    fn remove(
        &mut self,
        pn: u64,
        mut emit: impl FnMut(Packet, ControlDrain<'_>, StreamDrain<'_>),
    ) -> bool {
        let Some((slot, journal)) = self.remove_unindexed(pn) else {
            return false;
        };
        if self.slots.is_empty() {
            self.lowest = None;
            self.highest = None;
        } else {
            if self.lowest == Some(pn) {
                self.lowest = self.scan_up(pn + 1, self.highest.unwrap_or(pn));
            }
            if self.highest == Some(pn) {
                self.highest = self.scan_down(self.lowest.unwrap_or(pn), pn.saturating_sub(1));
            }
            if self.lowest.is_none() || self.highest.is_none() {
                debug_assert!(false, "journal bounds lost with {} entries", self.len());
                self.reindex();
            }
        }
        self.emit(slot, journal, &mut emit);
        true
    }

    fn remove_unindexed(&mut self, pn: u64) -> Option<(usize, Packet)> {
        if self.slots.capacity() == 0 {
            return None;
        }
        let slot = self.slot(pn);
        if self.slots.get(slot)?.pn != pn {
            return None;
        }
        Some((slot, self.slots.remove(slot)?))
    }

    fn emit(
        &mut self,
        slot: usize,
        journal: Packet,
        emit: &mut impl FnMut(Packet, ControlDrain<'_>, StreamDrain<'_>),
    ) {
        emit(journal, self.controls.drain(slot), self.streams.drain(slot));
    }

    fn reindex(&mut self) {
        self.lowest = None;
        self.highest = None;
        for present in self.slots.values() {
            self.lowest = Some(self.lowest.map_or(present.pn, |low| low.min(present.pn)));
            self.highest = Some(self.highest.map_or(present.pn, |high| high.max(present.pn)));
        }
    }

    /// First present pn in `from..=to`, one slot probe per pn.
    fn scan_up(&self, from: u64, to: u64) -> Option<u64> {
        (from..=to).find(|&pn| self.get(pn).is_some())
    }

    /// Last present pn in `from..=to`, one slot probe per pn.
    fn scan_down(&self, from: u64, to: u64) -> Option<u64> {
        (from..=to).rev().find(|&pn| self.get(pn).is_some())
    }

    fn drain_range(
        &mut self,
        smallest: u64,
        largest: u64,
        emit: &mut impl FnMut(Packet, ControlDrain<'_>, StreamDrain<'_>),
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
            if let Some((slot, journal)) = self.remove_unindexed(pn) {
                removed = true;
                self.emit(slot, journal, emit);
            }
        }
        if !removed {
            return;
        }
        if self.slots.is_empty() {
            self.lowest = None;
            self.highest = None;
            return;
        }
        if smallest == lowest {
            self.lowest = self.scan_up(largest + 1, highest);
        }
        if largest == highest {
            self.highest = self.scan_down(lowest, smallest - 1);
        }
        if self.lowest.is_none() || self.highest.is_none() {
            debug_assert!(false, "journal bounds lost with {} entries", self.len());
            self.reindex();
        }
    }

    fn drain_where(
        &mut self,
        mut predicate: impl FnMut(&Packet) -> bool,
        emit: &mut impl FnMut(Packet, ControlDrain<'_>, StreamDrain<'_>),
    ) {
        let capacity = self.slots.capacity();
        let slots = &mut self.slots;
        let controls = &mut self.controls;
        let streams = &mut self.streams;
        let mut removed = false;
        slots.drain_where(
            |journal| predicate(journal),
            |journal| {
                removed = true;
                let slot = journal.pn as usize % capacity;
                emit(journal, controls.drain(slot), streams.drain(slot));
            },
        );
        if removed {
            self.reindex();
        }
    }

    fn vacant(&self, pn: u64) -> bool {
        if self.slots.capacity() == 0 {
            return false;
        }
        let slot = self.slot(pn);
        self.slots.vacant(slot)
            && self.controls.lane_is_empty(slot)
            && self.streams.lane_is_empty(slot)
    }

    fn has_carrier_room(&self, controls: usize, streams: usize) -> bool {
        self.controls.available() >= controls && self.streams.available() >= streams
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut Packet> {
        self.slots.values_mut()
    }
}

pub(super) struct Table {
    rings: [Ring; 3],
    len: usize,
    limit: usize,
}

impl Default for Table {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

impl Table {
    pub(super) fn new(limit: usize, control_capacity: usize, stream_capacity: usize) -> Self {
        let crypto_capacity = limit.min(128);
        Self {
            rings: [
                Ring::new(crypto_capacity, 0, 0),
                Ring::new(crypto_capacity, 0, 0),
                Ring::new(limit, control_capacity, stream_capacity),
            ],
            len: 0,
            limit,
        }
    }

    fn ring(&self, epoch: Epoch) -> &Ring {
        &self.rings[epoch as usize]
    }

    fn ring_mut(&mut self, epoch: Epoch) -> &mut Ring {
        &mut self.rings[epoch as usize]
    }

    pub(super) fn insert(&mut self, journal: Packet) -> Option<PacketKey> {
        if self.len == self.limit {
            return None;
        }
        let epoch = journal.epoch;
        let slot = self.ring_mut(epoch).insert(journal)?;
        self.len += 1;
        Some(PacketKey { epoch, slot })
    }

    pub(super) fn push_control(
        &mut self,
        key: PacketKey,
        handle: Handle<delivery::Control>,
    ) -> bool {
        self.ring_mut(key.epoch).push_control(key.slot, handle)
    }

    pub(super) fn push_stream(&mut self, key: PacketKey, handle: Handle<delivery::Stream>) -> bool {
        self.ring_mut(key.epoch).push_stream(key.slot, handle)
    }

    pub(super) fn remove(
        &mut self,
        epoch: Epoch,
        pn: u64,
        emit: impl FnMut(Packet, ControlDrain<'_>, StreamDrain<'_>),
    ) -> bool {
        if !self.ring_mut(epoch).remove(pn, emit) {
            return false;
        }
        self.len -= 1;
        true
    }

    pub(super) fn drain_application_ack(
        &mut self,
        largest: u64,
        first_range: u64,
        additional: AckRanges<'_>,
        mut emit: impl FnMut(Packet, ControlDrain<'_>, StreamDrain<'_>),
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
        self.recount();
    }

    pub(super) fn drain_application_lost(
        &mut self,
        largest_acked: u64,
        lost_send_time: Instant,
        mut emit: impl FnMut(Packet, ControlDrain<'_>, StreamDrain<'_>),
    ) {
        let ring = self.ring_mut(Epoch::Application);
        let Some(lowest) = ring.lowest else {
            return;
        };
        let highest = ring.highest.unwrap_or(lowest).min(largest_acked);
        let mut removed = false;
        for pn in lowest..=highest {
            let Some(journal) = ring.get(pn).copied() else {
                continue;
            };
            let lost = largest_acked.saturating_sub(pn) >= PACKET_THRESHOLD
                || (!journal.pto_protected && journal.sent_time <= lost_send_time);
            if lost {
                if let Some((slot, journal)) = ring.remove_unindexed(pn) {
                    removed = true;
                    ring.emit(slot, journal, &mut emit);
                }
            } else if !journal.pto_protected {
                break;
            }
        }
        if removed {
            ring.reindex();
        }
        self.recount();
    }

    pub(super) fn drain_where(
        &mut self,
        predicate: impl Copy + Fn(&Packet) -> bool,
        mut emit: impl FnMut(Packet, ControlDrain<'_>, StreamDrain<'_>),
    ) {
        for ring in &mut self.rings {
            ring.drain_where(predicate, &mut emit);
        }
        self.recount();
    }

    pub(super) fn application_iter_mut(&mut self) -> impl Iterator<Item = &mut Packet> {
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

    pub(super) fn has_carrier_room(&self, controls: usize, streams: usize) -> bool {
        self.ring(Epoch::Application)
            .has_carrier_room(controls, streams)
    }

    pub(super) fn count_epoch(&self, epoch: Epoch) -> usize {
        self.ring(epoch).len()
    }

    fn recount(&mut self) {
        self.len = self.rings.iter().map(Ring::len).sum();
    }
}

#[cfg(test)]
mod tests {
    use super::super::delivery::{Control, Stream, Tracker};
    use super::*;

    fn packet(pn: u64) -> Packet {
        Packet {
            epoch: Epoch::Application,
            pn,
            early_data: false,
            sent_time: Instant::now(),
            ack_eliciting: true,
            in_flight: true,
            bytes_sent: 1_200,
            pto_protected: false,
            crypto: None,
        }
    }

    #[test]
    fn typed_carriers_follow_the_packet_slot_and_return_capacity() {
        let mut controls = Tracker::new(2);
        let control_a = controls
            .insert(Epoch::Application, Control::MaxData(1))
            .unwrap();
        let control_b = controls
            .insert(Epoch::Application, Control::MaxData(2))
            .unwrap();
        let mut streams = Tracker::new(1);
        let stream = streams
            .insert(
                Epoch::Application,
                Stream {
                    stream_id: 0,
                    offset: 0,
                    len: 1,
                    fin: false,
                    retransmit: false,
                },
            )
            .unwrap();
        let mut table = Table::new(4, 2, 1);

        assert!(table.has_room_for(Epoch::Application, 5, 1));
        assert!(table.has_carrier_room(2, 1));
        let key = table.insert(packet(5)).unwrap();
        assert!(table.push_control(key, control_a));
        assert!(table.push_control(key, control_b));
        assert!(table.push_stream(key, stream));
        assert!(!table.has_room_for(Epoch::Application, 9, 1));
        assert!(!table.has_carrier_room(1, 0));

        let mut drained_controls = Vec::new();
        let mut drained_streams = Vec::new();
        assert!(
            table.remove(Epoch::Application, 5, |packet, controls, streams| {
                assert_eq!(packet.pn, 5);
                drained_controls.extend(controls);
                drained_streams.extend(streams);
            })
        );
        assert_eq!(drained_controls, [control_b, control_a]);
        assert_eq!(drained_streams, [stream]);
        assert!(table.has_room_for(Epoch::Application, 9, 1));
        assert!(table.has_carrier_room(2, 1));
    }

    #[test]
    fn crypto_rings_have_no_carrier_storage_or_cross_epoch_lane_aliases() {
        let mut table = Table::new(4, 1, 1);
        assert!(
            table
                .insert(Packet {
                    epoch: Epoch::Initial,
                    ..packet(1)
                })
                .is_some()
        );
        assert!(table.insert(packet(1)).is_some());

        let mut initial = 0;
        assert!(table.remove(Epoch::Initial, 1, |_, controls, streams| {
            initial += 1;
            assert_eq!(controls.count(), 0);
            assert_eq!(streams.count(), 0);
        }));
        assert_eq!(initial, 1);
        assert_eq!(table.count_epoch(Epoch::Application), 1);
    }
}
