use std::net::SocketAddr;
use std::time::Instant;

use dope::core::driver::schedule;

use crate::conn::{self, Handle};
use crate::pmtud::BASE_PMTU;
use crate::stream::ReceiveBuffer;

use super::routing::{DeadlineOps as _, SlotOps as _};
use super::{
    DrivePhase, Entry, FLUSH_BYTE_QUANTUM, FLUSH_PACKET_QUANTUM, FlushRound, Handler, MuxInner,
    NONE, Outgoing, QueueKind, QueueLinks, QueueState,
};

pub(super) struct Queues {
    pub(super) notify: QueueState,
    pub(super) flush: QueueState,
    pub(super) reap: QueueState,
    pub(super) phase: DrivePhase,
}

impl Default for Queues {
    fn default() -> Self {
        Self {
            notify: QueueState::default(),
            flush: QueueState::default(),
            reap: QueueState::default(),
            phase: DrivePhase::Notify,
        }
    }
}

pub(crate) trait OutputOps {
    fn flush_conn_round(&mut self, handle: Handle, now: Instant) -> FlushRound;
    fn recycle_packet(&mut self, packet: Vec<u8>);
    fn take_packet_buffer(&mut self, required: usize) -> Option<Vec<u8>>;
    fn coalesce_gso(addr: SocketAddr, batch: &mut conn::packet::Gso) -> Option<Outgoing>;
    fn has_outgoing_room(&self) -> bool;
    fn flush_one(&mut self, now: Instant) -> bool;
    fn push_outgoing(&mut self, outgoing: Outgoing) -> Result<(), Outgoing>;
    fn push_or_recycle(&mut self, outgoing: Outgoing) -> bool;
    fn packet_fits(&self, bytes: usize, packet_ceiling: usize) -> bool;
}

pub(crate) trait DriveOps {
    fn schedule_flush(&mut self, handle: Handle);
    fn schedule_notify(&mut self, handle: Handle);
    fn pop_flush(&mut self) -> Option<Handle>;
    fn unschedule_flush(&mut self, handle: Handle);
    fn drive_one<'turn, 'd>(
        &mut self,
        permit: schedule::ApplicationPermit<'turn, 'd>,
        now: Instant,
    ) -> bool;
    fn has_drive_work(&self, now: Instant) -> bool;
    fn drive_one_inner(&mut self, now: Instant) -> bool;
    fn promote_deadline_one(&mut self, now: Instant) -> bool;
    fn reap_one(&mut self, now: Instant) -> bool;
}

pub(super) trait QueueOps {
    fn queue(&self, kind: QueueKind) -> &QueueState;
    fn queue_mut(&mut self, kind: QueueKind) -> &mut QueueState;
    fn queue_links(&self, kind: QueueKind, index: usize) -> &QueueLinks;
    fn queue_links_mut(&mut self, kind: QueueKind, index: usize) -> &mut QueueLinks;
    fn queue_push_back(&mut self, kind: QueueKind, index: usize) -> bool;
    fn queue_pop_front(&mut self, kind: QueueKind) -> Option<usize>;
    fn queue_remove(&mut self, kind: QueueKind, index: usize) -> bool;
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    OutputOps for MuxInner<'tls, H, P, DOMAIN, B>
{
    fn flush_conn_round(&mut self, handle: Handle, now: Instant) -> FlushRound {
        let packet_room = self
            .outgoing
            .pending
            .capacity()
            .saturating_sub(self.outgoing.packets)
            .min(FLUSH_PACKET_QUANTUM);
        if packet_room == 0 {
            return FlushRound::Backpressure;
        }
        let Some(idx) = self.handle_index(handle) else {
            return FlushRound::Closed;
        };
        let Some(max_packet_bytes) =
            self.registry
                .entries
                .get(idx)
                .and_then(Entry::slot)
                .map(|slot| {
                    if slot.first_flush {
                        BASE_PMTU as usize
                    } else {
                        slot.max_packet_bytes
                    }
                })
        else {
            return FlushRound::Closed;
        };
        if max_packet_bytes > self.outgoing.bytes_capacity {
            self.remove_slot(handle);
            return FlushRound::Closed;
        }
        let global_byte_room = self
            .outgoing
            .bytes_capacity
            .saturating_sub(self.outgoing.bytes);
        let gso_limits = self.outgoing.batch.as_ref().map(conn::packet::Gso::limits);
        let byte_quantum = match gso_limits {
            Some(limits) => FLUSH_BYTE_QUANTUM.min(limits.max_bytes),
            None => FLUSH_BYTE_QUANTUM,
        };
        let byte_room = global_byte_room.min(byte_quantum.max(max_packet_bytes));
        let mut packet_limit = packet_room.min(byte_room / max_packet_bytes);
        if let Some(limits) = gso_limits {
            packet_limit = packet_limit.min(limits.max_segments);
        }
        if packet_limit == 0 {
            return FlushRound::Backpressure;
        }
        if let Some(mut batch) = self.outgoing.batch.take() {
            let addr = match self.registry.entries.get_mut(idx).and_then(Entry::slot_mut) {
                Some(s) => {
                    s.conn.transmit().send_gso_batch(
                        &mut batch,
                        now,
                        packet_limit,
                        max_packet_bytes,
                    );
                    s.peer_addr
                }
                None => {
                    self.outgoing.batch = Some(batch);
                    return FlushRound::Closed;
                }
            };
            let outgoing = Self::coalesce_gso(addr, &mut batch);
            let mut produced = false;
            if let Some(outgoing) = outgoing
                && self.push_or_recycle(outgoing)
            {
                produced = true;
                if let Some(slot) = self.registry.entries.get_mut(idx).and_then(Entry::slot_mut) {
                    slot.first_flush = false;
                }
            }
            self.outgoing.batch = Some(batch);
            let pending = self
                .registry
                .entries
                .get(idx)
                .and_then(Entry::slot)
                .is_some_and(|slot| {
                    crate::conn::transmit::eligibility::has_pending_output(&slot.conn)
                });
            if pending && produced {
                FlushRound::More
            } else if pending {
                FlushRound::Waiting
            } else {
                FlushRound::Idle
            }
        } else {
            let addr = match self.registry.entries.get(idx).and_then(Entry::slot) {
                Some(s) => s.peer_addr,
                None => return FlushRound::Closed,
            };
            let mut packets_left = packet_limit;
            while packets_left != 0 {
                let mut packet = self.outgoing.recycled.pop().unwrap_or_default();
                packet.clear();
                let emitted = match self.registry.entries.get_mut(idx).and_then(Entry::slot_mut) {
                    Some(s) => s
                        .conn
                        .transmit()
                        .send_one(&mut packet, now, max_packet_bytes),
                    None => false,
                };
                if !emitted {
                    self.recycle_packet(packet);
                    break;
                }
                if !self.push_or_recycle(Outgoing::Plain(addr, packet)) {
                    break;
                }
                if let Some(slot) = self.registry.entries.get_mut(idx).and_then(Entry::slot_mut) {
                    slot.first_flush = false;
                }
                packets_left -= 1;
            }
            let pending = self
                .registry
                .entries
                .get(idx)
                .and_then(Entry::slot)
                .is_some_and(|slot| {
                    crate::conn::transmit::eligibility::has_pending_output(&slot.conn)
                });
            if pending && packets_left != packet_limit {
                FlushRound::More
            } else if pending {
                FlushRound::Waiting
            } else {
                FlushRound::Idle
            }
        }
    }

    fn recycle_packet(&mut self, packet: Vec<u8>) {
        self.outgoing.recycle_packet(packet);
    }

    fn take_packet_buffer(&mut self, required: usize) -> Option<Vec<u8>> {
        self.outgoing.take_packet(required)
    }

    fn coalesce_gso(addr: SocketAddr, batch: &mut conn::packet::Gso) -> Option<Outgoing> {
        let (payload, segment_size, packets) = batch.take()?;
        if packets == 1 {
            Some(Outgoing::Plain(addr, payload))
        } else {
            Some(Outgoing::Batch(addr, payload, segment_size))
        }
    }

    fn has_outgoing_room(&self) -> bool {
        self.outgoing.packets < self.outgoing.pending.capacity()
            && self.outgoing.bytes < self.outgoing.bytes_capacity
    }

    fn flush_one(&mut self, now: Instant) -> bool {
        if !self.has_outgoing_room() {
            return false;
        }
        let Some(handle) = self.pop_flush() else {
            return false;
        };
        match self.flush_conn_round(handle, now) {
            FlushRound::More | FlushRound::Backpressure => {
                if self.handle_index(handle).is_some() {
                    self.schedule_flush(handle);
                }
            }
            FlushRound::Idle | FlushRound::Waiting | FlushRound::Closed => {}
        }
        self.refresh_deadline(handle, now);
        true
    }

    fn push_outgoing(&mut self, outgoing: Outgoing) -> Result<(), Outgoing> {
        let packets = outgoing.packets();
        let bytes = outgoing.bytes();
        if packets > self.outgoing.pending.capacity() - self.outgoing.packets
            || bytes > self.outgoing.bytes_capacity - self.outgoing.bytes
        {
            return Err(outgoing);
        }
        self.outgoing.pending.push_back(outgoing)?;
        self.outgoing.packets += packets;
        self.outgoing.bytes += bytes;
        Ok(())
    }

    fn push_or_recycle(&mut self, outgoing: Outgoing) -> bool {
        match self.push_outgoing(outgoing) {
            Ok(()) => true,
            Err(outgoing) => {
                self.recycle_packet(outgoing.into_storage());
                false
            }
        }
    }

    fn packet_fits(&self, bytes: usize, packet_ceiling: usize) -> bool {
        bytes != 0
            && bytes <= packet_ceiling
            && self.outgoing.packets < self.outgoing.pending.capacity()
            && bytes
                <= self
                    .outgoing
                    .bytes_capacity
                    .saturating_sub(self.outgoing.bytes)
    }
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    DriveOps for MuxInner<'tls, H, P, DOMAIN, B>
{
    fn schedule_flush(&mut self, handle: Handle) {
        let Some(idx) = self.handle_index(handle) else {
            return;
        };
        self.queue_push_back(QueueKind::Flush, idx);
    }

    fn schedule_notify(&mut self, handle: Handle) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        self.queue_push_back(QueueKind::Notify, index);
    }

    fn pop_flush(&mut self) -> Option<Handle> {
        let index = self.queue_pop_front(QueueKind::Flush)?;
        Some(self.handle_for_index(index))
    }

    fn unschedule_flush(&mut self, handle: Handle) {
        let Some(idx) = self.handle_index(handle) else {
            return;
        };
        self.queue_remove(QueueKind::Flush, idx);
    }

    fn drive_one<'turn, 'd>(
        &mut self,
        _permit: schedule::ApplicationPermit<'turn, 'd>,
        now: Instant,
    ) -> bool {
        self.drive_one_inner(now)
    }

    fn has_drive_work(&self, now: Instant) -> bool {
        self.queues.notify.len != 0
            || self.queues.reap.len != 0
            || self
                .deadline_peek()
                .is_some_and(|(_, deadline)| deadline <= now)
            || (self.queues.flush.len != 0 && self.has_outgoing_room())
    }

    fn drive_one_inner(&mut self, now: Instant) -> bool {
        for _ in 0..DrivePhase::COUNT {
            let phase = self.queues.phase;
            self.queues.phase = phase.next();
            let driven = match phase {
                DrivePhase::Notify => self.notify_one(),
                DrivePhase::Deadline => self.promote_deadline_one(now),
                DrivePhase::Reap => self.reap_one(now),
                DrivePhase::Flush => self.flush_one(now),
            };
            if driven {
                return true;
            }
        }
        false
    }

    fn promote_deadline_one(&mut self, now: Instant) -> bool {
        let Some((index, deadline)) = self.deadline_peek() else {
            return false;
        };
        if deadline > now {
            return false;
        }
        self.deadline_remove(index);
        if self.registry.entries[index].slot().is_some() {
            self.queue_push_back(QueueKind::Reap, index);
        }
        true
    }

    fn reap_one(&mut self, now: Instant) -> bool {
        let Some(index) = self.queue_pop_front(QueueKind::Reap) else {
            return false;
        };
        let handle = self.handle_for_index(index);
        let Some(slot) = self.registry.entries[index].slot_mut() else {
            return true;
        };
        conn::recovery::Loss::new(&mut slot.conn).check_loss(now);
        if slot.conn.status().is_closed() {
            self.remove_slot(handle);
        } else {
            self.schedule_notify(handle);
            self.schedule_flush(handle);
            self.refresh_deadline(handle, now);
        }
        true
    }
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    QueueOps for MuxInner<'tls, H, P, DOMAIN, B>
{
    fn queue(&self, kind: QueueKind) -> &QueueState {
        match kind {
            QueueKind::Notify => &self.queues.notify,
            QueueKind::Flush => &self.queues.flush,
            QueueKind::Reap => &self.queues.reap,
        }
    }

    fn queue_mut(&mut self, kind: QueueKind) -> &mut QueueState {
        match kind {
            QueueKind::Notify => &mut self.queues.notify,
            QueueKind::Flush => &mut self.queues.flush,
            QueueKind::Reap => &mut self.queues.reap,
        }
    }

    fn queue_links(&self, kind: QueueKind, index: usize) -> &QueueLinks {
        let entry = &self.registry.entries[index];
        match kind {
            QueueKind::Notify => &entry.notify,
            QueueKind::Flush => &entry.flush,
            QueueKind::Reap => &entry.reap,
        }
    }

    fn queue_links_mut(&mut self, kind: QueueKind, index: usize) -> &mut QueueLinks {
        let entry = &mut self.registry.entries[index];
        match kind {
            QueueKind::Notify => &mut entry.notify,
            QueueKind::Flush => &mut entry.flush,
            QueueKind::Reap => &mut entry.reap,
        }
    }

    fn queue_push_back(&mut self, kind: QueueKind, index: usize) -> bool {
        if self.queue_links(kind, index).linked {
            return false;
        }
        let tail = self.queue(kind).tail;
        if tail != NONE {
            self.queue_links_mut(kind, tail as usize).next = index as u32;
        }
        let links = self.queue_links_mut(kind, index);
        links.prev = tail;
        links.next = NONE;
        links.linked = true;
        let queue = self.queue_mut(kind);
        if tail == NONE {
            queue.head = index as u32;
        }
        queue.tail = index as u32;
        queue.len += 1;
        true
    }

    fn queue_pop_front(&mut self, kind: QueueKind) -> Option<usize> {
        let index = self.queue(kind).head;
        (index != NONE).then(|| {
            let index = index as usize;
            self.queue_remove(kind, index);
            index
        })
    }

    fn queue_remove(&mut self, kind: QueueKind, index: usize) -> bool {
        let links = self.queue_links(kind, index);
        if !links.linked {
            return false;
        }
        let prev = links.prev;
        let next = links.next;
        if prev == NONE {
            self.queue_mut(kind).head = next;
        } else {
            self.queue_links_mut(kind, prev as usize).next = next;
        }
        if next == NONE {
            self.queue_mut(kind).tail = prev;
        } else {
            self.queue_links_mut(kind, next as usize).prev = prev;
        }
        *self.queue_links_mut(kind, index) = QueueLinks::default();
        self.queue_mut(kind).len -= 1;
        true
    }
}
