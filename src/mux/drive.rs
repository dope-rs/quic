use std::net;
use std::time;

use dope::core::driver::schedule;

use crate::conn;
use crate::conn::transmit::eligibility;

use crate::stream;

use crate::mux;
use crate::mux::routing::{DeadlineOps as _, SlotOps as _};

pub(super) struct Queues {
    pub(super) notify: mux::QueueState,
    pub(super) flush: mux::QueueState,
    pub(super) reap: mux::QueueState,
    pub(super) phase: mux::DrivePhase,
}

impl Default for Queues {
    fn default() -> Self {
        Self {
            notify: mux::QueueState::default(),
            flush: mux::QueueState::default(),
            reap: mux::QueueState::default(),
            phase: mux::DrivePhase::Notify,
        }
    }
}

pub(crate) trait OutputOps {
    fn flush_conn_round(&mut self, handle: conn::Handle, now: time::Instant) -> mux::FlushRound;
    fn recycle_packet(&mut self, packet: Vec<u8>);
    fn take_packet_buffer(&mut self, required: usize) -> Option<Vec<u8>>;
    fn coalesce_gso(addr: net::SocketAddr, batch: &mut conn::packet::Gso) -> Option<mux::Outgoing>;
    fn has_outgoing_room(&self) -> bool;
    fn flush_one(&mut self, now: time::Instant) -> bool;
    fn push_outgoing(&mut self, outgoing: mux::Outgoing) -> Result<(), mux::Outgoing>;
    fn push_or_recycle(&mut self, outgoing: mux::Outgoing) -> bool;
    fn packet_fits(&self, bytes: usize, packet_ceiling: usize) -> bool;
}

pub(crate) trait DriveOps {
    fn schedule_flush(&mut self, handle: conn::Handle);
    fn schedule_notify(&mut self, handle: conn::Handle);
    fn pop_flush(&mut self) -> Option<conn::Handle>;
    fn unschedule_flush(&mut self, handle: conn::Handle);
    fn drive_one<'turn, 'd>(
        &mut self,
        permit: schedule::ApplicationPermit<'turn, 'd>,
        now: time::Instant,
    ) -> bool;
    fn has_drive_work(&self, now: time::Instant) -> bool;
    fn drive_one_inner(&mut self, now: time::Instant) -> bool;
    fn promote_deadline_one(&mut self, now: time::Instant) -> bool;
    fn reap_one(&mut self, now: time::Instant) -> bool;
}

pub(super) trait QueueOps {
    fn queue(&self, kind: mux::QueueKind) -> &mux::QueueState;
    fn queue_mut(&mut self, kind: mux::QueueKind) -> &mut mux::QueueState;
    fn queue_links(&self, kind: mux::QueueKind, index: usize) -> &mux::QueueLinks;
    fn queue_links_mut(&mut self, kind: mux::QueueKind, index: usize) -> &mut mux::QueueLinks;
    fn queue_push_back(&mut self, kind: mux::QueueKind, index: usize) -> bool;
    fn queue_pop_front(&mut self, kind: mux::QueueKind) -> Option<usize>;
    fn queue_remove(&mut self, kind: mux::QueueKind, index: usize) -> bool;
}

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> OutputOps for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn flush_conn_round(&mut self, handle: conn::Handle, now: time::Instant) -> mux::FlushRound {
        let packet_room = self
            .outgoing
            .pending
            .capacity()
            .saturating_sub(self.outgoing.packets)
            .min(crate::mux::FLUSH_PACKET_QUANTUM);
        if packet_room == 0 {
            return mux::FlushRound::Backpressure;
        }
        let Some(idx) = self.handle_index(handle) else {
            return mux::FlushRound::Closed;
        };
        let Some(max_packet_bytes) = self
            .registry
            .entries
            .get(idx)
            .and_then(crate::mux::Entry::slot)
            .map(|slot| {
                if slot.first_flush {
                    crate::pmtud::BASE_PMTU as usize
                } else {
                    slot.max_packet_bytes
                }
            })
        else {
            return mux::FlushRound::Closed;
        };
        if max_packet_bytes > self.outgoing.bytes_capacity {
            self.remove_slot(handle);
            return mux::FlushRound::Closed;
        }
        let global_byte_room = self
            .outgoing
            .bytes_capacity
            .saturating_sub(self.outgoing.bytes);
        let gso_limits = self.outgoing.batch.as_ref().map(conn::packet::Gso::limits);
        let byte_quantum = match gso_limits {
            Some(limits) => crate::mux::FLUSH_BYTE_QUANTUM.min(limits.max_bytes),
            None => crate::mux::FLUSH_BYTE_QUANTUM,
        };
        let byte_room = global_byte_room.min(byte_quantum.max(max_packet_bytes));
        let mut packet_limit = packet_room.min(byte_room / max_packet_bytes);
        if let Some(limits) = gso_limits {
            packet_limit = packet_limit.min(limits.max_segments);
        }
        if packet_limit == 0 {
            return mux::FlushRound::Backpressure;
        }
        if let Some(mut batch) = self.outgoing.batch.take() {
            let addr = match self
                .registry
                .entries
                .get_mut(idx)
                .and_then(crate::mux::Entry::slot_mut)
            {
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
                    return mux::FlushRound::Closed;
                }
            };
            let outgoing = Self::coalesce_gso(addr, &mut batch);
            let mut produced = false;
            if let Some(outgoing) = outgoing
                && self.push_or_recycle(outgoing)
            {
                produced = true;
                if let Some(slot) = self
                    .registry
                    .entries
                    .get_mut(idx)
                    .and_then(crate::mux::Entry::slot_mut)
                {
                    slot.first_flush = false;
                }
            }
            self.outgoing.batch = Some(batch);
            let pending = self
                .registry
                .entries
                .get(idx)
                .and_then(crate::mux::Entry::slot)
                .is_some_and(|slot| eligibility::Eligibility::new(&slot.conn).has_pending_output());
            if pending && produced {
                mux::FlushRound::More
            } else if pending {
                mux::FlushRound::Waiting
            } else {
                mux::FlushRound::Idle
            }
        } else {
            let addr = match self
                .registry
                .entries
                .get(idx)
                .and_then(crate::mux::Entry::slot)
            {
                Some(s) => s.peer_addr,
                None => return mux::FlushRound::Closed,
            };
            let mut packets_left = packet_limit;
            while packets_left != 0 {
                let mut packet = self.outgoing.recycled.pop().unwrap_or_default();
                packet.clear();
                let emitted = match self
                    .registry
                    .entries
                    .get_mut(idx)
                    .and_then(crate::mux::Entry::slot_mut)
                {
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
                if !self.push_or_recycle(mux::Outgoing::Plain(addr, packet)) {
                    break;
                }
                if let Some(slot) = self
                    .registry
                    .entries
                    .get_mut(idx)
                    .and_then(crate::mux::Entry::slot_mut)
                {
                    slot.first_flush = false;
                }
                packets_left -= 1;
            }
            let pending = self
                .registry
                .entries
                .get(idx)
                .and_then(crate::mux::Entry::slot)
                .is_some_and(|slot| eligibility::Eligibility::new(&slot.conn).has_pending_output());
            if pending && packets_left != packet_limit {
                mux::FlushRound::More
            } else if pending {
                mux::FlushRound::Waiting
            } else {
                mux::FlushRound::Idle
            }
        }
    }

    fn recycle_packet(&mut self, packet: Vec<u8>) {
        self.outgoing.recycle_packet(packet);
    }

    fn take_packet_buffer(&mut self, required: usize) -> Option<Vec<u8>> {
        self.outgoing.take_packet(required)
    }

    fn coalesce_gso(addr: net::SocketAddr, batch: &mut conn::packet::Gso) -> Option<mux::Outgoing> {
        let (payload, segment_size, packets) = batch.take()?;
        if packets == 1 {
            Some(mux::Outgoing::Plain(addr, payload))
        } else {
            Some(mux::Outgoing::Batch(addr, payload, segment_size))
        }
    }

    fn has_outgoing_room(&self) -> bool {
        self.outgoing.packets < self.outgoing.pending.capacity()
            && self.outgoing.bytes < self.outgoing.bytes_capacity
    }

    fn flush_one(&mut self, now: time::Instant) -> bool {
        if !self.has_outgoing_room() {
            return false;
        }
        let Some(handle) = self.pop_flush() else {
            return false;
        };
        match self.flush_conn_round(handle, now) {
            mux::FlushRound::More | mux::FlushRound::Backpressure => {
                if self.handle_index(handle).is_some() {
                    self.schedule_flush(handle);
                }
            }
            mux::FlushRound::Idle | mux::FlushRound::Waiting | mux::FlushRound::Closed => {}
        }
        self.refresh_deadline(handle, now);
        true
    }

    fn push_outgoing(&mut self, outgoing: mux::Outgoing) -> Result<(), mux::Outgoing> {
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

    fn push_or_recycle(&mut self, outgoing: mux::Outgoing) -> bool {
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

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> DriveOps for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn schedule_flush(&mut self, handle: conn::Handle) {
        let Some(idx) = self.handle_index(handle) else {
            return;
        };
        self.queue_push_back(mux::QueueKind::Flush, idx);
    }

    fn schedule_notify(&mut self, handle: conn::Handle) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        self.queue_push_back(mux::QueueKind::Notify, index);
    }

    fn pop_flush(&mut self) -> Option<conn::Handle> {
        let index = self.queue_pop_front(mux::QueueKind::Flush)?;
        Some(self.handle_for_index(index))
    }

    fn unschedule_flush(&mut self, handle: conn::Handle) {
        let Some(idx) = self.handle_index(handle) else {
            return;
        };
        self.queue_remove(mux::QueueKind::Flush, idx);
    }

    fn drive_one<'turn, 'd>(
        &mut self,
        _permit: schedule::ApplicationPermit<'turn, 'd>,
        now: time::Instant,
    ) -> bool {
        self.drive_one_inner(now)
    }

    fn has_drive_work(&self, now: time::Instant) -> bool {
        self.queues.notify.len != 0
            || self.queues.reap.len != 0
            || self
                .deadline_peek()
                .is_some_and(|(_, deadline)| deadline <= now)
            || (self.queues.flush.len != 0 && self.has_outgoing_room())
    }

    fn drive_one_inner(&mut self, now: time::Instant) -> bool {
        for _ in 0..mux::DrivePhase::COUNT {
            let phase = self.queues.phase;
            self.queues.phase = phase.next();
            let driven = match phase {
                mux::DrivePhase::Notify => self.notify_one(),
                mux::DrivePhase::Deadline => self.promote_deadline_one(now),
                mux::DrivePhase::Reap => self.reap_one(now),
                mux::DrivePhase::Flush => self.flush_one(now),
            };
            if driven {
                return true;
            }
        }
        false
    }

    fn promote_deadline_one(&mut self, now: time::Instant) -> bool {
        let Some((index, deadline)) = self.deadline_peek() else {
            return false;
        };
        if deadline > now {
            return false;
        }
        self.deadline_remove(index);
        if self.registry.entries[index].slot().is_some() {
            self.queue_push_back(mux::QueueKind::Reap, index);
        }
        true
    }

    fn reap_one(&mut self, now: time::Instant) -> bool {
        let Some(index) = self.queue_pop_front(mux::QueueKind::Reap) else {
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

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> QueueOps for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn queue(&self, kind: mux::QueueKind) -> &mux::QueueState {
        match kind {
            mux::QueueKind::Notify => &self.queues.notify,
            mux::QueueKind::Flush => &self.queues.flush,
            mux::QueueKind::Reap => &self.queues.reap,
        }
    }

    fn queue_mut(&mut self, kind: mux::QueueKind) -> &mut mux::QueueState {
        match kind {
            mux::QueueKind::Notify => &mut self.queues.notify,
            mux::QueueKind::Flush => &mut self.queues.flush,
            mux::QueueKind::Reap => &mut self.queues.reap,
        }
    }

    fn queue_links(&self, kind: mux::QueueKind, index: usize) -> &mux::QueueLinks {
        let entry = &self.registry.entries[index];
        match kind {
            mux::QueueKind::Notify => &entry.notify,
            mux::QueueKind::Flush => &entry.flush,
            mux::QueueKind::Reap => &entry.reap,
        }
    }

    fn queue_links_mut(&mut self, kind: mux::QueueKind, index: usize) -> &mut mux::QueueLinks {
        let entry = &mut self.registry.entries[index];
        match kind {
            mux::QueueKind::Notify => &mut entry.notify,
            mux::QueueKind::Flush => &mut entry.flush,
            mux::QueueKind::Reap => &mut entry.reap,
        }
    }

    fn queue_push_back(&mut self, kind: mux::QueueKind, index: usize) -> bool {
        if self.queue_links(kind, index).linked {
            return false;
        }
        let tail = self.queue(kind).tail;
        if tail != mux::NONE {
            self.queue_links_mut(kind, tail as usize).next = index as u32;
        }
        let links = self.queue_links_mut(kind, index);
        links.prev = tail;
        links.next = mux::NONE;
        links.linked = true;
        let queue = self.queue_mut(kind);
        if tail == mux::NONE {
            queue.head = index as u32;
        }
        queue.tail = index as u32;
        queue.len += 1;
        true
    }

    fn queue_pop_front(&mut self, kind: mux::QueueKind) -> Option<usize> {
        let index = self.queue(kind).head;
        (index != mux::NONE).then(|| {
            let index = index as usize;
            self.queue_remove(kind, index);
            index
        })
    }

    fn queue_remove(&mut self, kind: mux::QueueKind, index: usize) -> bool {
        let links = self.queue_links(kind, index);
        if !links.linked {
            return false;
        }
        let prev = links.prev;
        let next = links.next;
        if prev == mux::NONE {
            self.queue_mut(kind).head = next;
        } else {
            self.queue_links_mut(kind, prev as usize).next = next;
        }
        if next == mux::NONE {
            self.queue_mut(kind).tail = prev;
        } else {
            self.queue_links_mut(kind, next as usize).prev = prev;
        }
        *self.queue_links_mut(kind, index) = mux::QueueLinks::default();
        self.queue_mut(kind).len -= 1;
        true
    }
}
