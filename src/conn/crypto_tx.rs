use crate::conn;
use crate::conn::delivery;
use shin::connection;
use std::mem;

const NONE: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Links {
    prev: u32,
    next: u32,
}

impl Links {
    const EMPTY: Self = Self {
        prev: NONE,
        next: NONE,
    };
}

#[derive(Clone, Copy)]
struct Chain {
    head: u32,
    tail: u32,
}

impl Chain {
    const EMPTY: Self = Self {
        head: NONE,
        tail: NONE,
    };
}

#[derive(Clone, Copy)]
enum Status {
    Queued,
    InFlight { carriers: u16 },
    Acknowledged,
}

struct Entry {
    epoch: conn::Epoch,
    record: delivery::Crypto,
    status: Status,
    ready_next: u32,
    flight: Links,
    order_next: u32,
}

struct Slot {
    generation: u32,
    next_free: u32,
    entry: Option<Entry>,
}

struct Space {
    bytes: Vec<u8>,
    limit: usize,
    stored_offset: u64,
    reclaim_offset: u64,
    next_unsent: u64,
    ready: u32,
    in_flight: Chain,
    order: Chain,
    probe_cursor: u32,
}

impl Space {
    fn new(capacity: usize, limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
            limit,
            stored_offset: 0,
            reclaim_offset: 0,
            next_unsent: 0,
            ready: NONE,
            in_flight: Chain::EMPTY,
            order: Chain::EMPTY,
            probe_cursor: NONE,
        }
    }

    fn end_offset(&self) -> Option<u64> {
        self.stored_offset
            .checked_add(u64::try_from(self.bytes.len()).ok()?)
    }

    fn index(&self, offset: u64) -> Option<usize> {
        usize::try_from(offset.checked_sub(self.stored_offset)?).ok()
    }

    fn prepare_append(&mut self, maximum: usize) {
        if self.limit.saturating_sub(self.bytes.len()) < maximum {
            self.compact();
        }
    }

    fn compact(&mut self) {
        let Some(prefix) = self.index(self.reclaim_offset) else {
            return;
        };
        if prefix == 0 {
            return;
        }
        self.bytes.copy_within(prefix.., 0);
        self.bytes.truncate(self.bytes.len() - prefix);
        self.stored_offset = self.reclaim_offset;
    }

    fn reclaim_to(&mut self, offset: u64) {
        self.reclaim_offset = offset;
        if self.end_offset() == Some(offset) {
            self.bytes.clear();
            self.stored_offset = offset;
        }
    }
}

/// Borrowed CRYPTO range selected from one immutable epoch byte store.
pub(super) struct Selection<'a> {
    pub(super) record: delivery::Crypto,
    pub(super) handle: Option<delivery::Handle<delivery::Crypto>>,
    pub(super) data: &'a [u8],
}

/// Single owner for QUIC CRYPTO bytes, range state and delivery generations.
///
/// TLS appends each byte once. Packets, retransmissions and PTO probes borrow
/// ranges from that storage; ACK and loss resolve generation handles directly.
/// The validated TLS flight bound reserves Initial and Handshake concurrently;
/// discarded backing storage is recycled for Application post-handshake bytes.
pub(super) struct Tx {
    spaces: [Space; 3],
    spare: Vec<u8>,
    slots: Vec<Slot>,
    free_head: u32,
    len: usize,
    limit: usize,
}

impl Tx {
    pub(super) fn new(limit: usize, layout: connection::OutboundLayout) -> Self {
        let limit = limit.min((u32::MAX - 1) as usize);
        let recycled_initial_capacity = layout.plaintext().max(layout.application());
        Self {
            spaces: [
                Space::new(recycled_initial_capacity, layout.plaintext()),
                Space::new(layout.handshake(), layout.handshake()),
                Space::new(0, layout.application()),
            ],
            spare: Vec::new(),
            slots: Vec::with_capacity(limit),
            free_head: NONE,
            len: 0,
            limit,
        }
    }

    pub(super) fn begin(
        &mut self,
        epoch: conn::Epoch,
    ) -> Result<connection::OutboundFlight<'_>, conn::Error> {
        let space = &mut self.spaces[epoch as usize];
        if space.bytes.is_empty()
            && space.bytes.capacity() < space.limit
            && self.spare.capacity() >= space.limit
        {
            mem::swap(&mut space.bytes, &mut self.spare);
        }
        space.compact();
        let maximum = space
            .limit
            .checked_sub(space.bytes.len())
            .ok_or(conn::Error::EventCapacity)?;
        connection::OutboundFlight::from_reserved(&mut space.bytes, maximum)
            .ok_or(conn::Error::EventCapacity)
    }

    pub(super) fn append(&mut self, epoch: conn::Epoch, data: &[u8]) -> Result<(), conn::Error> {
        let space = &mut self.spaces[epoch as usize];
        if space.bytes.is_empty()
            && space.bytes.capacity() < space.limit
            && self.spare.capacity() >= space.limit
        {
            mem::swap(&mut space.bytes, &mut self.spare);
        }
        space.prepare_append(data.len());
        let end = space
            .bytes
            .len()
            .checked_add(data.len())
            .filter(|end| *end <= space.limit)
            .ok_or(conn::Error::EventCapacity)?;
        if end > space.bytes.capacity() {
            return Err(conn::Error::EventCapacity);
        }
        space.bytes.extend_from_slice(data);
        Ok(())
    }

    pub(super) fn has_sendable(&self, epoch: conn::Epoch) -> bool {
        let space = &self.spaces[epoch as usize];
        space.ready != NONE
            || space
                .end_offset()
                .is_some_and(|end| space.next_unsent < end)
    }

    pub(super) fn has_room(&self, needed: usize) -> bool {
        self.len.saturating_add(needed) <= self.limit
    }

    pub(super) fn peek(&self, epoch: conn::Epoch) -> Option<delivery::Crypto> {
        let space = &self.spaces[epoch as usize];
        if space.ready != NONE {
            return self.slots[space.ready as usize]
                .entry
                .as_ref()
                .map(|entry| entry.record);
        }
        let len = usize::try_from(space.end_offset()?.checked_sub(space.next_unsent)?).ok()?;
        (len != 0).then_some(delivery::Crypto {
            offset: space.next_unsent,
            len,
        })
    }

    pub(super) fn select(&self, epoch: conn::Epoch, max_len: usize) -> Option<Selection<'_>> {
        if max_len == 0 {
            return None;
        }
        let space = &self.spaces[epoch as usize];
        let (handle, offset, available) = if space.ready == NONE {
            (
                None,
                space.next_unsent,
                usize::try_from(space.end_offset()?.checked_sub(space.next_unsent)?).ok()?,
            )
        } else {
            let index = space.ready as usize;
            let entry = self.slots[index].entry.as_ref()?;
            (self.handle(index), entry.record.offset, entry.record.len)
        };
        let len = max_len.min(available);
        let start = space.index(offset)?;
        let end = start.checked_add(len)?;
        Some(Selection {
            record: delivery::Crypto { offset, len },
            handle,
            data: space.bytes.get(start..end)?,
        })
    }

    pub(super) fn select_probe(&self, epoch: conn::Epoch, max_len: usize) -> Option<Selection<'_>> {
        let space = &self.spaces[epoch as usize];
        let current = space.probe_cursor;
        if current == NONE {
            return None;
        }
        let index = current as usize;
        let entry = self.slots[index].entry.as_ref()?;
        if entry.record.len > max_len {
            return None;
        }
        let start = space.index(entry.record.offset)?;
        let end = start.checked_add(entry.record.len)?;
        Some(Selection {
            record: entry.record,
            handle: self.handle(index),
            data: space.bytes.get(start..end)?,
        })
    }

    pub(super) fn commit(
        &mut self,
        epoch: conn::Epoch,
        record: delivery::Crypto,
        selected: Option<delivery::Handle<delivery::Crypto>>,
    ) -> Option<delivery::Handle<delivery::Crypto>> {
        if record.len == 0 {
            return None;
        }
        if let Some(handle) = selected {
            let index = handle.index();
            let entry = self.resolve(handle)?;
            if entry.epoch != epoch || entry.record.offset != record.offset {
                return None;
            }
            match entry.status {
                Status::Queued
                    if self.spaces[epoch as usize].ready == index as u32
                        && record.len <= entry.record.len =>
                {
                    let original_len = entry.record.len;
                    if record.len < original_len && !self.has_room(1) {
                        return None;
                    }
                    self.unlink_ready(index);
                    if record.len < original_len {
                        let remainder = delivery::Crypto {
                            offset: record.offset.checked_add(u64::try_from(record.len).ok()?)?,
                            len: original_len - record.len,
                        };
                        self.insert_queued_after(index, epoch, remainder)?;
                    }
                    let entry = self.slots[index].entry.as_mut().unwrap();
                    entry.record = record;
                    entry.status = Status::InFlight { carriers: 1 };
                    self.link_flight(index);
                    return Some(handle);
                }
                Status::InFlight { carriers } if entry.record == record => {
                    let carriers = carriers.checked_add(1)?;
                    let next = entry.flight.next;
                    self.slots[index].entry.as_mut().unwrap().status =
                        Status::InFlight { carriers };
                    self.spaces[epoch as usize].probe_cursor = next;
                    return Some(handle);
                }
                Status::Queued | Status::InFlight { .. } | Status::Acknowledged => return None,
            }
        }

        let space = &self.spaces[epoch as usize];
        if record.offset != space.next_unsent
            || record.offset.checked_add(u64::try_from(record.len).ok()?)? > space.end_offset()?
            || !self.has_room(1)
        {
            return None;
        }
        let index = self.allocate()?;
        self.slots[index].entry = Some(Entry {
            epoch,
            record,
            status: Status::InFlight { carriers: 1 },
            ready_next: NONE,
            flight: Links::EMPTY,
            order_next: NONE,
        });
        self.len += 1;
        self.spaces[epoch as usize].next_unsent =
            record.offset.checked_add(u64::try_from(record.len).ok()?)?;
        self.link_order_tail(index);
        self.link_flight(index);
        self.handle(index)
    }

    pub(super) fn acknowledge(&mut self, handle: delivery::Handle<delivery::Crypto>) -> bool {
        let index = handle.index();
        let Some(entry) = self.resolve(handle) else {
            return false;
        };
        if !matches!(entry.status, Status::InFlight { .. }) {
            return false;
        }
        let epoch = entry.epoch;
        self.unlink_flight(index);
        self.slots[index].entry.as_mut().unwrap().status = Status::Acknowledged;
        self.reclaim(epoch);
        true
    }

    pub(super) fn lose(&mut self, handle: delivery::Handle<delivery::Crypto>) {
        let index = handle.index();
        let Some(entry) = self.resolve(handle) else {
            return;
        };
        let Status::InFlight { carriers } = entry.status else {
            return;
        };
        if carriers > 1 {
            self.slots[index].entry.as_mut().unwrap().status = Status::InFlight {
                carriers: carriers - 1,
            };
            return;
        }
        if !self.bump_generation(index) {
            return;
        }
        self.unlink_flight(index);
        self.slots[index].entry.as_mut().unwrap().status = Status::Queued;
        self.link_ready(index);
    }

    pub(super) fn arm_probes(&mut self, epoch: conn::Epoch) {
        let space = &mut self.spaces[epoch as usize];
        space.probe_cursor = space.in_flight.head;
    }

    pub(super) fn discard(&mut self, epoch: conn::Epoch) {
        self.clear_epoch(epoch, true);
    }

    pub(super) fn retry_initial(&mut self) {
        self.clear_epoch(conn::Epoch::Initial, false);
    }

    pub(super) fn bytes(&self, epoch: conn::Epoch) -> &[u8] {
        &self.spaces[epoch as usize].bytes
    }

    fn clear_epoch(&mut self, epoch: conn::Epoch, clear_bytes: bool) {
        let space = &mut self.spaces[epoch as usize];
        space.ready = NONE;
        space.in_flight = Chain::EMPTY;
        space.order = Chain::EMPTY;
        space.probe_cursor = NONE;
        if clear_bytes {
            let end = space.end_offset().unwrap_or(space.stored_offset);
            let mut released = mem::take(&mut space.bytes);
            released.clear();
            if released.capacity() > self.spare.capacity() {
                mem::swap(&mut released, &mut self.spare);
            }
            space.stored_offset = end;
            space.reclaim_offset = end;
            space.next_unsent = end;
        } else {
            space.next_unsent = space.stored_offset;
        }
        for index in 0..self.slots.len() {
            if self.slots[index]
                .entry
                .as_ref()
                .is_some_and(|entry| entry.epoch == epoch)
            {
                self.remove_unlinked(index);
            }
        }
    }

    fn insert_queued_after(
        &mut self,
        previous: usize,
        epoch: conn::Epoch,
        record: delivery::Crypto,
    ) -> Option<delivery::Handle<delivery::Crypto>> {
        let index = self.allocate()?;
        self.slots[index].entry = Some(Entry {
            epoch,
            record,
            status: Status::Queued,
            ready_next: NONE,
            flight: Links::EMPTY,
            order_next: NONE,
        });
        self.len += 1;
        self.link_order_after(previous, index);
        self.link_ready(index);
        self.handle(index)
    }

    fn reclaim(&mut self, epoch: conn::Epoch) {
        loop {
            let index = self.spaces[epoch as usize].order.head;
            if index == NONE {
                break;
            }
            let index = index as usize;
            let Some(entry) = self.slots[index].entry.as_ref() else {
                break;
            };
            if !matches!(entry.status, Status::Acknowledged) {
                break;
            }
            let Ok(len) = u64::try_from(entry.record.len) else {
                break;
            };
            let Some(offset) = entry.record.offset.checked_add(len) else {
                break;
            };
            self.unlink_order_head(index);
            self.remove_unlinked(index);
            if epoch != conn::Epoch::Initial {
                self.spaces[epoch as usize].reclaim_to(offset);
            }
        }
    }

    fn allocate(&mut self) -> Option<usize> {
        if self.len == self.limit {
            return None;
        }
        if self.free_head != NONE {
            let index = self.free_head as usize;
            self.free_head = self.slots[index].next_free;
            self.slots[index].next_free = NONE;
            return Some(index);
        }
        if self.slots.len() == self.limit {
            return None;
        }
        let index = self.slots.len();
        self.slots.push(Slot {
            generation: 0,
            next_free: NONE,
            entry: None,
        });
        Some(index)
    }

    fn remove_unlinked(&mut self, index: usize) {
        self.slots[index].entry.take();
        self.len -= 1;
        if self.bump_generation(index) {
            self.slots[index].next_free = self.free_head;
            self.free_head = index as u32;
        }
    }

    fn bump_generation(&mut self, index: usize) -> bool {
        let Some(next) = self.slots[index].generation.checked_add(1) else {
            return false;
        };
        self.slots[index].generation = next;
        true
    }

    fn handle(&self, index: usize) -> Option<delivery::Handle<delivery::Crypto>> {
        delivery::Handle::new(index, self.slots.get(index)?.generation)
    }

    fn resolve(&self, handle: delivery::Handle<delivery::Crypto>) -> Option<&Entry> {
        let slot = self.slots.get(handle.index())?;
        (slot.generation == handle.generation())
            .then_some(slot.entry.as_ref())
            .flatten()
    }

    fn link_order_tail(&mut self, index: usize) {
        let epoch = self.slots[index].entry.as_ref().unwrap().epoch as usize;
        let tail = self.spaces[epoch].order.tail;
        self.slots[index].entry.as_mut().unwrap().order_next = NONE;
        if tail == NONE {
            self.spaces[epoch].order.head = index as u32;
        } else {
            self.slots[tail as usize].entry.as_mut().unwrap().order_next = index as u32;
        }
        self.spaces[epoch].order.tail = index as u32;
    }

    fn link_order_after(&mut self, previous: usize, index: usize) {
        let epoch = self.slots[previous].entry.as_ref().unwrap().epoch as usize;
        let next = self.slots[previous].entry.as_ref().unwrap().order_next;
        self.slots[index].entry.as_mut().unwrap().order_next = next;
        self.slots[previous].entry.as_mut().unwrap().order_next = index as u32;
        if next == NONE {
            self.spaces[epoch].order.tail = index as u32;
        }
    }

    fn unlink_order_head(&mut self, index: usize) {
        let entry = self.slots[index].entry.as_ref().unwrap();
        let epoch = entry.epoch as usize;
        debug_assert_eq!(self.spaces[epoch].order.head, index as u32);
        let next = entry.order_next;
        self.spaces[epoch].order.head = next;
        if next == NONE {
            self.spaces[epoch].order.tail = NONE;
        }
        self.slots[index].entry.as_mut().unwrap().order_next = NONE;
    }

    fn link_ready(&mut self, index: usize) {
        let epoch = self.slots[index].entry.as_ref().unwrap().epoch as usize;
        self.slots[index].entry.as_mut().unwrap().ready_next = self.spaces[epoch].ready;
        self.spaces[epoch].ready = index as u32;
    }

    fn unlink_ready(&mut self, index: usize) {
        let entry = self.slots[index].entry.as_ref().unwrap();
        let epoch = entry.epoch as usize;
        debug_assert_eq!(self.spaces[epoch].ready, index as u32);
        self.spaces[epoch].ready = entry.ready_next;
        self.slots[index].entry.as_mut().unwrap().ready_next = NONE;
    }

    fn link_flight(&mut self, index: usize) {
        let epoch = self.slots[index].entry.as_ref().unwrap().epoch as usize;
        let tail = self.spaces[epoch].in_flight.tail;
        self.slots[index].entry.as_mut().unwrap().flight = Links {
            prev: tail,
            next: NONE,
        };
        if tail == NONE {
            self.spaces[epoch].in_flight.head = index as u32;
        } else {
            self.slots[tail as usize]
                .entry
                .as_mut()
                .unwrap()
                .flight
                .next = index as u32;
        }
        self.spaces[epoch].in_flight.tail = index as u32;
    }

    fn unlink_flight(&mut self, index: usize) {
        let entry = self.slots[index].entry.as_ref().unwrap();
        let epoch = entry.epoch as usize;
        let links = entry.flight;
        if links.prev == NONE {
            self.spaces[epoch].in_flight.head = links.next;
        } else {
            self.slots[links.prev as usize]
                .entry
                .as_mut()
                .unwrap()
                .flight
                .next = links.next;
        }
        if links.next == NONE {
            self.spaces[epoch].in_flight.tail = links.prev;
        } else {
            self.slots[links.next as usize]
                .entry
                .as_mut()
                .unwrap()
                .flight
                .prev = links.prev;
        }
        if self.spaces[epoch].probe_cursor == index as u32 {
            self.spaces[epoch].probe_cursor = links.next;
        }
        self.slots[index].entry.as_mut().unwrap().flight = Links::EMPTY;
    }
}

const _: () = assert!(std::mem::size_of::<Entry>() == 5 * std::mem::size_of::<usize>());
