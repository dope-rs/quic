use crate::conn::delivery::{Control, Handle};

use super::linkage::Linkage;
use super::{Entry, Links, NONE, NewConnectionId, OwnerKey, Pending, Slot, Status, kind_bit, lane};

pub(super) trait Records {
    fn queue<Kind>(
        &mut self,
        owner: &mut Option<OwnerKey<Kind>>,
        record: Control,
        new_connection_id: Option<NewConnectionId>,
    ) -> Option<Handle<Control>>;
    fn replace(
        &mut self,
        index: usize,
        record: Control,
        new_connection_id: Option<NewConnectionId>,
    );
    fn allocate(&mut self) -> Option<usize>;
    fn remove_owner<Kind>(&mut self, owner: &mut Option<OwnerKey<Kind>>) -> bool;
    fn remove(&mut self, index: usize) -> Option<Control>;
    fn add_kind(&mut self, record: Control);
    fn remove_kind(&mut self, record: Control);
    fn bump_generation(&mut self, index: usize) -> bool;
    fn handle(&self, index: usize) -> Option<Handle<Control>>;
    fn resolve(&self, handle: Handle<Control>) -> Option<&Entry>;
    fn resolve_owner<Kind>(&self, owner: Option<OwnerKey<Kind>>) -> Option<&Entry>;
    fn owner_index<Kind>(&self, owner: OwnerKey<Kind>) -> Option<usize>;
}

impl Records for Pending {
    fn queue<Kind>(
        &mut self,
        owner: &mut Option<OwnerKey<Kind>>,
        record: Control,
        new_connection_id: Option<NewConnectionId>,
    ) -> Option<Handle<Control>> {
        if let Some(index) = (*owner).and_then(|owner| self.owner_index(owner)) {
            let unchanged = {
                let entry = self.slots[index].entry.as_ref().unwrap();
                entry.record == record
                    && match (&entry.new_connection_id, &new_connection_id) {
                        (None, None) => true,
                        (Some(old), Some(new)) => old.key == new.key,
                        _ => false,
                    }
            };
            if unchanged {
                return self.handle(index);
            }
            self.replace(index, record, new_connection_id);
            return self.handle(index);
        }
        *owner = None;
        if self.len == self.limit {
            self.overflowed = true;
            return None;
        }
        let Some(index) = self.allocate() else {
            self.overflowed = true;
            return None;
        };
        self.slots[index].entry = Some(Entry {
            record,
            new_connection_id,
            status: Status::Queued,
            ready: Links::EMPTY,
            flight: Links::EMPTY,
        });
        self.len += 1;
        self.add_kind(record);
        self.link_ready(index);
        *owner = OwnerKey::new(index, self.slots[index].owner_generation);
        self.handle(index)
    }

    fn replace(
        &mut self,
        index: usize,
        record: Control,
        new_connection_id: Option<NewConnectionId>,
    ) {
        let entry = self.slots[index].entry.as_ref().unwrap();
        let status = entry.status;
        let previous = entry.record;
        if !self.bump_generation(index) {
            return;
        }
        if matches!(status, Status::InFlight { .. }) {
            self.unlink_flight(index);
        }
        let previous_bit = kind_bit(previous);
        let next_bit = kind_bit(record);
        let remains_ready =
            matches!(status, Status::Queued) && previous_bit != 0 && previous_bit == next_bit;
        if matches!(status, Status::Queued) && previous_bit != 0 && previous_bit != next_bit {
            self.unlink_ready(index);
        }
        if previous_bit != next_bit {
            self.remove_kind(previous);
            self.add_kind(record);
        }
        let entry = self.slots[index].entry.as_mut().unwrap();
        entry.record = record;
        entry.new_connection_id = new_connection_id;
        entry.status = Status::Queued;
        entry.flight = Links::EMPTY;
        if !remains_ready && next_bit != 0 {
            entry.ready = Links::EMPTY;
            self.link_ready(index);
        }
    }

    fn allocate(&mut self) -> Option<usize> {
        if self.free_head != NONE {
            let index = self.free_head as usize;
            self.free_head = self.slots[index].next_free;
            self.slots[index].next_free = NONE;
            return Some(index);
        }
        if self.slots.len() >= self.limit {
            return None;
        }
        let index = self.slots.len();
        self.slots.push(Slot {
            delivery_generation: 0,
            owner_generation: 0,
            next_free: NONE,
            entry: None,
        });
        Some(index)
    }

    fn remove_owner<Kind>(&mut self, owner: &mut Option<OwnerKey<Kind>>) -> bool {
        if let Some(index) = owner.take().and_then(|owner| self.owner_index(owner)) {
            self.remove(index);
            self.free_head == index as u32
        } else {
            false
        }
    }

    fn remove(&mut self, index: usize) -> Option<Control> {
        let entry = self.slots.get(index)?.entry.as_ref()?;
        let record = entry.record;
        if matches!(entry.status, Status::Queued) && kind_bit(record) != 0 {
            self.unlink_ready(index);
        } else if matches!(entry.status, Status::InFlight { .. }) {
            self.unlink_flight(index);
        }
        self.slots[index].entry.take();
        self.len -= 1;
        self.remove_kind(record);
        if !self.bump_generation(index) {
            return Some(record);
        }
        let Some(next_owner_generation) = self.slots[index]
            .owner_generation
            .checked_add(1)
            .filter(|generation| *generation <= i32::MAX as u32)
        else {
            self.overflowed = true;
            return Some(record);
        };
        self.slots[index].owner_generation = next_owner_generation;
        self.slots[index].next_free = self.free_head;
        self.free_head = index as u32;
        Some(record)
    }

    fn add_kind(&mut self, record: Control) {
        let bit = kind_bit(record);
        if bit == 0 {
            return;
        }
        let lane = lane(bit);
        self.kind_counts[lane] += 1;
        self.bits |= bit;
    }

    fn remove_kind(&mut self, record: Control) {
        let bit = kind_bit(record);
        if bit == 0 {
            return;
        }
        let lane = lane(bit);
        self.kind_counts[lane] -= 1;
        if self.kind_counts[lane] == 0 {
            self.bits &= !bit;
        }
    }

    fn bump_generation(&mut self, index: usize) -> bool {
        let Some(next) = self.slots[index].delivery_generation.checked_add(1) else {
            self.overflowed = true;
            return false;
        };
        self.slots[index].delivery_generation = next;
        true
    }

    fn handle(&self, index: usize) -> Option<Handle<Control>> {
        Handle::new(index, self.slots.get(index)?.delivery_generation)
    }

    fn resolve(&self, handle: Handle<Control>) -> Option<&Entry> {
        let slot = self.slots.get(handle.index())?;
        (slot.delivery_generation == handle.generation())
            .then_some(slot.entry.as_ref())
            .flatten()
    }

    fn resolve_owner<Kind>(&self, owner: Option<OwnerKey<Kind>>) -> Option<&Entry> {
        let index = self.owner_index(owner?)?;
        self.slots[index].entry.as_ref()
    }

    fn owner_index<Kind>(&self, owner: OwnerKey<Kind>) -> Option<usize> {
        let slot = self.slots.get(owner.index())?;
        (slot.owner_generation == owner.generation() && slot.entry.is_some())
            .then_some(owner.index())
    }
}
