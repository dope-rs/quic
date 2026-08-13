use crate::conn::delivery;

use crate::conn::control;
use crate::conn::control::linkage::Linkage as _;

pub(super) trait Records {
    fn queue<Kind>(
        &mut self,
        owner: &mut Option<control::OwnerKey<Kind>>,
        record: delivery::Control,
        new_connection_id: Option<control::NewConnectionId>,
    ) -> Option<delivery::Handle<delivery::Control>>;
    fn replace(
        &mut self,
        index: usize,
        record: delivery::Control,
        new_connection_id: Option<control::NewConnectionId>,
    );
    fn allocate(&mut self) -> Option<usize>;
    fn remove_owner<Kind>(&mut self, owner: &mut Option<control::OwnerKey<Kind>>) -> bool;
    fn remove(&mut self, index: usize) -> Option<delivery::Control>;
    fn add_kind(&mut self, record: delivery::Control);
    fn remove_kind(&mut self, record: delivery::Control);
    fn bump_generation(&mut self, index: usize) -> bool;
    fn handle(&self, index: usize) -> Option<delivery::Handle<delivery::Control>>;
    fn resolve(&self, handle: delivery::Handle<delivery::Control>) -> Option<&control::Entry>;
    fn resolve_owner<Kind>(
        &self,
        owner: Option<control::OwnerKey<Kind>>,
    ) -> Option<&control::Entry>;
    fn owner_index<Kind>(&self, owner: control::OwnerKey<Kind>) -> Option<usize>;
}

impl Records for control::Pending {
    fn queue<Kind>(
        &mut self,
        owner: &mut Option<control::OwnerKey<Kind>>,
        record: delivery::Control,
        new_connection_id: Option<control::NewConnectionId>,
    ) -> Option<delivery::Handle<delivery::Control>> {
        if let Some(index) = (*owner).and_then(|owner| self.owner_index(owner)) {
            let unchanged = {
                let entry = self.storage.slots[index].entry.as_ref().unwrap();
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
        if self.storage.len == self.storage.limit {
            self.storage.overflowed = true;
            return None;
        }
        let Some(index) = self.allocate() else {
            self.storage.overflowed = true;
            return None;
        };
        self.storage.slots[index].entry = Some(control::Entry {
            record,
            new_connection_id,
            status: control::Status::Queued,
            ready: control::Links::EMPTY,
            flight: control::Links::EMPTY,
        });
        self.storage.len += 1;
        self.add_kind(record);
        self.link_ready(index);
        *owner = control::OwnerKey::new(index, self.storage.slots[index].owner_generation);
        self.handle(index)
    }

    fn replace(
        &mut self,
        index: usize,
        record: delivery::Control,
        new_connection_id: Option<control::NewConnectionId>,
    ) {
        let entry = self.storage.slots[index].entry.as_ref().unwrap();
        let status = entry.status;
        let previous = entry.record;
        if !self.bump_generation(index) {
            return;
        }
        if matches!(status, control::Status::InFlight { .. }) {
            self.unlink_flight(index);
        }
        let previous_bit = control::kind_bit(previous);
        let next_bit = control::kind_bit(record);
        let remains_ready = matches!(status, control::Status::Queued)
            && previous_bit != 0
            && previous_bit == next_bit;
        if matches!(status, control::Status::Queued)
            && previous_bit != 0
            && previous_bit != next_bit
        {
            self.unlink_ready(index);
        }
        if previous_bit != next_bit {
            self.remove_kind(previous);
            self.add_kind(record);
        }
        let entry = self.storage.slots[index].entry.as_mut().unwrap();
        entry.record = record;
        entry.new_connection_id = new_connection_id;
        entry.status = control::Status::Queued;
        entry.flight = control::Links::EMPTY;
        if !remains_ready && next_bit != 0 {
            entry.ready = control::Links::EMPTY;
            self.link_ready(index);
        }
    }

    fn allocate(&mut self) -> Option<usize> {
        if self.storage.free_head != crate::conn::control::NONE {
            let index = self.storage.free_head as usize;
            self.storage.free_head = self.storage.slots[index].next_free;
            self.storage.slots[index].next_free = crate::conn::control::NONE;
            return Some(index);
        }
        if self.storage.slots.len() >= self.storage.limit {
            return None;
        }
        let index = self.storage.slots.len();
        self.storage.slots.push(crate::conn::control::Slot {
            delivery_generation: 0,
            owner_generation: 0,
            next_free: crate::conn::control::NONE,
            entry: None,
        });
        Some(index)
    }

    fn remove_owner<Kind>(&mut self, owner: &mut Option<control::OwnerKey<Kind>>) -> bool {
        if let Some(index) = owner.take().and_then(|owner| self.owner_index(owner)) {
            self.remove(index);
            self.storage.free_head == index as u32
        } else {
            false
        }
    }

    fn remove(&mut self, index: usize) -> Option<delivery::Control> {
        let entry = self.storage.slots.get(index)?.entry.as_ref()?;
        let record = entry.record;
        if matches!(entry.status, control::Status::Queued) && control::kind_bit(record) != 0 {
            self.unlink_ready(index);
        } else if matches!(entry.status, control::Status::InFlight { .. }) {
            self.unlink_flight(index);
        }
        self.storage.slots[index].entry.take();
        self.storage.len -= 1;
        self.remove_kind(record);
        if !self.bump_generation(index) {
            return Some(record);
        }
        let Some(next_owner_generation) = self.storage.slots[index]
            .owner_generation
            .checked_add(1)
            .filter(|generation| *generation <= i32::MAX as u32)
        else {
            self.storage.overflowed = true;
            return Some(record);
        };
        self.storage.slots[index].owner_generation = next_owner_generation;
        self.storage.slots[index].next_free = self.storage.free_head;
        self.storage.free_head = index as u32;
        Some(record)
    }

    fn add_kind(&mut self, record: delivery::Control) {
        let bit = control::kind_bit(record);
        if bit == 0 {
            return;
        }
        let lane = control::lane(bit);
        self.lanes.kind_counts[lane] += 1;
        self.lanes.bits |= bit;
    }

    fn remove_kind(&mut self, record: delivery::Control) {
        let bit = control::kind_bit(record);
        if bit == 0 {
            return;
        }
        let lane = control::lane(bit);
        self.lanes.kind_counts[lane] -= 1;
        if self.lanes.kind_counts[lane] == 0 {
            self.lanes.bits &= !bit;
        }
    }

    fn bump_generation(&mut self, index: usize) -> bool {
        let Some(next) = self.storage.slots[index].delivery_generation.checked_add(1) else {
            self.storage.overflowed = true;
            return false;
        };
        self.storage.slots[index].delivery_generation = next;
        true
    }

    fn handle(&self, index: usize) -> Option<delivery::Handle<delivery::Control>> {
        delivery::Handle::new(index, self.storage.slots.get(index)?.delivery_generation)
    }

    fn resolve(&self, handle: delivery::Handle<delivery::Control>) -> Option<&control::Entry> {
        let slot = self.storage.slots.get(handle.index())?;
        (slot.delivery_generation == handle.generation())
            .then_some(slot.entry.as_ref())
            .flatten()
    }

    fn resolve_owner<Kind>(
        &self,
        owner: Option<control::OwnerKey<Kind>>,
    ) -> Option<&control::Entry> {
        let index = self.owner_index(owner?)?;
        self.storage.slots[index].entry.as_ref()
    }

    fn owner_index<Kind>(&self, owner: control::OwnerKey<Kind>) -> Option<usize> {
        let slot = self.storage.slots.get(owner.index())?;
        (slot.owner_generation == owner.generation() && slot.entry.is_some())
            .then_some(owner.index())
    }
}
