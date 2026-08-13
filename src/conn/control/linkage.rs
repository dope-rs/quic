use crate::conn;
use crate::conn::control;

pub(super) trait Linkage {
    fn link_ready(&mut self, index: usize);
    fn unlink_ready(&mut self, index: usize);
    fn link_flight(&mut self, index: usize, epoch: conn::Epoch);
    fn unlink_flight(&mut self, index: usize);
}

impl Linkage for control::Pending {
    fn link_ready(&mut self, index: usize) {
        let bit = control::kind_bit(self.slots[index].entry.as_ref().unwrap().record);
        if bit == 0 {
            return;
        }
        let lane = control::lane(bit);
        let tail = self.ready[lane].tail;
        self.slots[index].entry.as_mut().unwrap().ready = control::Links {
            prev: tail,
            next: control::NONE,
        };
        if tail == control::NONE {
            self.ready[lane].head = index as u32;
        } else {
            self.slots[tail as usize].entry.as_mut().unwrap().ready.next = index as u32;
        }
        self.ready[lane].tail = index as u32;
        self.ready_bits |= bit;
    }

    fn unlink_ready(&mut self, index: usize) {
        let record = self.slots[index].entry.as_ref().unwrap().record;
        let bit = control::kind_bit(record);
        debug_assert_ne!(bit, 0);
        let lane = control::lane(bit);
        let links = self.slots[index].entry.as_ref().unwrap().ready;
        if links.prev == control::NONE {
            self.ready[lane].head = links.next;
        } else {
            self.slots[links.prev as usize]
                .entry
                .as_mut()
                .unwrap()
                .ready
                .next = links.next;
        }
        if links.next == control::NONE {
            self.ready[lane].tail = links.prev;
        } else {
            self.slots[links.next as usize]
                .entry
                .as_mut()
                .unwrap()
                .ready
                .prev = links.prev;
        }
        self.slots[index].entry.as_mut().unwrap().ready = control::Links::EMPTY;
        if self.ready[lane].head == control::NONE {
            self.ready_bits &= !bit;
        }
    }

    fn link_flight(&mut self, index: usize, epoch: conn::Epoch) {
        let epoch_index = epoch as usize;
        let tail = self.in_flight[epoch_index].tail;
        self.slots[index].entry.as_mut().unwrap().flight = control::Links {
            prev: tail,
            next: control::NONE,
        };
        if tail == control::NONE {
            self.in_flight[epoch_index].head = index as u32;
        } else {
            self.slots[tail as usize]
                .entry
                .as_mut()
                .unwrap()
                .flight
                .next = index as u32;
        }
        self.in_flight[epoch_index].tail = index as u32;
    }

    fn unlink_flight(&mut self, index: usize) {
        let control::Status::InFlight { epoch, .. } =
            self.slots[index].entry.as_ref().unwrap().status
        else {
            return;
        };
        let epoch_index = epoch as usize;
        let links = self.slots[index].entry.as_ref().unwrap().flight;
        if links.prev == control::NONE {
            self.in_flight[epoch_index].head = links.next;
        } else {
            self.slots[links.prev as usize]
                .entry
                .as_mut()
                .unwrap()
                .flight
                .next = links.next;
        }
        if links.next == control::NONE {
            self.in_flight[epoch_index].tail = links.prev;
        } else {
            self.slots[links.next as usize]
                .entry
                .as_mut()
                .unwrap()
                .flight
                .prev = links.prev;
        }
        if self.probe_cursor[epoch_index] == index as u32 {
            self.probe_cursor[epoch_index] = links.next;
        }
        self.slots[index].entry.as_mut().unwrap().flight = control::Links::EMPTY;
    }
}
