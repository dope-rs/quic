use crate::conn::{
    Epoch,
    delivery::{Control, Handle},
};

use super::linkage::Linkage;
use super::records::Records;
use super::{Effect, NONE, Pending, Status, kind_bit};

pub(in crate::conn) struct Delivery<'a> {
    pending: &'a mut Pending,
}

impl<'a> Delivery<'a> {
    pub(in crate::conn) fn new(pending: &'a mut Pending) -> Self {
        Self { pending }
    }

    pub(in crate::conn) fn commit(
        &mut self,
        epoch: Epoch,
        record: Control,
        selected: Handle<Control>,
    ) -> Option<Handle<Control>> {
        let index = selected.index();
        let entry = self.pending.resolve(selected)?;
        match entry.status {
            Status::Queued if entry.record == record => {
                if kind_bit(record) != 0 {
                    self.pending.unlink_ready(index);
                }
                let probe_round = self.pending.probe_round[epoch as usize];
                self.pending.slots[index].entry.as_mut().unwrap().status = Status::InFlight {
                    epoch,
                    carriers: 1,
                    probe_round,
                };
                self.pending.link_flight(index, epoch);
                Some(selected)
            }
            Status::InFlight {
                epoch: delivery_epoch,
                carriers,
                ..
            } if delivery_epoch == epoch => {
                let carriers = carriers.checked_add(1)?;
                let next = entry.flight.next;
                let round = self.pending.probe_round[epoch as usize];
                let entry = self.pending.slots[index].entry.as_mut().unwrap();
                entry.status = Status::InFlight {
                    epoch,
                    carriers,
                    probe_round: round,
                };
                self.pending.probe_cursor[epoch as usize] = next;
                Some(selected)
            }
            Status::Queued | Status::InFlight { .. } => None,
        }
    }

    pub(in crate::conn) fn acknowledge(&mut self, handle: Handle<Control>) -> Effect {
        let index = handle.index();
        let Some(entry) = self.pending.resolve(handle) else {
            return Effect::None;
        };
        if !matches!(entry.status, Status::InFlight { .. }) {
            return Effect::None;
        }
        let record = entry.record;
        match record {
            Control::DataBlocked(_) | Control::StreamDataBlocked(_, _) => {
                self.pending.remove(index);
                Effect::None
            }
            Control::ResetStream(stream_id, _, _) => {
                self.pending.remove(index);
                Effect::RetireStream(stream_id)
            }
            _ => {
                self.pending.remove(index);
                Effect::None
            }
        }
    }

    pub(in crate::conn) fn lose(&mut self, handle: Handle<Control>) {
        let index = handle.index();
        let Some(entry) = self.pending.resolve(handle) else {
            return;
        };
        let Status::InFlight {
            epoch,
            carriers,
            probe_round,
        } = entry.status
        else {
            return;
        };
        if carriers > 1 {
            self.pending.slots[index].entry.as_mut().unwrap().status = Status::InFlight {
                epoch,
                carriers: carriers - 1,
                probe_round,
            };
            return;
        }
        if !self.pending.bump_generation(index) {
            return;
        }
        self.pending.unlink_flight(index);
        let entry = self.pending.slots[index].entry.as_mut().unwrap();
        entry.status = Status::Queued;
        entry.flight.prev = NONE;
        entry.flight.next = NONE;
        if kind_bit(entry.record) != 0 {
            self.pending.link_ready(index);
        }
    }
}
