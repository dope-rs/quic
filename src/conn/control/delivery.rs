use crate::conn;
use crate::conn::delivery;

use crate::conn::control;
use crate::conn::control::linkage::Linkage as _;
use crate::conn::control::records::Records as _;

pub(in crate::conn) struct Delivery<'a> {
    pending: &'a mut control::Pending,
}

impl<'a> Delivery<'a> {
    pub(in crate::conn) fn new(pending: &'a mut control::Pending) -> Self {
        Self { pending }
    }

    pub(in crate::conn) fn commit(
        &mut self,
        epoch: conn::Epoch,
        record: delivery::Control,
        selected: delivery::Handle<delivery::Control>,
    ) -> Option<delivery::Handle<delivery::Control>> {
        let index = selected.index();
        let entry = self.pending.resolve(selected)?;
        match entry.status {
            control::Status::Queued if entry.record == record => {
                if control::kind_bit(record) != 0 {
                    self.pending.unlink_ready(index);
                }
                let probe_round = self.pending.flights.probe_round[epoch as usize];
                self.pending.storage.slots[index]
                    .entry
                    .as_mut()
                    .unwrap()
                    .status = control::Status::InFlight {
                    epoch,
                    carriers: 1,
                    probe_round,
                };
                self.pending.link_flight(index, epoch);
                Some(selected)
            }
            control::Status::InFlight {
                epoch: delivery_epoch,
                carriers,
                ..
            } if delivery_epoch == epoch => {
                let carriers = carriers.checked_add(1)?;
                let next = entry.flight.next;
                let round = self.pending.flights.probe_round[epoch as usize];
                let entry = self.pending.storage.slots[index].entry.as_mut().unwrap();
                entry.status = control::Status::InFlight {
                    epoch,
                    carriers,
                    probe_round: round,
                };
                self.pending.flights.probe_cursor[epoch as usize] = next;
                Some(selected)
            }
            control::Status::Queued | control::Status::InFlight { .. } => None,
        }
    }

    pub(in crate::conn) fn acknowledge(
        &mut self,
        handle: delivery::Handle<delivery::Control>,
    ) -> control::Effect {
        let index = handle.index();
        let Some(entry) = self.pending.resolve(handle) else {
            return control::Effect::None;
        };
        if !matches!(entry.status, control::Status::InFlight { .. }) {
            return control::Effect::None;
        }
        let record = entry.record;
        match record {
            delivery::Control::DataBlocked(_) | delivery::Control::StreamDataBlocked(_, _) => {
                self.pending.remove(index);
                control::Effect::None
            }
            delivery::Control::ResetStream(stream_id, _, _) => {
                self.pending.remove(index);
                control::Effect::RetireStream(stream_id)
            }
            _ => {
                self.pending.remove(index);
                control::Effect::None
            }
        }
    }
}
