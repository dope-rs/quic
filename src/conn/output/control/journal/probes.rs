use crate::conn;
use crate::conn::output::{control, delivery};

use crate::conn::output::control::journal::{self, State, storage};
use control::encode::Selected;

/// Probe selection tied to one exact generation-checked control journal.
#[repr(transparent)]
pub(in crate::conn) struct Probes<P>(P);

impl<P> Probes<P> {
    pub(in crate::conn) const fn new(pending: P) -> Self {
        Self(pending)
    }
}

impl Probes<&mut control::Pending> {
    pub(in crate::conn) fn arm(&mut self, epoch: conn::Epoch) {
        self.0.storage.arm_probes(epoch);
    }
}

impl<'a> Probes<&'a control::Pending> {
    pub(in crate::conn) fn next(
        &self,
        epoch: conn::Epoch,
        mut excluded: impl FnMut(Selected<'a>) -> bool,
    ) -> Option<Selected<'a>> {
        let round = self.0.storage.topology().flights.probe_round(epoch);
        let mut current = journal::Flight::cursor(self.0, epoch)?;
        while let Some(live) = current.next_entry() {
            let (_, handle, entry) = journal::Flight::project(live);
            if let storage::Status::InFlight {
                epoch: sent,
                probe_round: probe,
                carriers,
            } = entry.status
                && sent == epoch
                && probe != round
                && !matches!(
                    entry.record(),
                    delivery::Control::PathValidation(_) | delivery::Control::PathResponse(_)
                )
            {
                let Some(carriers) = carriers.checked_add(1) else {
                    continue;
                };
                let selected = Selected::new(
                    handle,
                    entry,
                    State::Probe {
                        epoch,
                        carriers,
                        round,
                    },
                    self.0.probe(),
                );
                if !excluded(selected) {
                    return Some(selected);
                }
            }
        }
        None
    }
}
