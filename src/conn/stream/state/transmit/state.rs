use o3::buffer;

use crate::conn::stream::state::transmit::{log, peer, queue};
use crate::conn::{
    self,
    machine::storage::capacity,
    output::{control, delivery},
    stream::state::streams,
};
use crate::proto::param;
use crate::wire::{
    stream::{Id, Initiator},
    varint::VarInt,
};
use log::journal;

pub(in crate::conn) struct State<D: buffer::raw::Segment> {
    pub(in crate::conn::stream::state::transmit) scratch_pending: Vec<queue::Handle>,
    pub(in crate::conn::stream::state::transmit) deliveries: journal::Journal,
    pub(in crate::conn::stream::state::transmit) map: queue::Map<D>,
    pub(in crate::conn) peer: peer::Peer,
}

impl<D: buffer::raw::Segment> State<D> {
    pub(in crate::conn) fn new(
        mut scratch: Vec<queue::Handle>,
        map: queue::Map<D>,
        journal: capacity::Capacity<capacity::Stream>,
    ) -> Self {
        scratch.clear();
        Self {
            scratch_pending: scratch,
            deliveries: journal::Journal::new(journal),
            map,
            peer: peer::Peer::new(queue::Credit::new(VarInt::ZERO)),
        }
    }

    pub(in crate::conn) fn map(&self) -> &queue::Map<D> {
        &self.map
    }

    pub(in crate::conn) fn deliveries(&self) -> &journal::Journal {
        &self.deliveries
    }

    pub(in crate::conn) fn has_snapshot(&self) -> bool {
        !self.scratch_pending.is_empty()
    }

    pub(in crate::conn) fn snapshot(
        &mut self,
        control: &mut control::Pending,
        work: usize,
        admit: impl Fn(Id) -> bool,
    ) -> Result<(), control::Admission> {
        self.map
            .snapshot(&mut self.scratch_pending, control, work, admit)
    }

    pub(in crate::conn) fn selection(&mut self) -> (log::Selection<'_>, &queue::Map<D>) {
        (log::Selection::new(&mut self.deliveries), &self.map)
    }

    pub(in crate::conn) fn set_credit(
        &mut self,
        peer: &param::Set,
        local: Initiator,
        early: bool,
        control: &mut control::Pending,
    ) -> Result<(), conn::Error> {
        self.map.try_for_each::<conn::Error>(|mut occupied| {
            let relative = streams::Relative::new(occupied.id(), local);
            let limit = queue::Entry::limit(Some(peer), relative);
            let credit = occupied.credit_mut();
            if early {
                credit.raise(limit, control);
            } else {
                credit.replace(limit, control);
            }
            occupied.refresh();
            Ok(())
        })
    }

    pub(in crate::conn) fn lose(&mut self, handle: delivery::Handle<delivery::Stream>) {
        self.deliveries.lose(handle);
    }

    pub(in crate::conn) fn arm_probes(&mut self) {
        self.deliveries.arm_probes();
    }

    pub(in crate::conn) fn reject_early(
        &mut self,
        control: &mut control::Pending,
    ) -> Result<(), conn::Error> {
        self.map.try_for_each::<conn::Error>(|mut occupied| {
            occupied.reject_early(&mut self.deliveries, control)?;
            occupied.refresh();
            Ok(())
        })?;
        self.peer.reject_early();
        Ok(())
    }
}
