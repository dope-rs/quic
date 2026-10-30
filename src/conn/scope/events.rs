use crate::{conn, stream};
use conn::output::transmit::permit;
use conn::stream::{BoundEvent, event::queue};
use o3::buffer;
use std::time;

#[repr(transparent)]
pub(crate) struct Events<'access, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    machine: &'access mut conn::Machine<DOMAIN, B, D>,
}

#[repr(transparent)]
pub(crate) struct Lease {
    raw: queue::Lease,
}

impl Lease {
    pub(crate) fn bound_event(&self) -> BoundEvent<'_> {
        BoundEvent::new(self.raw.event().bind(), self.raw.stream_key())
    }
}

impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Events<'_, DOMAIN, B, D> {
    pub(super) fn new(machine: &mut conn::Machine<DOMAIN, B, D>) -> Events<'_, DOMAIN, B, D> {
        Events { machine }
    }

    pub(crate) fn retry(&mut self, now: time::Instant) -> Option<time::Instant> {
        permit::reconcile(self.machine, now)
    }

    pub(crate) fn mark(&mut self, bits: u8) {
        self.machine.peer.reconcile.insert(bits);
    }

    pub(crate) fn merge(&mut self, effects: conn::Effects) {
        self.machine.peer.reconcile.merge(effects);
    }

    pub(crate) fn take(&mut self) -> conn::Effects {
        self.machine.peer.reconcile.take()
    }

    pub(crate) fn early(&mut self) -> conn::Early {
        let effects = &mut self.machine.peer.reconcile;
        if effects.contains(conn::Effects::EARLY_DATA_REJECTED) {
            effects.remove(conn::Effects::EARLY_DATA_REJECTED);
            conn::Early::Rejected
        } else {
            conn::Early::None
        }
    }

    pub(crate) fn poll_stream(&mut self) -> Option<Lease> {
        let raw = self.machine.streams.events.poll_mux()?;
        Some(Lease { raw })
    }

    pub(crate) fn finish(&mut self, lease: Lease, accept: bool) {
        self.machine.streams.finish_mux(lease.raw, accept);
    }

    pub(crate) fn has_stream(&self) -> bool {
        !self.machine.streams.events.is_empty()
    }

    pub(crate) fn has_datagram(&self) -> bool {
        !self.machine.receive.datagrams.is_empty()
    }
}
