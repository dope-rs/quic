use crate::conn::wire::crypto::tx::stores::{Entry, Key, Probe, table::Slots};
use crate::conn::{output::delivery, wire::crypto::tx};
use o3::depot::{self, arena, index::Initialized, queue::links};
use std::{mem, num::NonZero};

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Queued,
    InFlight,
    Acknowledged,
}

pub(in crate::conn::wire::crypto::tx) struct Status(
    arena::raw::StagedValue<Phase, (), NonZero<u16>>,
);

/// Borrows one original entry while its InFlight payload remains initialized.
pub(super) struct InFlight<'a>(&'a Entry);

impl Status {
    pub(super) fn queued() -> Self {
        Self(arena::raw::StagedValue::queued(Phase::Queued, ()))
    }

    pub(super) fn flight(carriers: NonZero<u16>) -> Self {
        Self(arena::raw::StagedValue::parked(Phase::InFlight, carriers))
    }

    pub(super) fn acknowledged() -> Self {
        Self(arena::raw::StagedValue::queued(Phase::Acknowledged, ()))
    }

    pub(super) fn phase(&self) -> Phase {
        *self.0.key()
    }
}

impl<'a> InFlight<'a> {
    pub(super) fn new(entry: &'a Entry) -> Option<Self> {
        match entry.status.phase() {
            Phase::InFlight => Some(Self(entry)),
            Phase::Queued | Phase::Acknowledged => None,
        }
    }

    pub(super) fn project(
        live: depot::raw::Proof<(Probe<'a>, links::Index), Initialized<tx::Flights>>,
    ) -> (Key, Self) {
        // SAFETY: the retained Probe names the original slot, whose active
        // InFlight payload cannot change during the shared Set loan.
        let live = unsafe { live.map(|(probe, index)| (&probe.owner.slots, index)) };
        let (key, entry) = Slots::project(live);
        (key, Self(entry))
    }

    pub(super) fn record(&self) -> delivery::Crypto {
        self.0.record
    }

    pub(super) fn carriers(&self) -> NonZero<u16> {
        // SAFETY: construction admits only this original entry's InFlight
        // phase; the borrowed entry prevents replacement of its parked value.
        unsafe { *self.0.status.0.parked_ref() }
    }
}

const _: () = {
    assert!(mem::size_of::<Status>() == 4);
    assert!(!mem::needs_drop::<Status>());
    assert!(mem::size_of::<InFlight<'static>>() == mem::size_of::<usize>());
};
