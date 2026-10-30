mod queues;
use crate::conn::wire::path::probe;
use crate::conn::{
    self,
    output::control::{self, journal::storage::View, revision},
};
use o3::depot;
use o3::depot::index::Access;
use o3::depot::index::Initialized;
use o3::depot::queue::{indexed::keyed, links};
pub(in crate::conn::output::control) use queues::Queues;
use std::num::NonZero;

pub(in crate::conn) mod cursor;
pub(in crate::conn) mod probes;
pub(in crate::conn) mod records;
pub(in crate::conn) mod storage;

#[derive(Clone, Copy)]
pub(in crate::conn) enum State {
    Ready,
    Probe {
        epoch: conn::Epoch,
        carriers: NonZero<u16>,
        round: u32,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::conn) enum Error {
    Vacant,
    Revision(revision::Key),
}

const _: () = {
    assert!(std::mem::size_of::<Queues>() == 200);
    assert!(std::mem::size_of::<Lanes>() == 136);
    assert!(std::mem::size_of::<Flights>() == 64);
    assert!(std::mem::size_of::<Error>() == 8);
    assert!(std::mem::size_of::<State>() == 8);
};

/// Consumes the selected slot, packet operation, and original exclusive owner.
pub(in crate::conn) fn commit(
    live: depot::raw::Proof<((&mut control::Pending, State), revision::Key), Initialized<State>>,
) -> revision::Key {
    let live = unsafe {
        live.map(|((pending, state), key)| {
            (
                (&mut pending.storage, (state, key)),
                depot::raw::Word::from_offset(key.index()),
            )
        })
    };
    let (mut slot, (state, key)) = storage::Set::project(live);
    match state {
        State::Ready => {
            slot.dispatch(conn::Epoch::Application);
        }
        State::Probe {
            epoch,
            carriers,
            round,
        } => {
            slot.probe(epoch, carriers, round);
        }
    }
    key
}

pub(in crate::conn::output::control::journal) struct Lane<'a> {
    pending: &'a control::Pending,
    lane: control::Lane,
    remaining: u16,
}

impl<'a> Lane<'a> {
    pub(in crate::conn::output::control::journal) fn new(
        pending: &'a control::Pending,
        mask: u16,
    ) -> Option<Self> {
        let bits = pending.storage.topology().lanes.ready_bits() & mask;
        if bits == 0 {
            return None;
        }
        let bit = 1 << bits.trailing_zeros();
        let lane = control::Lane::from_bit(bit)?;
        Some(Self {
            pending,
            lane,
            remaining: bits & !bit,
        })
    }

    pub(in crate::conn::output::control::journal) fn next(&self) -> Option<Self> {
        let bits = self.remaining;
        if bits == 0 {
            return None;
        }
        let bit = 1 << bits.trailing_zeros();
        let lane = control::Lane::from_bit(bit)?;
        Some(Self {
            pending: self.pending,
            lane,
            remaining: bits & !bit,
        })
    }

    pub(in crate::conn::output::control::journal) fn probe(&self) -> probe::View<'a> {
        self.pending.probe()
    }

    pub(in crate::conn::output::control::journal) fn project(
        live: depot::raw::Proof<(&Self, links::Index), Initialized<()>>,
    ) -> (storage::Key, revision::Key, &'a storage::Entry) {
        let live = unsafe { live.map(|(lane, index)| (lane.pending.storage.view(), index)) };
        View::project(live)
    }
}

unsafe impl depot::raw::KeySource for Lane<'_> {
    type Key = storage::Key;

    fn fifo(&self) -> &keyed::Fifo<Self::Key> {
        self.lane.bind(&self.pending.storage.topology().lanes.ready)
    }
}

unsafe impl depot::raw::KeyRead for Lane<'_> {
    fn entry<'a>(
        live: depot::raw::Proof<(&'a Self, links::Index), Initialized<()>>,
    ) -> keyed::Entry<'a, Self::Key> {
        let live = unsafe { live.map(|(lane, index)| (lane.pending.storage.view(), index)) };
        keyed::Entry::from_source(storage::Projected(live))
    }
}

pub(in crate::conn::output::control::journal) struct Flight<'a> {
    pending: &'a control::Pending,
    epoch: conn::Epoch,
}

struct Probe<'a> {
    flight: Flight<'a>,
    key: storage::Key,
}

impl<'a> Flight<'a> {
    pub(in crate::conn::output::control::journal) fn cursor(
        pending: &'a control::Pending,
        epoch: conn::Epoch,
    ) -> Option<keyed::Iter<Self>> {
        let key = *epoch.bind(&pending.storage.topology().flights.probe_cursor);
        let probe = Probe {
            flight: Self { pending, epoch },
            key: key?,
        };
        let live = Access::into_live(probe);
        let live = unsafe {
            live.map(|(probe, key)| (probe.flight, depot::raw::Word::from_offset(key.index())))
        };
        Some(keyed::Iter::from_live(live))
    }

    pub(in crate::conn::output::control::journal) fn project(
        live: depot::raw::Proof<(&Self, links::Index), Initialized<()>>,
    ) -> (storage::Key, revision::Key, &'a storage::Entry) {
        let live = unsafe { live.map(|(flight, index)| (flight.pending.storage.view(), index)) };
        View::project(live)
    }
}

unsafe impl depot::raw::Source for Probe<'_> {
    type Key = storage::Key;

    fn key(&self) -> Self::Key {
        self.key
    }
}

unsafe impl depot::raw::KeySource for Flight<'_> {
    type Key = storage::Key;

    fn fifo(&self) -> &keyed::Fifo<Self::Key> {
        self.epoch
            .bind(&self.pending.storage.topology().flights.in_flight)
    }
}

unsafe impl depot::raw::KeyRead for Flight<'_> {
    fn entry<'a>(
        live: depot::raw::Proof<(&'a Self, links::Index), Initialized<()>>,
    ) -> keyed::Entry<'a, Self::Key> {
        let live = unsafe { live.map(|(flight, index)| (flight.pending.storage.view(), index)) };
        keyed::Entry::from_source(storage::Projected(live))
    }
}

struct Front<'a> {
    entries: View<'a>,
    chain: &'a keyed::Fifo<storage::Key>,
}

unsafe impl depot::raw::KeySource for Front<'_> {
    type Key = storage::Key;

    fn fifo(&self) -> &keyed::Fifo<Self::Key> {
        self.chain
    }
}

pub(in crate::conn::output::control) struct Lanes {
    bits: u16,
    ready_bits: u16,
    kind_counts: [u32; control::LANE_COUNT],
    ready: [keyed::Fifo<storage::Key>; control::LANE_COUNT],
}

pub(in crate::conn::output::control) struct Flights {
    in_flight: [keyed::Fifo<storage::Key>; 3],
    probe_cursor: [Option<storage::Key>; 3],
    probe_round: [u32; 3],
}

impl Lanes {
    fn new() -> Self {
        Self {
            bits: 0,
            ready_bits: 0,
            kind_counts: [0; control::LANE_COUNT],
            ready: [const { keyed::Fifo::new() }; control::LANE_COUNT],
        }
    }

    pub(in crate::conn::output::control) fn bits(&self) -> u16 {
        self.bits
    }

    pub(in crate::conn::output::control) fn ready_bits(&self) -> u16 {
        self.ready_bits
    }
}

impl Flights {
    fn new() -> Self {
        Self {
            in_flight: [const { keyed::Fifo::new() }; 3],
            probe_cursor: [None; 3],
            probe_round: [0; 3],
        }
    }

    pub(in crate::conn::output::control) fn probe_round(&self, epoch: conn::Epoch) -> u32 {
        *epoch.bind(&self.probe_round)
    }
}
