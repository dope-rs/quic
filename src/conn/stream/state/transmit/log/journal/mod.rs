mod reserves;
use crate::conn::{
    machine::storage::{self, capacity, demand},
    output::delivery,
    stream::state::transmit::log::{self, links, planes},
};
use links::{
    storage::{Records, Scan},
    topology::{Group, Record, Tables},
};
use o3::depot::{
    capacity::{Count, Reason},
    queue::indexed::keyed,
};
pub(in crate::conn) use reserves::{
    Credit, Ready, Reserve, ReserveError, Schedule, Scope, Written,
};
pub(in crate::conn::stream::state::transmit) use reserves::{Debit, Insert};
use std::mem;

pub(in crate::conn) mod raw;

pub(super) struct ProbeQueue {
    pub(super) chain: keyed::Fifo<storage::Key<log::GroupTag>, planes::Probe>,
    pub(super) cursor: Option<log::Position>,
}

pub(super) struct Queues {
    pub(super) retry: keyed::Fifo<storage::Key<log::GroupTag>, planes::Retry>,
    pub(super) reclaim: keyed::Fifo<storage::Key<log::GroupTag>, planes::Reclaim>,
    pub(super) probe: ProbeQueue,
}

pub(super) struct Ledger {
    pub(super) active: u16,
    pub(super) limit: u16,
}

pub(in crate::conn) enum Entry {
    Fresh(Written),
    Retry(log::Retry),
    Probe(log::Probe),
}

impl Ledger {
    fn new(limit: capacity::Capacity<capacity::Stream>) -> Self {
        Self {
            active: 0,
            limit: limit.get(),
        }
    }

    fn has_room(&self, count: usize) -> bool {
        usize::from(self.active)
            .checked_add(count)
            .is_some_and(|active| active <= usize::from(self.limit))
    }
}

/// Fixed-capacity owner for stream records whose bytes remain retained.
/// Cancellation invalidates a group in O(1); nodes remain reachable until
/// ACK/loss while becoming immediately eligible for generation-safe reuse.
pub(in crate::conn) struct Journal {
    pub(super) storage: Tables,
    pub(super) queues: Queues,
    pub(super) ledger: Ledger,
    pub(super) retry_work: log::RetryLedger,
}

impl Journal {
    pub(in crate::conn) fn new(capacity: capacity::Capacity<capacity::Stream>) -> Self {
        let ledger = Ledger::new(capacity);
        Self {
            storage: Tables {
                nodes: demand::Table::with_limit(Count::new(capacity.as_u32())),
                groups: demand::Table::with_limit(Count::new(capacity.as_u32())),
            },
            queues: Queues {
                retry: keyed::Fifo::new(),
                reclaim: keyed::Fifo::new(),
                probe: ProbeQueue {
                    chain: keyed::Fifo::new(),
                    cursor: None,
                },
            },
            ledger,
            retry_work: log::RetryLedger::default(),
        }
    }

    pub(in crate::conn) fn has_room(&self, needed: usize) -> bool {
        self.ledger.has_room(needed)
    }

    fn try_grow(&mut self, upper: usize) -> Result<(), Reason> {
        if !self.ledger.has_room(upper) {
            return Err(Reason::Full);
        }
        let mut records = Records::new(self);
        records.try_reap(upper)?;
        records.try_prune(upper)?;
        let count = Count::new(upper as u32);
        let Tables { nodes, groups } = &mut self.storage;
        let groups = groups.try_grow(count)?;
        let nodes = nodes.try_grow(count)?;
        groups.commit();
        nodes.commit();
        Ok(())
    }

    pub(in crate::conn) fn resident(&self) -> usize {
        self.storage
            .nodes
            .bytes()
            .saturating_add(self.storage.groups.bytes())
    }

    pub(in crate::conn) fn has_retry(&self) -> bool {
        !self.retry_work.is_empty()
    }

    pub(in crate::conn) fn has_floor(&self, bytes: usize, minimum: usize) -> bool {
        self.retry_work.has_floor(bytes, minimum)
    }

    pub(in crate::conn) fn cancel(&mut self, id: log::GroupId) {
        let Some(ready) = Group::new(self, id) else {
            return;
        };
        ready.cancel();
    }

    pub(in crate::conn) fn lose(&mut self, handle: delivery::Handle<delivery::Stream>) {
        if let Some(record) = Record::bind(self, handle) {
            record.lose();
        }
    }

    pub(in crate::conn) fn arm_probes(&mut self) {
        let Some(scan) = Scan::<planes::Probe>::first(self) else {
            self.queues.probe.cursor = None;
            return;
        };
        self.queues.probe.cursor = Some(scan.get().0);
    }

    pub(in crate::conn) fn probe_work(&self) -> log::ProbeWork {
        log::ProbeWork {
            cursor: self.queues.probe.cursor,
        }
    }
}

const _: () = {
    assert!(mem::size_of::<Ledger>() == mem::size_of::<u32>());
    assert!(mem::size_of::<Entry>() == 32);
};
