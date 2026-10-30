use crate::conn::Selected;
use crate::{
    conn::{
        machine::storage::{self, demand},
        output::delivery,
        stream::state::transmit::{log, queue},
    },
    proto::recovery::pmtud,
};
use links::{
    storage::Scan,
    topology::{Record, Transfer},
};
use o3::depot;
use o3::depot::index::Access;
use o3::depot::queue::indexed::keyed;
use o3::depot::queue::links::Index;
use std::{mem, num};

pub(in crate::conn) mod journal;
mod links;
mod planes;
pub(in crate::conn) mod raw;

/// The inserted node and its group retain the same journal topology and accounting loans.
type Insertion<'a, G> = (
    &'a mut demand::Table<Node, NodeTag, { u32::MAX }>,
    (
        demand::Occupied<'a, Group, GroupTag, { u32::MAX }, G>,
        &'a mut journal::Queues,
        &'a mut journal::Ledger,
        &'a mut RetryLedger,
    ),
);

struct GroupNodes {
    all: keyed::Fifo<storage::Key<NodeTag>, planes::All>,
    retry: keyed::Fifo<storage::Key<NodeTag>, planes::Delivery>,
    inflight: keyed::Fifo<storage::Key<NodeTag>, planes::Delivery>,
}

/// Exact encoder-observed STREAM-frame work linked into retry topology.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct RetryLedger {
    wire_bytes: u32,
    frames: u16,
    /// Conservative maximum after removals. Additions are exact; retaining a
    /// removed maximum can only keep GSO disabled until the ledger empties.
    wire_ceiling: u16,
}

impl RetryLedger {
    fn is_empty(self) -> bool {
        self == Self::default()
    }

    /// Proves a conservative lower bound after every record is sendable.
    fn has_floor(self, bytes: usize, minimum: usize) -> bool {
        if self.is_empty() {
            return false;
        }
        if usize::from(self.wire_ceiling) > bytes {
            return false;
        }
        if minimum <= 1 {
            return true;
        }
        let prior = minimum - 1;
        self.wire_bytes as usize > bytes.saturating_mul(prior)
            || self.frames as usize > crate::conn::PACKET_STREAM_CAPACITY.saturating_mul(prior)
    }
}

pub(in crate::conn) enum GroupTag {}
pub(in crate::conn) enum NodeTag {}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(in crate::conn) struct GroupId(storage::Key<GroupTag>);

impl GroupId {
    fn new(key: storage::Key<GroupTag>) -> Self {
        Self(key)
    }

    fn key(self) -> storage::Key<GroupTag> {
        self.0
    }
}

/// Retry traversal capability tied to one packet-building turn.
/// Every candidate consumes one unit, including size or duplicate rejections,
/// and the capability cannot outlive its borrowed counter.
pub(super) enum Step {
    Taken,
    Empty,
}

pub(in crate::conn) struct RetryWork<'turn> {
    remaining: &'turn mut usize,
    cursor: Cursor,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Position {
    group: storage::Key<GroupTag>,
    node: storage::Key<NodeTag>,
}

enum Cursor {
    Start,
    At(Position),
    End,
}

impl<'turn> RetryWork<'turn> {
    pub(in crate::conn) fn new(left: &'turn mut usize) -> Self {
        Self {
            remaining: left,
            cursor: Cursor::Start,
        }
    }

    fn take(&mut self) -> Step {
        let Some(next) = self.remaining.checked_sub(1) else {
            return Step::Empty;
        };
        *self.remaining = next;
        Step::Taken
    }
}

pub(in crate::conn) struct ProbeWork {
    cursor: Option<Position>,
}

const _: () = {
    assert!(std::mem::size_of::<Option<Position>>() == 16);
    assert!(std::mem::size_of::<ProbeWork>() == 16);
    assert!(std::mem::size_of::<RetryWork<'static>>() == 32);
};

struct Node {
    group: GroupId,
    record: delivery::Stream,
    carriers: u16,
    all: keyed::Link<storage::Key<NodeTag>, planes::All>,
    delivery: keyed::Link<storage::Key<NodeTag>, planes::Delivery>,
}

impl Node {
    fn new(index: Index, group: GroupId, record: delivery::Stream) -> Self {
        Self {
            group,
            record,
            carriers: 1,
            all: keyed::Link::from(index),
            delivery: keyed::Link::from(index),
        }
    }

    /// An acknowledged node remains in its stream-order list until every
    /// preceding node is acknowledged. Its existing link state is the tag, so
    /// retaining an ACK hole costs no extra storage in the fixed node pool.
    fn is_acked(&self, key: storage::Key<NodeTag>) -> bool {
        self.carriers == 0 && !self.delivery.is_linked(key)
    }
}

struct Group {
    owner: queue::Handle,
    active: bool,
    retry_work: RetryLedger,
    /// Capacity-bounded resident count preserving the group slot layout.
    len: u16,
    nodes: GroupNodes,
    retry: keyed::Link<storage::Key<GroupTag>, planes::Retry>,
    reclaim: keyed::Link<storage::Key<GroupTag>, planes::Reclaim>,
    probe: keyed::Link<storage::Key<GroupTag>, planes::Probe>,
}

impl Group {
    fn new(index: Index, owner: queue::Handle) -> Self {
        Self {
            owner,
            active: true,
            retry_work: RetryLedger::default(),
            len: 0,
            nodes: GroupNodes {
                all: keyed::Fifo::new(),
                retry: keyed::Fifo::new(),
                inflight: keyed::Fifo::new(),
            },
            retry: keyed::Link::from(index),
            reclaim: keyed::Link::from(index),
            probe: keyed::Link::from(index),
        }
    }
}

const _: () = assert!(std::mem::size_of::<RetryLedger>() == std::mem::size_of::<u64>());
const _: () = assert!(
    u16::MAX as u64 * pmtud::MAX_PMTU <= u32::MAX as u64,
    "every capacity-bounded retry record must fit the aggregate wire ledger"
);
const _: () = assert!(std::mem::size_of::<Node>() <= 64);
const _: () = assert!(std::mem::size_of::<Option<Node>>() == 64);
const _: () = assert!(std::mem::size_of::<Option<Group>>() == 72);
const _: () = assert!(std::mem::size_of::<demand::Table<Node, NodeTag, { u32::MAX }>>() == 32);
const _: () = assert!(std::mem::size_of::<demand::Table<Group, GroupTag, { u32::MAX }>>() == 32);

mod acks;
pub(in crate::conn::stream) use acks::Ack;
pub(crate) use acks::Acknowledged;
pub(in crate::conn::stream::state::transmit) use acks::Retired;

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub(in crate::conn) struct Retry(storage::Key<log::NodeTag>);

// SAFETY: retry traversal selects only members of the active retry groups.
unsafe impl log::raw::Selected for Retry {}

impl Retry {
    fn new(key: storage::Key<log::NodeTag>) -> Self {
        Self(key)
    }

    pub(in crate::conn) fn key(self) -> storage::Key<log::NodeTag> {
        self.0
    }

    pub(in crate::conn) fn commit(
        live: Selected<(&mut journal::Journal, Self), storage::Key<log::NodeTag>, Self>,
    ) -> delivery::Handle<delivery::Stream> {
        let (record, retry) = Record::project(live);
        let handle = delivery::Handle::from_slot(retry.0.index() as u16, retry.0.generation());
        Transfer::resend(record).commit();
        handle
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::conn) struct Probe {
    key: storage::Key<log::NodeTag>,
    carriers: num::NonZero<u16>,
}

// SAFETY: probe traversal selects only carriers in the active probe groups.
unsafe impl log::raw::Selected for Probe {}

impl Probe {
    fn new(key: storage::Key<log::NodeTag>, carriers: num::NonZero<u16>) -> Self {
        Self { key, carriers }
    }

    pub(in crate::conn) fn key(self) -> storage::Key<log::NodeTag> {
        self.key
    }

    pub(in crate::conn) fn commit(
        live: Selected<(&mut journal::Journal, Self), storage::Key<log::NodeTag>, Self>,
    ) -> delivery::Handle<delivery::Stream> {
        let (record, probe) = Record::project(live);
        let handle = delivery::Handle::from_slot(probe.key.index() as u16, probe.key.generation());
        record.probe(probe.carriers);
        handle
    }
}

pub(in crate::conn) enum Append {
    Done,
    Skip,
    Full,
    Retired,
}

#[repr(transparent)]
pub(in crate::conn) struct Selection<'a>(&'a mut journal::Journal);

impl<'a> Selection<'a> {
    pub(in crate::conn) fn new(journal: &'a mut journal::Journal) -> Self {
        Self(journal)
    }

    pub(in crate::conn) fn retry<E>(
        &mut self,
        room: usize,
        work: &mut log::RetryWork<'_>,
        mut append: impl FnMut(Retry, queue::Handle, delivery::Stream) -> Result<Append, E>,
    ) -> Result<Option<Retry>, E> {
        loop {
            let retired = 'scan: {
                let mut next = match work.cursor {
                    log::Cursor::Start => Scan::<planes::Retry>::first(self.0),
                    log::Cursor::At(position) => Scan::<planes::Retry>::bind(self.0, position),
                    log::Cursor::End => None,
                };
                while let log::Step::Taken = work.take() {
                    let Some(scan) = next else { return Ok(None) };
                    let (position, group, node) = scan.get();
                    let send = group.owner;
                    let retry = Retry::new(position.node);
                    let record = node.record;
                    next = scan.next();
                    work.cursor = match &next {
                        Some(scan) => log::Cursor::At(scan.get().0),
                        None => log::Cursor::End,
                    };
                    if record.range.len_usize() > room {
                        continue;
                    }
                    match append(retry, send, record)? {
                        Append::Done => return Ok(Some(retry)),
                        Append::Skip => {}
                        Append::Full => return Ok(None),
                        Append::Retired => break 'scan retry,
                    }
                }
                return Ok(None);
            };
            Candidate {
                journal: self.0,
                selected: retired,
            }
            .cancel();
            work.cursor = log::Cursor::Start;
        }
    }

    pub(in crate::conn) fn probe<E>(
        &mut self,
        work: &mut log::ProbeWork,
        mut append: impl FnMut(Probe, queue::Handle, delivery::Stream) -> Result<Append, E>,
    ) -> Result<Option<Probe>, E> {
        loop {
            let retired = 'scan: {
                let Some(cursor) = work.cursor else {
                    return Ok(None);
                };
                let mut next = Scan::<planes::Probe>::bind(self.0, cursor);
                while let Some(scan) = next {
                    let (position, group, entry) = scan.get();
                    let record = entry.record;
                    let send = group.owner;
                    let carriers = entry
                        .carriers
                        .checked_add(1)
                        .and_then(num::NonZero::<u16>::new);
                    next = scan.next();
                    work.cursor = next.as_ref().map(|scan| scan.get().0);
                    let Some(carriers) = carriers else { continue };
                    let probe = Probe::new(position.node, carriers);
                    match append(probe, send, record)? {
                        Append::Done => return Ok(Some(probe)),
                        Append::Skip => {}
                        Append::Full => return Ok(None),
                        Append::Retired => break 'scan probe,
                    }
                }
                return Ok(None);
            };
            Candidate {
                journal: self.0,
                selected: retired,
            }
            .cancel();
            work.cursor = self.0.queues.probe.cursor;
        }
    }
}

struct Candidate<'a, P> {
    journal: &'a mut journal::Journal,
    selected: P,
}

// SAFETY: only Selection constructs this owner, from the immediately preceding
// traversal of the same exclusive journal; the callback cannot access it.
unsafe impl depot::raw::Source<Retry> for Candidate<'_, Retry> {
    type Key = storage::Key<log::NodeTag>;
    fn key(&self) -> Self::Key {
        self.selected.key()
    }
}

impl Candidate<'_, Retry> {
    fn cancel(self) {
        let live = Access::into_live(self);
        let live = unsafe { live.map(|(owner, key)| ((owner.journal, owner.selected), key)) };
        Record::project(live).0.cancel();
    }
}

// SAFETY: this probe was selected under the same retained journal loan, with
// its exact native generation and carrier count, before any mutation.
unsafe impl depot::raw::Source<Probe> for Candidate<'_, Probe> {
    type Key = storage::Key<log::NodeTag>;
    fn key(&self) -> Self::Key {
        self.selected.key()
    }
}

impl Candidate<'_, Probe> {
    fn cancel(self) {
        let live = Access::into_live(self);
        let live = unsafe { live.map(|(owner, key)| ((owner.journal, owner.selected), key)) };
        Record::project(live).0.cancel();
    }
}

const _: () = {
    assert!(mem::size_of::<Retry>() == mem::size_of::<u64>());
    assert!(mem::size_of::<Probe>() == 2 * mem::size_of::<u64>());
    assert!(mem::size_of::<Option<Retry>>() == mem::size_of::<Retry>());
    assert!(mem::size_of::<Option<Probe>>() == mem::size_of::<Probe>());
    assert!(!mem::needs_drop::<Retry>());
    assert!(!mem::needs_drop::<Probe>());
    assert!(mem::size_of::<Selection<'static>>() == mem::size_of::<usize>());
    assert!(mem::size_of::<Candidate<'static, Retry>>() == 16);
    assert!(mem::size_of::<Candidate<'static, Probe>>() == 24);
};
