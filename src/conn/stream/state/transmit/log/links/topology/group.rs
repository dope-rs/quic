use crate::conn::{
    machine::storage::{self, demand},
    stream::state::transmit::log::{
        self, journal,
        links::{storage::Walk, topology::Member},
        planes,
    },
};
use o3::depot;
use o3::depot::queue::indexed::keyed::{self, Fifo};

pub(in crate::conn::stream::state::transmit::log) struct Active(pub(super) ());

pub(in crate::conn::stream::state::transmit::log) struct Group<'a, 'nodes, G = ()> {
    pub(super) entry: demand::Occupied<'a, log::Group, log::GroupTag, { u32::MAX }, G>,
    pub(super) nodes: demand::Entries<'nodes, log::Node, log::NodeTag>,
    pub(super) queues: &'a mut journal::Queues,
    pub(super) ledger: &'a mut journal::Ledger,
    pub(super) work: &'a mut log::RetryLedger,
    pub(super) active: Active,
}

impl<'a> Group<'a, 'a> {
    pub(in crate::conn::stream::state::transmit::log) fn new(
        journal: &'a mut journal::Journal,
        group: log::GroupId,
    ) -> Option<Self> {
        let demand::Entry::Occupied(entry) = journal.storage.groups.entry(group.key().handle())
        else {
            return None;
        };
        if !entry.get().active {
            return None;
        }
        Some(Self {
            entry,
            nodes: journal.storage.nodes.entries(),
            queues: &mut journal.queues,
            ledger: &mut journal.ledger,
            work: &mut journal.retry_work,
            active: Active(()),
        })
    }
}

impl Group<'_, '_> {
    /// Consumes the active group's partition of the same retained journal,
    /// removing its complete resident and retry charges exactly once.
    pub(in crate::conn::stream::state::transmit::log) fn cancel(mut self) {
        let Active(()) = self.active;
        let len = self.entry.get().len;
        let active = self.ledger.active - len;
        let retry = self.entry.get().retry_work;
        self.work.frames -= retry.frames;
        self.work.wire_bytes -= retry.wire_bytes;
        if self.work.frames == 0 {
            self.work.wire_ceiling = 0;
        }
        Self::unlink::<planes::Retry>(&mut self.entry, &self.queues.retry);
        Self::probe(&mut self.entry, self.queues, self.nodes);
        self.ledger.active = active;
        if len == 0 {
            self.entry.remove();
        } else {
            let group = self.entry.get_mut();
            group.active = false;
            group.retry_work = log::RetryLedger::default();
            // SAFETY: only cancellation inserts an active group's vacant reclaim link.
            unsafe {
                keyed::Slot::from_source(depot::raw::Proof::new(Member {
                    entry: &mut self.entry,
                    queue: &self.queues.reclaim,
                }))
            }
            .push::<false>();
        }
    }
}

impl<G> Group<'_, '_, G> {
    pub(super) fn unlink<P: planes::Plane<Value = log::Group, Tag = log::GroupTag>>(
        entry: &mut demand::Occupied<'_, log::Group, log::GroupTag, { u32::MAX }, G>,
        queue: &keyed::Fifo<storage::Key<log::GroupTag>, P>,
    ) {
        if let Ok(member) = keyed::Slot::try_new(Member { entry, queue }) {
            member.remove();
        }
    }

    pub(super) fn probe(
        entry: &mut demand::Occupied<'_, log::Group, log::GroupTag, { u32::MAX }, G>,
        queues: &mut journal::Queues,
        nodes: demand::Entries<'_, log::Node, log::NodeTag>,
    ) {
        let key = storage::Key::new(entry.key());
        let journal::ProbeQueue { chain, cursor } = &mut queues.probe;
        if let Ok(member) = keyed::Slot::try_new(Member {
            entry,
            queue: chain,
        }) {
            if cursor.is_some_and(|position| position.group == key) {
                Self::advance(&member, nodes, cursor);
            }
            member.remove();
        }
    }
    pub(super) fn advance(
        member: &keyed::Slot<Member<'_, '_, planes::Probe, G>, planes::Probe>,
        nodes: demand::Entries<'_, log::Node, log::NodeTag>,
        cursor: &mut Option<log::Position>,
    ) {
        match member.successor() {
            Some(next) => {
                let live = unsafe {
                    next.as_ref()
                        .map(|(owner, index)| (owner.entry.as_table().entries(), index))
                };
                let (key, group) = demand::Entries::project(live);
                // SAFETY: only the current group can be empty before unlink;
                // this retained successor keeps its nonempty inflight FIFO.
                let live = Fifo::front(unsafe {
                    depot::raw::Proof::new(Walk {
                        entries: nodes,
                        queue: &group.nodes.inflight,
                    })
                });
                *cursor = Some(log::Position {
                    group: storage::Key::new(key),
                    node: Walk::get(unsafe { live.as_ref() }).0,
                });
            }
            None => *cursor = None,
        }
    }
}

const _: () = assert!(std::mem::size_of::<Group<'static, 'static>>() == 48);
