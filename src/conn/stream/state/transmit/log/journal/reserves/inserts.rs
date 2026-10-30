use crate::conn::{
    machine::storage::{self, demand},
    output::delivery,
    stream::state::transmit::{
        log::{self, journal, links},
        queue,
    },
};
use journal::reserves::Insert;
use links::topology::{Member, Tables};
use o3::depot;
use o3::depot::queue::{indexed::keyed, links::Index};
use std::mem;

struct Groups<'a> {
    table: &'a mut demand::Table<log::Group, log::GroupTag, { u32::MAX }>,
    send: queue::Handle,
}

// SAFETY: only the admitted scope constructs this consuming group vacancy,
// once per original Fresh entry; the reserve grew both tables for that bound.
unsafe impl<'a> demand::raw::Owner<{ u32::MAX }> for Groups<'a> {
    type Value = log::Group;
    type Tag = log::GroupTag;
    type Plane = ();
    type Output = (
        &'a mut demand::Table<log::Group, log::GroupTag, { u32::MAX }>,
        (),
    );
    type Context<'b>
        = queue::Handle
    where
        Self: 'b;

    fn parts(
        &mut self,
    ) -> (
        &mut demand::Table<Self::Value, Self::Tag, { u32::MAX }>,
        Self::Context<'_>,
    ) {
        (self.table, self.send)
    }

    fn build<'b>(index: Index, send: Self::Context<'b>) -> Self::Value
    where
        Self: 'b,
    {
        log::Group::new(index, send)
    }

    fn finish(self) -> Self::Output {
        (self.table, ())
    }
}

pub(super) struct Fresh<'a> {
    pub(super) journal: &'a mut journal::Journal,
    pub(super) send: queue::Handle,
    pub(super) value: delivery::Stream,
    pub(super) owner: &'a mut Option<log::GroupId>,
}

impl Fresh<'_> {
    pub(super) fn insert(self) -> delivery::Handle<delivery::Stream> {
        use demand::raw::Owner as _;

        let Self {
            journal,
            send,
            value,
            owner,
        } = self;
        let journal::Journal {
            storage: Tables { nodes, groups },
            queues,
            ledger,
            retry_work: work,
        } = journal;
        let group = match *owner {
            Some(id) => groups.entry(id.key().handle()),
            None => demand::Entry::Stale(groups),
        };
        let group = match group {
            demand::Entry::Occupied(group) if group.get().active && group.get().owner == send => {
                group
            }
            group => {
                let table = match group {
                    demand::Entry::Occupied(group) => group.into_table(),
                    demand::Entry::Stale(table) => table,
                };
                let live = Groups { table, send }.insert();
                let group = demand::Occupied::project(live).0;
                *owner = Some(log::GroupId::new(storage::Key::new(group.key())));
                group
            }
        };
        let live = Nodes {
            nodes,
            group,
            queues,
            ledger,
            work,
            value,
        }
        .insert();
        let (mut node, (mut group, queues, ledger, _)) = demand::Occupied::project(live);
        ledger.active += 1;
        let key = node.key();
        let handle = delivery::Handle::from_slot(key.index() as u16, key.generation().get());
        if group.get().nodes.inflight.is_empty() {
            unsafe {
                keyed::Slot::from_source(depot::raw::Proof::new(Member {
                    entry: &mut group,
                    queue: &queues.probe.chain,
                }))
            }
            .push::<false>();
        }
        unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(Member {
                entry: &mut node,
                queue: &group.get().nodes.all,
            }))
        }
        .push::<false>();
        unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(Member {
                entry: &mut node,
                queue: &group.get().nodes.inflight,
            }))
        }
        .push::<false>();
        group.get_mut().len += 1;
        handle
    }
}

struct Nodes<'a> {
    nodes: &'a mut demand::Table<log::Node, log::NodeTag, { u32::MAX }>,
    group: demand::Occupied<'a, log::Group, log::GroupTag, { u32::MAX }>,
    queues: &'a mut journal::Queues,
    ledger: &'a mut journal::Ledger,
    work: &'a mut log::RetryLedger,
    value: delivery::Stream,
}

// SAFETY: Fresh is issued only for the current original entry of one admitted
// scope. The node and ledger budget cannot change outside that scope.
unsafe impl<'a> demand::raw::Owner<{ u32::MAX }> for Nodes<'a> {
    type Value = log::Node;
    type Tag = log::NodeTag;
    type Plane = Insert;
    type Output = log::Insertion<'a, ()>;
    type Context<'b>
        = (log::GroupId, delivery::Stream)
    where
        Self: 'b;

    fn parts(
        &mut self,
    ) -> (
        &mut demand::Table<Self::Value, Self::Tag, { u32::MAX }>,
        Self::Context<'_>,
    ) {
        (
            self.nodes,
            (
                log::GroupId::new(storage::Key::new(self.group.key())),
                self.value,
            ),
        )
    }

    fn build<'b>(index: Index, (id, value): Self::Context<'b>) -> Self::Value
    where
        Self: 'b,
    {
        log::Node::new(index, id, value)
    }

    fn finish(self) -> Self::Output {
        let Self {
            nodes,
            group,
            queues,
            ledger,
            work,
            value: _,
        } = self;
        (nodes, (group, queues, ledger, work))
    }
}

const _: () = assert!(mem::size_of::<Groups<'static>>() == 2 * mem::size_of::<usize>());
