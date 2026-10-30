use crate::conn::machine::storage::demand;
use o3::depot;
use o3::depot::index::Initialized;
use o3::depot::queue::{indexed::keyed, links};

use crate::conn::stream::state::transmit::log::links::storage::Walk;
use crate::conn::stream::state::transmit::log::{self, journal, planes};

pub(in crate::conn::stream::state::transmit::log) struct Scan<'a, P: planes::Groups> {
    group: depot::raw::Proof<(Walk<'a, P>, links::Index), Initialized<P>>,
    node: depot::raw::Proof<
        (Walk<'a, planes::Delivery>, links::Index),
        Initialized<planes::Delivery>,
    >,
}

impl<'a, P: planes::Groups> Scan<'a, P> {
    pub(in crate::conn::stream::state::transmit::log) fn first(
        journal: &'a journal::Journal,
    ) -> Option<Self> {
        let group = keyed::Fifo::first(Walk {
            entries: journal.storage.groups.entries(),
            queue: P::fifo(&journal.queues),
        })?;
        Some(Self::head(group, journal.storage.nodes.entries()))
    }

    pub(in crate::conn::stream::state::transmit::log) fn bind(
        journal: &'a journal::Journal,
        position: log::Position,
    ) -> Option<Self> {
        let group = Walk {
            entries: journal.storage.groups.entries(),
            queue: P::fifo(&journal.queues),
        }
        .bind(position.group)?;
        let state = Walk::get(unsafe { group.as_ref() }).1;
        let node = Walk {
            entries: journal.storage.nodes.entries(),
            queue: P::nodes(state),
        }
        .bind(position.node)?;
        if Walk::get(unsafe { node.as_ref() }).1.group != log::GroupId::new(position.group) {
            return None;
        }
        Some(Self { group, node })
    }

    fn head(
        group: depot::raw::Proof<(Walk<'a, P>, links::Index), Initialized<P>>,
        entries: demand::Entries<'a, log::Node, log::NodeTag>,
    ) -> Self {
        let state = Walk::get(unsafe { group.as_ref() }).1;
        // SAFETY: Retry/Probe membership retains this group's nonempty child FIFO.
        // Every caller supplies the node table from that same retained journal;
        // its shared loan excludes all publication and removal transitions.
        let node = keyed::Fifo::front(unsafe {
            depot::raw::Proof::new(Walk {
                entries,
                queue: P::nodes(state),
            })
        });
        Self { group, node }
    }

    pub(in crate::conn::stream::state::transmit::log) fn get(
        &self,
    ) -> (log::Position, &'a log::Group, &'a log::Node) {
        let (group, parent) = Walk::get(unsafe { self.group.as_ref() });
        let (node, value) = Walk::get(unsafe { self.node.as_ref() });
        (log::Position { group, node }, parent, value)
    }

    pub(in crate::conn::stream::state::transmit::log) fn next(self) -> Option<Self> {
        let entries = self.node.source().entries;
        match keyed::Iter::successor(self.node) {
            Some(node) => Some(Self {
                group: self.group,
                node,
            }),
            None => Some(Self::head(keyed::Iter::successor(self.group)?, entries)),
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<Scan<'static, planes::Retry>>() == 48);
    assert!(std::mem::size_of::<Option<Scan<'static, planes::Retry>>>() == 48);
    assert!(std::mem::size_of::<Scan<'static, planes::Probe>>() == 48);
};
