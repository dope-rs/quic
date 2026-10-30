use crate::conn::machine::storage::demand;
use o3::depot;
use o3::depot::index::Access;
use o3::depot::index::Initialized;
use o3::depot::queue::links;

use crate::conn::output::delivery;
use crate::conn::stream::state::transmit::log::{self};

pub(in crate::conn::stream::state::transmit::log) struct Tables {
    pub(in crate::conn::stream::state::transmit::log) nodes:
        demand::Table<log::Node, log::NodeTag, { u32::MAX }>,
    pub(in crate::conn::stream::state::transmit::log) groups:
        demand::Table<log::Group, log::GroupTag, { u32::MAX }>,
}

struct Parent<'a, P> {
    node: demand::Occupied<'a, log::Node, log::NodeTag, { u32::MAX }, P>,
    groups: &'a mut demand::Table<log::Group, log::GroupTag, { u32::MAX }>,
}

impl Tables {
    pub(super) fn project<'a, C, P>(
        live: depot::raw::Proof<((&'a mut Self, C), links::Index), Initialized<P>>,
    ) -> (
        demand::Occupied<'a, log::Group, log::GroupTag, { u32::MAX }>,
        demand::Occupied<'a, log::Node, log::NodeTag, { u32::MAX }, P>,
        C,
    ) {
        let live = unsafe {
            live.map(|((tables, context), index)| {
                ((&mut tables.nodes, (&mut tables.groups, context)), index)
            })
        };
        let (node, (groups, context)) = demand::Occupied::project(live);
        let live = Access::into_live(Parent { node, groups });
        let live = unsafe { live.map(|(parent, index)| ((parent.groups, parent.node), index)) };
        let (group, node) = demand::Occupied::project(live);
        (group, node, context)
    }

    pub(super) fn bind(
        &mut self,
        handle: delivery::Handle<delivery::Stream>,
    ) -> Option<(
        demand::Occupied<'_, log::Group, log::GroupTag, { u32::MAX }>,
        demand::Occupied<'_, log::Node, log::NodeTag, { u32::MAX }>,
    )> {
        let node = self.nodes.entry_at(handle.index_u32())?;
        if node.key().generation().get() != handle.generation() {
            return None;
        }
        let live = Access::into_live(Parent {
            node,
            groups: &mut self.groups,
        });
        let live = unsafe { live.map(|(parent, index)| ((parent.groups, parent.node), index)) };
        Some(demand::Occupied::project(live))
    }
}

// SAFETY: Tables removes a group only after its last node. The original node
// guard and the disjoint group-table loan retain that parent until projection.
unsafe impl<P> depot::raw::Source for Parent<'_, P> {
    type Key = links::Index;

    fn key(&self) -> Self::Key {
        unsafe { depot::raw::Word::from_offset(self.node.get().group.key().index() as usize) }
    }
}
