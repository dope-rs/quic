use crate::conn::delivery;
use crate::conn::send;
use crate::conn::stream_journal;
use crate::conn::stream_journal::journal;

use crate::conn::stream_journal::links::groups::GroupOps as _;
use crate::conn::stream_journal::links::nodes::NodeOps as _;

pub(in crate::conn::stream_journal) trait StorageOps {
    fn ensure_group(
        &mut self,
        send_handle: send::Handle,
        owner: &mut Option<stream_journal::GroupId>,
    ) -> Option<stream_journal::GroupId>;
    fn take_node(&mut self) -> Option<u32>;
    fn reclaim_one(&mut self) -> bool;
    fn validate_node(&self, handle: delivery::Handle<delivery::Stream>) -> Option<u32>;
    fn handle_at(&self, index: u32) -> Option<delivery::Handle<delivery::Stream>>;
    fn group(&self, id: stream_journal::GroupId) -> Option<&stream_journal::Group>;
    fn discard_node(&mut self, index: u32, active: bool);
    fn release_node(&mut self, index: u32);
    fn release_group(&mut self, index: u32);
}

impl StorageOps for journal::Journal {
    fn ensure_group(
        &mut self,
        send_handle: send::Handle,
        owner: &mut Option<stream_journal::GroupId>,
    ) -> Option<stream_journal::GroupId> {
        if let Some(id) = *owner
            && self
                .group(id)
                .is_some_and(|group| group.active && group.owner == send_handle)
        {
            return Some(id);
        }
        *owner = None;
        let (index, generation) = match self.storage.groups.take() {
            Some(slot) => slot,
            None if self.reclaim_one() => self.storage.groups.take()?,
            None => return None,
        };
        let id = stream_journal::GroupId::new(index, generation);
        let slot = &mut self.storage.groups[index as usize];
        slot.value = Some(stream_journal::Group {
            owner: send_handle,
            active: true,
            len: 0,
            nodes: crate::conn::stream_journal::GroupNodes {
                all: crate::conn::stream_journal::Chain::EMPTY,
                retry: crate::conn::stream_journal::Chain::EMPTY,
                inflight: crate::conn::stream_journal::Chain::EMPTY,
            },
            retry: crate::conn::stream_journal::Membership::DETACHED,
            reclaim: crate::conn::stream_journal::Membership::DETACHED,
            probe: crate::conn::stream_journal::Membership::DETACHED,
        });
        *owner = Some(id);
        Some(id)
    }

    fn take_node(&mut self) -> Option<u32> {
        match self.storage.nodes.take() {
            Some((index, _)) => Some(index),
            None if self.reclaim_one() => self.storage.nodes.take().map(|(index, _)| index),
            None => None,
        }
    }

    fn reclaim_one(&mut self) -> bool {
        let group_index = self.queues.reclaim.head;
        if group_index == crate::conn::stream_journal::NONE {
            return false;
        }
        let node_index = self.storage.groups[group_index as usize]
            .value
            .as_ref()
            .expect("reclaim queue contains a group")
            .nodes
            .all
            .head;
        debug_assert_ne!(node_index, crate::conn::stream_journal::NONE);
        self.discard_node(node_index, false);
        true
    }

    fn validate_node(&self, handle: delivery::Handle<delivery::Stream>) -> Option<u32> {
        let index = u32::try_from(handle.index()).ok()?;
        let slot = self.storage.nodes.get(index as usize)?;
        (slot.generation == handle.generation()
            && slot.value.is_some_and(|node| !node.acknowledged()))
        .then_some(index)
    }

    fn handle_at(&self, index: u32) -> Option<delivery::Handle<delivery::Stream>> {
        delivery::Handle::new(
            index as usize,
            self.storage.nodes.get(index as usize)?.generation,
        )
    }

    fn group(&self, id: stream_journal::GroupId) -> Option<&stream_journal::Group> {
        let slot = self.storage.groups.get(id.index() as usize)?;
        (slot.generation == id.generation())
            .then_some(slot.value.as_ref())
            .flatten()
    }

    fn discard_node(&mut self, index: u32, active: bool) {
        let node = self.storage.nodes[index as usize]
            .value
            .expect("discarding live node");
        if node.retry.linked {
            self.unlink_retry(node.group, index);
        }
        if node.inflight.linked {
            self.unlink_inflight(node.group, index);
        }
        self.unlink_all(node.group, index);
        self.storage.nodes[index as usize].value = None;
        if active {
            self.capacity.active -= 1;
        }
        self.release_node(index);
        if self.group(node.group).is_some_and(|group| group.len == 0) {
            self.release_group(node.group.index());
        }
    }

    fn release_node(&mut self, index: u32) {
        self.storage.nodes.release(index);
    }

    fn release_group(&mut self, index: u32) {
        let Some(group) = self.storage.groups[index as usize].value.as_ref() else {
            return;
        };
        debug_assert_eq!(group.len, 0);
        if group.retry.linked {
            self.unlink_retry_group(index);
        }
        if self.storage.groups[index as usize]
            .value
            .as_ref()
            .expect("group still present")
            .probe
            .linked
        {
            self.unlink_probe_group(index);
        }
        if self.storage.groups[index as usize]
            .value
            .as_ref()
            .expect("group still present")
            .reclaim
            .linked
        {
            self.unlink_reclaim_group(index);
        }
        let slot = &mut self.storage.groups[index as usize];
        slot.value = None;
        self.storage.groups.release(index);
    }
}
