use crate::conn::delivery;
use crate::conn::send;
use crate::conn::stream_journal;
use crate::conn::stream_journal::links::groups::GroupOps as _;
use crate::conn::stream_journal::links::nodes::NodeOps as _;
use crate::conn::stream_journal::links::storage::StorageOps as _;

pub(super) struct Storage {
    pub(super) nodes: stream_journal::Arena<stream_journal::Node>,
    pub(super) groups: stream_journal::Arena<stream_journal::Group>,
}

pub(super) struct ProbeQueue {
    pub(super) chain: stream_journal::Chain,
    pub(super) group_cursor: u32,
    pub(super) node_cursor: u32,
}

pub(super) struct Queues {
    pub(super) retry: stream_journal::Chain,
    pub(super) reclaim: stream_journal::Chain,
    pub(super) probe: ProbeQueue,
}

pub(super) struct Capacity {
    pub(super) active: usize,
    pub(super) limit: usize,
}

/// One fixed-capacity owner for in-flight, retryable, and acknowledged stream
/// records whose byte prefix cannot yet be released.
///
/// A stream cancellation invalidates its group in O(1). Nodes stay reachable
/// through packet journal handles until ACK/loss, but are immediately eligible
/// for generation-safe reuse through the reclaim-group queue.
pub(in crate::conn) struct Journal {
    pub(super) storage: Storage,
    pub(super) queues: Queues,
    pub(super) capacity: Capacity,
}

impl Journal {
    pub(in crate::conn) fn new(capacity: usize) -> Self {
        debug_assert!(capacity < u32::MAX as usize);
        Self {
            storage: Storage {
                nodes: stream_journal::Arena::new(capacity),
                groups: stream_journal::Arena::new(capacity),
            },
            queues: Queues {
                retry: stream_journal::Chain::EMPTY,
                reclaim: stream_journal::Chain::EMPTY,
                probe: ProbeQueue {
                    chain: stream_journal::Chain::EMPTY,
                    group_cursor: stream_journal::NONE,
                    node_cursor: stream_journal::NONE,
                },
            },
            capacity: Capacity {
                active: 0,
                limit: capacity,
            },
        }
    }

    pub(in crate::conn) fn has_room(&self, needed: usize) -> bool {
        self.capacity.active.saturating_add(needed) <= self.capacity.limit
    }

    pub(in crate::conn) fn has_retransmit(&self) -> bool {
        self.queues.retry.head != stream_journal::NONE
    }

    pub(in crate::conn) fn insert(
        &mut self,
        send_handle: send::Handle,
        owner: &mut Option<stream_journal::GroupId>,
        record: delivery::Stream,
    ) -> Option<delivery::Handle<delivery::Stream>> {
        let group = self.ensure_group(send_handle, owner)?;
        let Some(index) = self.take_node() else {
            if self.group(group).is_some_and(|group| group.len == 0) {
                self.release_group(group.index());
                *owner = None;
            }
            return None;
        };
        let handle = self.handle_at(index)?;
        self.storage.nodes[index as usize].value = Some(stream_journal::Node {
            group,
            record,
            carriers: 1,
            all: crate::conn::stream_journal::Links::DETACHED,
            retry: crate::conn::stream_journal::Membership::DETACHED,
            inflight: crate::conn::stream_journal::Membership::DETACHED,
        });
        self.link_all(group, index);
        self.link_inflight(group, index);
        self.capacity.active += 1;
        Some(handle)
    }

    pub(in crate::conn) fn cancel(&mut self, id: stream_journal::GroupId) {
        let Some(group) = self.group(id) else {
            return;
        };
        if !group.active {
            return;
        }
        let index = id.index();
        let len = group.len;
        self.unlink_retry_group(index);
        self.unlink_probe_group(index);
        self.storage.groups[index as usize]
            .value
            .as_mut()
            .expect("validated group")
            .active = false;
        self.capacity.active = self
            .capacity
            .active
            .checked_sub(len)
            .expect("active delivery count contains group");
        if len == 0 {
            self.release_group(index);
        } else {
            self.link_reclaim_group(index);
        }
    }

    pub(in crate::conn) fn acknowledge(
        &mut self,
        handle: delivery::Handle<delivery::Stream>,
    ) -> Option<stream_journal::Acknowledged<'_>> {
        let index = self.validate_node(handle)?;
        let group = self.storage.nodes[index as usize].value?.group;
        if !self.group(group).is_some_and(|group| group.active) {
            self.discard_node(index, false);
            return None;
        }
        if self.storage.nodes[index as usize]
            .value
            .is_some_and(|node| node.retry.linked)
        {
            self.unlink_retry(group, index);
        }
        if self.storage.nodes[index as usize]
            .value
            .is_some_and(|node| node.inflight.linked)
        {
            self.unlink_inflight(group, index);
        }
        self.storage.nodes[index as usize]
            .value
            .as_mut()
            .expect("validated acknowledged node")
            .carriers = 0;

        let head = self.group(group)?.nodes.all.head;
        self.storage.nodes[head as usize]
            .value
            .is_some_and(stream_journal::Node::acknowledged)
            .then_some(stream_journal::Acknowledged {
                journal: self,
                group,
            })
    }

    /// Restores capacity when an internal stream owner disappeared before a
    /// probe or retry record was consumed.
    pub(in crate::conn) fn discard_group(&mut self, handle: delivery::Handle<delivery::Stream>) {
        let Some(index) = self.validate_node(handle) else {
            return;
        };
        let group = self.storage.nodes[index as usize]
            .value
            .expect("validated orphan node")
            .group;
        if self.group(group).is_some_and(|group| group.active) {
            self.cancel(group);
        } else {
            self.discard_node(index, false);
        }
    }

    pub(in crate::conn) fn lose(&mut self, handle: delivery::Handle<delivery::Stream>) {
        let Some(index) = self.validate_node(handle) else {
            return;
        };
        let group = self.storage.nodes[index as usize]
            .value
            .expect("validated node")
            .group;
        if !self.group(group).is_some_and(|group| group.active) {
            self.discard_node(index, false);
            return;
        }
        let node = self.storage.nodes[index as usize]
            .value
            .as_mut()
            .expect("validated node");
        if node.carriers > 1 {
            node.carriers -= 1;
            return;
        }
        node.carriers = 0;
        self.unlink_inflight(group, index);
        self.link_retry(group, index);
    }

    pub(in crate::conn) fn add_carrier(
        &mut self,
        handle: delivery::Handle<delivery::Stream>,
    ) -> bool {
        let Some(index) = self.validate_node(handle) else {
            return false;
        };
        let group = self.storage.nodes[index as usize]
            .value
            .expect("validated node")
            .group;
        if !self.group(group).is_some_and(|group| group.active) {
            self.discard_node(index, false);
            return false;
        }
        let retry = self.storage.nodes[index as usize]
            .value
            .expect("validated node")
            .retry
            .linked;
        if retry {
            self.unlink_retry(group, index);
            self.storage.nodes[index as usize]
                .value
                .as_mut()
                .expect("validated node")
                .carriers = 1;
            self.link_inflight(group, index);
        } else {
            let node = self.storage.nodes[index as usize]
                .value
                .as_mut()
                .expect("validated node");
            let Some(carriers) = node.carriers.checked_add(1) else {
                return false;
            };
            node.carriers = carriers;
        }
        true
    }

    pub(in crate::conn) fn next_retransmit(
        &mut self,
        room: usize,
        work: &mut stream_journal::RetryWork<'_>,
        mut excluded: impl FnMut(delivery::Handle<delivery::Stream>) -> bool,
    ) -> Option<(
        delivery::Handle<delivery::Stream>,
        send::Handle,
        delivery::Stream,
    )> {
        while work.spend() {
            let group_index = self.queues.retry.head;
            if group_index == stream_journal::NONE {
                return None;
            }
            let node_index = self.storage.groups[group_index as usize]
                .value
                .as_ref()
                .expect("retry queue contains a group")
                .nodes
                .retry
                .head;
            let send_handle = self.storage.groups[group_index as usize]
                .value
                .as_ref()
                .expect("retry queue contains a group")
                .owner;
            let handle = self.handle_at(node_index)?;
            let record = self.storage.nodes[node_index as usize]
                .value
                .expect("retry group contains a node")
                .record;
            self.rotate_retry_node(group_index, node_index);
            self.rotate_retry_group(group_index);
            let Ok(len) = usize::try_from(record.len) else {
                continue;
            };
            if excluded(handle) || len > room {
                continue;
            }
            return Some((handle, send_handle, record));
        }
        None
    }

    pub(in crate::conn) fn arm_probes(&mut self) {
        self.queues.probe.group_cursor = self.queues.probe.chain.head;
        self.queues.probe.node_cursor = if self.queues.probe.chain.head == stream_journal::NONE {
            stream_journal::NONE
        } else {
            self.storage.groups[self.queues.probe.chain.head as usize]
                .value
                .as_ref()
                .expect("probe queue contains a group")
                .nodes
                .inflight
                .head
        };
    }

    pub(in crate::conn) fn next_probe(
        &mut self,
        mut excluded: impl FnMut(delivery::Handle<delivery::Stream>) -> bool,
    ) -> Option<(
        delivery::Handle<delivery::Stream>,
        send::Handle,
        delivery::Stream,
    )> {
        while self.queues.probe.group_cursor != stream_journal::NONE {
            let group_index = self.queues.probe.group_cursor;
            let node_index = self.queues.probe.node_cursor;
            let group = self.storage.groups[group_index as usize]
                .value
                .as_ref()
                .expect("probe cursor contains a group");
            if node_index == stream_journal::NONE {
                self.queues.probe.group_cursor = group.probe.links.next;
                self.queues.probe.node_cursor = if group.probe.links.next == stream_journal::NONE {
                    stream_journal::NONE
                } else {
                    self.storage.groups[group.probe.links.next as usize]
                        .value
                        .as_ref()
                        .expect("next probe group")
                        .nodes
                        .inflight
                        .head
                };
                continue;
            }
            let node = self.storage.nodes[node_index as usize]
                .value
                .expect("probe group contains an in-flight node");
            self.queues.probe.node_cursor = node.inflight.links.next;
            let handle = self.handle_at(node_index)?;
            if !excluded(handle) {
                return Some((handle, group.owner, node.record));
            }
        }
        None
    }
}
