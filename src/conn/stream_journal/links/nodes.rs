use crate::conn::stream_journal;
use crate::conn::stream_journal::journal;

use crate::conn::stream_journal::links::groups::GroupOps as _;

pub(in crate::conn::stream_journal) trait NodeOps {
    fn link_all(&mut self, id: stream_journal::GroupId, index: u32);
    fn unlink_all(&mut self, id: stream_journal::GroupId, index: u32);
    fn link_retry(&mut self, id: stream_journal::GroupId, index: u32);
    fn unlink_retry(&mut self, id: stream_journal::GroupId, index: u32);
    fn link_inflight(&mut self, id: stream_journal::GroupId, index: u32);
    fn unlink_inflight(&mut self, id: stream_journal::GroupId, index: u32);
}

impl NodeOps for journal::Journal {
    fn link_all(&mut self, id: stream_journal::GroupId, index: u32) {
        let group_index = id.index();
        let tail = self.storage.groups[group_index as usize]
            .value
            .as_ref()
            .expect("validated group")
            .nodes
            .all
            .tail;
        self.storage.nodes[index as usize]
            .value
            .as_mut()
            .expect("allocated node")
            .all
            .previous = tail;
        if tail == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .all
                .head = index;
        } else {
            self.storage.nodes[tail as usize]
                .value
                .as_mut()
                .expect("group tail")
                .all
                .next = index;
        }
        let group = self.storage.groups[group_index as usize]
            .value
            .as_mut()
            .expect("validated group");
        group.nodes.all.tail = index;
        group.len += 1;
    }

    fn unlink_all(&mut self, id: stream_journal::GroupId, index: u32) {
        let node = self.storage.nodes[index as usize]
            .value
            .expect("unlinking live node");
        let group_index = id.index();
        if node.all.previous == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .all
                .head = node.all.next;
        } else {
            self.storage.nodes[node.all.previous as usize]
                .value
                .as_mut()
                .expect("previous group node")
                .all
                .next = node.all.next;
        }
        if node.all.next == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .all
                .tail = node.all.previous;
        } else {
            self.storage.nodes[node.all.next as usize]
                .value
                .as_mut()
                .expect("next group node")
                .all
                .previous = node.all.previous;
        }
        self.storage.groups[group_index as usize]
            .value
            .as_mut()
            .expect("validated group")
            .len -= 1;
    }

    fn link_retry(&mut self, id: stream_journal::GroupId, index: u32) {
        if self.storage.nodes[index as usize]
            .value
            .expect("validated node")
            .retry
            .linked
        {
            return;
        }
        let group_index = id.index();
        let tail = self.storage.groups[group_index as usize]
            .value
            .as_ref()
            .expect("validated group")
            .nodes
            .retry
            .tail;
        {
            let node = self.storage.nodes[index as usize]
                .value
                .as_mut()
                .expect("validated node");
            node.retry.links.previous = tail;
            node.retry.links.next = stream_journal::NONE;
            node.retry.linked = true;
        }
        if tail == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .retry
                .head = index;
        } else {
            self.storage.nodes[tail as usize]
                .value
                .as_mut()
                .expect("retry tail")
                .retry
                .links
                .next = index;
        }
        let was_empty = tail == stream_journal::NONE;
        self.storage.groups[group_index as usize]
            .value
            .as_mut()
            .expect("validated group")
            .nodes
            .retry
            .tail = index;
        if was_empty {
            self.link_retry_group(group_index);
        }
    }

    fn unlink_retry(&mut self, id: stream_journal::GroupId, index: u32) {
        let node = self.storage.nodes[index as usize]
            .value
            .expect("unlinking retry node");
        if !node.retry.linked {
            return;
        }
        let group_index = id.index();
        if node.retry.links.previous == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .retry
                .head = node.retry.links.next;
        } else {
            self.storage.nodes[node.retry.links.previous as usize]
                .value
                .as_mut()
                .expect("previous retry node")
                .retry
                .links
                .next = node.retry.links.next;
        }
        if node.retry.links.next == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .retry
                .tail = node.retry.links.previous;
        } else {
            self.storage.nodes[node.retry.links.next as usize]
                .value
                .as_mut()
                .expect("next retry node")
                .retry
                .links
                .previous = node.retry.links.previous;
        }
        let node = self.storage.nodes[index as usize]
            .value
            .as_mut()
            .expect("validated node");
        node.retry.links.previous = stream_journal::NONE;
        node.retry.links.next = stream_journal::NONE;
        node.retry.linked = false;
        if self.storage.groups[group_index as usize]
            .value
            .as_ref()
            .expect("validated group")
            .nodes
            .retry
            .head
            == stream_journal::NONE
        {
            self.unlink_retry_group(group_index);
        }
    }

    fn link_inflight(&mut self, id: stream_journal::GroupId, index: u32) {
        if self.storage.nodes[index as usize]
            .value
            .expect("validated node")
            .inflight
            .linked
        {
            return;
        }
        let group_index = id.index();
        let tail = self.storage.groups[group_index as usize]
            .value
            .as_ref()
            .expect("validated group")
            .nodes
            .inflight
            .tail;
        {
            let node = self.storage.nodes[index as usize]
                .value
                .as_mut()
                .expect("validated node");
            node.inflight.links.previous = tail;
            node.inflight.links.next = stream_journal::NONE;
            node.inflight.linked = true;
        }
        if tail == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .inflight
                .head = index;
        } else {
            self.storage.nodes[tail as usize]
                .value
                .as_mut()
                .expect("in-flight tail")
                .inflight
                .links
                .next = index;
        }
        let was_empty = tail == stream_journal::NONE;
        self.storage.groups[group_index as usize]
            .value
            .as_mut()
            .expect("validated group")
            .nodes
            .inflight
            .tail = index;
        if was_empty {
            self.link_probe_group(group_index);
        }
    }

    fn unlink_inflight(&mut self, id: stream_journal::GroupId, index: u32) {
        let node = self.storage.nodes[index as usize]
            .value
            .expect("unlinking in-flight node");
        if !node.inflight.linked {
            return;
        }
        let group_index = id.index();
        if self.queues.probe.group_cursor == group_index && self.queues.probe.node_cursor == index {
            self.queues.probe.node_cursor = node.inflight.links.next;
        }
        if node.inflight.links.previous == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .inflight
                .head = node.inflight.links.next;
        } else {
            self.storage.nodes[node.inflight.links.previous as usize]
                .value
                .as_mut()
                .expect("previous in-flight node")
                .inflight
                .links
                .next = node.inflight.links.next;
        }
        if node.inflight.links.next == stream_journal::NONE {
            self.storage.groups[group_index as usize]
                .value
                .as_mut()
                .expect("validated group")
                .nodes
                .inflight
                .tail = node.inflight.links.previous;
        } else {
            self.storage.nodes[node.inflight.links.next as usize]
                .value
                .as_mut()
                .expect("next in-flight node")
                .inflight
                .links
                .previous = node.inflight.links.previous;
        }
        let node = self.storage.nodes[index as usize]
            .value
            .as_mut()
            .expect("validated node");
        node.inflight.links.previous = stream_journal::NONE;
        node.inflight.links.next = stream_journal::NONE;
        node.inflight.linked = false;
        if self.storage.groups[group_index as usize]
            .value
            .as_ref()
            .expect("validated group")
            .nodes
            .inflight
            .head
            == stream_journal::NONE
        {
            self.unlink_probe_group(group_index);
        }
    }
}
