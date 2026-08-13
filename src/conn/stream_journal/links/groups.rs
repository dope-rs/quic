use crate::conn::stream_journal;
use crate::conn::stream_journal::journal;

pub(in crate::conn::stream_journal) trait GroupOps {
    fn link_retry_group(&mut self, index: u32);
    fn link_probe_group(&mut self, index: u32);
    fn unlink_probe_group(&mut self, index: u32);
    fn unlink_retry_group(&mut self, index: u32);
    fn rotate_retry_group(&mut self, index: u32);
    fn rotate_retry_node(&mut self, group_index: u32, index: u32);
    fn link_reclaim_group(&mut self, index: u32);
    fn unlink_reclaim_group(&mut self, index: u32);
}

impl GroupOps for journal::Journal {
    fn link_retry_group(&mut self, index: u32) {
        if self.storage.groups[index as usize]
            .value
            .as_ref()
            .expect("validated group")
            .retry
            .linked
        {
            return;
        }
        let previous = self.queues.retry.tail;
        {
            let group = self.storage.groups[index as usize]
                .value
                .as_mut()
                .expect("validated group");
            group.retry.links.previous = previous;
            group.retry.links.next = stream_journal::NONE;
            group.retry.linked = true;
        }
        if previous == stream_journal::NONE {
            self.queues.retry.head = index;
        } else {
            self.storage.groups[previous as usize]
                .value
                .as_mut()
                .expect("retry group tail")
                .retry
                .links
                .next = index;
        }
        self.queues.retry.tail = index;
    }

    fn link_probe_group(&mut self, index: u32) {
        if self.storage.groups[index as usize]
            .value
            .as_ref()
            .expect("validated group")
            .probe
            .linked
        {
            return;
        }
        let previous = self.queues.probe.chain.tail;
        {
            let group = self.storage.groups[index as usize]
                .value
                .as_mut()
                .expect("validated group");
            group.probe.links.previous = previous;
            group.probe.links.next = stream_journal::NONE;
            group.probe.linked = true;
        }
        if previous == stream_journal::NONE {
            self.queues.probe.chain.head = index;
        } else {
            self.storage.groups[previous as usize]
                .value
                .as_mut()
                .expect("probe group tail")
                .probe
                .links
                .next = index;
        }
        self.queues.probe.chain.tail = index;
    }

    fn unlink_probe_group(&mut self, index: u32) {
        let Some(group) = self.storage.groups[index as usize].value.as_ref() else {
            return;
        };
        if !group.probe.linked {
            return;
        }
        let previous = group.probe.links.previous;
        let next = group.probe.links.next;
        if self.queues.probe.group_cursor == index {
            self.queues.probe.group_cursor = next;
            self.queues.probe.node_cursor = if next == stream_journal::NONE {
                stream_journal::NONE
            } else {
                self.storage.groups[next as usize]
                    .value
                    .as_ref()
                    .expect("next probe group")
                    .nodes
                    .inflight
                    .head
            };
        }
        if previous == stream_journal::NONE {
            self.queues.probe.chain.head = next;
        } else {
            self.storage.groups[previous as usize]
                .value
                .as_mut()
                .expect("previous probe group")
                .probe
                .links
                .next = next;
        }
        if next == stream_journal::NONE {
            self.queues.probe.chain.tail = previous;
        } else {
            self.storage.groups[next as usize]
                .value
                .as_mut()
                .expect("next probe group")
                .probe
                .links
                .previous = previous;
        }
        let group = self.storage.groups[index as usize]
            .value
            .as_mut()
            .expect("validated group");
        group.probe.links.previous = stream_journal::NONE;
        group.probe.links.next = stream_journal::NONE;
        group.probe.linked = false;
    }

    fn unlink_retry_group(&mut self, index: u32) {
        let Some(group) = self.storage.groups[index as usize].value.as_ref() else {
            return;
        };
        if !group.retry.linked {
            return;
        }
        let previous = group.retry.links.previous;
        let next = group.retry.links.next;
        if previous == stream_journal::NONE {
            self.queues.retry.head = next;
        } else {
            self.storage.groups[previous as usize]
                .value
                .as_mut()
                .expect("previous retry group")
                .retry
                .links
                .next = next;
        }
        if next == stream_journal::NONE {
            self.queues.retry.tail = previous;
        } else {
            self.storage.groups[next as usize]
                .value
                .as_mut()
                .expect("next retry group")
                .retry
                .links
                .previous = previous;
        }
        let group = self.storage.groups[index as usize]
            .value
            .as_mut()
            .expect("validated group");
        group.retry.links.previous = stream_journal::NONE;
        group.retry.links.next = stream_journal::NONE;
        group.retry.linked = false;
    }

    fn rotate_retry_group(&mut self, index: u32) {
        if self.queues.retry.head == self.queues.retry.tail || self.queues.retry.head != index {
            return;
        }
        self.unlink_retry_group(index);
        self.link_retry_group(index);
    }

    fn rotate_retry_node(&mut self, group_index: u32, index: u32) {
        let group = self.storage.groups[group_index as usize]
            .value
            .as_ref()
            .expect("validated retry group");
        if group.nodes.retry.head == group.nodes.retry.tail || group.nodes.retry.head != index {
            return;
        }
        let next = self.storage.nodes[index as usize]
            .value
            .expect("validated retry node")
            .retry
            .links
            .next;
        let tail = group.nodes.retry.tail;
        self.storage.groups[group_index as usize]
            .value
            .as_mut()
            .expect("validated retry group")
            .nodes
            .retry
            .head = next;
        self.storage.nodes[next as usize]
            .value
            .as_mut()
            .expect("next retry node")
            .retry
            .links
            .previous = stream_journal::NONE;
        self.storage.nodes[tail as usize]
            .value
            .as_mut()
            .expect("retry tail")
            .retry
            .links
            .next = index;
        let node = self.storage.nodes[index as usize]
            .value
            .as_mut()
            .expect("validated retry node");
        node.retry.links.previous = tail;
        node.retry.links.next = stream_journal::NONE;
        self.storage.groups[group_index as usize]
            .value
            .as_mut()
            .expect("validated retry group")
            .nodes
            .retry
            .tail = index;
    }

    fn link_reclaim_group(&mut self, index: u32) {
        let previous = self.queues.reclaim.tail;
        {
            let group = self.storage.groups[index as usize]
                .value
                .as_mut()
                .expect("validated group");
            if group.reclaim.linked {
                return;
            }
            group.reclaim.links.previous = previous;
            group.reclaim.links.next = stream_journal::NONE;
            group.reclaim.linked = true;
        }
        if previous == stream_journal::NONE {
            self.queues.reclaim.head = index;
        } else {
            self.storage.groups[previous as usize]
                .value
                .as_mut()
                .expect("reclaim group tail")
                .reclaim
                .links
                .next = index;
        }
        self.queues.reclaim.tail = index;
    }

    fn unlink_reclaim_group(&mut self, index: u32) {
        let group = self.storage.groups[index as usize]
            .value
            .as_ref()
            .expect("validated group");
        if !group.reclaim.linked {
            return;
        }
        let previous = group.reclaim.links.previous;
        let next = group.reclaim.links.next;
        if previous == stream_journal::NONE {
            self.queues.reclaim.head = next;
        } else {
            self.storage.groups[previous as usize]
                .value
                .as_mut()
                .expect("previous reclaim group")
                .reclaim
                .links
                .next = next;
        }
        if next == stream_journal::NONE {
            self.queues.reclaim.tail = previous;
        } else {
            self.storage.groups[next as usize]
                .value
                .as_mut()
                .expect("next reclaim group")
                .reclaim
                .links
                .previous = previous;
        }
        let group = self.storage.groups[index as usize]
            .value
            .as_mut()
            .expect("validated group");
        group.reclaim.links.previous = stream_journal::NONE;
        group.reclaim.links.next = stream_journal::NONE;
        group.reclaim.linked = false;
    }
}
