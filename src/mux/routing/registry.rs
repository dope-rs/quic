use std::hash::RandomState;
use std::time::Instant;

use o3::collections::heap::Min;

use crate::conn::{self, Handle};
use crate::mux::{CidLink, Entry, NONE, QueueLinks, reset_index};
use crate::stream::ReceiveBuffer;

pub(in crate::mux) struct Registry<
    'tls,
    C,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: ReceiveBuffer,
> {
    pub(in crate::mux) entries: Vec<Entry<'tls, C, P, DOMAIN, B>>,
    pub(in crate::mux) free_head: u32,
    pub(in crate::mux) indexes: Indexes,
    pub(in crate::mux) deadlines: Min<Instant>,
    pub(in crate::mux) active_conns: usize,
    pub(in crate::mux) max_conns: usize,
    pub(in crate::mux) dirty_connection: Option<Handle>,
}

pub(in crate::mux) struct Indexes {
    pub(in crate::mux) cid_buckets: Box<[Option<CidLink>]>,
    pub(in crate::mux) cid_hasher: RandomState,
    pub(in crate::mux) reset: reset_index::ResetIndex,
    pub(in crate::mux) cid_counter: u64,
}

impl<'tls, C, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    Registry<'tls, C, P, DOMAIN, B>
{
    pub(in crate::mux) fn new(max_connections: usize) -> Self {
        Self {
            entries: Self::entries(max_connections),
            free_head: 0,
            indexes: Indexes {
                cid_buckets: vec![None; Self::bucket_count(max_connections)].into_boxed_slice(),
                cid_hasher: RandomState::new(),
                reset: reset_index::ResetIndex::with_connection_capacity(max_connections),
                cid_counter: 0,
            },
            deadlines: Min::with_capacity(max_connections),
            active_conns: 0,
            max_conns: max_connections,
            dirty_connection: None,
        }
    }

    pub(in crate::mux) fn resize(&mut self, max_connections: usize) {
        if max_connections > self.entries.len() {
            let old_len = self.entries.len();
            let old_free = self.free_head;
            self.deadlines.grow_to(max_connections);
            self.entries.reserve(max_connections - old_len);
            self.entries
                .extend((old_len..max_connections).map(|index| Entry {
                    slot: None,
                    generation: 0,
                    used: false,
                    free_next: if index + 1 == max_connections {
                        old_free
                    } else {
                        index as u32 + 1
                    },
                    notify: QueueLinks::default(),
                    flush: QueueLinks::default(),
                    reap: QueueLinks::default(),
                }));
            self.free_head = old_len as u32;
        }
        self.max_conns = max_connections;
        self.indexes.cid_buckets =
            vec![None; Self::bucket_count(max_connections)].into_boxed_slice();
        self.indexes.reset = reset_index::ResetIndex::with_connection_capacity(max_connections);
    }

    fn bucket_count(max_connections: usize) -> usize {
        max_connections
            .max(1)
            .saturating_mul(2)
            .checked_next_power_of_two()
            .unwrap_or(1usize << (usize::BITS - 1))
    }

    fn entries(capacity: usize) -> Vec<Entry<'tls, C, P, DOMAIN, B>> {
        (0..capacity)
            .map(|index| Entry {
                slot: None,
                generation: 0,
                used: false,
                free_next: if index + 1 == capacity {
                    NONE
                } else {
                    index as u32 + 1
                },
                notify: QueueLinks::default(),
                flush: QueueLinks::default(),
                reap: QueueLinks::default(),
            })
            .collect()
    }
}
