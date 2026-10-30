use crate::runtime::routing::registry;
use o3::buffer;
use std::{num::NonZero, time};

use o3::depot::{
    capacity,
    heap::indexed,
    queue::{
        indexed::{
            lanes::runtime,
            planes::{self, bound, groups, resident},
        },
        links,
    },
};
use o3::mem::slot;

use crate::runtime::mux;
use crate::runtime::mux::manage::config::ResizeError;
use crate::runtime::mux::router;
use crate::runtime::mux::router::drive::Step;
use crate::{conn, stream};
use conn::{id, life::status::schedule, wire::path::reset::Token};
use router::reset;
use router::routing::issuer;

use crate::runtime::routing::registry::Seed;

pub(super) mod entry;
pub(super) mod routes;
pub(super) mod scope;

use entry::{Entries, Entry};

type Root<C, const DOMAIN: u8, B, D, T> = planes::Set<
    slot::Storage<registry::Slot<C, DOMAIN, B, D, T>, registry::Epoch>,
    { mux::QUEUE_PLANES },
    groups::Index<time::Instant, capacity::Limit<{ mux::MAX_CONNECTIONS }>, Token, 2, 4>,
>;

type Bound<'a, 'id, C, const DOMAIN: u8, B, D, T> = bound::Scope<
    'a,
    'id,
    slot::Storage<registry::Slot<C, DOMAIN, B, D, T>, registry::Epoch>,
    { mux::QUEUE_PLANES },
    bound::Active<'a, time::Instant, capacity::Limit<{ mux::MAX_CONNECTIONS }>>,
>;

type Live<'a, 'id, C, const DOMAIN: u8, B, D, T> = resident::Scope<
    'a,
    'id,
    registry::Slot<C, DOMAIN, B, D, T>,
    registry::Epoch,
    { mux::QUEUE_PLANES },
    bound::Active<'a, time::Instant, capacity::Limit<{ mux::MAX_CONNECTIONS }>>,
    { mux::FREE_QUEUE },
>;

type Tokens<'a, 'id> =
    groups::Side<'a, 'id, Token, capacity::Limit<{ mux::MAX_CONNECTIONS }>, 2, 4>;

type Group<'a> = runtime::Group<
    'a,
    Token,
    groups::Rows<capacity::Limit<{ mux::MAX_CONNECTIONS }>, 2>,
    groups::Buckets<capacity::Limit<{ mux::MAX_CONNECTIONS }>, 4>,
    links::List,
    2,
>;

type Record<'a, C, const DOMAIN: u8, B, D, T> = planes::Entry<
    'a,
    slot::Storage<registry::Slot<C, DOMAIN, B, D, T>, registry::Epoch>,
    { mux::QUEUE_PLANES },
>;

/// Owns every initialized slot, current routing extent and lifecycle transition.
pub(in crate::runtime) struct Set<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
{
    entries: Root<C, DOMAIN, B, D, T>,
    cids: registry::Table,
    reset: reset::Reset,
    active: u32,
}

impl<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T> Set<C, DOMAIN, B, D, T> {
    pub(in crate::runtime) fn try_new(
        max: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
        issuer: &impl issuer::Source,
    ) -> Result<Self, router::Error> {
        let entries =
            planes::Set::<_, _, indexed::Min<_, _>>::try_seed_in::<{ mux::FREE_QUEUE }>(max, Seed)
                .map_err(router::Error::from)?;
        let cids = registry::Table::try_new(max, issuer.hash_seed::<{ issuer::CID_HASH_LANE }>())
            .map_err(|error| router::Error::Cids {
            capacity: max,
            error,
        })?;
        let hash = issuer.hash_seed::<{ issuer::RESET_HASH_LANE }>();
        let entries = Root::<C, DOMAIN, B, D, T>::try_from(entries).map_err(|error| {
            router::Error::Reset {
                capacity: max,
                error,
            }
        })?;
        Ok(Self {
            entries,
            cids,
            reset: reset::Reset::new(hash),
            active: 0,
        })
    }

    pub(in crate::runtime) fn try_resize(&mut self, max: usize) -> Result<(), ResizeError> {
        if let Some(actual) = NonZero::new(self.active as usize) {
            return Err(ResizeError::Active { actual });
        }
        let max = match capacity::Limit::<{ mux::MAX_CONNECTIONS }>::new(max) {
            Some(max) => max,
            None if max == 0 => return Err(ResizeError::Zero),
            None => {
                return Err(ResizeError::Limit {
                    requested: max,
                    maximum: mux::MAX_CONNECTIONS,
                });
            }
        };
        let reset = groups::Index::<
            time::Instant,
            capacity::Limit<{ mux::MAX_CONNECTIONS }>,
            Token,
            2,
            4,
        >::reserve(max)
        .map_err(|error| router::Error::Reset {
            capacity: max,
            error,
        })
        .map_err(ResizeError::Storage)?;
        let cids = self
            .cids
            .try_reserve(max)
            .map_err(|error| router::Error::Cids {
                capacity: max,
                error,
            })
            .map_err(ResizeError::Storage)?;
        let reset = self
            .entries
            .try_replace::<{ mux::FREE_QUEUE }>(reset, Seed)
            .map_err(router::Error::from)
            .map_err(ResizeError::Storage)?;
        cids();
        reset();
        Ok(())
    }

    pub(in crate::runtime) fn len(&self) -> usize {
        self.active as usize
    }

    pub(in crate::runtime) fn capacity(&self) -> usize {
        self.entries.len()
    }

    pub(in crate::runtime) fn is_empty_in<const PLANE: usize>(&self) -> bool {
        const { assert!(PLANE != mux::FREE_QUEUE) };
        self.entries.len_in::<PLANE>() == 0
    }

    pub(in crate::runtime) fn deadline(&self) -> Option<time::Instant> {
        self.entries.heap().peek().map(|(_, at)| *at)
    }

    pub(in crate::runtime) fn get<I: Copy>(
        &self,
        domain: id::Domain<I, DOMAIN>,
        handle: id::Handle<I, DOMAIN>,
    ) -> Option<&registry::Slot<C, DOMAIN, B, D, T>> {
        if !handle.belongs_to(domain) {
            return None;
        }
        let entry = self.entries.get(handle.index() as usize)?;
        if !entry.metadata().matches(handle.generation()) {
            return None;
        }
        entry.get()
    }

    pub(in crate::runtime) fn sole<I: Copy>(
        &self,
        domain: id::Domain<I, DOMAIN>,
    ) -> Option<id::Handle<I, DOMAIN>> {
        if self.len() != 1 {
            return None;
        }
        (0..self.entries.len()).find_map(|index| {
            let (index, entry) = self.entries.resolve(index)?;
            entry.get()?;
            Some(domain.handle(index, entry.metadata().get()))
        })
    }

    pub(in crate::runtime) fn refresh(
        timer: indexed::Entry<'_, time::Instant, capacity::Limit<{ mux::MAX_CONNECTIONS }>>,
        mut entry: Entry<'_, C, DOMAIN, B, D, T>,
        now: time::Instant,
        update: conn::DeadlineMode,
        retry: Option<time::Instant>,
    ) {
        entry.unlink::<{ mux::REAP_QUEUE }>();
        let slot = entry.get();
        if slot.conn.view().lifecycle().is_closed() {
            entry.link_back::<{ mux::REAP_QUEUE }>();
            if let indexed::Entry::Occupied(timer) = timer {
                timer.retire();
            }
            return;
        }
        let flush = entry.is_linked::<{ mux::FLUSH_QUEUE }>();
        let due = schedule::deadline_with_retry(slot.conn.machine(), now, !flush, retry);
        match (timer, due, update) {
            (indexed::Entry::Vacant(timer), Some(due), _) => {
                timer.set(due);
            }
            (indexed::Entry::Occupied(timer), Some(due), conn::DeadlineMode::Earlier)
                if due < *timer.priority() =>
            {
                timer.set(due);
            }
            (indexed::Entry::Occupied(timer), Some(due), conn::DeadlineMode::Exact)
                if due != *timer.priority() =>
            {
                timer.set(due);
            }
            (indexed::Entry::Occupied(timer), None, conn::DeadlineMode::Exact) => {
                timer.retire();
            }
            _ => {}
        }
    }

    pub(in crate::runtime) fn promote(&mut self, now: time::Instant) -> Step {
        let Some((timer, mut entry)) = self.entries.first() else {
            return Step::Idle;
        };
        if *timer.priority() > now {
            return Step::Idle;
        }
        timer.retire();
        if entry.get().is_some() {
            entry.plane::<{ mux::REAP_QUEUE }>().link_back();
        }
        Step::Driven
    }
}
