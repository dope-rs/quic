use crate::conn::{
    self,
    machine::storage,
    output::{
        control::{self, encode},
        delivery, journals,
    },
    stream::state::transmit::{self, log, peer, queue},
};
use crate::stream::{outbound, send};
use inserts::Fresh;
use journal::Entry;
use journals::streams;
use log::journal;

mod inserts;
use o3::depot::index::Access;
use o3::depot::index::Initialized;
use o3::depot::{array, capacity::Reason};
use o3::{
    alloc,
    buffer::{self, write},
    depot,
};
use std::mem;

/// Retains one packet owner while traversing its original batch snapshot once.
#[must_use]
pub(in crate::conn) struct Schedule<O: journal::raw::Schedule> {
    owner: O,
    next: usize,
    count: usize,
}

/// Frozen selections and the original owner that produced them.
#[must_use]
pub(in crate::conn) struct Ready<O: journal::raw::Owner> {
    owner: O,
}

pub(in crate::conn) struct Selection<'a, D: buffer::raw::Segment> {
    occupied: queue::Occupied<'a, D>,
    vacancy: array::Vacant<'a, Entry, { conn::PACKET_STREAM_CAPACITY }>,
    peer: &'a mut peer::Peer,
    count: &'a mut usize,
}

#[must_use]
pub(in crate::conn) struct Prepared<'a, D: buffer::raw::Segment> {
    occupied: queue::Occupied<'a, D>,
    selected: outbound::Prepared,
    vacancy: array::Vacant<'a, Entry, { conn::PACKET_STREAM_CAPACITY }>,
    count: &'a mut usize,
}

pub(in crate::conn) struct Written {
    owner: queue::Handle,
    written: outbound::Written,
}

impl<O: journal::raw::Schedule> Schedule<O> {
    pub(in crate::conn) fn new(owner: O) -> Self {
        Self {
            owner,
            next: 0,
            count: 0,
        }
    }

    pub(in crate::conn) fn next<'a, R, E>(
        &'a mut self,
        apply: impl for<'s> FnOnce(Selection<'s, O::Send>, O::Context<'a>) -> Result<R, E>,
    ) -> Result<Option<R>, E> {
        let (state, entries, context) = self.owner.parts();
        while let Some(handle) = state.scratch_pending.get(self.next).copied() {
            let Some(vacancy) = entries.vacancy() else {
                return Ok(None);
            };
            if !state.deliveries.has_room(self.count + 1) {
                return Ok(None);
            }
            self.next += 1;
            let Some(occupied) = state.map.occupied(handle) else {
                continue;
            };
            return apply(
                Selection {
                    occupied,
                    vacancy,
                    peer: &mut state.peer,
                    count: &mut self.count,
                },
                context,
            )
            .map(Some);
        }
        Ok(None)
    }

    pub(in crate::conn) fn finish(self) -> Ready<O::Output> {
        Ready {
            owner: journal::raw::Schedule::finish(self.owner),
        }
    }
}

impl<O: journal::raw::Owner> Ready<O> {
    pub(in crate::conn) fn owner(&self) -> &O {
        &self.owner
    }

    pub(in crate::conn) fn scratch(&mut self) -> &mut conn::Scratch {
        self.owner.scratch()
    }

    pub(in crate::conn) fn cancel(mut self) -> O {
        self.owner.discard();
        self.owner
    }
}

impl<'a, D: buffer::raw::Segment> Selection<'a, D> {
    pub(in crate::conn) fn state(&mut self) -> &queue::Entry {
        self.occupied.state()
    }

    pub(in crate::conn) fn budget(&self, fresh: u64) -> u64 {
        self.peer.budget(fresh)
    }

    pub(in crate::conn) fn try_data<E: From<control::Admission>>(
        &mut self,
        pending: &mut control::Pending,
        emit: impl for<'b> FnOnce(encode::Selected<'b>) -> Result<(), E>,
    ) -> Result<(), E> {
        control::Blocked::new(pending, &mut self.peer.data_credit).try_data(emit)
    }

    pub(in crate::conn) fn try_stream<E: From<control::Admission>>(
        &mut self,
        pending: &mut control::Pending,
        emit: impl for<'b> FnOnce(encode::Selected<'b>) -> Result<(), E>,
    ) -> Result<(), E> {
        control::Blocked::new(pending, &mut self.occupied).try_stream(emit)
    }

    pub(in crate::conn) fn prepare(mut self, limit: usize) -> Option<Prepared<'a, D>> {
        let entry = self.state();
        if !matches!(entry.phase(), queue::Phase::Open | queue::Phase::Marked) {
            return None;
        }
        let selected = entry.view().prepare(limit);
        let range = selected.range();
        if range.len() == 0 && matches!(range.boundary(), send::Boundary::More) {
            return None;
        }
        Some(Prepared {
            occupied: self.occupied,
            selected,
            vacancy: self.vacancy,
            count: self.count,
        })
    }
}

impl<D: buffer::raw::Segment> Prepared<'_, D> {
    pub(in crate::conn) fn range(&self) -> outbound::Range {
        self.selected.range()
    }

    pub(in crate::conn) fn write(
        mut self,
        out: &mut write::Append<'_>,
        limit: usize,
    ) -> Result<bool, alloc::Error> {
        let Some((owner, written)) = self.occupied.write(self.selected, out, limit)? else {
            return Ok(false);
        };
        self.vacancy
            .insert(Entry::Fresh(Written { owner, written }));
        *self.count += 1;
        Ok(true)
    }
}

#[must_use]
pub(in crate::conn) struct Reserve<O: journal::raw::Owner> {
    owner: O,
    pending: usize,
    sent: u64,
}

#[derive(Debug)]
pub(in crate::conn) enum ReserveError {
    Capacity { reason: Reason, records: usize },
    Credit { sent: u64, additional: u64 },
}

/// The completed packet retains the original queue and its admitted aggregate.
#[must_use]
pub(in crate::conn::stream::state::transmit) struct Debit<'a, D: buffer::raw::Segment> {
    map: &'a mut queue::Map<D>,
    next: usize,
}

impl<'a, D: buffer::raw::Segment> Debit<'a, D> {
    pub(in crate::conn::stream::state::transmit) fn into_parts(
        self,
    ) -> (&'a mut queue::Map<D>, usize) {
        (self.map, self.next)
    }
}

#[must_use]
pub(in crate::conn) struct Credit<'a> {
    peer: &'a mut peer::Peer,
    next: u64,
}

impl<'a> Credit<'a> {
    pub(in crate::conn) fn into_parts(self) -> (&'a mut peer::Peer, u64) {
        (self.peer, self.next)
    }
}

pub(in crate::conn) struct Scope<'a, D: buffer::raw::Segment> {
    state: &'a mut transmit::State<D>,
    entries: &'a mut array::Vec<Entry, { conn::PACKET_STREAM_CAPACITY }>,
    pending: usize,
    sent: u64,
}

pub(in crate::conn::stream::state::transmit) enum Insert {}

impl<O: journal::raw::Owner> Reserve<O> {
    /// Each frozen selection owns a distinct prefix of the retained queue.
    pub(in crate::conn) fn try_new(mut ready: Ready<O>) -> Result<Self, (O, ReserveError)> {
        let (state, entries, _) = ready.owner.parts();
        let mut pending = state.map.view().pending();
        let mut sent = state.peer.total_sent();
        let mut count = 0;
        for entry in entries.as_slice() {
            if let Entry::Fresh(fresh) = entry {
                let bytes = fresh.written.len();
                pending -= bytes;
                let extra = bytes as u64;
                let Some(next) = sent.checked_add(extra) else {
                    return Err((
                        ready.cancel(),
                        ReserveError::Credit {
                            sent,
                            additional: extra,
                        },
                    ));
                };
                sent = next;
                count += 1;
            }
        }
        if let Err(reason) = state.deliveries.try_grow(count) {
            return Err((
                ready.cancel(),
                ReserveError::Capacity {
                    reason,
                    records: count,
                },
            ));
        }
        Ok(Self {
            owner: ready.owner,
            pending,
            sent,
        })
    }

    pub(in crate::conn) fn take_crypto(&mut self) -> Option<O::Selection> {
        self.owner.selection().take()
    }

    pub(in crate::conn) fn owner(&self) -> &O {
        &self.owner
    }

    pub(in crate::conn) fn cancel(mut self) -> O {
        self.owner.discard();
        self.owner
    }

    pub(in crate::conn) fn parts(&mut self) -> (Scope<'_, O::Send>, O::Context<'_>) {
        let (state, entries, context) = self.owner.parts();
        (
            Scope {
                state,
                entries,
                pending: self.pending,
                sent: self.sent,
            },
            context,
        )
    }
}

impl<'a, D: buffer::raw::Segment> Scope<'a, D> {
    pub(in crate::conn) fn write(
        self,
        supply: journals::Supply<streams::Tag>,
        mut emit: impl FnMut(journals::Slot<'a, streams::Tag>, delivery::Handle<delivery::Stream>),
    ) {
        for (entry, slot) in supply.consume(self.entries.drain()) {
            let handle = match entry {
                Entry::Retry(selected) => {
                    let live = Access::into_live(Selected {
                        journal: &mut self.state.deliveries,
                        selected,
                    });
                    let live =
                        unsafe { live.map(|(owner, key)| ((owner.journal, owner.selected), key)) };
                    log::Retry::commit(live)
                }
                Entry::Probe(selected) => {
                    let live = Access::into_live(Selected {
                        journal: &mut self.state.deliveries,
                        selected,
                    });
                    let live =
                        unsafe { live.map(|(owner, key)| ((owner.journal, owner.selected), key)) };
                    log::Probe::commit(live)
                }
                Entry::Fresh(fresh) => {
                    let Written { owner, written } = fresh;
                    let range = written.range();
                    let wire_len = written.wire_len();
                    let transmit::State {
                        deliveries: journal,
                        map,
                        ..
                    } = &mut *self.state;
                    // SAFETY: this scope retains the original map and frozen
                    // selection; admission and publication cannot recycle it.
                    let live = unsafe {
                        depot::raw::Proof::<(_, _), Initialized<Insert>>::new((map, owner))
                    };
                    let mut occupied = live.into();
                    let value = delivery::Stream {
                        id: occupied.id(),
                        range,
                        wire_len,
                    };
                    let handle = occupied.publish(written, |send, owner| {
                        Fresh {
                            journal,
                            send,
                            value,
                            owner,
                        }
                        .insert()
                    });
                    occupied.refresh();
                    handle
                }
            };
            emit(slot, handle);
        }
        queue::Map::publish(Debit {
            map: &mut self.state.map,
            next: self.pending,
        });
        peer::Peer::sent(Credit {
            peer: &mut self.state.peer,
            next: self.sent,
        });
    }
}

struct Selected<'a, P> {
    journal: &'a mut journal::Journal,
    selected: P,
}

// SAFETY: this retry comes from the immutable inputs retained by Reserve.
unsafe impl depot::raw::Source<log::Retry> for Selected<'_, log::Retry> {
    type Key = storage::Key<log::NodeTag>;
    fn key(&self) -> Self::Key {
        self.selected.key()
    }
}

// SAFETY: this probe retains its original journal, generation and carrier proof.
unsafe impl depot::raw::Source<log::Probe> for Selected<'_, log::Probe> {
    type Key = storage::Key<log::NodeTag>;
    fn key(&self) -> Self::Key {
        self.selected.key()
    }
}

const _: () = {
    assert!(
        mem::size_of::<Scope<'static, o3::buffer::resident::Shared<'static>>>()
            == 4 * mem::size_of::<usize>()
    );
    assert!(
        mem::size_of::<queue::Occupied<'static, o3::buffer::storage::Shared, Insert>>()
            == 4 * mem::size_of::<usize>()
    );
    assert!(
        mem::size_of::<Option<queue::Occupied<'static, o3::buffer::storage::Shared, Insert>>>()
            == mem::size_of::<queue::Occupied<'static, o3::buffer::storage::Shared, Insert>>()
    );
};
