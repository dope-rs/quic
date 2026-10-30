use o3::{
    alloc,
    buffer::{self, write},
    depot::queue::pool,
};

use crate::wire::stream::Id;
use crate::{
    conn, errors,
    stream::{outbound, release, send},
};
use conn::stream::event::queue::Pending;
use conn::stream::{self, Error, resident, state::resident::Table};
use conn::{
    output::control,
    stream::state::transmit::{log, queue},
};
use control::kind::StreamBlock;
use log::journal;
use outbound::chunk;
use queue::{Data, Handle, Removal, Side, budget, recycle};
use release::batch;
use resident::slot::{plane, store};
use send::admit;

/// A returned prefix and the original queue budget that still accounts for it.
#[must_use]
pub(in crate::conn::stream::state::transmit) struct Released<'a, M: release::Mode> {
    source: admit::Source,
    budget: &'a mut budget::Budget,
    batch: batch::Batch<M>,
}

impl<M: release::Mode> Released<'_, M> {
    pub(in crate::conn::stream::state::transmit) fn commit<E: release::Sink<Mode = M>>(
        self,
        cause: release::Cause,
        events: &mut Pending,
        evidence: &mut E,
    ) {
        self.batch.commit(
            self.source,
            cause,
            |charge| self.budget.release(charge, events),
            evidence,
        );
    }
}

/// Admission retains this queue's sender and aggregate until both are committed.
pub(super) struct Append<'a> {
    stream: outbound::Append<'a>,
    pending: &'a mut usize,
    next: usize,
}

impl<'a> Append<'a> {
    pub(super) fn new(
        open: outbound::Open<'a>,
        pending: &'a mut usize,
        bytes: usize,
    ) -> Option<Self> {
        let stream = open.plan_append(bytes)?;
        let next = pending.checked_add(bytes)?;
        Some(Self {
            stream,
            pending,
            next,
        })
    }

    pub(super) fn commit(self, boundary: send::Boundary) {
        self.stream.commit(boundary);
        *self.pending = self.next;
    }
}

pub(crate) struct Publication<'a> {
    sender: &'a mut outbound::Sender,
    written: outbound::Written,
}

impl<'a> Publication<'a> {
    pub(crate) fn into_parts(self) -> (&'a mut outbound::Sender, outbound::Written) {
        (self.sender, self.written)
    }
}

pub(crate) struct Reclaim<'a, D: buffer::raw::Segment> {
    sender: &'a mut outbound::Sender,
    chunks: pool::Lane<'a, chunk::Node<D>>,
    buffers: &'a mut outbound::BufferCache,
    run: log::Acknowledged,
}

impl<'a, D: buffer::raw::Segment> Reclaim<'a, D> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        &'a mut outbound::Sender,
        pool::Lane<'a, chunk::Node<D>>,
        &'a mut outbound::BufferCache,
        log::Acknowledged,
    ) {
        (self.sender, self.chunks, self.buffers, self.run)
    }
}

impl<D: buffer::raw::Segment, P> Occupied<'_, D, P> {
    pub(in crate::conn::stream::state::transmit) fn mark_fin(&mut self) {
        if let Ok(open) = self.entry.get_mut().open() {
            open.mark_fin();
        }
    }

    pub(in crate::conn::stream::state::transmit) fn write(
        &mut self,
        selected: outbound::Prepared,
        out: &mut write::Append<'_>,
        limit: usize,
    ) -> Result<Option<(Handle, outbound::Written)>, alloc::Error> {
        let id = self.id();
        let (handle, entry, chunks, _, _, _) = self.split();
        Ok(selected
            .write(&entry.stream, out, limit, id, chunks.into())?
            .map(|written| (handle, written)))
    }

    /// The occupied owner retains its contribution to the aggregate through draining.
    fn discard<E: release::Sink, R>(
        &mut self,
        log: &mut journal::Journal,
        apply: impl FnOnce(
            &mut queue::Entry,
            &mut pool::Lane<'_, chunk::Node<D>>,
            &mut outbound::BufferCache,
        ) -> (batch::Batch<E::Mode>, R),
    ) -> (Released<'_, E::Mode>, R) {
        let source = admit::Source::new(self.id());
        let (_, entry, mut chunks, pending, budget, buffers) = self.split();
        let bytes = entry.view().unsent_len();
        if let Some(group) = entry.delivery_group.take() {
            log.cancel(group);
        }
        let (batch, result) = apply(entry, &mut chunks, buffers);
        *pending -= bytes;
        (
            Released {
                source,
                budget,
                batch,
            },
            result,
        )
    }

    pub(in crate::conn::stream::state::transmit) fn stop<E: release::Sink>(
        &mut self,
        log: &mut journal::Journal,
        code: errors::Code,
    ) -> Released<'_, E::Mode> {
        self.discard::<E, _>(log, |entry, chunks, buffers| {
            (entry.stream.stop::<E>(chunks, buffers, code), ())
        })
        .0
    }

    pub(in crate::conn::stream::state::transmit) fn stop_reset<E: release::Sink>(
        &mut self,
        log: &mut journal::Journal,
        control: &mut control::Pending,
        code: errors::Code,
    ) -> (Released<'_, E::Mode>, bool) {
        self.discard::<E, _>(log, |entry, chunks, buffers| {
            let (released, reset) = entry.stream.stop_reset::<E>(chunks, buffers, code);
            control.remove(&mut entry.credit.blocked);
            if reset {
                control.reset(&mut entry.reset_stream, code);
            }
            (released, reset)
        })
    }

    pub(in crate::conn::stream::state::transmit) fn reset<E: release::Sink>(
        &mut self,
        log: &mut journal::Journal,
        control: &mut control::Pending,
        code: errors::Code,
    ) -> Option<Released<'_, E::Mode>> {
        if self.state().is_reset() {
            return None;
        }
        let (released, ()) = self.discard::<E, _>(log, |entry, chunks, buffers| {
            let released = entry.stream.reset_sent::<E>(chunks, buffers, code);
            control.remove(&mut entry.credit.blocked);
            control.reset(&mut entry.reset_stream, code);
            (released, ())
        });
        Some(released)
    }

    /// Replayed bytes remain charged to this same queue's bounded budget.
    pub(in crate::conn::stream::state::transmit) fn reject_early(
        &mut self,
        log: &mut journal::Journal,
        control: &mut control::Pending,
    ) -> Result<(), conn::Error> {
        let (_, entry, _, pending, _, _) = self.split();
        if let Some(error) = entry.reset_error() {
            control.reset(&mut entry.reset_stream, error);
            entry.stream.reject_reset();
        } else {
            let replay = entry
                .stream
                .try_replay()
                .map_err(|_| conn::Error::ProtocolViolation)?;
            let next = *pending + replay.bytes();
            if let Some(group) = entry.delivery_group.take() {
                log.cancel(group);
            }
            replay.commit();
            *pending = next;
        }
        Ok(())
    }
}

impl<D: buffer::raw::Segment> Occupied<'_, D, journal::Insert> {
    pub(in crate::conn::stream::state::transmit) fn publish<R>(
        &mut self,
        written: outbound::Written,
        insert: impl FnOnce(queue::Handle, &mut Option<log::GroupId>) -> R,
    ) -> R {
        let (send, entry, _, _, _, _) = self.split();
        let result = insert(send, &mut entry.delivery_group);
        outbound::Sender::publish(Publication {
            sender: &mut entry.stream,
            written,
        });
        result
    }
}

impl<'map, D: buffer::raw::Segment> Occupied<'map, D> {
    pub(in crate::conn::stream::state::transmit) fn ack<E: release::Sink>(
        ack: log::Ack<'_, 'map, D>,
        events: &mut Pending,
        evidence: &mut E,
    ) -> (Id, outbound::Acked<()>, Self) {
        let (mut sender, run) = ack.into_parts();
        let id = sender.id();
        let (_, entry, chunks, _, budget, buffers) = sender.split();
        let acked = outbound::Sender::ack::<E, D>(Reclaim {
            sender: &mut entry.stream,
            chunks,
            buffers,
            run,
        });
        let (batch, closed) = match acked {
            outbound::Acked::Live(batch) => (batch, false),
            outbound::Acked::Closed(batch) => (batch, true),
        };
        let acked = if closed {
            entry.delivery_group = None;
            outbound::Acked::Closed(())
        } else {
            outbound::Acked::Live(())
        };
        Released {
            source: admit::Source::new(id),
            budget,
            batch,
        }
        .commit(release::Cause::Acked, events, evidence);
        (id, acked, sender)
    }
}

pub(in crate::conn) struct Occupied<'map, D: buffer::raw::Segment, P = ()> {
    pub(super) entry: store::Occupied<'map, Side, queue::Entry, (), plane::RoundRobin<Side>, P>,
    pub(super) data: &'map mut Data<D>,
}

impl<'map, D: buffer::raw::Segment, P> Occupied<'map, D, P> {
    pub(super) fn split(
        &mut self,
    ) -> (
        Handle,
        &mut queue::Entry,
        pool::Lane<'_, chunk::Node<D>>,
        &mut usize,
        &mut budget::Budget,
        &mut outbound::BufferCache,
    ) {
        use o3::depot;

        let handle = Handle::from_storage(self.entry.handle());
        // SAFETY: this exclusive capability retains a live entry and the lane allocation
        // of its original inseparable owner; the fixed domains were allocated together.
        let lane = unsafe { depot::raw::Proof::new((&mut self.data.lanes, handle.index())) }.into();
        (
            handle,
            self.entry.get_mut(),
            lane,
            &mut self.data.pending,
            &mut self.data.budget,
            &mut self.data.buffers,
        )
    }

    pub(in crate::conn) fn id(&self) -> stream::Id {
        self.entry.id()
    }

    pub(in crate::conn) fn state(&self) -> &queue::Entry {
        self.entry.get()
    }

    pub(in crate::conn) fn credit_mut(&mut self) -> &mut queue::Credit<StreamBlock> {
        &mut self.entry.get_mut().credit
    }

    pub(in crate::conn) fn refresh(&mut self) {
        let active = {
            let entry = self.entry.get_mut();
            entry.is_deferred()
                || entry.view().has_pending()
                    && matches!(entry.phase(), queue::Phase::Open | queue::Phase::Marked)
        };
        self.entry.set_active(active);
    }
}

impl<'map, D: buffer::raw::Segment> Occupied<'map, D> {
    pub(in crate::conn::stream::state::transmit) fn retire(
        retired: log::Retired<'map, D>,
        key: resident::Key,
        registry: &mut Table,
        recycle: recycle::Recycle<'_>,
    ) -> Removal {
        let sender = retired.into_inner();
        let id = sender.entry.id();
        let slot = sender.entry.handle().index();
        if registry.side::<true>().remove(key, id, slot).is_none() {
            return Removal::Absent;
        }
        sender.entry.retire(recycle);
        Removal::Removed
    }
}

impl<D: buffer::raw::Segment> Occupied<'_, D> {
    pub(in crate::conn::stream::state::transmit) fn copy(
        &mut self,
        data: &[u8],
    ) -> Result<(), Error> {
        use crate::stream::outbound::{Charge, chunk::Node};
        use o3::depot::capacity::Shortage;
        use std::num::NonZero;
        let (_, entry, mut chunks, pending, budget, buffers) = self.split();
        let Ok(open) = entry.open() else {
            return Ok(());
        };
        let Some(append) = Append::new(open, pending, data.len()) else {
            return Err(Error::ValueOutOfRange);
        };
        let Some(vacant) = chunks.vacant() else {
            return Err(Error::Chunks(Shortage {
                requested: NonZero::<usize>::MIN,
                available: 0,
            }));
        };
        let buffer = buffers.copy(data).map_err(|error| Error::Allocation {
            error,
            requested: data.len(),
        })?;
        let charge = Charge::for_buffer(&buffer);
        match budget.admit(charge) {
            Ok(()) => {}
            Err(error) => {
                budget.recycle(
                    buffers,
                    send::Parts::new(buffer, None, send::Boundary::More),
                );
                return Err(match error {
                    budget::Denied::Blocked => Error::Capacity,
                    budget::Denied::TooLarge => Error::ValueOutOfRange,
                });
            }
        }
        vacant.append(Node::Buffer(buffer));
        budget.commit(charge, buffers);
        append.commit(send::Boundary::More);
        self.refresh();
        Ok(())
    }
}
