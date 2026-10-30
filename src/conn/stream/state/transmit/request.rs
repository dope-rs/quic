use o3::buffer;

use crate::stream::release;

use crate::wire::stream::Id;
use crate::{conn, errors, proto, stream};

use conn::output::control;
use conn::stream::event::queue::Pending;
use conn::stream::state::streams;
use conn::stream::state::transmit::log::journal;
use conn::stream::{Access, Error, Streams, resident, state::transmit};
use proto::param;
use transmit::queue;

pub(in crate::conn) struct Request<'a, E, T> {
    target: T,
    error: errors::Code,
    params: Option<&'a param::Set>,
    ready: bool,
    ctrl: &'a mut control::Pending,
    proof: &'a mut E,
}

impl<'a, E, T> Request<'a, E, T> {
    pub(in crate::conn) fn new(
        target: T,
        error: errors::Code,
        params: Option<&'a param::Set>,
        ready: bool,
        ctrl: &'a mut control::Pending,
        proof: &'a mut E,
    ) -> Self {
        Self {
            target,
            error,
            params,
            ready,
            ctrl,
            proof,
        }
    }
}

struct Commit<'a, E> {
    error: errors::Code,
    ctrl: &'a mut control::Pending,
    log: &'a mut journal::Journal,
    proof: &'a mut E,
    events: &'a mut Pending,
}

impl<E: release::Sink> Commit<'_, E> {
    fn apply<D: buffer::raw::Segment>(self, mut slot: queue::Occupied<'_, D>) {
        let Self {
            error,
            ctrl,
            log,
            proof,
            events,
        } = self;
        let Some(freed) = slot.reset::<E>(log, ctrl, error) else {
            return;
        };
        freed.commit(release::Cause::Reset, events, proof);
        slot.refresh();
    }
}

impl<E: release::Sink> Request<'_, E, Id> {
    pub(in crate::conn) fn apply<B: stream::Recv, D: buffer::raw::Segment>(
        self,
        sender: &mut transmit::Sender<'_, B, D>,
    ) -> Result<(), Error> {
        let Self {
            target: id,
            error,
            params,
            ready,
            ctrl,
            proof,
        } = self;
        sender.validate(id, Access::Send, ready)?;
        if sender.is_send_done(id) {
            return Ok(());
        }
        let stream = streams::Relative::new(id, sender.local());
        let credit = queue::Entry::limit(params, stream);
        let mode = queue::Preparation::new(stream);
        let Streams { state, events } = &mut *sender.streams;
        let (slots, tx) = (&mut state.resident, &mut state.transmit);
        let (log, map) = (&mut tx.deliveries, &mut tx.map);
        let Some(slot) =
            map.try_prepared(queue::Id::new(id), None, credit, mode, slots, |_, slot| {
                slot
            })?
        else {
            return Ok(());
        };
        Commit {
            error,
            ctrl,
            log,
            proof,
            events,
        }
        .apply(slot);
        Ok(())
    }
}

impl<E: release::Sink> Request<'_, E, resident::Local> {
    pub(in crate::conn) fn try_apply<B: stream::Recv, D: buffer::raw::Segment>(
        self,
        sender: &mut transmit::Sender<'_, B, D>,
    ) -> Result<(), resident::Error> {
        let Self {
            target: local,
            error,
            params,
            ready,
            ctrl,
            proof,
        } = self;
        let id = local.id();
        sender
            .validate(id, Access::Send, ready)
            .map_err(resident::Error::Stream)?;
        if sender.is_send_done(id) {
            return Ok(());
        }
        let stream = streams::Relative::new(id, sender.local());
        let credit = queue::Entry::limit(params, stream);
        let Streams { state, events } = &mut *sender.streams;
        let (slots, tx) = (&mut state.resident, &mut state.transmit);
        let (log, map) = (&mut tx.deliveries, &mut tx.map);
        let Some(slot) = map.try_live(local, credit, queue::Preparation::new(stream), slots)?
        else {
            return Ok(());
        };
        Commit {
            error,
            ctrl,
            log,
            proof,
            events,
        }
        .apply(slot);
        Ok(())
    }
}
